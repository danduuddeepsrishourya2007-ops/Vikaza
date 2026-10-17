"""Versioned JSON traces and deterministic decision-driven replay."""
from __future__ import annotations

from dataclasses import asdict, dataclass, is_dataclass
from typing import Any, Callable
import json

from .actions import ActionType, AgentDecision
from .decision_provider import DecisionProvider, collect_decisions
from .events import Event
from .world import World

TRACE_VERSION = 1


class TraceError(ValueError):
    """Raised when a trace is malformed or incompatible with the runner."""


def _json_safe(value: Any) -> Any:
    if isinstance(value, set | frozenset):
        return sorted(_json_safe(item) for item in value)
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    if hasattr(value, "value") and isinstance(value.value, (str, int, float, bool)):
        return value.value
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise TypeError(f"Value is not JSON serializable: {type(value).__name__}")


def _policy_snapshot(policy: Any) -> Any:
    """Serialize the active policy, including nested policy configuration."""
    if policy is None:
        return None
    if is_dataclass(policy):
        return _json_safe(asdict(policy))
    if hasattr(policy, "__dict__"):
        return _json_safe(vars(policy))
    raise TraceError(
        f"Cannot snapshot active policy of type {type(policy).__name__}"
    )


def _scheduler_snapshot(world: World) -> dict[str, Any]:
    """Capture pending scheduler work without pretending callbacks are portable."""
    scheduler = world.scheduler
    pending = []
    for tick, sequence, item in sorted(scheduler._event_queue):
        if item.callback is not None:
            callback_name = getattr(item.callback, "__qualname__", type(item.callback).__name__)
            raise TraceError(
                "Cannot verify replay with pending scheduler callback "
                f"{callback_name!r}; callback serialization is unsupported"
            )
        if item.event is None:
            raise TraceError(
                f"Cannot snapshot scheduler item {item.schedule_id!r} without an event or callback"
            )
        pending.append({
            "tick": tick,
            "sequence": sequence,
            "schedule_id": item.schedule_id,
            "event": _json_safe(item.event.to_dict()),
        })
    return {
        "sequence_count": scheduler._sequence_count,
        "pending": pending,
    }


def world_snapshot(world: World) -> dict[str, Any]:
    """Stable JSON-compatible snapshot used to verify replay equivalence."""
    state = world.state

    def fields(obj):
        return {key: _json_safe(value) for key, value in vars(obj).items()}

    try:
        rng_state = _json_safe(world.random_generator.getstate())
    except (AttributeError, TypeError) as exc:
        raise TraceError("World random generator does not expose a serializable state") from exc

    return {
        "tick": state.tick,
        "rng_seed": state.rng_seed,
        "rng_state": rng_state,
        "scenario_id": state.scenario_id,
        "hosts": {key: fields(value) for key, value in sorted(state.hosts.items())},
        "network": {key: sorted(value) for key, value in sorted(state.network.items())},
        "agents": {key: fields(value) for key, value in sorted(state.agents.items())},
        "data_stores": {key: fields(value) for key, value in sorted(state.data_stores.items())},
        "resource_pool": _json_safe(state.resource_pool),
        "metrics_snapshot": _json_safe(state.metrics_snapshot),
        "active_policy": _policy_snapshot(state.active_policy),
        "scheduler": _scheduler_snapshot(world),
        "next_event_id": state.next_event_id,
        "events": [_json_safe(event.to_dict()) for event in state.events],
    }


def decision_to_dict(decision: AgentDecision) -> dict[str, Any]:
    result = {
        "agent_id": decision.agent_id,
        "tick": decision.tick,
        "action_type": decision.action_type.value,
        "target": decision.target,
        "rationale": decision.rationale,
        "source": decision.source,
    }
    if decision.failure_reason is not None:
        result["failure_reason"] = decision.failure_reason
    return result


def decision_from_dict(data: Any) -> AgentDecision:
    if not isinstance(data, dict):
        raise TraceError("Each recorded decision must be an object")

    required = {"agent_id", "tick", "action_type", "target", "rationale", "source"}
    allowed = required | {"failure_reason"}

    if not required.issubset(data):
        raise TraceError(f"Decision is missing fields: {sorted(required - set(data))}")
    if set(data) - allowed:
        raise TraceError(f"Decision contains unsupported fields: {sorted(set(data) - allowed)}")

    if not isinstance(data["source"], str) or data["source"] not in {
        "scripted", "fallback_heuristic", "llm"
    }:
        raise TraceError(
            "Decision source must be scripted, fallback_heuristic, or llm"
        )

    try:
        action_type = ActionType(data["action_type"])
    except (ValueError, TypeError) as exc:
        raise TraceError(f"Invalid recorded decision action_type: {exc}") from exc

    if not isinstance(data["agent_id"], str) or not data["agent_id"].strip() or len(data["agent_id"]) > 128:
        raise TraceError("Decision agent_id must be a non-empty string of at most 128 characters")
    if not isinstance(data["rationale"], str) or len(data["rationale"]) > 500:
        raise TraceError("Decision rationale must be a string of at most 500 characters")
    if data["target"] is not None and (
        not isinstance(data["target"], str)
        or not data["target"].strip()
        or len(data["target"]) > 256
    ):
        raise TraceError("Decision target must be null or a non-empty string of at most 256 characters")
    if data.get("failure_reason") is not None and (
        not isinstance(data["failure_reason"], str)
        or len(data["failure_reason"]) > 128
    ):
        raise TraceError("Decision failure_reason must be null or a string of at most 128 characters")
    if not isinstance(data["tick"], int) or isinstance(data["tick"], bool) or data["tick"] < 0:
        raise TraceError("Decision tick must be a non-negative integer")
    if action_type == ActionType.NO_OP and data["target"] is not None:
        raise TraceError("NO_OP target must be null")

    return AgentDecision(
        agent_id=data["agent_id"],
        tick=data["tick"],
        action_type=action_type,
        target=data["target"],
        rationale=data["rationale"],
        source=data["source"],
        failure_reason=data.get("failure_reason"),
    )


@dataclass
class SimulationTrace:
    trace_version: int
    scenario_id: str
    seed: int
    policy_id: str
    max_ticks: int
    decisions_by_tick: list[list[dict[str, Any]]]
    expected_final_snapshot: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "trace_version": self.trace_version,
            "scenario_id": self.scenario_id,
            "seed": self.seed,
            "policy_id": self.policy_id,
            "max_ticks": self.max_ticks,
            "decisions_by_tick": self.decisions_by_tick,
            "expected_final_snapshot": self.expected_final_snapshot,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"), allow_nan=False)

    @classmethod
    def from_json(cls, value: str) -> "SimulationTrace":
        try:
            data = json.loads(value)
        except (TypeError, json.JSONDecodeError) as exc:
            raise TraceError(f"Trace is not valid JSON: {exc}") from exc
        if not isinstance(data, dict):
            raise TraceError("Trace root must be a JSON object")
        required = {"trace_version", "scenario_id", "seed", "policy_id", "max_ticks", "decisions_by_tick", "expected_final_snapshot"}
        if not required.issubset(data):
            raise TraceError(f"Trace is missing fields: {sorted(required - set(data))}")
        if data["trace_version"] != TRACE_VERSION:
            raise TraceError(f"Unsupported trace version: {data['trace_version']!r}")
        if not isinstance(data["seed"], int) or isinstance(data["seed"], bool):
            raise TraceError("Trace seed must be an integer")
        if not isinstance(data["max_ticks"], int) or isinstance(data["max_ticks"], bool) or data["max_ticks"] < 1:
            raise TraceError("Trace max_ticks must be a positive integer")
        rows = data["decisions_by_tick"]
        if not isinstance(rows, list) or len(rows) != data["max_ticks"] or any(not isinstance(row, list) for row in rows):
            raise TraceError("decisions_by_tick must contain exactly max_ticks decision lists")
        for tick, row in enumerate(rows):
            for item in row:
                decision = decision_from_dict(item)
                if decision.tick != tick:
                    raise TraceError(f"Decision tick {decision.tick} is stored under tick {tick}")
        if not isinstance(data["expected_final_snapshot"], dict):
            raise TraceError("expected_final_snapshot must be an object")
        if not isinstance(data["scenario_id"], str) or not data["scenario_id"]:
            raise TraceError("scenario_id must be a non-empty string")
        if not isinstance(data["policy_id"], str) or not data["policy_id"]:
            raise TraceError("policy_id must be a non-empty string")
        return cls(**{key: data[key] for key in required})


def run_and_record(world: World, provider: DecisionProvider, policy_id: str, max_ticks: int = 5) -> SimulationTrace:
    if max_ticks < 1:
        raise ValueError("max_ticks must be positive")
    if world.state.tick != 0:
        raise ValueError("Recording requires a fresh world at tick 0")
    if not isinstance(policy_id, str) or not policy_id.strip():
        raise ValueError("policy_id must be a non-empty string")
    rows: list[list[dict[str, Any]]] = []
    for _ in range(max_ticks):
        decisions = collect_decisions(world, provider)
        rows.append([decision_to_dict(item) for item in decisions])
        world.apply_decisions(decisions)
        world.step()
    return SimulationTrace(
        trace_version=TRACE_VERSION,
        scenario_id=world.state.scenario_id,
        seed=world.state.rng_seed,
        policy_id=policy_id,
        max_ticks=max_ticks,
        decisions_by_tick=rows,
        expected_final_snapshot=world_snapshot(world),
    )


def replay_trace(trace: SimulationTrace | str, world_factory: Callable[[int], World]) -> World:
    """Replay recorded decisions through the authoritative engine and verify result."""
    if isinstance(trace, str):
        trace = SimulationTrace.from_json(trace)
    elif isinstance(trace, SimulationTrace):
        # Validate manually constructed objects through the same strict parser
        # used for serialized traces before trusting their tick/decision layout.
        try:
            trace = SimulationTrace.from_json(trace.to_json())
        except (TypeError, ValueError) as exc:
            if isinstance(exc, TraceError):
                raise
            raise TraceError(f"Invalid trace object: {exc}") from exc
    else:
        raise TraceError("trace must be SimulationTrace or JSON text")
    world = world_factory(trace.seed)
    if world.state.scenario_id != trace.scenario_id:
        raise TraceError(
            f"Scenario mismatch: trace={trace.scenario_id!r}, world={world.state.scenario_id!r}"
        )
    if world.state.tick != 0:
        raise TraceError("Replay factory must return a fresh world at tick 0")
    if world.state.rng_seed != trace.seed:
        raise TraceError(
            f"Seed mismatch: trace={trace.seed!r}, world={world.state.rng_seed!r}"
        )
    for tick, row in enumerate(trace.decisions_by_tick):
        if world.state.tick != tick:
            raise TraceError(f"Replay tick mismatch: expected {tick}, got {world.state.tick}")
        decisions = [decision_from_dict(item) for item in row]
        world.apply_decisions(decisions)
        world.step()
    actual = world_snapshot(world)
    if actual != trace.expected_final_snapshot:
        raise TraceError("Replay result does not match the recorded final snapshot")
    return world
