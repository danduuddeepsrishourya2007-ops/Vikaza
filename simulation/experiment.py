"""Comparable seeded experiments for baseline and model-backed decision providers."""
from __future__ import annotations

from typing import Any, Callable

from scenarios.cyber_containment import SCENARIO_ID, build_initial_world, policy_config
from simulation.baselines import DoNothingProvider, ScriptedDefensiveProvider
from simulation.policy import ContainmentStrategy
from simulation.replay import run_and_record, replay_trace
from simulation.evaluation import summarize_world


def configured_world(seed: int):
    world = build_initial_world(seed)
    world.state.active_policy = policy_config("nexus_experiment", ContainmentStrategy.IMMEDIATE)
    return world


def evaluate_provider(provider, policy_id: str, seed: int = 7, max_ticks: int = 5,
                      verify_replay: bool = True) -> dict[str, Any]:
    """Run one provider with a fixed seed and return trace plus measured outcomes."""
    if not policy_id.strip():
        raise ValueError("policy_id must not be empty")
    if max_ticks < 1:
        raise ValueError("max_ticks must be positive")
    world = configured_world(seed)
    initial_resources = dict(world.state.resource_pool)
    trace = run_and_record(world, provider, policy_id, max_ticks=max_ticks)
    if verify_replay:
        final_world = replay_trace(trace.to_json(), configured_world)
    else:
        final_world = world
    return {
        "policy_id": policy_id,
        "scenario_id": SCENARIO_ID,
        "seed": seed,
        "max_ticks": max_ticks,
        "metrics": summarize_world(final_world, initial_resources),
        "replay_verified": verify_replay,
        "trace": trace.to_dict(),
        "provider_stats": _provider_stats(provider),
    }


def compare_providers(providers: list[tuple[str, Callable[[], Any]]], seeds: list[int],
                      max_ticks: int = 5) -> dict[str, Any]:
    """Evaluate each provider on every seed, constructing a fresh provider each run."""
    if not providers:
        raise ValueError("at least one provider is required")
    if not seeds:
        raise ValueError("at least one seed is required")
    if len(set(seeds)) != len(seeds):
        raise ValueError("seeds must be unique")
    runs = []
    for seed in seeds:
        for policy_id, factory in providers:
            runs.append(evaluate_provider(factory(), policy_id, seed, max_ticks))
    grouped: dict[str, dict[str, Any]] = {}
    for run in runs:
        row = grouped.setdefault(run["policy_id"], {"run_count": 0, "metrics": {}})
        row["run_count"] += 1
        for key, value in run["metrics"].items():
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                row["metrics"].setdefault(key, []).append(value)
    summaries = {}
    for policy_id, row in grouped.items():
        summaries[policy_id] = {
            "run_count": row["run_count"],
            "mean_metrics": {
                key: round(sum(values) / len(values), 4)
                for key, values in sorted(row["metrics"].items()) if values
            },
        }
    return {
        "report_version": 1,
        "scenario_id": SCENARIO_ID,
        "seeds": list(seeds),
        "max_ticks": max_ticks,
        "summaries": summaries,
        "runs": runs,
    }


def baseline_provider_factories():
    return [
        (DoNothingProvider.policy_id, DoNothingProvider),
        (ScriptedDefensiveProvider.policy_id, ScriptedDefensiveProvider),
    ]


def _provider_stats(provider) -> dict[str, Any] | None:
    """Expose safe numeric counters without leaking endpoint URLs or credentials."""
    result: dict[str, Any] = {}
    stats = getattr(provider, "stats", None)
    if stats is not None and hasattr(stats, "__dict__"):
        result["wrapper"] = dict(vars(stats))
    primary = getattr(provider, "primary", None)
    if primary is not None:
        result["primary"] = {
            key: getattr(primary, key)
            for key in ("calls", "failures", "total_latency_seconds")
            if isinstance(getattr(primary, key, None), (int, float))
        }
    return result or None
