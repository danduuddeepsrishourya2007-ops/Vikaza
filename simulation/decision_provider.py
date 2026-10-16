"""Decision-provider boundary for deterministic and future model-backed agents."""
from __future__ import annotations

from typing import Mapping, Protocol, Sequence

from .actions import ActionType, AgentDecision
from .observations import AgentView, observe
from .world import World


class DecisionProvider(Protocol):
    """Provider returns a proposed decision; it never mutates world state."""
    def decide(self, view: AgentView) -> AgentDecision: ...


class ScriptedProvider:
    """Deterministic provider keyed by (agent_id, tick), with safe NO_OP fallback."""
    def __init__(self, decisions: Mapping[tuple[str, int], AgentDecision] | None = None):
        self._decisions = dict(decisions or {})

    def decide(self, view: AgentView) -> AgentDecision:
        decision = self._decisions.get((view.agent_id, view.tick))
        if decision is None:
            return AgentDecision(
                agent_id=view.agent_id,
                tick=view.tick,
                action_type=ActionType.NO_OP,
                target=None,
                rationale="No scripted decision configured for this agent and tick",
                source="scripted",
            )
        # Return a fresh value object, not the provider's stored instance.
        return AgentDecision(
            agent_id=decision.agent_id,
            tick=decision.tick,
            action_type=decision.action_type,
            target=decision.target,
            rationale=decision.rationale,
            source=decision.source,
        )


def collect_decisions(world: World, provider: DecisionProvider) -> list[AgentDecision]:
    """Ask the provider once per active agent in stable ID order.

    Provider output is checked for agent/tick identity before it is returned.
    Authoritative action legality is still checked by World.apply_decisions.
    """
    decisions: list[AgentDecision] = []
    for agent_id in sorted(world.state.agents):
        agent = world.state.agents[agent_id]
        if getattr(agent, "status", "active") != "active":
            continue
        view = observe(world, agent_id)
        decision = provider.decide(view)
        if not isinstance(decision, AgentDecision):
            raise TypeError(f"Provider returned {type(decision).__name__}, expected AgentDecision")
        if decision.agent_id != agent_id:
            raise ValueError(f"Provider decision agent_id {decision.agent_id!r} does not match view {agent_id!r}")
        if decision.tick != world.state.tick:
            raise ValueError(f"Provider decision tick {decision.tick} does not match world tick {world.state.tick}")
        decisions.append(decision)
    return decisions


def run_provider_tick(world: World, provider: DecisionProvider):
    """Collect scoped decisions and hand them to the existing authoritative engine.

    Does not advance the clock; caller controls when World.step() occurs.
    """
    decisions = collect_decisions(world, provider)
    return world.apply_decisions(decisions)
