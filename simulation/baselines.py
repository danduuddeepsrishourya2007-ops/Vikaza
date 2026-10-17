"""Deterministic, observation-only baseline decision providers."""
from __future__ import annotations

from .actions import ActionType, AgentDecision
from .observations import AgentView


class DoNothingProvider:
    """Return a safe NO_OP for every observed agent."""

    policy_id = "do_nothing_v1"

    def decide(self, view: AgentView) -> AgentDecision:
        return AgentDecision(
            agent_id=view.agent_id,
            tick=view.tick,
            action_type=ActionType.NO_OP,
            target=None,
            rationale="Do-nothing baseline",
            source="scripted",
        )


class ScriptedDefensiveProvider:
    """Apply a deterministic isolate-then-patch defensive rule.

    The policy reads only the supplied AgentView. In the standard cyber
    scenario the security engineer acts; the IT administrator emits NO_OP to
    avoid duplicate decisions for the same target. This baseline is scoped to
    the standard scenario's role assignment rather than inferring hidden agents.
    """

    policy_id = "scripted_defensive_v1"

    def decide(self, view: AgentView) -> AgentDecision:
        if view.role not in {"security_engineer", "it_administrator"}:
            return self._noop(view, "Role is not authorized for baseline defense")

        # The scenario's security engineer is the single active strategist;
        # the IT administrator emits NO_OP to avoid duplicate target actions.
        if view.role == "it_administrator":
            return self._noop(view, "Security engineer has primary response responsibility")

        hosts = sorted(view.hosts, key=lambda host: host.host_id)
        for host in hosts:
            if host.is_compromised and not host.isolated:
                return self._decision(view, ActionType.ISOLATE_HOST, host.host_id,
                                      "Isolate a compromised host before remediation")
        for host in hosts:
            if host.is_compromised and host.isolated:
                return self._decision(view, ActionType.PATCH_HOST, host.host_id,
                                      "Patch an isolated compromised host")
        for host in hosts:
            if host.isolated and not host.is_compromised and any(
                not running for _, running in host.running_services
            ):
                return self._decision(view, ActionType.RESTORE_SERVICE, host.host_id,
                                      "Restore services after remediation")
        return self._noop(view, "No eligible defensive action is currently required")

    @staticmethod
    def _decision(view: AgentView, action: ActionType, target: str, rationale: str) -> AgentDecision:
        return AgentDecision(
            agent_id=view.agent_id,
            tick=view.tick,
            action_type=action,
            target=target,
            rationale=rationale,
            source="scripted",
        )

    @staticmethod
    def _noop(view: AgentView, rationale: str) -> AgentDecision:
        return AgentDecision(
            agent_id=view.agent_id,
            tick=view.tick,
            action_type=ActionType.NO_OP,
            target=None,
            rationale=rationale,
            source="scripted",
        )


def build_baseline(policy_id: str):
    """Construct a baseline by its stable identifier."""
    if policy_id == DoNothingProvider.policy_id:
        return DoNothingProvider()
    if policy_id == ScriptedDefensiveProvider.policy_id:
        return ScriptedDefensiveProvider()
    raise ValueError(f"Unknown baseline policy_id: {policy_id!r}")
