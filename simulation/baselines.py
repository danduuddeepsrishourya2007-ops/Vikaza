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
            if host.isolated and not host.is_compromised:
                return self._decision(view, ActionType.UNISOLATE_HOST, host.host_id,
                                      "Reconnect the remediated host after containment")
        for host in hosts:
            if not host.isolated and not host.is_compromised and any(
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


class AttackScenarioProvider:
    """Compose a deterministic simulated red-team sequence with a defender policy.

    This provider only proposes actions against the in-memory cyber simulation.
    It never opens sockets or interacts with real hosts. Decisions are tick-based
    so the sequence is reproducible and recorded traces can be replayed exactly.
    """

    def __init__(self, defender_provider):
        self.defender_provider = defender_provider

    def decide(self, view: AgentView) -> AgentDecision:
        if view.role != "attacker":
            return self.defender_provider.decide(view)

        current = next((host for host in view.hosts if host.host_id == view.current_host), None)
        if current is None or current.isolated or not current.is_compromised:
            return self._noop(view, "Attacker has no active non-isolated foothold")

        sequence = {
            0: (ActionType.CREDENTIAL_DUMP, view.current_host, "Simulate credential access on the initial compromised host"),
            1: (ActionType.LATERAL_MOVE, "application_server", "Simulate lateral movement to the application tier"),
            2: (ActionType.COMMAND_AND_CONTROL, "application_server", "Establish simulated command-and-control on the application tier"),
            3: (ActionType.LATERAL_MOVE, "customer_database", "Simulate lateral movement to the database tier"),
            4: (ActionType.COMMAND_AND_CONTROL, "customer_database", "Establish simulated command-and-control on the database tier"),
            5: (ActionType.DATA_EXFILTRATION, "customer_database", "Simulate exfiltration of the database data store"),
            6: (ActionType.IMPACT, "customer_database", "Simulate service disruption on the database host"),
        }
        item = sequence.get(view.tick)
        if item is None:
            return self._noop(view, "Red-team scenario sequence is complete")
        action, target, rationale = item
        return AgentDecision(
            agent_id=view.agent_id, tick=view.tick, action_type=action,
            target=target, rationale=rationale, source="scripted",
        )

    @staticmethod
    def _noop(view: AgentView, rationale: str) -> AgentDecision:
        return AgentDecision(
            agent_id=view.agent_id, tick=view.tick, action_type=ActionType.NO_OP,
            target=None, rationale=rationale, source="scripted",
        )
