"""
Executable Nexus Cyber demonstration scenario and policy comparison.

This module uses the existing World decision/transition pipeline. Metrics are
computed from state and emitted events; no outcome values are hard-coded.
"""
from __future__ import annotations

from copy import deepcopy
from typing import Any

from simulation.actions import ActionType, AgentDecision
from simulation.policy import ContainmentStrategy, PolicyConfig
from simulation.world import AgentState, DataStoreState, HostState, World


SCENARIO_ID = "nexus_cyber_containment_v1"


def build_initial_world(seed: int = 7) -> World:
    """Build the same initial cyber environment for every policy run."""
    world = World(seed=seed)
    state = world.state
    state.scenario_id = SCENARIO_ID
    state.tick = 0
    state.hosts = {
        "developer_workstation": HostState(
            host_id="developer_workstation",
            hostname="dev-workstation-01",
            os_type="Linux",
            os_version="Ubuntu 24.04",
            ip_address="10.0.1.10",
            is_compromised=True,
            privilege_level=1,
            running_services={"developer_access": True},
            open_ports={22, 443},
            known_vulnerabilities=["stolen_credentials"],
        ),
        "application_server": HostState(
            host_id="application_server",
            hostname="app-01",
            os_type="Linux",
            os_version="Ubuntu 24.04",
            ip_address="10.0.2.10",
            running_services={"customer_api": True, "web": True},
            open_ports={443, 8443},
            known_vulnerabilities=["unpatched_application"],
        ),
        "customer_database": HostState(
            host_id="customer_database",
            hostname="db-01",
            os_type="Linux",
            os_version="Ubuntu 24.04",
            ip_address="10.0.3.10",
            running_services={"database": True},
            open_ports={5432},
            known_vulnerabilities=["weak_service_account"],
            data_stores=["customer_records"],
        ),
    }
    state.network = {
        "developer_workstation": {"application_server"},
        "application_server": {"developer_workstation", "customer_database"},
        "customer_database": {"application_server"},
    }
    state.data_stores = {
        "customer_records": DataStoreState(
            store_id="customer_records",
            name="Customer records",
            store_type="relational",
            location_host="customer_database",
            size_gb=50.0,
            sensitivity_level="high",
            encryption_enabled=True,
            backup_enabled=True,
        )
    }
    state.agents = {
        "security_engineer_1": AgentState(
            agent_id="security_engineer_1",
            role="security_engineer",
            current_host=None,
        ),
        "it_admin_1": AgentState(
            agent_id="it_admin_1",
            role="it_administrator",
            current_host=None,
        ),
    }
    state.resource_pool = {"analyst_hours": 20.0}
    return world


def build_attack_world(seed: int = 7) -> World:
    """Build the same network with a deterministic simulated attacker agent.

    Kept separate from ``build_initial_world`` so legacy baseline and scaling
    benchmark sizes remain stable and comparable.
    """
    world = build_initial_world(seed)
    world.state.agents["attacker_1"] = AgentState(
        agent_id="attacker_1",
        role="attacker",
        current_host="developer_workstation",
    )
    world.state.scenario_id = "nexus_cyber_attack_v1"
    return world


def policy_config(name: str, strategy: ContainmentStrategy) -> PolicyConfig:
    return PolicyConfig(
        name=name,
        containment_strategy=strategy,
        isolation_confidence_threshold=0.5,
        allowed_actions=[
            ActionType.INVESTIGATE_HOST.value,
            ActionType.ISOLATE_HOST.value,
            ActionType.UNISOLATE_HOST.value,
            ActionType.PATCH_HOST.value,
            ActionType.RESTORE_SERVICE.value,
            ActionType.BLOCK_CONNECTION.value,
            ActionType.NOTIFY_CUSTOMERS.value,
            ActionType.ESCALATE_INCIDENT.value,
            ActionType.NETWORK_SCAN.value,
            ActionType.PORT_SCAN.value,
            ActionType.VULNERABILITY_SCAN.value,
            ActionType.CREDENTIAL_DUMP.value,
            ActionType.PRIVILEGE_ESCALATION.value,
            ActionType.PERSISTENCE.value,
            ActionType.LATERAL_MOVE.value,
            ActionType.DATA_EXFILTRATION.value,
            ActionType.COMMAND_AND_CONTROL.value,
            ActionType.DEFENSE_EVASION.value,
            ActionType.IMPACT.value,
            ActionType.NO_OP.value,
        ],
        communication_delay_ticks=0,
        role_priority={"security_engineer": 0, "it_administrator": 1},
    )


def _decision(tick: int, action: ActionType, target: str | None, rationale: str) -> AgentDecision:
    actor = "security_engineer_1" if action in {
        ActionType.INVESTIGATE_HOST, ActionType.ISOLATE_HOST,
        ActionType.BLOCK_CONNECTION, ActionType.NOTIFY_CUSTOMERS,
        ActionType.ESCALATE_INCIDENT,
    } else "it_admin_1"
    return AgentDecision(
        agent_id=actor,
        tick=tick,
        action_type=action,
        target=target,
        rationale=rationale,
        source="scripted",
    )


def run_policy(name: str, strategy: ContainmentStrategy, seed: int = 7) -> dict[str, Any]:
    """Run one deterministic policy against a fresh, equivalent initial world."""
    world = build_initial_world(seed)
    world.state.active_policy = policy_config(name, strategy)
    initial_resources = dict(world.state.resource_pool)
    timeline: list[dict[str, Any]] = []
    action_schedule: dict[int, list[AgentDecision]] = {}

    if strategy is ContainmentStrategy.IMMEDIATE:
        action_schedule[0] = [
            _decision(0, ActionType.ISOLATE_HOST, "developer_workstation",
                      "Immediately isolate the host associated with compromised credentials")
        ]
        action_schedule[1] = [
            _decision(1, ActionType.PATCH_HOST, "developer_workstation",
                      "Patch and remediate the compromised workstation")
        ]
        action_schedule[2] = [
            _decision(2, ActionType.UNISOLATE_HOST, "developer_workstation",
                      "Reconnect the remediated workstation after containment")
        ]
        action_schedule[3] = [
            _decision(3, ActionType.RESTORE_SERVICE, "developer_workstation",
                      "Restore approved workstation services after remediation")
        ]
    elif strategy is ContainmentStrategy.GRADUAL:
        action_schedule[0] = [
            _decision(0, ActionType.INVESTIGATE_HOST, "developer_workstation",
                      "Investigate the alert before disruptive containment")
        ]
        action_schedule[1] = [
            _decision(1, ActionType.ISOLATE_HOST, "developer_workstation",
                      "Isolate after investigation confirms a compromise")
        ]
        action_schedule[2] = [
            _decision(2, ActionType.PATCH_HOST, "developer_workstation",
                      "Patch and remediate the compromised workstation")
        ]
        action_schedule[3] = [
            _decision(3, ActionType.UNISOLATE_HOST, "developer_workstation",
                      "Reconnect the remediated workstation after containment")
        ]
        action_schedule[4] = [
            _decision(4, ActionType.RESTORE_SERVICE, "developer_workstation",
                      "Restore approved workstation services after remediation")
        ]

    max_ticks = 5
    first_isolation_tick = None
    compromise_cleared_tick = None
    for _ in range(max_ticks):
        tick = world.state.tick
        decisions = action_schedule.get(tick, [])
        results = world.apply_decisions(decisions) if decisions else []
        host = world.state.hosts["developer_workstation"]
        if host.isolated and first_isolation_tick is None:
            first_isolation_tick = tick
        if not host.is_compromised and compromise_cleared_tick is None:
            compromise_cleared_tick = tick
        running_services = sum(
            sum(1 for running in h.running_services.values() if running)
            for h in world.state.hosts.values()
        )
        total_services = sum(len(h.running_services) for h in world.state.hosts.values())
        timeline.append({
            "tick": tick,
            "actions": [
                {"agent_id": item.agent_id, "action": item.action_type.value,
                 "target": item.target, "rationale": item.rationale}
                for item in decisions
            ],
            "accepted_actions": len(results),
            "compromised_hosts": sum(1 for h in world.state.hosts.values() if h.is_compromised),
            "isolated_hosts": sum(1 for h in world.state.hosts.values() if h.isolated),
            "services_running": running_services,
            "services_total": total_services,
            "events": [e.to_dict() for e in world.state.events if e.tick == tick],
        })
        world.step()

    final_state = world.state
    event_counts: dict[str, int] = {}
    for event in final_state.events:
        event_counts[event.event_type] = event_counts.get(event.event_type, 0) + 1
    return {
        "policy": name,
        "strategy": strategy.value,
        "seed": seed,
        "scenario_id": SCENARIO_ID,
        "initial_state": {
            "hosts": sorted(build_initial_world(seed).state.hosts.keys()),
            "compromised_hosts": 1,
            "resource_pool": initial_resources,
        },
        "metrics": {
            "final_compromised_hosts": sum(1 for h in final_state.hosts.values() if h.is_compromised),
            "final_isolated_hosts": sum(1 for h in final_state.hosts.values() if h.isolated),
            "final_services_running": sum(
                1 for h in final_state.hosts.values()
                for running in h.running_services.values() if running
            ),
            "total_services": sum(len(h.running_services) for h in final_state.hosts.values()),
            "events_recorded": len(final_state.events),
            "actions_accepted": sum(item["accepted_actions"] for item in timeline),
            "first_isolation_tick": first_isolation_tick,
            "compromise_cleared_tick": compromise_cleared_tick,
            "actions_rejected": sum(1 for e in final_state.events if e.event_type == "AgentActionRejected"),
            "analyst_hours_used": round(
                initial_resources.get("analyst_hours", 0.0)
                - final_state.resource_pool.get("analyst_hours", 0.0), 3
            ),
            "resource_pool_remaining": dict(final_state.resource_pool),
        },
        "event_counts": event_counts,
        "timeline": timeline,
    }


def compare_containment_policies(seed: int = 7) -> dict[str, Any]:
    """Run both policies from equivalent initial states and return comparable data."""
    immediate = run_policy("Immediate containment", ContainmentStrategy.IMMEDIATE, seed)
    gradual = run_policy("Gradual containment", ContainmentStrategy.GRADUAL, seed)
    return {
        "scenario_id": SCENARIO_ID,
        "seed": seed,
        "comparison": [immediate, gradual],
        "same_initial_host_ids": (
            immediate["initial_state"]["hosts"] == gradual["initial_state"]["hosts"]
        ),
    }
