"""End-to-end tests for simulated red-team behavior inside the in-memory world."""
from scenarios.cyber_containment import build_attack_world, policy_config
from simulation.actions import ActionType, AgentDecision
from simulation.experiment import attack_provider_factories, compare_providers, configured_attack_world
from simulation.policy import ContainmentStrategy


def _act(world, action, target):
    decision = AgentDecision(
        agent_id="attacker_1",
        tick=world.state.tick,
        action_type=action,
        target=target,
        rationale="Deterministic simulated red-team test action",
        source="scripted",
    )
    result = world.apply_decisions([decision])
    assert len(result) == 1, [event.to_dict() for event in world.state.events]
    world.step()


def test_attacker_actions_have_deterministic_in_memory_effects():
    world = build_attack_world(seed=7)
    world.state.active_policy = policy_config("attack_test", ContainmentStrategy.IMMEDIATE)

    _act(world, ActionType.NETWORK_SCAN, "developer_workstation")
    _act(world, ActionType.PORT_SCAN, "developer_workstation")
    _act(world, ActionType.VULNERABILITY_SCAN, "developer_workstation")
    _act(world, ActionType.CREDENTIAL_DUMP, "developer_workstation")
    assert world.state.agents["attacker_1"].credentials_obtained is True
    _act(world, ActionType.PRIVILEGE_ESCALATION, "developer_workstation")
    assert world.state.hosts["developer_workstation"].privilege_level == 2
    _act(world, ActionType.PERSISTENCE, "developer_workstation")
    assert world.state.hosts["developer_workstation"].persistence_installed is True
    _act(world, ActionType.DEFENSE_EVASION, "developer_workstation")
    assert world.state.hosts["developer_workstation"].defense_evasion_active is True
    _act(world, ActionType.COMMAND_AND_CONTROL, "developer_workstation")
    assert world.state.hosts["developer_workstation"].command_and_control_active is True

    _act(world, ActionType.LATERAL_MOVE, "application_server")
    assert world.state.hosts["application_server"].is_compromised is True
    assert world.state.agents["attacker_1"].current_host == "application_server"
    _act(world, ActionType.LATERAL_MOVE, "customer_database")
    assert world.state.hosts["customer_database"].is_compromised is True
    _act(world, ActionType.COMMAND_AND_CONTROL, "customer_database")
    _act(world, ActionType.DATA_EXFILTRATION, "customer_database")
    assert world.state.data_stores["customer_records"].is_exfiltrated is True
    _act(world, ActionType.IMPACT, "customer_database")
    assert world.state.hosts["customer_database"].running_services["database"] is False

    types = [event.event_type for event in world.state.events]
    assert "HostCompromised" in types
    assert "DataExfiltrated" in types
    assert "ServiceDown" in types
    assert sum(event.payload.get("size_gb", 0) for event in world.state.events) == 50.0


def test_defender_contains_attack_then_recovers_the_workstation():
    world = configured_attack_world(17)
    provider = dict(attack_provider_factories())["scripted_defensive_v1"]()
    from simulation.decision_provider import run_provider_tick

    for _ in range(7):
        run_provider_tick(world, provider)
        world.step()

    assert world.state.hosts["developer_workstation"].isolated is False
    assert world.state.hosts["developer_workstation"].is_compromised is False
    assert all(world.state.hosts["developer_workstation"].running_services.values())
    assert world.state.hosts["application_server"].is_compromised is False
    assert world.state.hosts["customer_database"].is_compromised is False
    assert world.state.data_stores["customer_records"].is_exfiltrated is False
    assert not any(event.event_type == "DataExfiltrated" for event in world.state.events)


def test_active_attack_comparison_is_replay_verified_and_measures_harm():
    report = compare_providers(
        attack_provider_factories(), seeds=[7], max_ticks=7,
        world_factory=configured_attack_world,
    )
    runs = {row["policy_id"]: row for row in report["runs"]}
    unmitigated = runs["do_nothing_v1"]
    defended = runs["scripted_defensive_v1"]

    assert unmitigated["replay_verified"] is True
    assert defended["replay_verified"] is True
    assert unmitigated["metrics"]["data_exfiltrated_gb"] == 50.0
    assert unmitigated["metrics"]["final_compromised_hosts"] == 3
    assert unmitigated["metrics"]["final_services_down"] == 1
    assert defended["metrics"]["data_exfiltrated_gb"] == 0.0
    assert defended["metrics"]["final_compromised_hosts"] == 0


def test_defender_network_scan_is_implemented_and_does_not_mutate_topology():
    world = build_attack_world(seed=5)
    world.state.active_policy = policy_config("scan_test", ContainmentStrategy.IMMEDIATE)
    before = {host: set(neighbors) for host, neighbors in world.state.network.items()}
    decision = AgentDecision(
        agent_id="security_engineer_1", tick=0, action_type=ActionType.NETWORK_SCAN,
        target=None, rationale="Inventory the simulated network", source="scripted",
    )
    accepted = world.apply_decisions([decision])
    assert len(accepted) == 1
    assert world.state.network == before
    event = world.state.events[-1]
    assert event.event_type == "AgentActionTaken"
    assert event.payload["scanned_hosts"] == sorted(world.state.hosts)
