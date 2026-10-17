from dataclasses import FrozenInstanceError

import pytest

from scenarios.cyber_containment import build_initial_world, policy_config
from simulation.policy import ContainmentStrategy
from simulation.actions import ActionType, AgentDecision
from simulation.decision_provider import ScriptedProvider, collect_decisions, run_provider_tick
from simulation.observations import observe


def configured_world(seed=7):
    world = build_initial_world(seed)
    world.state.active_policy = policy_config("test", ContainmentStrategy.IMMEDIATE)
    world.state.agents["security_engineer_1"].current_host = "developer_workstation"
    world.state.agents["it_admin_1"].current_host = "application_server"
    return world


def test_observation_is_detached_and_does_not_mutate_world():
    world = configured_world()
    before = repr(world.state)
    view = observe(world, "security_engineer_1")
    assert view.tick == world.state.tick
    assert {h.host_id for h in view.hosts} == set(world.state.hosts)
    assert repr(world.state) == before
    with pytest.raises(FrozenInstanceError):
        view.tick = 9
    with pytest.raises(TypeError):
        view.hosts[0].running_services[0] = ("evil", True)


def test_attacker_view_is_scoped_and_hides_sensitive_inventory():
    world = configured_world()
    world.state.agents["attacker_1"] = type(world.state.agents["security_engineer_1"])(
        agent_id="attacker_1", role="attacker", current_host="developer_workstation"
    )
    view = observe(world, "attacker_1")
    assert {h.host_id for h in view.hosts} == {"developer_workstation", "application_server"}
    assert view.data_stores == ()
    assert all(not h.known_vulnerabilities and not h.installed_patches for h in view.hosts)
    assert view.available_resources == ()


def test_unknown_agent_is_rejected():
    with pytest.raises(KeyError, match="Unknown agent"):
        observe(configured_world(), "missing")


def test_provider_is_deterministic_and_does_not_mutate_world():
    world = configured_world()
    view = observe(world, "security_engineer_1")
    provider = ScriptedProvider()
    first, second = provider.decide(view), provider.decide(view)
    assert first == second
    assert first.action_type is ActionType.NO_OP
    assert world.state.tick == 0


def test_collect_decisions_provides_independently_scoped_views():
    world = configured_world()
    world.state.agents["attacker_1"] = type(world.state.agents["security_engineer_1"])(
        agent_id="attacker_1", role="attacker", current_host="developer_workstation"
    )
    class CapturingProvider:
        def __init__(self): self.views = []
        def decide(self, view):
            self.views.append(view)
            return AgentDecision(view.agent_id, view.tick, ActionType.NO_OP, None, "test", "scripted")
    provider = CapturingProvider()
    decisions = collect_decisions(world, provider)
    assert [d.agent_id for d in decisions] == sorted(world.state.agents)
    attacker_view = next(v for v in provider.views if v.role == "attacker")
    defender_view = next(v for v in provider.views if v.role == "security_engineer")
    assert attacker_view.data_stores == ()
    assert defender_view.data_stores
    assert attacker_view is not defender_view


def test_provider_output_wrong_agent_or_tick_is_rejected():
    world = configured_world()
    class WrongAgent:
        def decide(self, view):
            return AgentDecision("someone_else", view.tick, ActionType.NO_OP, None, "bad", "scripted")
    with pytest.raises(ValueError, match="does not match view"):
        collect_decisions(world, WrongAgent())
    class WrongTick:
        def decide(self, view):
            return AgentDecision(view.agent_id, view.tick + 1, ActionType.NO_OP, None, "bad", "scripted")
    with pytest.raises(ValueError, match="does not match world tick"):
        collect_decisions(world, WrongTick())


def test_provider_decisions_flow_through_authoritative_engine():
    world = configured_world()
    decision = AgentDecision(
        agent_id="security_engineer_1", tick=0,
        action_type=ActionType.ISOLATE_HOST, target="developer_workstation",
        rationale="scripted containment", source="scripted",
    )
    provider = ScriptedProvider({("security_engineer_1", 0): decision})
    taken = run_provider_tick(world, provider)
    assert world.state.hosts["developer_workstation"].isolated is True
    assert any(item.agent_id == "security_engineer_1" for item in taken)
    # The second agent's fallback NO_OP is harmless and engine-validated.


def test_provider_invalid_action_is_rejected_by_engine_not_applied_directly():
    world = configured_world()
    decision = AgentDecision("it_admin_1", 0, ActionType.DATA_EXFILTRATION,
                             "customer_database", "unauthorized", "scripted")
    provider = ScriptedProvider({("it_admin_1", 0): decision})
    run_provider_tick(world, provider)
    assert world.state.data_stores["customer_records"].is_exfiltrated is False
    assert any(e.event_type == "AgentActionRejected" for e in world.state.events)


def test_engine_rejects_stale_decision_without_mutating_authoritative_state():
    from copy import deepcopy

    world = configured_world()
    decision = AgentDecision(
        "security_engineer_1", 1, ActionType.ISOLATE_HOST,
        "developer_workstation", "stale proposal", "llm",
    )
    hosts_before = deepcopy(world.state.hosts)
    resources_before = deepcopy(world.state.resource_pool)
    agents_before = deepcopy(world.state.agents)
    stores_before = deepcopy(world.state.data_stores)

    world.apply_decisions([decision])

    assert world.state.hosts == hosts_before
    assert world.state.resource_pool == resources_before
    assert world.state.agents == agents_before
    assert world.state.data_stores == stores_before
    rejection = [e for e in world.state.events if e.event_type == "AgentActionRejected"]
    assert len(rejection) == 1
    assert "tick" in rejection[0].payload["reason"].lower()
    assert rejection[0].payload["source"] == "llm"


@pytest.mark.parametrize(
    ("field", "bad_value", "expected_reason"),
    [
        ("action_type", "ISOLATE_HOST", "recognized ActionType"),
        ("target", 42, "target must be null or a non-empty string"),
        ("target", "x" * 257, "target must be null or a non-empty string"),
        ("rationale", "r" * 501, "rationale must be a string"),
    ],
)
def test_engine_rejects_malformed_decision_before_sorting_or_execution(field, bad_value, expected_reason):
    from copy import deepcopy

    world = configured_world()
    decision = AgentDecision(
        "security_engineer_1", 0, ActionType.ISOLATE_HOST,
        "developer_workstation", "valid shape", "llm",
    )
    setattr(decision, field, bad_value)
    hosts_before = deepcopy(world.state.hosts)
    resources_before = deepcopy(world.state.resource_pool)

    world.apply_decisions([decision])

    assert world.state.hosts == hosts_before
    assert world.state.resource_pool == resources_before
    rejected = [e for e in world.state.events if e.event_type == "AgentActionRejected"]
    assert len(rejected) == 1
    assert expected_reason in rejected[0].payload["reason"]


def test_engine_rejects_unhashable_source_without_crashing():
    world = configured_world()
    decision = AgentDecision(
        "security_engineer_1", 0, ActionType.ISOLATE_HOST,
        "developer_workstation", "mutated source", "llm",
    )
    decision.source = ["llm"]
    world.apply_decisions([decision])
    rejected = [e for e in world.state.events if e.event_type == "AgentActionRejected"]
    assert len(rejected) == 1
    assert "source must be" in rejected[0].payload["reason"]


def test_engine_rejects_no_op_with_target():
    world = configured_world()
    decision = AgentDecision(
        "security_engineer_1", 0, ActionType.NO_OP,
        "developer_workstation", "malformed no-op", "llm",
    )
    world.apply_decisions([decision])
    rejected = [e for e in world.state.events if e.event_type == "AgentActionRejected"]
    assert len(rejected) == 1
    assert rejected[0].payload["reason"] == "NO_OP target must be null"
