from copy import deepcopy

from scenarios.cyber_containment import build_initial_world, policy_config
from simulation.baselines import DoNothingProvider, ScriptedDefensiveProvider
from simulation.decision_provider import collect_decisions
from simulation.observations import observe
from simulation.policy import ContainmentStrategy
from simulation.replay import run_and_record


def configured_world(seed=7):
    world = build_initial_world(seed)
    world.state.active_policy = policy_config("test", ContainmentStrategy.IMMEDIATE)
    return world


def test_do_nothing_provider_is_deterministic_and_non_mutating():
    world = configured_world()
    before = deepcopy(world.state)
    provider = DoNothingProvider()
    first = provider.decide(observe(world, "security_engineer_1"))
    second = provider.decide(observe(world, "security_engineer_1"))
    assert first == second
    assert first.action_type.value == "NO_OP"
    assert world.state == before


def test_scripted_defense_isolate_then_patch_without_mutating_world():
    world = configured_world()
    provider = ScriptedDefensiveProvider()
    before = deepcopy(world.state)
    first = provider.decide(observe(world, "security_engineer_1"))
    assert first.action_type.value == "ISOLATE_HOST"
    assert first.target == "developer_workstation"
    assert world.state == before

    world.apply_decisions([first])
    world.step()
    second = provider.decide(observe(world, "security_engineer_1"))
    assert second.action_type.value == "PATCH_HOST"
    assert second.target == "developer_workstation"


def test_scripted_defense_respects_engine_role_validation():
    world = configured_world()
    provider = ScriptedDefensiveProvider()
    decisions = collect_decisions(world, provider)
    world.apply_decisions(decisions)
    assert world.state.hosts["developer_workstation"].isolated
    assert not any(event.event_type == "AgentActionRejected" for event in world.state.events)


def test_baseline_run_records_one_decision_batch_per_tick():
    world = configured_world()
    trace = run_and_record(world, DoNothingProvider(), DoNothingProvider.policy_id, max_ticks=3)
    assert len(trace.decisions_by_tick) == 3
    assert all(len(batch) == 2 for batch in trace.decisions_by_tick)
