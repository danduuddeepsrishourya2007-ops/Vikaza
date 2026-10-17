import json

import pytest

from simulation.baselines import DoNothingProvider, ScriptedDefensiveProvider
from simulation.evaluation import build_evaluation_world, evaluate_baselines
from simulation.replay import SimulationTrace, TraceError, replay_trace, run_and_record, world_snapshot


def test_trace_round_trip_and_replay_without_provider():
    world = build_evaluation_world(21)
    trace = run_and_record(world, ScriptedDefensiveProvider(), ScriptedDefensiveProvider.policy_id, 4)
    encoded = trace.to_json()
    decoded = SimulationTrace.from_json(encoded)

    def factory(seed):
        return build_evaluation_world(seed)

    replayed = replay_trace(decoded, factory)
    assert replayed.state.tick == 4
    assert replayed.state.events == world.state.events


def test_replay_does_not_need_original_provider_after_trace_creation():
    world = build_evaluation_world(9)
    trace = run_and_record(world, DoNothingProvider(), DoNothingProvider.policy_id, 2)
    replayed = replay_trace(trace.to_json(), build_evaluation_world)
    assert replayed.state.tick == world.state.tick
    assert replayed.state.hosts == world.state.hosts


def test_trace_rejects_bad_json_version_and_incomplete_tick_rows():
    with pytest.raises(TraceError):
        SimulationTrace.from_json("not json")

    world = build_evaluation_world(4)
    trace = run_and_record(world, DoNothingProvider(), DoNothingProvider.policy_id, 2)
    data = trace.to_dict()
    data["trace_version"] = 999
    with pytest.raises(TraceError, match="Unsupported trace version"):
        SimulationTrace.from_json(json.dumps(data))

    data = trace.to_dict()
    data["decisions_by_tick"] = data["decisions_by_tick"][:1]
    with pytest.raises(TraceError, match="exactly max_ticks"):
        SimulationTrace.from_json(json.dumps(data))


def test_replay_rejects_scenario_mismatch():
    world = build_evaluation_world(3)
    trace = run_and_record(world, DoNothingProvider(), DoNothingProvider.policy_id, 2)

    def wrong_factory(seed):
        other = build_evaluation_world(seed)
        other.state.scenario_id = "different-scenario"
        return other

    with pytest.raises(TraceError, match="Scenario mismatch"):
        replay_trace(trace, wrong_factory)


def test_evaluation_compares_same_initial_conditions_reproducibly():
    first = evaluate_baselines(seed=31, max_ticks=4)
    second = evaluate_baselines(seed=31, max_ticks=4)
    assert first == second
    assert first["same_initial_host_ids"] is True
    assert {item["policy_id"] for item in first["results"]} == {
        "do_nothing_v1", "scripted_defensive_v1"
    }
    assert first["results"][1]["metrics"]["resource_used"]["analyst_hours"] == 5.0
    by_id = {item["policy_id"]: item for item in first["results"]}
    assert by_id["do_nothing_v1"]["metrics"]["final_compromised_hosts"] == 1
    assert by_id["scripted_defensive_v1"]["metrics"]["final_compromised_hosts"] == 0


def test_snapshot_includes_active_policy_and_rng_state():
    world = build_evaluation_world(44)
    original = world_snapshot(world)

    world.state.active_policy = None
    assert world_snapshot(world) != original

    world = build_evaluation_world(44)
    original = world_snapshot(world)
    world.random()
    assert world_snapshot(world) != original


def test_snapshot_includes_pending_scheduled_events():
    world = build_evaluation_world(45)
    before = world_snapshot(world)
    world.schedule_event(20, "TickCompleted", "test-agent", {"marker": "pending"})
    after = world_snapshot(world)

    assert after != before
    assert after["scheduler"]["pending"][-1]["event"]["payload"]["marker"] == "pending"


def test_snapshot_fails_closed_for_pending_callbacks():
    world = build_evaluation_world(46)
    world.scheduler.schedule_event_callback(
        20,
        lambda callback_data, callback_world: None,
        event_data={"marker": "not serializable"},
    )

    with pytest.raises(TraceError, match="pending scheduler callback"):
        world_snapshot(world)


def test_replay_rejects_factory_with_wrong_seed():
    world = build_evaluation_world(12)
    trace = run_and_record(world, DoNothingProvider(), DoNothingProvider.policy_id, 2)

    with pytest.raises(TraceError, match="Seed mismatch"):
        replay_trace(trace.to_json(), lambda _seed: build_evaluation_world(13))


def test_run_and_record_requires_fresh_world_and_nonempty_policy_id():
    world = build_evaluation_world(17)
    world.step()
    with pytest.raises(ValueError, match="fresh world"):
        run_and_record(world, DoNothingProvider(), DoNothingProvider.policy_id, 1)

    with pytest.raises(ValueError, match="policy_id"):
        run_and_record(build_evaluation_world(17), DoNothingProvider(), "  ", 1)


def test_replay_validates_manually_constructed_trace_objects():
    world = build_evaluation_world(18)
    trace = run_and_record(world, DoNothingProvider(), DoNothingProvider.policy_id, 2)
    trace.decisions_by_tick = trace.decisions_by_tick[:1]

    with pytest.raises(TraceError, match="exactly max_ticks"):
        replay_trace(trace, build_evaluation_world)
