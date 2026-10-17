from simulation.scaling_benchmark import run_once, run_benchmark
from simulation.workloads import build_scaling_world


def test_scaling_world_has_requested_size():
    world = build_scaling_world(
        agent_count=10,
        host_count=10,
        seed=7,
    )

    assert len(world.state.agents) == 10
    assert len(world.state.hosts) == 10
    assert world.state.scenario_id == "nexus_cyber_scaling_v1"


def test_same_workload_produces_same_final_state():
    first = run_once(
        agent_count=4,
        host_count=5,
        seed=17,
        ticks=3,
    )
    second = run_once(
        agent_count=4,
        host_count=5,
        seed=17,
        ticks=3,
    )

    assert first["state_sha256"] == second["state_sha256"]
    assert first["final_tick"] == second["final_tick"] == 3
    assert first["decisions"] == second["decisions"] == 12


def test_benchmark_reports_determinism():
    report = run_benchmark(
        sizes=[(2, 3), (4, 5)],
        seeds=[7],
        ticks=2,
        repeats=2,
        warmups=0,
    )

    assert len(report["results"]) == 2
    assert all(result["deterministic"] for result in report["results"])
    assert all(
        result["median_decisions_per_second"] > 0
        for result in report["results"]
    )

def test_state_digest_includes_active_policy_configuration():
    from simulation.scaling_benchmark import state_digest

    world = build_scaling_world(agent_count=2, host_count=3, seed=7)
    original_digest = state_digest(world)
    world.state.active_policy.name = "changed_policy"

    assert state_digest(world) != original_digest
