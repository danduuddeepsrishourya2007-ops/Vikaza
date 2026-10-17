
from simulation.stateful_scaling_benchmark import run_once, run_benchmark


def test_stateful_workload_changes_world():
    result = run_once(
        agent_count=2,
        host_count=3,
        seed=7,
        ticks=3,
    )

    assert result["final_tick"] == 3
    assert result["isolated_hosts"] == 3
    assert result["remaining_unisolated_compromised_hosts"] == 0
    assert result["accepted_actions"] > 0


def test_stateful_workload_is_deterministic():
    first = run_once(3, 4, 17, 3)
    second = run_once(3, 4, 17, 3)

    assert first["state_sha256"] == second["state_sha256"]
    assert first["isolated_hosts"] == second["isolated_hosts"]


def test_stateful_benchmark_reports_results():
    report = run_benchmark(
        sizes=[(2, 3), (4, 5)],
        seeds=[7],
        ticks=3,
        repeats=2,
        warmups=0,
    )

    assert len(report["results"]) == 2
    assert all(item["deterministic"] for item in report["results"])
    assert all(item["isolated_hosts"] == 3 for item in report["results"])


import pytest


@pytest.mark.parametrize(
    "kwargs, message",
    [
        ({"sizes": [(2, 3), (2, 3)], "seeds": [7], "ticks": 2, "repeats": 2, "warmups": 0}, "unique"),
        ({"sizes": [(True, 3)], "seeds": [7], "ticks": 2, "repeats": 2, "warmups": 0}, "integers"),
        ({"sizes": [(2, 3)], "seeds": [7, 7], "ticks": 2, "repeats": 2, "warmups": 0}, "unique"),
        ({"sizes": [(2, 3)], "seeds": [7], "ticks": True, "repeats": 2, "warmups": 0}, "positive integer"),
    ],
)
def test_stateful_benchmark_rejects_invalid_configuration(kwargs, message):
    with pytest.raises(ValueError, match=message):
        run_benchmark(**kwargs)


def test_stateful_run_reports_consistent_decision_and_resource_accounting():
    result = run_once(agent_count=10, host_count=10, seed=7, ticks=20)

    assert result["final_tick"] == result["ticks"]
    assert result["accepted_decisions"] + result["rejected_actions"] == 10 * 20
    assert result["analyst_hours_remaining"] >= 0
    assert result["isolated_hosts"] + result["remaining_unisolated_compromised_hosts"] == 10
