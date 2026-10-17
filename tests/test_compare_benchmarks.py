
import pytest

from simulation.compare_benchmarks import compare_reports, render_markdown


def make_result(
    *,
    ticks_per_second: float,
    decisions_per_second: float,
    deterministic: bool = True,
) -> dict:
    return {
        "agents": 2,
        "hosts": 3,
        "seed": 7,
        "ticks": 20,
        "median_ticks_per_second": ticks_per_second,
        "median_decisions_per_second": decisions_per_second,
        "deterministic": deterministic,
    }


def test_comparison_calculates_throughput_ratio_and_resource_outcome():
    noop = {
        "results": [
            make_result(ticks_per_second=100, decisions_per_second=200)
        ]
    }
    stateful_result = make_result(
        ticks_per_second=50,
        decisions_per_second=100,
    )
    stateful_result.update({
        "state_sha256": "abc123",
        "isolated_hosts": 2,
        "accepted_isolation_actions": 2,
        "rejected_actions": 1,
        "rejection_reasons": {"Insufficient resources": 1},
        "analyst_hours_initial": 4.0,
        "analyst_hours_remaining": 0.0,
        "remaining_unisolated_compromised_hosts": 1,
    })
    stateful = {"results": [stateful_result]}

    report = compare_reports(noop, stateful)
    row = report["comparisons"][0]

    assert row["tick_throughput_ratio_stateful_vs_noop"] == 0.5
    assert row["tick_throughput_change_percent"] == -50.0
    assert row["resource_exhausted"] is True
    assert row["rejected_actions"] == 1
    assert report["summary"]["resource_exhaustion_cases"] == 1


def test_comparison_rejects_mismatched_workload_keys():
    noop = {
        "results": [
            make_result(ticks_per_second=100, decisions_per_second=200)
        ]
    }
    stateful = {
        "results": [
            {
                **make_result(
                    ticks_per_second=50,
                    decisions_per_second=100,
                ),
                "hosts": 10,
            }
        ]
    }

    with pytest.raises(ValueError, match="do not match"):
        compare_reports(noop, stateful)


def test_markdown_contains_results_and_limitations():
    noop = {
        "results": [
            make_result(ticks_per_second=100, decisions_per_second=200)
        ]
    }
    stateful = {
        "results": [
            {
                **make_result(
                    ticks_per_second=50,
                    decisions_per_second=100,
                ),
                "isolated_hosts": 2,
                "rejected_actions": 1,
                "analyst_hours_remaining": 0.0,
            }
        ]
    }

    markdown = render_markdown(compare_reports(noop, stateful))

    assert "NEXUS Stage 4C" in markdown
    assert "Resource-exhaustion cases: 1" in markdown
    assert "exclude external LLM inference" in markdown


def test_comparison_reports_non_deterministic_inputs():
    noop = {
        "results": [
            make_result(
                ticks_per_second=100,
                decisions_per_second=200,
                deterministic=False,
            )
        ]
    }
    stateful = {
        "results": [
            make_result(ticks_per_second=50, decisions_per_second=100)
        ]
    }

    report = compare_reports(noop, stateful)

    assert report["summary"]["all_noop_runs_deterministic"] is False
    assert report["summary"]["all_stateful_runs_deterministic"] is True


@pytest.mark.parametrize("invalid_rate", [float("nan"), float("inf"), float("-inf"), True])
def test_comparison_rejects_non_finite_or_boolean_throughput(invalid_rate):
    noop = {
        "results": [
            make_result(
                ticks_per_second=invalid_rate,
                decisions_per_second=200,
            )
        ]
    }
    stateful = {
        "results": [
            make_result(ticks_per_second=50, decisions_per_second=100)
        ]
    }

    with pytest.raises(ValueError, match="finite non-negative"):
        compare_reports(noop, stateful)


@pytest.mark.parametrize("invalid_agents", [2.5, True, "2"])
def test_comparison_rejects_non_integer_workload_identifiers(invalid_agents):
    noop_result = make_result(ticks_per_second=100, decisions_per_second=200)
    stateful_result = make_result(ticks_per_second=50, decisions_per_second=100)
    noop_result["agents"] = invalid_agents
    stateful_result["agents"] = invalid_agents

    with pytest.raises(ValueError, match="invalid agents"):
        compare_reports({"results": [noop_result]}, {"results": [stateful_result]})


def test_comparison_rejects_invalid_workload_dimensions():
    noop_result = make_result(ticks_per_second=100, decisions_per_second=200)
    stateful_result = make_result(ticks_per_second=50, decisions_per_second=100)
    noop_result["hosts"] = 2
    stateful_result["hosts"] = 2

    with pytest.raises(ValueError, match="workload size"):
        compare_reports({"results": [noop_result]}, {"results": [stateful_result]})
