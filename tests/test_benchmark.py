import pytest

from simulation.benchmark import run_benchmark


def test_benchmark_reports_measurements_and_deterministic_outcomes():
    report = run_benchmark(
        seeds=[7],
        ticks=2,
        repeats=2,
        warmups=0,
    )

    assert report["benchmark_version"] == 1
    assert report["configuration"]["agent_count"] == 2
    assert report["configuration"]["host_count"] == 3
    assert report["all_outcomes_deterministic"] is True
    assert len(report["results"]) == 2

    for result in report["results"]:
        assert result["elapsed_seconds"]["median"] > 0
        assert result["elapsed_seconds"]["p95"] > 0
        assert result["median_ticks_per_second"] > 0
        assert result["outcomes_deterministic_across_repeats"] is True
        assert len(result["outcome_sha256"]) == 64


def test_benchmark_rejects_invalid_repeat_count():
    with pytest.raises(ValueError, match="at least 2"):
        run_benchmark(
            seeds=[7],
            ticks=2,
            repeats=1,
            warmups=0,
        )


def test_benchmark_rejects_duplicate_seeds():
    with pytest.raises(ValueError, match="unique"):
        run_benchmark(
            seeds=[7, 7],
            ticks=2,
            repeats=2,
            warmups=0,
        )
