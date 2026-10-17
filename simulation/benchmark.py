"""Reproducible local performance benchmark for NEXUS.

Run from the repository root:

    python -m simulation.benchmark --seeds 7,17,42 --ticks 20 --repeats 5 --warmups 1 --output artifacts/nexus-stage4-benchmark.json

Timing excludes replay verification and external LLM inference.
The current cyber-containment scenario uses a fixed initial world.
This benchmark does not claim agent-count scaling.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import statistics
import sys
import time
from pathlib import Path
from typing import Any, Callable

from scenarios.cyber_containment import build_initial_world
from simulation.baselines import (
    DoNothingProvider,
    ScriptedDefensiveProvider,
)
from simulation.experiment import evaluate_provider


def _parse_seeds(value: str) -> list[int]:
    """Parse and validate a comma-separated list of unique seeds."""
    try:
        seeds = [
            int(part.strip())
            for part in value.split(",")
            if part.strip()
        ]
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "seeds must be comma-separated integers"
        ) from exc

    if not seeds:
        raise argparse.ArgumentTypeError(
            "provide at least one seed"
        )

    if len(set(seeds)) != len(seeds):
        raise argparse.ArgumentTypeError(
            "seeds must be unique"
        )

    return seeds


def _percentile(
    values: list[float],
    percentile: float,
) -> float:
    """Calculate a nearest-rank percentile without extra dependencies."""
    if not values:
        raise ValueError(
            "percentile requires at least one value"
        )

    ordered = sorted(values)
    rank = max(
        1,
        int((percentile / 100.0) * len(ordered) + 0.999999),
    )

    return ordered[min(rank - 1, len(ordered) - 1)]


def _canonical_hash(value: Any) -> str:
    """Return a stable SHA-256 hash for JSON-compatible data."""
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")

    return hashlib.sha256(encoded).hexdigest()


def run_benchmark(
    seeds: list[int] | None = None,
    ticks: int = 20,
    repeats: int = 5,
    warmups: int = 1,
) -> dict[str, Any]:
    """Benchmark baseline policies and verify outcome repeatability."""

    if seeds is None:
        seeds = [7, 17, 42]
    else:
        seeds = list(seeds)

    if (
        not seeds
        or any(
            not isinstance(seed, int) or isinstance(seed, bool)
            for seed in seeds
        )
    ):
        raise ValueError(
            "seeds must contain at least one integer"
        )

    if len(set(seeds)) != len(seeds):
        raise ValueError("seeds must be unique")

    if (
        not isinstance(ticks, int)
        or isinstance(ticks, bool)
        or ticks < 1
    ):
        raise ValueError(
            "ticks must be a positive integer"
        )

    if (
        not isinstance(repeats, int)
        or isinstance(repeats, bool)
        or repeats < 2
    ):
        raise ValueError(
            "repeats must be an integer of at least 2"
        )

    if (
        not isinstance(warmups, int)
        or isinstance(warmups, bool)
        or warmups < 0
    ):
        raise ValueError(
            "warmups must be a non-negative integer"
        )

    providers: list[tuple[str, Callable[[], Any]]] = [
        (
            DoNothingProvider.policy_id,
            DoNothingProvider,
        ),
        (
            ScriptedDefensiveProvider.policy_id,
            ScriptedDefensiveProvider,
        ),
    ]

    # Record the actual size of the existing initial scenario.
    sample_world = build_initial_world(seeds[0])

    agent_count = len(sample_world.state.agents)
    host_count = len(sample_world.state.hosts)
    data_store_count = len(sample_world.state.data_stores)

    results: list[dict[str, Any]] = []

    for seed in seeds:
        for policy_id, provider_factory in providers:

            # Warm-up runs are excluded from timing statistics.
            for _ in range(warmups):
                evaluate_provider(
                    provider_factory(),
                    policy_id,
                    seed=seed,
                    max_ticks=ticks,
                    verify_replay=False,
                )

            durations: list[float] = []
            outcome_hashes: list[str] = []
            first_metrics: dict[str, Any] | None = None

            for _ in range(repeats):
                started = time.perf_counter()

                run = evaluate_provider(
                    provider_factory(),
                    policy_id,
                    seed=seed,
                    max_ticks=ticks,
                    verify_replay=False,
                )

                elapsed = time.perf_counter() - started
                durations.append(elapsed)

                metrics = run["metrics"]
                outcome_hashes.append(
                    _canonical_hash(metrics)
                )

                if first_metrics is None:
                    first_metrics = metrics

            outcomes_deterministic = (
                len(set(outcome_hashes)) == 1
            )

            median_seconds = statistics.median(durations)

            results.append(
                {
                    "policy_id": policy_id,
                    "seed": seed,
                    "ticks_requested": ticks,
                    "repeat_count": repeats,
                    "warmup_count": warmups,
                    "agent_count": agent_count,
                    "host_count": host_count,
                    "data_store_count": data_store_count,
                    "elapsed_seconds": {
                        "min": round(min(durations), 8),
                        "median": round(median_seconds, 8),
                        "mean": round(
                            statistics.mean(durations), 8
                        ),
                        "p95": round(
                            _percentile(durations, 95), 8
                        ),
                        "max": round(max(durations), 8),
                    },
                    "median_ticks_per_second": (
                        round(ticks / median_seconds, 3)
                        if median_seconds > 0
                        else None
                    ),
                    "median_runs_per_second": (
                        round(1.0 / median_seconds, 3)
                        if median_seconds > 0
                        else None
                    ),
                    "outcomes_deterministic_across_repeats": (
                        outcomes_deterministic
                    ),
                    "outcome_sha256": outcome_hashes[0],
                    "outcome_metrics": first_metrics,
                }
            )

    return {
        "benchmark_version": 1,
        "benchmark_scope": (
            "Fixed cyber-containment scenario. Runtime excludes "
            "replay verification and external LLM inference. "
            "No agent-count scaling claim is made."
        ),
        "configuration": {
            "seeds": seeds,
            "ticks_per_run": ticks,
            "repeats_per_policy_seed": repeats,
            "warmups_per_policy_seed": warmups,
            "agent_count": agent_count,
            "host_count": host_count,
            "data_store_count": data_store_count,
        },
        "environment": {
            "python_version": sys.version.split()[0],
            "implementation": platform.python_implementation(),
            "operating_system": platform.platform(),
            "machine": platform.machine(),
            "processor": (
                platform.processor()
                or "not reported by platform"
            ),
            "cpu_count_logical": os.cpu_count(),
        },
        "all_outcomes_deterministic": all(
            result[
                "outcomes_deterministic_across_repeats"
            ]
            for result in results
        ),
        "results": results,
    }


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line argument parser."""
    parser = argparse.ArgumentParser(
        description=(
            "Benchmark the existing NEXUS cyber simulation locally"
        )
    )

    parser.add_argument(
        "--seeds",
        type=_parse_seeds,
        default=[7, 17, 42],
        help="comma-separated seeds (default: 7,17,42)",
    )

    parser.add_argument(
        "--ticks",
        type=int,
        default=20,
        help="ticks per simulation run (default: 20)",
    )

    parser.add_argument(
        "--repeats",
        type=int,
        default=5,
        help="measured repetitions per policy and seed (minimum: 2)",
    )

    parser.add_argument(
        "--warmups",
        type=int,
        default=1,
        help="unmeasured warm-up runs per policy and seed",
    )

    parser.add_argument(
        "--output",
        type=Path,
        default=Path(
            "artifacts/nexus-stage4-benchmark.json"
        ),
        help="path for the JSON benchmark report",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the benchmark and write a JSON report."""
    args = build_parser().parse_args(argv)

    report = run_benchmark(
        seeds=args.seeds,
        ticks=args.ticks,
        repeats=args.repeats,
        warmups=args.warmups,
    )

    args.output.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    args.output.write_text(
        json.dumps(
            report,
            indent=2,
            sort_keys=True,
            allow_nan=False,
        )
        + "\n",
        encoding="utf-8",
    )

    summary = {
        "output": str(args.output),
        "all_outcomes_deterministic": (
            report["all_outcomes_deterministic"]
        ),
        "environment": report["environment"],
        "results": [
            {
                "policy_id": result["policy_id"],
                "seed": result["seed"],
                "median_seconds": (
                    result["elapsed_seconds"]["median"]
                ),
                "p95_seconds": (
                    result["elapsed_seconds"]["p95"]
                ),
                "median_ticks_per_second": (
                    result["median_ticks_per_second"]
                ),
                "deterministic": (
                    result[
                        "outcomes_deterministic_across_repeats"
                    ]
                ),
            }
            for result in report["results"]
        ],
    }

    print(
        json.dumps(
            summary,
            indent=2,
            sort_keys=True,
        )
    )

    return (
        0
        if report["all_outcomes_deterministic"]
        else 2
    )


if __name__ == "__main__":
    raise SystemExit(main())
