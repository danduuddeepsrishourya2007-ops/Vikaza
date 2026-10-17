
"""Compare NEXUS no-op and state-changing scaling benchmarks."""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
from typing import Any


def _index_results(
    report: dict[str, Any],
    label: str,
) -> dict[tuple[int, int, int, int], dict[str, Any]]:
    results = report.get("results")
    if not isinstance(results, list):
        raise ValueError(f"{label} report must contain a results list")

    indexed = {}

    for result in results:
        if not isinstance(result, dict):
            raise ValueError(f"{label} results must contain objects")

        identifiers = ("agents", "hosts", "seed", "ticks")
        raw_identifiers = {}
        for field in identifiers:
            value = result.get(field)
            if not isinstance(value, int) or isinstance(value, bool):
                raise ValueError(
                    f"{label} result has invalid {field}; expected an integer"
                )
            raw_identifiers[field] = value

        if raw_identifiers["agents"] < 2 or raw_identifiers["hosts"] < 3:
            raise ValueError(
                f"{label} result has invalid workload size; agents must be >= 2 "
                "and hosts must be >= 3"
            )
        if raw_identifiers["ticks"] < 1:
            raise ValueError(f"{label} result ticks must be at least 1")

        key = tuple(raw_identifiers[field] for field in identifiers)

        if key in indexed:
            raise ValueError(f"Duplicate {label} workload: {key}")

        for field in (
            "median_ticks_per_second",
            "median_decisions_per_second",
        ):
            value = result.get(field)
            if (
                not isinstance(value, (int, float))
                or isinstance(value, bool)
                or not math.isfinite(value)
                or value < 0
            ):
                raise ValueError(
                    f"{label} workload {key} has invalid {field}; "
                    "expected a finite non-negative number"
                )

        if not isinstance(result.get("deterministic"), bool):
            raise ValueError(
                f"{label} workload {key} must report determinism"
            )

        indexed[key] = result

    return indexed


def compare_reports(
    noop_report: dict[str, Any],
    stateful_report: dict[str, Any],
) -> dict[str, Any]:
    """Compare matching workload configurations without mixing state hashes."""

    noop = _index_results(noop_report, "No-op")
    stateful = _index_results(stateful_report, "Stateful")

    noop_keys = set(noop)
    stateful_keys = set(stateful)

    if not noop_keys or not stateful_keys:
        raise ValueError("Both reports must contain benchmark results")

    if noop_keys != stateful_keys:
        missing_stateful = sorted(noop_keys - stateful_keys)
        missing_noop = sorted(stateful_keys - noop_keys)
        raise ValueError(
            "Workload configurations do not match. "
            f"Missing from stateful report: {missing_stateful}; "
            f"missing from no-op report: {missing_noop}"
        )

    comparisons = []

    for key in sorted(noop):
        baseline = noop[key]
        active = stateful[key]

        noop_ticks = float(baseline["median_ticks_per_second"])
        stateful_ticks = float(active["median_ticks_per_second"])
        noop_decisions = float(baseline["median_decisions_per_second"])
        stateful_decisions = float(active["median_decisions_per_second"])

        comparisons.append({
            "agents": key[0],
            "hosts": key[1],
            "seed": key[2],
            "ticks": key[3],
            "noop_ticks_per_second": noop_ticks,
            "stateful_ticks_per_second": stateful_ticks,
            "tick_throughput_ratio_stateful_vs_noop": (
                stateful_ticks / noop_ticks if noop_ticks > 0 else None
            ),
            "tick_throughput_change_percent": (
                ((stateful_ticks / noop_ticks) - 1) * 100
                if noop_ticks > 0 else None
            ),
            "noop_decisions_per_second": noop_decisions,
            "stateful_decisions_per_second": stateful_decisions,
            "noop_deterministic": baseline["deterministic"],
            "stateful_deterministic": active["deterministic"],
            "stateful_state_sha256": active.get("state_sha256"),
            "isolated_hosts": active.get("isolated_hosts"),
            "accepted_isolation_actions": active.get(
                "accepted_isolation_actions"
            ),
            "rejected_actions": active.get("rejected_actions"),
            "rejection_reasons": active.get("rejection_reasons", {}),
            "analyst_hours_initial": active.get("analyst_hours_initial"),
            "analyst_hours_remaining": active.get(
                "analyst_hours_remaining"
            ),
            "remaining_unisolated_compromised_hosts": active.get(
                "remaining_unisolated_compromised_hosts"
            ),
            "resource_exhausted": (
                active.get("rejected_actions", 0) > 0
                and active.get("analyst_hours_remaining") == 0
            ),
        })

    return {
        "report": "nexus_stage4_comparison_v1",
        "scope": (
            "Local simulation benchmark comparison. External LLM inference "
            "and GPU execution are excluded. The two workloads have different "
            "state-transition behavior; throughput ratios describe this "
            "workload difference, not a pure engine overhead measurement."
        ),
        "workload_match": {
            "keys": ["agents", "hosts", "seed", "ticks"],
            "matched_configurations": len(comparisons),
        },
        "summary": {
            "all_noop_runs_deterministic": all(
                row["noop_deterministic"] for row in comparisons
            ),
            "all_stateful_runs_deterministic": all(
                row["stateful_deterministic"] for row in comparisons
            ),
            "resource_exhaustion_cases": sum(
                row["resource_exhausted"] for row in comparisons
            ),
        },
        "comparisons": comparisons,
    }


def render_markdown(report: dict[str, Any]) -> str:
    """Render a compact human-readable report."""

    summary = report["summary"]
    lines = [
        "# NEXUS Stage 4C — Benchmark Comparison",
        "",
        report["scope"],
        "",
        "## Summary",
        "",
        f"- Matched workload/seed configurations: "
        f"{report['workload_match']['matched_configurations']}",
        f"- All no-op runs deterministic: "
        f"{summary['all_noop_runs_deterministic']}",
        f"- All stateful runs deterministic: "
        f"{summary['all_stateful_runs_deterministic']}",
        f"- Resource-exhaustion cases: "
        f"{summary['resource_exhaustion_cases']}",
        "",
        "## Results",
        "",
        "| Agents | Hosts | Seed | No-op ticks/s | Stateful ticks/s "
        "| Ratio | Isolated | Rejected | Hours left |",
        "|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]

    for row in report["comparisons"]:
        ratio = row["tick_throughput_ratio_stateful_vs_noop"]
        ratio_text = f"{ratio:.3f}x" if ratio is not None else "N/A"
        isolated = (
            str(row["isolated_hosts"])
            if row["isolated_hosts"] is not None else "N/A"
        )
        rejected = (
            str(row["rejected_actions"])
            if row["rejected_actions"] is not None else "N/A"
        )
        hours = row["analyst_hours_remaining"]
        hours_text = f"{hours:.2f}" if isinstance(hours, (int, float)) else "N/A"

        lines.append(
            f"| {row['agents']} | {row['hosts']} | {row['seed']} "
            f"| {row['noop_ticks_per_second']:.2f} "
            f"| {row['stateful_ticks_per_second']:.2f} "
            f"| {ratio_text} | {isolated} | {rejected} | {hours_text} |"
        )

    lines.extend([
        "",
        "## Interpretation and limitations",
        "",
        "- The no-op workload emphasizes observation, decision validation, "
        "and tick advancement with minimal state change.",
        "- The stateful workload performs containment attempts and enforces "
        "the existing analyst-hour budget.",
        "- A ratio below 1 means the stateful workload processes fewer ticks "
        "per second than the matched no-op workload.",
        "- Rejected actions and remaining compromised hosts are operational "
        "outcomes, not performance errors by themselves.",
        "- Final-state hashes are workload-specific. Different workload "
        "hashes are expected and must not be treated as a determinism failure.",
        "- These measurements exclude external LLM inference and do not "
        "establish GPU performance or production capacity.",
        "",
    ])

    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Compare NEXUS no-op and stateful benchmark reports"
    )
    parser.add_argument(
        "--noop",
        type=Path,
        default=Path("artifacts/nexus-scaling-benchmark.json"),
        help="Stage 4A no-op benchmark JSON",
    )
    parser.add_argument(
        "--stateful",
        type=Path,
        default=Path("artifacts/nexus-stateful-scaling.json"),
        help="Stage 4B stateful benchmark JSON",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("artifacts/nexus-stage4-comparison.json"),
    )
    parser.add_argument(
        "--markdown-output",
        type=Path,
        default=Path("artifacts/nexus-stage4-comparison.md"),
    )
    args = parser.parse_args()

    for path in (args.noop, args.stateful):
        if not path.is_file():
            parser.error(f"Benchmark report not found: {path}")

    try:
        noop_report = json.loads(args.noop.read_text(encoding="utf-8"))
        stateful_report = json.loads(
            args.stateful.read_text(encoding="utf-8")
        )
        report = compare_reports(noop_report, stateful_report)
    except (json.JSONDecodeError, ValueError) as exc:
        parser.error(str(exc))

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, indent=2) + "\n",
        encoding="utf-8",
    )

    args.markdown_output.parent.mkdir(parents=True, exist_ok=True)
    args.markdown_output.write_text(
        render_markdown(report),
        encoding="utf-8",
    )

    print(f"JSON report: {args.output}")
    print(f"Markdown report: {args.markdown_output}")
    print(f"Matched configurations: {len(report['comparisons'])}")
    print(
        "All no-op runs deterministic: "
        f"{report['summary']['all_noop_runs_deterministic']}"
    )
    print(
        "All stateful runs deterministic: "
        f"{report['summary']['all_stateful_runs_deterministic']}"
    )
    print(
        "Resource-exhaustion cases: "
        f"{report['summary']['resource_exhaustion_cases']}"
    )


if __name__ == "__main__":
    main()
