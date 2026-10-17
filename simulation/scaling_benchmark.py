"""Deterministic workload-scaling benchmark for NEXUS."""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import math
import platform
import statistics
import time

from enum import Enum
from pathlib import Path
from typing import Any

from simulation.actions import ActionType, AgentDecision
from simulation.observations import observe
from simulation.workloads import build_scaling_world


def _normalize(value: Any) -> Any:
    """Convert state values to stable JSON-compatible structures."""
    if isinstance(value, Enum):
        return value.value

    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return _normalize(dataclasses.asdict(value))

    if isinstance(value, dict):
        return {
            str(key): _normalize(value[key])
            for key in sorted(value, key=str)
        }

    if isinstance(value, (set, frozenset)):
        normalized = [_normalize(item) for item in value]
        return sorted(
            normalized,
            key=lambda item: json.dumps(item, sort_keys=True),
        )

    if isinstance(value, (list, tuple)):
        return [_normalize(item) for item in value]

    if isinstance(value, float) and not math.isfinite(value):
        return repr(value)

    if value is None or isinstance(value, (str, int, float, bool)):
        return value

    raise TypeError(
        f"Unsupported value in deterministic state hash: {type(value).__name__}"
    )


def state_digest(world) -> str:
    """Hash authoritative state without including runtime objects."""
    state = world.state

    payload = {
        "tick": state.tick,
        "rng_seed": state.rng_seed,
        "scenario_id": state.scenario_id,
        "hosts": state.hosts,
        "network": state.network,
        "agents": state.agents,
        "data_stores": state.data_stores,
        "resource_pool": state.resource_pool,
        "events": state.events,
        "metrics_snapshot": state.metrics_snapshot,
        "next_event_id": state.next_event_id,
    }

    encoded = json.dumps(
        _normalize(payload),
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    return hashlib.sha256(encoded).hexdigest()


def run_once(
    agent_count: int,
    host_count: int,
    seed: int,
    ticks: int,
) -> dict[str, Any]:
    """Run one workload and report its timing and deterministic result."""
    if ticks < 1:
        raise ValueError("ticks must be at least 1")

    world = build_scaling_world(
        agent_count=agent_count,
        host_count=host_count,
        seed=seed,
    )

    expected_agents = len(world.state.agents)
    if expected_agents != agent_count:
        raise AssertionError(
            f"Expected {agent_count} agents, got {expected_agents}"
        )

    decision_count = 0
    started = time.perf_counter()

    for _ in range(ticks):
        decisions = []

        for agent_id in sorted(world.state.agents):
            view = observe(world, agent_id)

            decisions.append(
                AgentDecision(
                    agent_id=agent_id,
                    tick=view.tick,
                    action_type=ActionType.NO_OP,
                    target=None,
                    rationale="Deterministic scaling benchmark",
                    source="scripted",
                )
            )

        world.apply_decisions(decisions)
        world.step()
        decision_count += len(decisions)

    elapsed = time.perf_counter() - started

    if elapsed <= 0:
        raise RuntimeError("Benchmark timer returned a non-positive duration")

    return {
        "agents": agent_count,
        "hosts": host_count,
        "seed": seed,
        "ticks": ticks,
        "decisions": decision_count,
        "elapsed_seconds": elapsed,
        "ticks_per_second": ticks / elapsed,
        "decisions_per_second": decision_count / elapsed,
        "final_tick": world.state.tick,
        "state_sha256": state_digest(world),
    }


def parse_sizes(value: str) -> list[tuple[int, int]]:
    """Parse a comma-separated list such as 2:3,10:10,50:50."""
    result = []

    for item in value.split(","):
        try:
            agents_text, hosts_text = item.strip().split(":", maxsplit=1)
            agents, hosts = int(agents_text), int(hosts_text)
        except (ValueError, TypeError) as exc:
            raise argparse.ArgumentTypeError(
                f"Invalid workload {item!r}; expected AGENTS:HOSTS"
            ) from exc

        if agents < 2 or hosts < 3:
            raise argparse.ArgumentTypeError(
                "Each workload needs at least 2 agents and 3 hosts"
            )

        result.append((agents, hosts))

    if not result:
        raise argparse.ArgumentTypeError("At least one workload is required")

    return result


def parse_seeds(value: str) -> list[int]:
    try:
        seeds = [int(item.strip()) for item in value.split(",")]
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "Seeds must be comma-separated integers"
        ) from exc

    if not seeds:
        raise argparse.ArgumentTypeError("At least one seed is required")

    return seeds


def run_benchmark(
    sizes: list[tuple[int, int]],
    seeds: list[int],
    ticks: int = 20,
    repeats: int = 3,
    warmups: int = 1,
) -> dict[str, Any]:
    if ticks < 1 or repeats < 2 or warmups < 0:
        raise ValueError(
            "ticks must be positive, repeats at least 2, and warmups non-negative"
        )

    results = []

    for agent_count, host_count in sizes:
        for seed in seeds:
            for _ in range(warmups):
                run_once(agent_count, host_count, seed, ticks)

            runs = [
                run_once(agent_count, host_count, seed, ticks)
                for _ in range(repeats)
            ]

            hashes = {run["state_sha256"] for run in runs}
            deterministic = len(hashes) == 1

            elapsed_values = [
                run["elapsed_seconds"] for run in runs
            ]
            median_elapsed = statistics.median(elapsed_values)

            results.append({
                "agents": agent_count,
                "hosts": host_count,
                "seed": seed,
                "ticks": ticks,
                "repeats": repeats,
                "deterministic": deterministic,
                "state_sha256": runs[0]["state_sha256"],
                "median_elapsed_seconds": median_elapsed,
                "median_ticks_per_second": ticks / median_elapsed,
                "median_decisions_per_second": (
                    agent_count * ticks / median_elapsed
                ),
                "runs": runs,
            })

            if not deterministic:
                raise RuntimeError(
                    "Non-deterministic final state for "
                    f"agents={agent_count}, hosts={host_count}, seed={seed}"
                )

    return {
        "benchmark": "nexus_workload_scaling_v1",
        "measurement": (
            "Observation generation, decision application, and tick advancement; "
            "workload construction and external LLM inference excluded."
        ),
        "environment": {
            "python": platform.python_version(),
            "implementation": platform.python_implementation(),
            "platform": platform.platform(),
            "processor": platform.processor(),
        },
        "settings": {
            "sizes": [
                {"agents": agents, "hosts": hosts}
                for agents, hosts in sizes
            ],
            "seeds": seeds,
            "ticks": ticks,
            "repeats": repeats,
            "warmups": warmups,
        },
        "results": results,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Benchmark NEXUS deterministic engine workload scaling"
    )
    parser.add_argument(
        "--sizes",
        type=parse_sizes,
        default=parse_sizes("2:3,10:10,50:50"),
        help="Comma-separated AGENTS:HOSTS workloads",
    )
    parser.add_argument(
        "--seeds",
        type=parse_seeds,
        default=parse_seeds("7,17,42"),
    )
    parser.add_argument("--ticks", type=int, default=20)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--warmups", type=int, default=1)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("artifacts/nexus-scaling-benchmark.json"),
    )

    args = parser.parse_args()

    report = run_benchmark(
        sizes=args.sizes,
        seeds=args.seeds,
        ticks=args.ticks,
        repeats=args.repeats,
        warmups=args.warmups,
    )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, indent=2) + "\n",
        encoding="utf-8",
    )

    print(f"Benchmark: {report['benchmark']}")
    print(f"Output: {args.output}")
    print()
    print(
        f"{'Agents':>6} {'Hosts':>6} {'Seed':>6} "
        f"{'Ticks/s':>12} {'Decisions/s':>14} {'Deterministic':>14}"
    )

    for result in report["results"]:
        print(
            f"{result['agents']:>6} "
            f"{result['hosts']:>6} "
            f"{result['seed']:>6} "
            f"{result['median_ticks_per_second']:>12.2f} "
            f"{result['median_decisions_per_second']:>14.2f} "
            f"{str(result['deterministic']):>14}"
        )


if __name__ == "__main__":
    main()