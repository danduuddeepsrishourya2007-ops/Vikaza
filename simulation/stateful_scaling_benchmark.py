
"""Benchmark deterministic state-changing cyber workloads."""

from __future__ import annotations

import argparse
import json
import statistics
import time
from pathlib import Path
from typing import Any

from simulation.actions import ActionType, AgentDecision
from simulation.observations import observe
from simulation.scaling_benchmark import state_digest
from simulation.workloads import build_scaling_world


def run_once(
    agent_count: int,
    host_count: int,
    seed: int,
    ticks: int,
) -> dict[str, Any]:
    if not isinstance(ticks, int) or isinstance(ticks, bool) or ticks < 1:
        raise ValueError("ticks must be a positive integer")
    if not isinstance(agent_count, int) or isinstance(agent_count, bool) or agent_count < 2:
        raise ValueError("agent_count must be an integer of at least 2")
    if not isinstance(host_count, int) or isinstance(host_count, bool) or host_count < 3:
        raise ValueError("host_count must be an integer of at least 3")
    if not isinstance(seed, int) or isinstance(seed, bool):
        raise ValueError("seed must be an integer")

    world = build_scaling_world(agent_count, host_count, seed)

    # Synthetic incident: every host starts compromised.
    # The original cyber-containment scenario remains unchanged.
    for host in world.state.hosts.values():
        host.is_compromised = True
        host.isolated = False

    defenders = sorted(
        agent_id
        for agent_id, agent in world.state.agents.items()
        if agent.role == "security_engineer"
    )
    if not defenders:
        raise ValueError("Workload needs a security engineer")

    defender_id = defenders[0]

    initial_analyst_hours = world.state.resource_pool.get("analyst_hours")
    if initial_analyst_hours is None:
        raise ValueError("Workload needs an analyst_hours resource")

    accepted_actions = 0
    initial_event_count = len(world.state.events)

    started = time.perf_counter()

    for _ in range(ticks):
        decisions = []

        # Attempt one containment action per tick while eligible hosts remain.
        # Resource checks and action validation remain the engine's responsibility.
        target = next(
            (
                host_id
                for host_id, host in sorted(world.state.hosts.items())
                if host.is_compromised and not host.isolated
            ),
            None,
        )

        for agent_id in sorted(world.state.agents):
            view = observe(world, agent_id)

            if agent_id == defender_id and target is not None:
                decision = AgentDecision(
                    agent_id=agent_id,
                    tick=view.tick,
                    action_type=ActionType.ISOLATE_HOST,
                    target=target,
                    rationale="Deterministic scaling containment action",
                    source="scripted",
                )
            else:
                decision = AgentDecision(
                    agent_id=agent_id,
                    tick=view.tick,
                    action_type=ActionType.NO_OP,
                    target=None,
                    rationale="No additional action for this tick",
                    source="scripted",
                )

            decisions.append(decision)

        # Preserve the engine's accepted-decision count.
        accepted_actions += len(world.apply_decisions(decisions))
        world.step()

    elapsed = time.perf_counter() - started
    if elapsed <= 0:
        raise RuntimeError("Invalid benchmark duration")

    # Count rejection events generated during this benchmark run.
    new_events = world.state.events[initial_event_count:]
    rejection_events = [
        event
        for event in new_events
        if getattr(event, "event_type", None) == "AgentActionRejected"
    ]

    rejection_reasons: dict[str, int] = {}
    for event in rejection_events:
        payload = getattr(event, "payload", {})
        reason = str(payload.get("reason", "Unknown rejection reason"))
        rejection_reasons[reason] = rejection_reasons.get(reason, 0) + 1

    isolated_hosts = sum(
        1 for host in world.state.hosts.values() if host.isolated
    )

    remaining_unisolated_compromised_hosts = sum(
        1
        for host in world.state.hosts.values()
        if host.is_compromised and not host.isolated
    )

    remaining_analyst_hours = world.state.resource_pool["analyst_hours"]

    # Benchmark integrity checks: fail loudly rather than emit a misleading
    # report if engine behavior violates the workload's accounting contract.
    expected_decisions = agent_count * ticks
    if world.state.tick != ticks:
        raise RuntimeError(
            f"Expected final tick {ticks}, got {world.state.tick}"
        )
    if accepted_actions + len(rejection_events) != expected_decisions:
        raise RuntimeError(
            "Decision accounting mismatch: accepted plus rejected decisions "
            f"must equal {expected_decisions}"
        )
    if remaining_analyst_hours < 0:
        raise RuntimeError("Analyst-hour resource balance became negative")
    if isolated_hosts + remaining_unisolated_compromised_hosts != host_count:
        raise RuntimeError(
            "Containment accounting mismatch: isolated and remaining "
            "compromised hosts must equal the workload host count"
        )

    return {
        "agents": agent_count,
        "hosts": host_count,
        "seed": seed,
        "ticks": ticks,
        "elapsed_seconds": elapsed,
        "ticks_per_second": ticks / elapsed,
        "decisions_per_second": agent_count * ticks / elapsed,

        # Compatibility field used by existing tests.
        # This counts all accepted decisions, including NO_OP.
        "accepted_actions": accepted_actions,

        # Explicit name for the same engine-returned decision count.
        "accepted_decisions": accepted_actions,

        # Actual successful state-changing outcomes are counted separately.
        "accepted_isolation_actions": isolated_hosts,
        "isolated_hosts": isolated_hosts,
        "rejected_actions": len(rejection_events),
        "rejection_reasons": rejection_reasons,
        "analyst_hours_initial": initial_analyst_hours,
        "analyst_hours_remaining": remaining_analyst_hours,
        "remaining_unisolated_compromised_hosts": (
            remaining_unisolated_compromised_hosts
        ),
        "final_tick": world.state.tick,
        "state_sha256": state_digest(world),
    }


def run_benchmark(
    sizes: list[tuple[int, int]],
    seeds: list[int],
    ticks: int,
    repeats: int,
    warmups: int,
) -> dict[str, Any]:
    if not isinstance(ticks, int) or isinstance(ticks, bool) or ticks < 1:
        raise ValueError("ticks must be a positive integer")
    if not isinstance(repeats, int) or isinstance(repeats, bool) or repeats < 2:
        raise ValueError("repeats must be an integer of at least 2")
    if not isinstance(warmups, int) or isinstance(warmups, bool) or warmups < 0:
        raise ValueError("warmups must be a non-negative integer")
    if not sizes:
        raise ValueError("At least one workload size is required")
    if not seeds:
        raise ValueError("At least one seed is required")

    normalized_sizes = []
    for size in sizes:
        if not isinstance(size, (tuple, list)) or len(size) != 2:
            raise ValueError("Each workload size must be an (agents, hosts) pair")
        agents, hosts = size
        if (not isinstance(agents, int) or isinstance(agents, bool)
                or not isinstance(hosts, int) or isinstance(hosts, bool)):
            raise ValueError("Workload agent and host counts must be integers")
        if agents < 2 or hosts < 3:
            raise ValueError("Workloads require at least 2 agents and 3 hosts")
        normalized_sizes.append((agents, hosts))
    if len(set(normalized_sizes)) != len(normalized_sizes):
        raise ValueError("Workload sizes must be unique")

    if any(not isinstance(seed, int) or isinstance(seed, bool) for seed in seeds):
        raise ValueError("seeds must contain integers")
    if len(set(seeds)) != len(seeds):
        raise ValueError("seeds must be unique")

    sizes = normalized_sizes
    results = []

    for agents, hosts in sizes:
        for seed in seeds:
            for _ in range(warmups):
                run_once(agents, hosts, seed, ticks)

            runs = [
                run_once(agents, hosts, seed, ticks)
                for _ in range(repeats)
            ]

            hashes = {run["state_sha256"] for run in runs}
            if len(hashes) != 1:
                raise RuntimeError(
                    f"Non-deterministic result: agents={agents}, "
                    f"hosts={hosts}, seed={seed}"
                )

            median_elapsed = statistics.median(
                run["elapsed_seconds"] for run in runs
            )

            results.append({
                "agents": agents,
                "hosts": hosts,
                "seed": seed,
                "ticks": ticks,
                "repeats": repeats,
                "deterministic": True,
                "state_sha256": runs[0]["state_sha256"],
                "median_elapsed_seconds": median_elapsed,
                "median_ticks_per_second": ticks / median_elapsed,
                "median_decisions_per_second": (
                    agents * ticks / median_elapsed
                ),
                "accepted_actions": runs[0]["accepted_actions"],
                "accepted_decisions": runs[0]["accepted_decisions"],
                "accepted_isolation_actions": (
                    runs[0]["accepted_isolation_actions"]
                ),
                "isolated_hosts": runs[0]["isolated_hosts"],
                "rejected_actions": runs[0]["rejected_actions"],
                "rejection_reasons": runs[0]["rejection_reasons"],
                "analyst_hours_initial": runs[0]["analyst_hours_initial"],
                "analyst_hours_remaining": (
                    runs[0]["analyst_hours_remaining"]
                ),
                "remaining_unisolated_compromised_hosts": (
                    runs[0]["remaining_unisolated_compromised_hosts"]
                ),
                "runs": runs,
            })

    return {
        "benchmark": "nexus_stateful_scaling_v1",
        "measurement": (
            "Observation generation, validated decision application, "
            "state-changing containment, resource enforcement, and tick "
            "advancement. External LLM inference is excluded. "
            "Decision throughput includes NO_OP decisions; successful "
            "isolation outcomes are reported separately."
        ),
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
        description="Benchmark state-changing NEXUS workloads"
    )
    parser.add_argument(
        "--sizes",
        default="2:3,10:10,50:50",
        help="Comma-separated AGENTS:HOSTS pairs",
    )
    parser.add_argument("--seeds", default="7,17,42")
    parser.add_argument("--ticks", type=int, default=50)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--warmups", type=int, default=1)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("artifacts/nexus-stateful-scaling.json"),
    )
    args = parser.parse_args()

    try:
        sizes = [
            tuple(map(int, item.split(":")))
            for item in args.sizes.split(",")
        ]
        seeds = [int(item) for item in args.seeds.split(",")]
    except ValueError as exc:
        parser.error(f"Invalid sizes or seeds: {exc}")

    if any(len(size) != 2 for size in sizes):
        parser.error("Each size must use AGENTS:HOSTS format")

    if any(agents < 2 or hosts < 3 for agents, hosts in sizes):
        parser.error("Each workload requires at least 2 agents and 3 hosts")

    if not seeds:
        parser.error("At least one seed is required")

    report = run_benchmark(
        sizes=sizes,
        seeds=seeds,
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
    print(
        f"{'Agents':>6} {'Hosts':>6} {'Seed':>6} "
        f"{'Ticks/s':>12} {'Decisions/s':>14} "
        f"{'Isolated':>9} {'Rejected':>9} "
        f"{'Hours left':>11} {'Deterministic':>14}"
    )

    for result in report["results"]:
        print(
            f"{result['agents']:>6} "
            f"{result['hosts']:>6} "
            f"{result['seed']:>6} "
            f"{result['median_ticks_per_second']:>12.2f} "
            f"{result['median_decisions_per_second']:>14.2f} "
            f"{result['isolated_hosts']:>9} "
            f"{result['rejected_actions']:>9} "
            f"{result['analyst_hours_remaining']:>11.2f} "
            f"{str(result['deterministic']):>14}"
        )


if __name__ == "__main__":
    main()
