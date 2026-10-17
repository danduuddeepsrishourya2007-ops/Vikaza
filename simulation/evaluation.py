"""Reproducible baseline evaluation for the cyber-containment scenario."""
from __future__ import annotations

from typing import Any

from scenarios.cyber_containment import SCENARIO_ID, build_initial_world, policy_config
from simulation.baselines import DoNothingProvider, ScriptedDefensiveProvider
from simulation.policy import ContainmentStrategy
from simulation.replay import run_and_record, replay_trace


def build_evaluation_world(seed: int):
    world = build_initial_world(seed)
    world.state.active_policy = policy_config(
        "baseline_evaluation", ContainmentStrategy.IMMEDIATE
    )
    return world


def summarize_world(world, initial_resource_pool: dict[str, float] | None = None) -> dict[str, Any]:
    state = world.state
    hosts = list(state.hosts.values())
    total_services = sum(len(host.running_services) for host in hosts)
    running_services = sum(
        sum(1 for is_running in host.running_services.values() if is_running)
        for host in hosts
    )
    rejected = sum(1 for event in state.events if event.event_type == "AgentActionRejected")
    host_patched_events = sum(1 for event in state.events if event.event_type == "HostPatched")
    initial_resources = initial_resource_pool or {}
    resource_used = {
        key: round(value - state.resource_pool.get(key, 0.0), 3)
        for key, value in sorted(initial_resources.items())
    }
    return {
        "final_tick": state.tick,
        "final_compromised_hosts": sum(1 for host in hosts if host.is_compromised),
        "final_compromised_host_fraction": (
            sum(1 for host in hosts if host.is_compromised) / len(hosts) if hosts else 0.0
        ),
        "final_isolated_hosts": sum(1 for host in hosts if host.isolated),
        "hosts_patched_events": host_patched_events,
        "final_services_running": running_services,
        "total_services": total_services,
        "exfiltrated_stores": sum(1 for store in state.data_stores.values() if store.is_exfiltrated),
        "events_recorded": len(state.events),
        "actions_rejected": rejected,
        "resource_used": resource_used,
        "resource_pool_remaining": dict(sorted(state.resource_pool.items())),
    }


def evaluate_baselines(seed: int = 7, max_ticks: int = 5) -> dict[str, Any]:
    """Run both baselines from equivalent initial conditions and return traces + metrics."""
    if max_ticks < 1:
        raise ValueError("max_ticks must be positive")
    providers = [
        (DoNothingProvider.policy_id, DoNothingProvider()),
        (ScriptedDefensiveProvider.policy_id, ScriptedDefensiveProvider()),
    ]
    results = []
    initial_host_ids = sorted(build_initial_world(seed).state.hosts)
    for policy_id, provider in providers:
        world = build_evaluation_world(seed)
        initial_resources = dict(world.state.resource_pool)
        trace = run_and_record(world, provider, policy_id, max_ticks=max_ticks)
        # Replay the trace against a fresh world; evaluation fails loudly if it diverges.
        replayed = replay_trace(trace.to_json(), build_evaluation_world)
        results.append({
            "policy_id": policy_id,
            "seed": seed,
            "scenario_id": SCENARIO_ID,
            "initial_host_ids": initial_host_ids,
            "metrics": summarize_world(replayed, initial_resources),
            "trace": trace.to_dict(),
        })
    return {
        "evaluation_version": 1,
        "scenario_id": SCENARIO_ID,
        "seed": seed,
        "max_ticks": max_ticks,
        "same_initial_host_ids": all(item["initial_host_ids"] == initial_host_ids for item in results),
        "results": results,
    }
