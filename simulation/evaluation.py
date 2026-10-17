
"""Decision-quality metrics for the cyber-containment scenario."""
from __future__ import annotations

from typing import Any


def summarize_world(
    world,
    initial_resource_pool: dict[str, float] | None = None,
    *,
    initial_world=None,
    decisions_proposed: int | None = None,
) -> dict[str, Any]:
    """Calculate outcome metrics from authoritative state and recorded events.

    Containment means every host compromised at the start of the measured run
    has been isolated. A host compromised during the run is not part of that
    initial target set.

    If the initial target set is empty, containment is reported as unsuccessful
    with no containment time. This avoids treating an empty set as a successful
    containment outcome through vacuous truth.

    Exfiltrated GB is model-derived: this scenario models each data store as
    fully exfiltrated or not exfiltrated, rather than partial byte transfers.
    """
    state = world.state
    hosts = list(state.hosts.values())

    total_services = sum(len(host.running_services) for host in hosts)
    running_services = sum(
        sum(1 for is_running in host.running_services.values() if is_running)
        for host in hosts
    )

    events = list(state.events)
    rejected = sum(
        1 for event in events
        if event.event_type == "AgentActionRejected"
    )
    patched_events = sum(
        1 for event in events
        if event.event_type == "HostPatched"
    )

    accepted = (
        max(0, decisions_proposed - rejected)
        if decisions_proposed is not None
        else None
    )

    initial_resources = initial_resource_pool or {}
    resource_used = {
        key: round(value - state.resource_pool.get(key, 0.0), 3)
        for key, value in sorted(initial_resources.items())
    }

    # The initial world must be a separate, unmodified world snapshot/object.
    # Never infer the initial target set from HostCompromised events generated
    # during the measured run.
    initially_compromised = {
        host.host_id
        for host in (
            initial_world.state.hosts.values()
            if initial_world is not None
            else []
        )
        if host.is_compromised
    }

    isolated_initial_compromises: set[str] = set()
    containment_tick = None

    # Empty initial target sets do not count as successful containment.
    if initially_compromised:
        for event in sorted(events, key=lambda item: (item.tick, item.event_id)):
            if event.event_type == "HostIsolated":
                host_id = event.payload.get("host_id")
                if host_id in initially_compromised:
                    isolated_initial_compromises.add(host_id)

            if initially_compromised.issubset(isolated_initial_compromises):
                containment_tick = event.tick
                break

    final_compromised_hosts = sum(
        1 for host in hosts if host.is_compromised
    )
    exfiltrated_stores = [
        store
        for store in state.data_stores.values()
        if store.is_exfiltrated
    ]

    service_down_events = sum(
        1 for event in events if event.event_type == "ServiceDown"
    )
    service_restored_events = sum(
        1 for event in events if event.event_type == "ServiceRestored"
    )

    metrics = {
        "final_tick": state.tick,
        "initial_compromised_hosts": len(initially_compromised),
        "final_compromised_hosts": final_compromised_hosts,
        "final_compromised_host_fraction": (
            final_compromised_hosts / len(hosts) if hosts else 0.0
        ),
        "final_isolated_hosts": sum(
            1 for host in hosts if host.isolated
        ),
        "containment_achieved": containment_tick is not None,
        "time_to_containment_ticks": containment_tick,
        "hosts_patched": patched_events,
        "final_services_running": running_services,
        "total_services": total_services,
        "final_services_down": total_services - running_services,
        "service_availability_fraction": (
            running_services / total_services if total_services else 1.0
        ),
        "service_down_events": service_down_events,
        "service_restored_events": service_restored_events,
        "exfiltrated_stores": len(exfiltrated_stores),
        "data_exfiltrated_gb": round(
            sum(store.size_gb for store in exfiltrated_stores), 3
        ),
        "events_recorded": len(events),
        "actions_proposed": decisions_proposed,
        "actions_accepted": accepted,
        "actions_rejected": rejected,
        "action_acceptance_rate": (
            round(accepted / decisions_proposed, 4)
            if decisions_proposed is not None and decisions_proposed > 0
            else None
        ),
        "resource_used": resource_used,
        "analyst_hours_used": resource_used.get("analyst_hours", 0.0),
        "resource_pool_remaining": dict(sorted(state.resource_pool.items())),
    }
    return metrics

def build_evaluation_world(seed: int):
    """Build the standard evaluation world with its immediate-containment policy."""
    from scenarios.cyber_containment import (
        build_initial_world,
        policy_config,
    )
    from simulation.policy import ContainmentStrategy

    world = build_initial_world(seed)
    world.state.active_policy = policy_config(
        "baseline_evaluation",
        ContainmentStrategy.IMMEDIATE,
    )
    return world

def evaluate_baselines(seed: int = 7, max_ticks: int = 5) -> dict:
    """Preserve the evaluation API used by existing replay tests."""
    from simulation.experiment import evaluate_baselines as _evaluate_baselines

    return _evaluate_baselines(seed=seed, max_ticks=max_ticks)
