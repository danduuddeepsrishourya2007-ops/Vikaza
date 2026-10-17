"""Synthetic deterministic workloads for NEXUS engine benchmarks."""

from __future__ import annotations

from simulation.world import AgentState, HostState, World
from scenarios.cyber_containment import build_initial_world, policy_config


SCALING_SCENARIO_ID = "nexus_cyber_scaling_v1"


def build_scaling_world(
    agent_count: int,
    host_count: int,
    seed: int = 7,
) -> World:
    """Build a scaled workload while preserving the original scenario."""

    if agent_count < 2:
        raise ValueError("agent_count must be at least 2")
    if host_count < 3:
        raise ValueError("host_count must be at least 3")

    world = build_initial_world(seed=seed)
    state = world.state

    if agent_count < len(state.agents):
        raise ValueError(
            f"agent_count must be at least {len(state.agents)}"
        )
    if host_count < len(state.hosts):
        raise ValueError(
            f"host_count must be at least {len(state.hosts)}"
        )

    # Add hosts as a deterministic chain connected to the existing network.
    existing_host_ids = sorted(state.hosts)
    previous_host = "application_server"

    for index in range(len(state.hosts), host_count):
        host_id = f"scale_host_{index:04d}"

        state.hosts[host_id] = HostState(
            host_id=host_id,
            hostname=host_id,
            os_type="linux",
            os_version="benchmark",
            ip_address=f"10.200.{index // 250}.{index % 250 + 1}",
            running_services={"benchmark_service": True},
        )

        state.network.setdefault(host_id, set())
        state.network.setdefault(previous_host, set())

        state.network[previous_host].add(host_id)
        state.network[host_id].add(previous_host)

        previous_host = host_id

    host_ids = sorted(state.hosts)

    # Keep the original two agents. Additional agents are passive
    # IT administrators whose benchmark decisions are NO_OP.
    for index in range(agent_count - len(state.agents)):
        agent_id = f"scale_admin_{index:04d}"
        host_id = host_ids[index % len(host_ids)]

        state.agents[agent_id] = AgentState(
            agent_id=agent_id,
            role="it_administrator",
            current_host=host_id,
        )

    state.scenario_id = SCALING_SCENARIO_ID
    state.active_policy = policy_config(
        "nexus_scaling_noop",
        "custom",
    )

    return world