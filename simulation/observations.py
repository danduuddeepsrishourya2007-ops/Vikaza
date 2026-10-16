"""Role-scoped, immutable observations derived from the authoritative world."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .world import World, WorldState


@dataclass(frozen=True)
class HostView:
    host_id: str
    is_compromised: bool
    isolated: bool
    running_services: tuple[tuple[str, bool], ...]
    open_ports: tuple[int, ...]
    known_vulnerabilities: tuple[str, ...]
    installed_patches: tuple[str, ...]


@dataclass(frozen=True)
class DataStoreView:
    store_id: str
    location_host: str
    sensitivity_level: str
    encryption_enabled: bool
    is_exfiltrated: bool


@dataclass(frozen=True)
class AgentView:
    """Immutable snapshot an agent may inspect; never a WorldState reference."""
    agent_id: str
    role: str
    tick: int
    scenario_id: str
    current_host: Optional[str]
    hosts: tuple[HostView, ...]
    network_edges: tuple[tuple[str, str], ...]
    data_stores: tuple[DataStoreView, ...]
    visible_events: tuple[tuple[int, str, str], ...]
    available_resources: tuple[tuple[str, float], ...]


def observe(world: World | WorldState, agent_id: str) -> AgentView:
    """Build a detached, role-scoped snapshot without mutating simulation state.

    Defenders see the full environment and data-store metadata. Attackers see
    only their current host and its directly connected neighbors, and never
    receive data-store records or vulnerability/patch inventories.
    Unknown roles receive the conservative defender-like host inventory only
    when they are explicitly configured as a defender role.
    """
    state = world.state if isinstance(world, World) else world
    agent = state.agents.get(agent_id)
    if agent is None:
        raise KeyError(f"Unknown agent: {agent_id}")

    role = agent.role
    is_attacker = role == "attacker"
    if is_attacker:
        visible_ids: set[str] = set()
        if agent.current_host in state.hosts:
            visible_ids.add(agent.current_host)
            visible_ids.update(state.network.get(agent.current_host, set()))
        # No current foothold means no host inventory is exposed.
    else:
        visible_ids = set(state.hosts)

    host_views = []
    for host_id in sorted(visible_ids):
        host = state.hosts[host_id]
        host_views.append(HostView(
            host_id=host_id,
            is_compromised=host.is_compromised,
            isolated=host.isolated,
            running_services=tuple(sorted(host.running_services.items())),
            open_ports=tuple(sorted(host.open_ports)) if is_attacker else tuple(sorted(host.open_ports)),
            known_vulnerabilities=() if is_attacker else tuple(sorted(host.known_vulnerabilities)),
            installed_patches=() if is_attacker else tuple(sorted(host.installed_patches)),
        ))

    edges = tuple(sorted(
        (source, target)
        for source in visible_ids
        for target in state.network.get(source, set())
        if target in visible_ids
    ))
    stores = () if is_attacker else tuple(
        DataStoreView(
            store_id=s.store_id,
            location_host=s.location_host,
            sensitivity_level=s.sensitivity_level,
            encryption_enabled=s.encryption_enabled,
            is_exfiltrated=s.is_exfiltrated,
        )
        for _, s in sorted(state.data_stores.items())
    )
    # Events are copied into primitive immutable tuples; payloads/details are
    # intentionally excluded to avoid leaking unrelated private information.
    visible_events = tuple(
        (event.tick, str(event.event_type), str(event.actor_id or ""))
        for event in state.events[-10:]
    )
    return AgentView(
        agent_id=agent.agent_id,
        role=role,
        tick=state.tick,
        scenario_id=state.scenario_id,
        current_host=agent.current_host,
        hosts=tuple(host_views),
        network_edges=edges,
        data_stores=stores,
        visible_events=visible_events,
        available_resources=tuple(sorted(state.resource_pool.items())) if not is_attacker else (),
    )
