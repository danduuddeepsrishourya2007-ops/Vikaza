"""
World Simulation Module
Implements the core world state and time progression mechanics for NEXUS Core.
"""

import dataclasses
import random

from typing import (
    Dict,
    Any,
    Iterable,
    List,
    Optional,
    Tuple,
    Set,
    get_args,
)

from dataclasses import dataclass, field

from .events import Event, EventType
from .scheduler import Scheduler
from .policy import (
    PolicyConfig,
    AgentDecision,
    AgentActionTaken,
    order_decisions,
    validate_decision,
)
from .actions import ActionType
from .transitions import TRANSITION_DISPATCH


_VALID_EVENT_TYPES = frozenset(get_args(EventType))

# Upper bound on callback passes within one step().
MAX_CALLBACK_PASSES = 1000


# Attacker/legacy effects are looked up by name at call time.
_LEGACY_EFFECT_METHODS = {
    ActionType.NETWORK_SCAN: "_effect_network_scan",
    ActionType.PORT_SCAN: "_effect_port_scan",
    ActionType.VULNERABILITY_SCAN: "_effect_vulnerability_scan",
    ActionType.CREDENTIAL_DUMP: "_effect_credential_dump",
    ActionType.PRIVILEGE_ESCALATION: "_effect_privilege_escalation",
    ActionType.PERSISTENCE: "_effect_persistence",
    ActionType.LATERAL_MOVE: "_effect_lateral_move",
    ActionType.DATA_EXFILTRATION: "_effect_data_exfiltration",
    ActionType.COMMAND_AND_CONTROL: "_effect_command_and_control",
    ActionType.DEFENSE_EVASION: "_effect_defense_evasion",
    ActionType.IMPACT: "_effect_impact",
}


@dataclass
class HostState:
    """Represents the state of a host in the cyber simulation."""
    host_id: str = ""
    hostname: str = ""
    os_type: str = ""
    os_version: str = ""
    ip_address: str = ""

    is_compromised: bool = False
    isolated: bool = False

    privilege_level: int = 0

    running_services: Dict[str, bool] = field(
        default_factory=dict
    )

    open_ports: Set[int] = field(
        default_factory=set
    )

    known_vulnerabilities: List[str] = field(
        default_factory=list
    )

    installed_patches: Set[str] = field(
        default_factory=set
    )

    data_stores: List[str] = field(
        default_factory=list
    )

    logs: List[str] = field(
        default_factory=list
    )

    monitoring_alerts: List[str] = field(
        default_factory=list
    )

    cpu_usage: float = 0.0
    memory_usage: float = 0.0
    network_connections: int = 0


@dataclass
class DataStoreState:
    """Represents the state of a data store."""
    store_id: str = ""
    name: str = ""
    store_type: str = ""
    location_host: str = ""
    size_gb: float = 0.0
    sensitivity_level: str = "low"
    encryption_enabled: bool = False

    access_logs: List[str] = field(
        default_factory=list
    )

    backup_enabled: bool = False
    last_backup: Optional[str] = None
    is_exfiltrated: bool = False
    integrity_verified: bool = True


@dataclass
class AgentState:
    """Represents the state of an agent."""
    agent_id: str = ""
    role: str = ""
    current_host: Optional[str] = None


@dataclass
class WorldState:
    """Authoritative cyber WorldState for deterministic simulation."""
    tick: int = 0
    rng_seed: int = 0
    scenario_id: str = ""

    hosts: Dict[str, "HostState"] = field(
        default_factory=dict
    )

    network: Dict[str, Set[str]] = field(
        default_factory=dict
    )

    agents: Dict[str, "AgentState"] = field(
        default_factory=dict
    )

    data_stores: Dict[str, "DataStoreState"] = field(
        default_factory=dict
    )

    resource_pool: Dict[str, float] = field(
        default_factory=dict
    )

    active_policy: Optional["PolicyConfig"] = None

    events: List["Event"] = field(
        default_factory=list
    )

    metrics_snapshot: Dict[str, float] = field(
        default_factory=dict
    )

    next_event_id: int = 0


class World:
    """Represents the simulated world state with deterministic progression."""

    def __init__(
        self,
        seed: Optional[int] = None,
    ):
        """Initialize the world with an optional seed."""
        self.seed = seed

        self.random_generator = (
            random.Random(seed)
            if seed is not None
            else random.Random()
        )

        self.state = WorldState()
        self.scheduler = Scheduler()

        self._initialize_default_state()

    def _initialize_default_state(self):
        """Initialize default cyber-specific world state."""

        self.state.hosts = {}
        self.state.network = {}
        self.state.agents = {}
        self.state.data_stores = {}

        self.state.resource_pool = {
            "cpu_cycles": 1000.0,
            "memory_mb": 4096.0,
            "bandwidth_mbps": 100.0,
        }

        self.state.events = []
        self.state.metrics_snapshot = {}

        self._scanned_list = None
        self._events_scanned = 0

        self.state.rng_seed = (
            self.seed
            if self.seed is not None
            else 0
        )

    # ------------------------------------------------------------------
    # Event emission
    # ------------------------------------------------------------------

    def _sync_event_counter(self) -> None:
        """Ensure next_event_id is above every event already in the log."""

        events = self.state.events

        if (
            events is not self._scanned_list
            or len(events) < self._events_scanned
        ):
            self._scanned_list = events
            self._events_scanned = 0

        for event in events[self._events_scanned:]:
            if event.event_id >= self.state.next_event_id:
                self.state.next_event_id = (
                    event.event_id + 1
                )

        self._events_scanned = len(events)

    def _allocate_event_id(self) -> int:
        self._sync_event_counter()

        event_id = self.state.next_event_id
        self.state.next_event_id += 1

        return event_id

    @staticmethod
    def _check_event_type(event_type: Any) -> None:
        if event_type not in _VALID_EVENT_TYPES:
            raise ValueError(
                f"Unknown event type {event_type!r}; "
                "must be one of EventType"
            )

    def emit_event(
        self,
        event_type: str,
        actor_id: Optional[str],
        payload: Optional[Dict[str, Any]] = None,
        tags: Iterable[str] = (),
    ) -> Event:
        """Create an Event at the current tick and append it immediately."""

        self._check_event_type(event_type)

        event = Event(
            event_id=self._allocate_event_id(),
            tick=self.state.tick,
            event_type=event_type,
            actor_id=actor_id,
            payload=dict(payload or {}),
            visibility_tags=frozenset(tags),
        )

        self.state.events.append(event)

        return event

    def schedule_event(
        self,
        tick: int,
        event_type: str,
        actor_id: Optional[str],
        payload: Optional[Dict[str, Any]] = None,
        tags: Iterable[str] = (),
    ) -> str:
        """Schedule a genuinely delayed authoritative Event."""

        if tick < self.state.tick:
            raise ValueError(
                "cannot schedule an event in the past"
            )

        self._check_event_type(event_type)

        event = Event(
            event_id=self._allocate_event_id(),
            tick=tick,
            event_type=event_type,
            actor_id=actor_id,
            payload=dict(payload or {}),
            visibility_tags=frozenset(tags),
        )

        return self.scheduler.schedule_event(
            tick,
            event,
        )

    # ------------------------------------------------------------------
    # Tick advance
    # ------------------------------------------------------------------

    def step(self) -> int:
        """
        Advance the world by one tick.

        Order:
            1. Archive due Events.
            2. Execute due callbacks.
            3. Increment tick.
        """

        due_events = self.scheduler.process_events(
            self.state.tick
        )

        self._sync_event_counter()

        seen_ids = {
            event.event_id
            for event in self.state.events
        }

        for event in due_events:
            if event.event_id in seen_ids:
                event = dataclasses.replace(
                    event,
                    event_id=self._allocate_event_id(),
                )

            seen_ids.add(event.event_id)
            self.state.events.append(event)

        for _ in range(MAX_CALLBACK_PASSES):
            if (
                self.scheduler.process_callbacks(
                    self.state.tick,
                    self,
                )
                == 0
            ):
                break
        else:
            raise RuntimeError(
                "Scheduler callbacks did not settle within "
                f"{MAX_CALLBACK_PASSES} passes"
            )

        self.state.tick += 1

        return self.state.tick

    # ------------------------------------------------------------------
    # Decision pipeline
    # ------------------------------------------------------------------

    def apply_decisions(
        self,
        decisions: List[AgentDecision],
    ) -> List[AgentActionTaken]:
        """
        Apply agent decisions sequentially in deterministic order.
        """

        policy = self.state.active_policy

        if not policy:
            return []

        actions_taken: List[AgentActionTaken] = []
        seen_agents: Set[str] = set()

        for decision in order_decisions(
            policy,
            self.state,
            decisions,
        ):

            if decision.agent_id in seen_agents:
                self._record_rejection(
                    decision,
                    "Duplicate decision from agent in the same batch",
                )
                continue

            seen_agents.add(decision.agent_id)

            is_valid, reason = validate_decision(
                policy,
                decision,
                self.state,
            )

            if not is_valid:
                self._record_rejection(
                    decision,
                    reason,
                )
                continue

            if not self._has_effect_implementation(
                decision.action_type
            ):
                self._record_rejection(
                    decision,
                    (
                        "No transition implemented for "
                        f"{decision.action_type.value}"
                    ),
                )
                continue

            action_taken = self._apply_action(
                decision
            )

            if action_taken is None:
                self._record_rejection(
                    decision,
                    "Transition did not apply",
                )
                continue

            actions_taken.append(action_taken)

        self._update_metrics_snapshot()

        return actions_taken

    def _record_rejection(
        self,
        decision: AgentDecision,
        reason: Optional[str],
    ) -> None:
        """Record a rejected decision."""

        self.emit_event(
            "AgentActionRejected",
            decision.agent_id,
            {
                "action_type": decision.action_type.value,
                "target": decision.target,
                "reason": reason or "unspecified",
            },
            [f"agent:{decision.agent_id}"],
        )

    def _has_effect_implementation(
        self,
        action_type: ActionType,
    ) -> bool:
        if action_type in TRANSITION_DISPATCH:
            return True

        name = _LEGACY_EFFECT_METHODS.get(
            action_type
        )

        return bool(name) and callable(
            getattr(self, name, None)
        )

    def _run_legacy_effect(
        self,
        decision: AgentDecision,
    ) -> Tuple[
        bool,
        Optional[Dict[str, Any]],
    ]:
        """
        Run an attacker/legacy effect method.

        Expected contract:
            (success: bool, event_data: dict | None)
        """

        effect = getattr(
            self,
            _LEGACY_EFFECT_METHODS[
                decision.action_type
            ],
        )

        result = effect(decision)

        if (
            not isinstance(result, tuple)
            or len(result) != 2
            or not isinstance(result[0], bool)
            or not (
                result[1] is None
                or isinstance(result[1], dict)
            )
        ):
            raise TypeError(
                f"{_LEGACY_EFFECT_METHODS[decision.action_type]} "
                "must return (bool, dict | None); "
                f"got {result!r}"
            )

        return result

    def _apply_action(
        self,
        decision: AgentDecision,
    ) -> Optional[AgentActionTaken]:
        """Apply one already-validated decision."""

        handler = TRANSITION_DISPATCH.get(
            decision.action_type
        )

        if handler is not None:
            success, event_data = handler(
                self.state,
                decision,
            )
        else:
            success, event_data = (
                self._run_legacy_effect(
                    decision
                )
            )

        if not success:
            return None

        event = None

        if event_data:
            event = self.emit_event(
                event_data.get("type"),
                decision.agent_id,
                event_data.get(
                    "payload",
                    {},
                ),
                event_data.get(
                    "tags",
                    (),
                ),
            )

        return AgentActionTaken(
            agent_id=decision.agent_id,
            tick=decision.tick,
            action_type=decision.action_type,
            target=decision.target,
            rationale=decision.rationale,
            source=decision.source,
            event_id=(
                event.event_id
                if event
                else None
            ),
        )

    def _update_metrics_snapshot(self) -> None:
        """Update the smallest deterministic state-derived metrics snapshot."""

        hosts = list(
            self.state.hosts.values()
        )

        compromised = sum(
            1
            for host in hosts
            if host.is_compromised
        )

        self.state.metrics_snapshot = {
            "hosts_total": float(
                len(hosts)
            ),
            "hosts_compromised": float(
                compromised
            ),
            "hosts_isolated": float(
                sum(
                    1
                    for host in hosts
                    if host.isolated
                )
            ),
            "breach_spread": (
                compromised / len(hosts)
                if hosts
                else 0.0
            ),
        }

    # ------------------------------------------------------------------
    # State access
    # ------------------------------------------------------------------

    def get_state(self) -> Dict[str, Any]:
        """Get the current world state."""

        return {
            "tick": self.state.tick,
            "rng_seed": self.state.rng_seed,
            "scenario_id": self.state.scenario_id,

            "hosts": {
                host_id: host.__dict__
                for host_id, host
                in self.state.hosts.items()
            },

            "network": {
                host_id: connections.copy()
                for host_id, connections
                in self.state.network.items()
            },

            "agents": {
                agent_id: agent.__dict__
                for agent_id, agent
                in self.state.agents.items()
            },

            "data_stores": {
                store_id: store.__dict__
                for store_id, store
                in self.state.data_stores.items()
            },

            "resource_pool": (
                self.state.resource_pool.copy()
            ),

            "active_policy": self.state.active_policy,

            "events": [
                event.__dict__
                for event in self.state.events
            ],

            "metrics_snapshot": (
                self.state.metrics_snapshot.copy()
            ),
        }

    def get_time(self) -> float:
        """
        Get the current simulation time.

        Kept as a compatibility accessor.
        """
        return float(self.state.tick)

    # ------------------------------------------------------------------
    # Reset
    # ------------------------------------------------------------------

    def reset(
        self,
        seed: Optional[int] = None,
    ):
        """Reset the world to its initial state."""

        if seed is not None:
            self.seed = seed
            self.random_generator = random.Random(
                seed
            )

        elif self.seed is not None:
            self.random_generator = random.Random(
                self.seed
            )

        self.state = WorldState()
        self.scheduler = Scheduler()

        self._initialize_default_state()

    # ------------------------------------------------------------------
    # Compatibility entity accessors
    # ------------------------------------------------------------------

    def add_entity(
        self,
        entity_id: str,
        entity_data: Dict[str, Any],
    ):
        """Add an entity to the appropriate cyber structure."""

        if (
            "host_id" in entity_data
            or "hostname" in entity_data
            or "os_type" in entity_data
        ):
            if "host_id" not in entity_data:
                entity_data["host_id"] = entity_id

            self.state.hosts[entity_id] = HostState(
                **entity_data
            )

        elif (
            "agent_id" in entity_data
            or "role" in entity_data
            or "current_host" in entity_data
        ):
            if "agent_id" not in entity_data:
                entity_data["agent_id"] = entity_id

            self.state.agents[entity_id] = AgentState(
                **entity_data
            )

        elif (
            "store_id" in entity_data
            or "name" in entity_data
            or "store_type" in entity_data
        ):
            if "store_id" not in entity_data:
                entity_data["store_id"] = entity_id

            self.state.data_stores[
                entity_id
            ] = DataStoreState(
                **entity_data
            )

        else:
            if "host_id" not in entity_data:
                entity_data["host_id"] = entity_id

            self.state.hosts[entity_id] = HostState(
                **entity_data
            )

    def update_entity(
        self,
        entity_id: str,
        updates: Dict[str, Any],
    ):
        """Update an entity in the appropriate cyber structure."""

        if entity_id in self.state.hosts:
            entity = self.state.hosts[entity_id]

        elif entity_id in self.state.agents:
            entity = self.state.agents[entity_id]

        elif entity_id in self.state.data_stores:
            entity = self.state.data_stores[
                entity_id
            ]

        else:
            return

        for key, value in updates.items():
            if hasattr(entity, key):
                setattr(
                    entity,
                    key,
                    value,
                )

    def get_entity(
        self,
        entity_id: str,
    ) -> Optional[Dict[str, Any]]:
        """Get an entity's data."""

        if entity_id in self.state.hosts:
            return self.state.hosts[
                entity_id
            ].__dict__

        if entity_id in self.state.agents:
            return self.state.agents[
                entity_id
            ].__dict__

        if entity_id in self.state.data_stores:
            return self.state.data_stores[
                entity_id
            ].__dict__

        return None

    # ------------------------------------------------------------------
    # Resources
    # ------------------------------------------------------------------

    def add_resource(
        self,
        resource_key: str,
        value: Any,
    ):
        """Add or update a resource."""
        self.state.resource_pool[
            resource_key
        ] = value

    def get_resource(
        self,
        resource_key: str,
    ) -> Any:
        """Get a resource value."""
        return self.state.resource_pool.get(
            resource_key
        )

    # ------------------------------------------------------------------
    # Deterministic random helpers
    # ------------------------------------------------------------------

    def random(self) -> float:
        """Get a deterministic random float."""
        return self.random_generator.random()

    def randint(
        self,
        a: int,
        b: int,
    ) -> int:
        """Get a deterministic random integer."""
        return self.random_generator.randint(
            a,
            b,
        )

    def choice(
        self,
        seq: List[Any],
    ) -> Any:
        """Choose a deterministic random element."""
        return self.random_generator.choice(
            seq
        )