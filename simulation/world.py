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
    persistence_installed: bool = False
    command_and_control_active: bool = False
    defense_evasion_active: bool = False
    impact_applied: bool = False

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
    credentials_obtained: bool = False


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
    # Deterministic simulated attacker effects (no external system access)
    # ------------------------------------------------------------------

    def _attacker_host(self, decision, *, target: bool = True):
        """Resolve a host target for a simulated red-team action."""
        agent = self.state.agents.get(decision.agent_id)
        host_id = decision.target if target else (agent.current_host if agent else None)
        if agent is None or agent.role != "attacker":
            return None, None
        host = self.state.hosts.get(host_id) if host_id else None
        if host is None or host.isolated:
            return agent, None
        return agent, host

    def _effect_network_scan(self, decision):
        actor = self.state.agents.get(decision.agent_id)
        if actor is None:
            return False, None
        if actor.role == "attacker":
            agent, host = self._attacker_host(decision, target=decision.target is not None)
            source = self.state.hosts.get(agent.current_host) if agent else None
            if agent is None or source is None or source.isolated or not source.is_compromised:
                return False, None
            if host is None:
                host = source
            if host.host_id != source.host_id and host.host_id not in self.state.network.get(source.host_id, set()):
                return False, None
            discovered = sorted(self.state.network.get(host.host_id, set()))
            host.logs.append(f"network_scan_tick_{self.state.tick}_by_{decision.agent_id}")
            return True, {"type": "AgentActionTaken", "payload": {
                "action": decision.action_type.value, "host_id": host.host_id,
                "discovered_hosts": discovered,
            }, "tags": ["attacker"]}

        # Authorized defenders can inventory the topology without an attacker foothold.
        if actor.role not in {"security_engineer", "it_administrator"}:
            return False, None
        if decision.target is not None and decision.target not in self.state.hosts:
            return False, None
        scanned = [decision.target] if decision.target else sorted(self.state.hosts)
        discovered = sorted({
            neighbor for host_id in scanned
            for neighbor in self.state.network.get(host_id, set())
        })
        return True, {"type": "AgentActionTaken", "payload": {
            "action": decision.action_type.value, "scanned_hosts": scanned,
            "discovered_hosts": discovered,
        }, "tags": ["security_team"]}

    def _effect_port_scan(self, decision):
        agent, host = self._attacker_host(decision)
        source = self.state.hosts.get(agent.current_host) if agent else None
        if (agent is None or source is None or source.isolated or not source.is_compromised
                or host is None or host.host_id not in {agent.current_host, *self.state.network.get(agent.current_host, set())}):
            return False, None
        host.logs.append(f"port_scan_tick_{self.state.tick}_by_{decision.agent_id}")
        return True, {"type": "AgentActionTaken", "payload": {
            "action": decision.action_type.value, "host_id": host.host_id,
            "open_ports": sorted(host.open_ports),
        }, "tags": ["attacker"]}

    def _effect_vulnerability_scan(self, decision):
        agent, host = self._attacker_host(decision)
        source = self.state.hosts.get(agent.current_host) if agent else None
        if (agent is None or source is None or source.isolated or not source.is_compromised
                or host is None or host.host_id not in {agent.current_host, *self.state.network.get(agent.current_host, set())}):
            return False, None
        findings = sorted(set(host.known_vulnerabilities) - host.installed_patches)
        host.logs.append(f"vulnerability_scan_tick_{self.state.tick}_by_{decision.agent_id}")
        return True, {"type": "AgentActionTaken", "payload": {
            "action": decision.action_type.value, "host_id": host.host_id,
            "finding_count": len(findings),
        }, "tags": ["attacker"]}

    def _effect_credential_dump(self, decision):
        agent, host = self._attacker_host(decision, target=decision.target is not None)
        if agent is None or host is None or host.host_id != agent.current_host or not host.is_compromised:
            return False, None
        agent.credentials_obtained = True
        host.logs.append(f"credential_access_tick_{self.state.tick}")
        return True, {"type": "AgentActionTaken", "payload": {
            "action": decision.action_type.value, "host_id": host.host_id,
            "credentials_obtained": True,
        }, "tags": ["attacker"]}

    def _effect_privilege_escalation(self, decision):
        agent, host = self._attacker_host(decision, target=decision.target is not None)
        if agent is None or host is None or host.host_id != agent.current_host or not host.is_compromised or not agent.credentials_obtained:
            return False, None
        host.privilege_level = min(3, host.privilege_level + 1)
        return True, {"type": "AgentActionTaken", "payload": {
            "action": decision.action_type.value, "host_id": host.host_id,
            "privilege_level": host.privilege_level,
        }, "tags": ["attacker"]}

    def _effect_persistence(self, decision):
        agent, host = self._attacker_host(decision, target=decision.target is not None)
        if agent is None or host is None or host.host_id != agent.current_host or not host.is_compromised or host.privilege_level < 1:
            return False, None
        host.persistence_installed = True
        return True, {"type": "AgentActionTaken", "payload": {
            "action": decision.action_type.value, "host_id": host.host_id,
            "persistence_installed": True,
        }, "tags": ["attacker"]}

    def _effect_lateral_move(self, decision):
        agent, target = self._attacker_host(decision)
        source = self.state.hosts.get(agent.current_host) if agent else None
        if (agent is None or source is None or target is None or source.isolated
                or not source.is_compromised or not agent.credentials_obtained
                or target.host_id not in self.state.network.get(source.host_id, set())
                or target.is_compromised):
            return False, None
        target.is_compromised = True
        target.privilege_level = max(target.privilege_level, 1 if source.privilege_level else 0)
        agent.current_host = target.host_id
        return True, {"type": "HostCompromised", "payload": {
            "host_id": target.host_id, "source_host_id": source.host_id,
            "method": "lateral_movement",
        }, "tags": ["attacker", "security_team"]}

    def _effect_command_and_control(self, decision):
        agent, host = self._attacker_host(decision, target=decision.target is not None)
        if agent is None or host is None or host.host_id != agent.current_host or not host.is_compromised:
            return False, None
        host.command_and_control_active = True
        return True, {"type": "AgentActionTaken", "payload": {
            "action": decision.action_type.value, "host_id": host.host_id,
            "command_and_control_active": True,
        }, "tags": ["attacker"]}

    def _effect_defense_evasion(self, decision):
        agent, host = self._attacker_host(decision, target=decision.target is not None)
        if agent is None or host is None or host.host_id != agent.current_host or not host.is_compromised:
            return False, None
        host.defense_evasion_active = True
        return True, {"type": "AgentActionTaken", "payload": {
            "action": decision.action_type.value, "host_id": host.host_id,
            "defense_evasion_active": True,
        }, "tags": ["attacker"]}

    def _effect_data_exfiltration(self, decision):
        agent, host = self._attacker_host(decision)
        if (agent is None or host is None or host.host_id != agent.current_host
                or not host.is_compromised or not host.command_and_control_active):
            return False, None
        stores = [store for store in self.state.data_stores.values()
                  if store.location_host == host.host_id and not store.is_exfiltrated]
        if not stores:
            return False, None
        total_gb = 0.0
        store_ids = []
        for store in sorted(stores, key=lambda item: item.store_id):
            store.is_exfiltrated = True
            store.access_logs.append(f"exfiltrated_tick_{self.state.tick}")
            total_gb += store.size_gb
            store_ids.append(store.store_id)
        return True, {"type": "DataExfiltrated", "payload": {
            "host_id": host.host_id, "store_ids": store_ids,
            "size_gb": round(total_gb, 3),
        }, "tags": ["attacker", "security_team"]}

    def _effect_impact(self, decision):
        agent, host = self._attacker_host(decision)
        if agent is None or host is None or host.host_id != agent.current_host or not host.is_compromised:
            return False, None
        down = sorted(name for name, running in host.running_services.items() if running)
        if not down:
            return False, None
        for service in down:
            host.running_services[service] = False
        host.impact_applied = True
        return True, {"type": "ServiceDown", "payload": {
            "host_id": host.host_id, "services": down,
            "action": decision.action_type.value,
        }, "tags": ["attacker", "security_team"]}

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

    @staticmethod
    def _decision_shape_failure(decision: Any, current_tick: int) -> Optional[str]:
        """Validate untrusted decision structure before sorting or execution."""
        if not isinstance(decision, AgentDecision):
            return "Decision must be an AgentDecision instance"
        if not isinstance(decision.agent_id, str) or not decision.agent_id.strip() or len(decision.agent_id) > 128:
            return "agent_id must be a non-empty string of at most 128 characters"
        if not isinstance(decision.tick, int) or isinstance(decision.tick, bool) or decision.tick < 0:
            return "tick must be a non-negative integer"
        if decision.tick != current_tick:
            return f"Stale or future decision tick {decision.tick}; current tick is {current_tick}"
        if not isinstance(decision.action_type, ActionType):
            return "action_type must be a recognized ActionType"
        if decision.action_type == ActionType.NO_OP and decision.target is not None:
            return "NO_OP target must be null"
        if decision.target is not None and (
            not isinstance(decision.target, str)
            or not decision.target.strip()
            or len(decision.target) > 256
        ):
            return "target must be null or a non-empty string of at most 256 characters"
        if not isinstance(decision.rationale, str) or len(decision.rationale) > 500:
            return "rationale must be a string of at most 500 characters"
        if not isinstance(decision.source, str) or decision.source not in {"scripted", "fallback_heuristic", "llm"}:
            return "source must be scripted, fallback_heuristic, or llm"
        if decision.failure_reason is not None and (
            not isinstance(decision.failure_reason, str) or len(decision.failure_reason) > 128
        ):
            return "failure_reason must be null or a string of at most 128 characters"
        return None

    def apply_decisions(
        self,
        decisions: List[AgentDecision],
    ) -> List[AgentActionTaken]:
        """Validate and apply proposals in deterministic order.

        Structurally invalid or stale proposals are rejected before ordering,
        preventing malformed values from crashing the scheduler or reaching a
        transition. Rejection events are the only intended state change for a
        rejected proposal.
        """
        policy = self.state.active_policy
        if not policy:
            return []

        actions_taken: List[AgentActionTaken] = []
        seen_agents: Set[str] = set()
        valid_decisions: List[AgentDecision] = []

        for decision in decisions:
            shape_failure = self._decision_shape_failure(decision, self.state.tick)
            if shape_failure:
                self._record_rejection(decision, shape_failure)
            else:
                valid_decisions.append(decision)

        for decision in order_decisions(
            policy,
            self.state,
            valid_decisions,
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
        decision: Any,
        reason: Optional[str],
    ) -> None:
        """Record a rejection without trusting malformed decision fields."""
        raw_agent_id = getattr(decision, "agent_id", None)
        agent_id = raw_agent_id if isinstance(raw_agent_id, str) and raw_agent_id.strip() else None
        raw_action = getattr(decision, "action_type", None)
        action_name = raw_action.value if isinstance(raw_action, ActionType) else f"<invalid:{type(raw_action).__name__}>"
        raw_target = getattr(decision, "target", None)
        target = raw_target if raw_target is None or isinstance(raw_target, str) else f"<invalid:{type(raw_target).__name__}>"
        source = getattr(decision, "source", None)
        if not isinstance(source, str) or source not in {"scripted", "fallback_heuristic", "llm"}:
            source = "unknown"
        failure_reason = getattr(decision, "failure_reason", None)
        if not isinstance(failure_reason, str):
            failure_reason = None

        tags = [f"agent:{agent_id}"] if agent_id else []
        self.emit_event(
            "AgentActionRejected",
            agent_id,
            {
                "action_type": action_name,
                "target": target,
                "source": source,
                "failure_reason": failure_reason,
                "reason": (reason or "unspecified")[:300],
            },
            tags,
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
                event_data.get("payload", {}),
                event_data.get("tags", ()),
            )
            for extra in event_data.get("additional_events", []):
                self.emit_event(
                    extra.get("type"),
                    decision.agent_id,
                    extra.get("payload", {}),
                    extra.get("tags", ()),
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