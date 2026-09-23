"""
World Simulation Module
Implements the core world state and time progression mechanics for NEXUS Core.
"""

import random
from typing import Dict, Any, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from .events import Event
from .scheduler import Scheduler
from .policy import PolicyConfig, AgentDecision, AgentActionTaken
from .actions import ActionType


@dataclass
class HostState:
    """Represents the state of a host in the cyber simulation."""
    host_id: str = ""
    hostname: str = ""
    os_type: str = ""
    os_version: str = ""
    ip_address: str = ""
    is_compromised: bool = False
    privilege_level: int = 0  # 0=user, 1=admin, 2=SYSTEM/root
    running_services: Dict[str, bool] = field(default_factory=dict)  # service_name -> is_running
    open_ports: Set[int] = field(default_factory=set)
    known_vulnerabilities: List[str] = field(default_factory=list)
    installed_patches: Set[str] = field(default_factory=set)
    data_stores: List[str] = field(default_factory=list)  # IDs of data stores on this host
    logs: List[str] = field(default_factory=list)
    monitoring_alerts: List[str] = field(default_factory=list)
    cpu_usage: float = 0.0
    memory_usage: float = 0.0
    network_connections: int = 0


@dataclass
class DataStoreState:
    """Represents the state of a data store in the cyber simulation."""
    store_id: str = ""
    name: str = ""
    store_type: str = ""  # database, file_server, etc.
    location_host: str = ""  # Host ID where this data store resides
    size_gb: float = 0.0
    sensitivity_level: str = "low"  # low, medium, high, critical
    encryption_enabled: bool = False
    access_logs: List[str] = field(default_factory=list)
    backup_enabled: bool = False
    last_backup: Optional[str] = None
    is_exfiltrated: bool = False
    integrity_verified: bool = True


@dataclass
class WorldState:
    """Authoritative cyber WorldState for deterministic simulation."""
    tick: int = 0
    rng_seed: int = 0
    scenario_id: str = ""
    hosts: Dict[str, 'HostState'] = field(default_factory=dict)
    network: Dict[str, Set[str]] = field(default_factory=dict)
    agents: Dict[str, 'AgentState'] = field(default_factory=dict)
    data_stores: Dict[str, 'DataStoreState'] = field(default_factory=dict)
    resource_pool: Dict[str, float] = field(default_factory=dict)
    active_policy: Optional['PolicyConfig'] = None
    events: List['Event'] = field(default_factory=list)
    metrics_snapshot: Dict[str, float] = field(default_factory=dict)


class World:
    """Represents the simulated world state with deterministic progression."""

    def __init__(self, seed: Optional[int] = None):
        """Initialize the world with an optional seed for deterministic results.

        Args:
            seed (int, optional): Seed for reproducible simulation
        """
        self.seed = seed
        self.random_generator = random.Random(seed) if seed is not None else random.Random()
        self.state = WorldState()
        self.scheduler = Scheduler()
        self._initialize_default_state()

    def _initialize_default_state(self):
        """Initialize default cyber-specific world state."""
        # Initialize with empty cyber-specific structures
        # These will be populated by the scenario loader
        self.state.hosts = {}
        self.state.network = {}
        self.state.agents = {}
        self.state.data_stores = {}
        self.state.resource_pool = {
            "cpu_cycles": 1000.0,
            "memory_mb": 4096.0,
            "bandwidth_mbps": 100.0
        }
        self.state.events = []
        self.state.metrics_snapshot = {}

    def step(self) -> float:
        """Advance the world by one time step.

        Returns:
            float: The new simulation time after the step
        """
        # Process all events scheduled for current time
        processed_events = self.scheduler.process_events(self.state.time)

        # Apply event effects to world state
        for event in processed_events:
            self._apply_event(event)

        # Advance time by one tick (can be made configurable)
        self.state.time += 1.0
        self.state.tick += 1

        return self.state.time

    def apply_decisions(self, decisions: List[AgentDecision]) -> List[AgentActionTaken]:
        """Apply agent decisions to the world state, returning actions taken.

        This is the core deterministic action and transition engine for Phase 1B.

        Args:
            decisions: List of agent decisions to apply

        Returns:
            List of actions that were successfully taken
        """
        if not self.state.active_policy:
            # No policy means no actions allowed
            return []

        # Validate decisions using policy validation
        validation_results = validate_decision_batch(self.state, decisions)

        # Filter to only valid decisions
        valid_decisions = [
            decision for decision, (is_valid, _) in zip(decisions, validation_results)
            if is_valid
        ]

        # Apply each valid decision
        actions_taken = []
        for decision in valid_decisions:
            action_taken = self._apply_action(decision)
            if action_taken:
                actions_taken.append(action_taken)

        # Update metrics snapshot after applying actions
        self._update_metrics_snapshot()

        return actions_taken

    def _apply_action(self, decision: AgentDecision) -> Optional[AgentActionTaken]:
        """Apply a single agent decision to the world state.

        Args:
            decision: The agent decision to apply

        Returns:
            AgentActionTaken if the action was successful, None otherwise
        """
        # Import here to avoid circular imports
        from .actions import AgentActionTaken
        from .events import Event
        import uuid

        # Dispatch to the appropriate action effect function
        action_effect_map = {
            ActionType.NETWORK_SCAN: self._effect_network_scan,
            ActionType.PORT_SCAN: self._effect_port_scan,
            ActionType.VULNERABILITY_SCAN: self._effect_vulnerability_scan,
            ActionType.CREDENTIAL_DUMP: self._effect_credential_dump,
            ActionType.PRIVILEGE_ESCALATION: self._effect_privilege_escalation,
            ActionType.PERSISTENCE: self._effect_persistence,
            ActionType.LATERAL_MOVE: self._effect_lateral_move,
            ActionType.DATA_EXFILTRATION: self._effect_data_exfiltration,
            ActionType.COMMAND_AND_CONTROL: self._effect_command_and_control,
            ActionType.DEFENSE_EVASION: self._effect_defense_evasion,
            ActionType.IMPACT: self._effect_impact,
        }

        effect_func = action_effect_map.get(decision.action_type)
        if not effect_func:
            return None

        # Apply the action effect
        success, event_data = effect_func(decision)

        if success:
            # Create the action taken record
            action_taken = AgentActionTaken(
                agent_id=decision.agent_id,
                tick=decision.tick,
                action_type=decision.action_type,
                target=decision.target,
                rationale=decision.rationale,
                source=decision.source,
                event_id=str(uuid.uuid4()) if event_data else None
            )

            # Create and schedule an event if event data was produced
            if event_data:
                event = Event(
                    event_id=int(uuid.uuid4().int & (1<<30)-1),  # Generate integer ID
                    tick=self.state.tick,
                    event_type=event_data.get("type", "UnknownAction"),
                    actor_id=decision.agent_id,
                    payload=event_data.get("payload", {}),
                    visibility_tags=frozenset(event_data.get("tags", []))
                )
                self.scheduler.schedule_event(event, self.state.tick + 1)
                self.state.events.append(event)

            return action_taken

        return None

    def _apply_event(self, event: Event):
        """Apply an event's effects to the world state.

        Args:
            event (Event): The event to apply
        """
        # Basic event application - can be extended for specific event types
        if event.event_type == "entity_create":
            entity_id = event.data.get("entity_id")
            entity_data = event.data.get("data", {})
            if entity_id:
                self.state.entities[entity_id] = entity_data
        elif event.event_type == "entity_update":
            entity_id = event.data.get("entity_id")
            updates = event.data.get("updates", {})
            if entity_id and entity_id in self.state.entities:
                self.state.entities[entity_id].update(updates)
        elif event.event_type == "resource_add":
            resource_key = event.data.get("resource_key")
            resource_value = event.data.get("value")
            if resource_key is not None:
                self.state.resources[resource_key] = resource_value
        elif event.event_type == "resource_update":
            resource_key = event.data.get("resource_key")
            update_value = event.data.get("update")
            if resource_key is not None and resource_key in self.state.resources:
                if isinstance(self.state.resources[resource_key], (int, float)) and isinstance(update_value, (int, float)):
                    self.state.resources[resource_key] += update_value
                else:
                    self.state.resources[resource_key] = update_value

    def get_state(self) -> Dict[str, Any]:
        """Get the current world state.

        Returns:
            dict: Current world state
        """
        return {
            'time': self.state.time,
            'entities': self.state.entities.copy(),
            'resources': self.state.resources.copy(),
            'metadata': self.state.metadata.copy()
        }

    def get_time(self) -> float:
        """Get the current simulation time.

        Returns:
            float: Current simulation time
        """
        return self.state.time

    def reset(self, seed: Optional[int] = None):
        """Reset the world to initial state.

        Args:
            seed (int, optional): New seed for deterministic results
        """
        if seed is not None:
            self.seed = seed
            self.random_generator = random.Random(seed)
        elif self.seed is not None:
            self.random_generator = random.Random(self.seed)

        self.state = WorldState()
        self.scheduler = Scheduler()
        self._initialize_default_state()

    def add_entity(self, entity_id: str, entity_data: Dict[str, Any]):
        """Add an entity to the world.

        Args:
            entity_id (str): Unique identifier for the entity
            entity_data (dict): Initial data for the entity
        """
        self.state.entities[entity_id] = entity_data.copy()

    def update_entity(self, entity_id: str, updates: Dict[str, Any]):
        """Update an entity's data.

        Args:
            entity_id (str): Entity identifier
            updates (dict): Data to update
        """
        if entity_id in self.state.entities:
            self.state.entities[entity_id].update(updates)

    def get_entity(self, entity_id: str) -> Optional[Dict[str, Any]]:
        """Get an entity's data.

        Args:
            entity_id (str): Entity identifier

        Returns:
            dict or None: Entity data if found
        """
        return self.state.entities.get(entity_id)

    def add_resource(self, resource_key: str, value: Any):
        """Add or update a resource.

        Args:
            resource_key (str): Resource identifier
            value (any): Resource value
        """
        self.state.resources[resource_key] = value

    def get_resource(self, resource_key: str) -> Any:
        """Get a resource value.

        Args:
            resource_key (str): Resource identifier

        Returns:
            any: Resource value
        """
        return self.state.resources.get(resource_key)

    def random(self) -> float:
        """Get a random float [0, 1) using the world's random generator.

        Returns:
            float: Random value
        """
        return self.random_generator.random()

    def randint(self, a: int, b: int) -> int:
        """Get a random integer in range [a, b] using the world's random generator.

        Args:
            a (int): Lower bound (inclusive)
            b (int): Upper bound (inclusive)

        Returns:
            int: Random integer
        """
        return self.random_generator.randint(a, b)

    def choice(self, seq: List[Any]) -> Any:
        """Choose a random element from a sequence.

        Args:
            seq (list): Sequence to choose from

        Returns:
            any: Randomly chosen element
        """
        return self.random_generator.choice(seq)