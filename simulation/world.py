"""
World Simulation Module
Implements the core world state and time progression mechanics for NEXUS Core.
"""

import random
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from .events import Event
from .scheduler import Scheduler


@dataclass
class WorldState:
    """Represents the current state of the simulated world."""
    time: float = 0.0
    entities: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    resources: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


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
        """Initialize default world state."""
        self.state.entities = {}
        self.state.resources = {}
        self.state.metadata = {
            'created_at': self.state.time,
            'version': '1.0.0'
        }

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

        return self.state.time

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