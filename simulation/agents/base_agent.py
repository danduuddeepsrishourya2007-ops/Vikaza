"""
Agent Base Module
Implements the base agent representation for NEXUS Core.
"""

from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
import uuid


@dataclass
class AgentState:
    """Represents the current state of an agent."""
    health: float = 1.0
    energy: float = 1.0
    resources: Dict[str, Any] = field(default_factory=dict)
    status: str = "active"  # active, inactive, disabled, destroyed
    position: Optional[List[float]] = None  # For spatial simulations
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AgentMemory:
    """Represents an agent's memory (simple deterministic memory for Stage 1)."""
    short_term: List[Dict[str, Any]] = field(default_factory=list)
    long_term: List[Dict[str, Any]] = field(default_factory=list)
    max_short_term: int = 10
    max_long_term: int = 100

    def add_short_term(self, item: Dict[str, Any]):
        """Add an item to short-term memory, maintaining size limit."""
        self.short_term.append(item)
        if len(self.short_term) > self.max_short_term:
            self.short_term.pop(0)  # Remove oldest

    def add_long_term(self, item: Dict[str, Any]):
        """Add an item to long-term memory, maintaining size limit."""
        self.long_term.append(item)
        if len(self.long_term) > self.max_long_term:
            self.long_term.pop(0)  # Remove oldest

    def get_recent_memories(self, count: int = 5) -> List[Dict[str, Any]]:
        """Get recent memories from short-term memory."""
        return self.short_term[-count:] if self.short_term else []

    def clear(self):
        """Clear all memory."""
        self.short_term.clear()
        self.long_term.clear()


class BaseAgent:
    """Base class for all agents in the simulation."""

    def __init__(self, agent_id: Optional[str] = None, role: str = "agent",
                 goals: Optional[List[str]] = None, resources: Optional[Dict[str, Any]] = None,
                 permissions: Optional[List[str]] = None):
        """Initialize a base agent.

        Args:
            agent_id (str, optional): Unique identifier for the agent
            role (str): Role/type of the agent
            goals (list): List of goals for the agent
            resources (dict): Initial resources for the agent
            permissions (list): List of permissions for the agent
        """
        self.agent_id = agent_id or str(uuid.uuid4())
        self.role = role
        self.goals = goals or []
        self.resources = resources or {}
        self.permissions = permissions or []
        self.state = AgentState()
        self.memory = AgentMemory()
        self._initialize_default_state()

    def _initialize_default_state(self):
        """Initialize default agent state."""
        # Set some default values if not provided
        if self.state.health <= 0:
            self.state.health = 1.0
        if self.state.energy <= 0:
            self.state.energy = 1.0
        if not self.state.status:
            self.state.status = "active"

    def step(self, world):
        """Perform one step of agent behavior.

        This method should be overridden by subclasses to implement specific agent behavior.

        Args:
            world (World): The world instance the agent exists in
        """
        # Default behavior: do nothing
        # Agents can perceive the world, make decisions, and act
        pass

    def perceive(self, world) -> Dict[str, Any]:
        """Perceive the current state of the world.

        Args:
            world (World): The world instance to perceive

        Returns:
            dict: Perceived world state (subset of full world state)
        """
        # By default, agents perceive a limited view of the world
        # This can be overridden for more sophisticated perception
        world_state = world.get_state()
        return {
            'time': world_state['time'],
            'entities': {self.agent_id: world_state['entities'].get(self.agent_id, {})},
            'resources': world_state['resources'],
            'metadata': world_state['metadata']
        }

    def act(self, world, action: Dict[str, Any]):
        """Perform an action in the world.

        Args:
            world (World): The world instance to act in
            action (dict): Action to perform
        """
        # Default action implementation - can be overridden
        action_type = action.get('type')
        if action_type == "communicate":
            self._communicate(world, action.get('data', {}))
        elif action_type == "modify_self":
            self._modify_self(action.get('data', {}))
            # Default behavior: log the action in memory
            self.memory.add_short_term({
                'type': 'action',
                'action': action,
                'world_time': world.get_time()
            })
        elif action_type == "use_resource":
            self._use_resource(action.get('resource'), action.get('amount', 1))
            # Default behavior: log the action in memory
            self.memory.add_short_term({
                'type': 'action',
                'action': action,
                'world_time': world.get_time()
            })
        else:
            # Default behavior: log the action in memory for unknown action types
            self.memory.add_short_term({
                'type': 'action',
                'action': action,
                'world_time': world.get_time()
            })

    def _communicate(self, world, data: Dict[str, Any]):
        """Communicate with other agents or the environment.

        Args:
            world (World): The world instance
            data (dict): Communication data
        """
        # Store communication in memory
        self.memory.add_short_term({
            'type': 'communication',
            'data': data,
            'world_time': world.get_time()
        })

    def _modify_self(self, data: Dict[str, Any]):
        """Modify the agent's own state.

        Args:
            data (dict): Modification data
        """
        for key, value in data.items():
            if hasattr(self.state, key):
                setattr(self.state, key, value)

    def _use_resource(self, resource_key: str, amount: float = 1):
        """Use a resource from the agent's resources.

        Args:
            resource_key (str): Resource to use
            amount (float): Amount to use
        """
        if resource_key in self.state.resources:
            current = self.state.resources[resource_key]
            if isinstance(current, (int, float)):
                self.state.resources[resource_key] = max(0, current - amount)
            else:
                # For non-numeric resources, just note usage
                pass
        elif resource_key in self.resources:
            current = self.resources[resource_key]
            if isinstance(current, (int, float)):
                self.resources[resource_key] = max(0, current - amount)
            else:
                # For non-numeric resources, just note usage
                pass

    def get_state_dict(self) -> Dict[str, Any]:
        """Get the agent's current state as a dictionary.

        Returns:
            dict: Agent state
        """
        return {
            'agent_id': self.agent_id,
            'role': self.role,
            'goals': self.goals.copy(),
            'resources': self.resources.copy(),
            'permissions': self.permissions.copy(),
            'state': {
                'health': self.state.health,
                'energy': self.state.energy,
                'resources': self.state.resources.copy(),
                'status': self.state.status,
                'position': self.state.position.copy() if self.state.position else None,
                'metadata': self.state.metadata.copy()
            },
            'memory': {
                'short_term_count': len(self.memory.short_term),
                'long_term_count': len(self.memory.long_term),
                'recent_memories': self.memory.get_recent_memories()
            }
        }

    def can_perform(self, permission: str) -> bool:
        """Check if the agent has a specific permission.

        Args:
            permission (str): Permission to check

        Returns:
            bool: True if agent has permission
        """
        return permission in self.permissions

    def receive_event(self, event):
        """Receive and process an event.

        Args:
            event (Event): Event received by the agent
        """
        # Store event in memory
        self.memory.add_short_term({
            'type': 'event',
            'event': {
                'timestamp': event.timestamp,
                'event_type': event.event_type,
                'data': event.data
            },
            'world_time': getattr(event, 'world_time', None)  # If available
        })

    def __str__(self) -> str:
        """String representation of the agent."""
        return f"Agent(id={self.agent_id}, role={self.role}, status={self.state.status})"

    def __repr__(self) -> str:
        """Detailed string representation of the agent."""
        return self.__str__()