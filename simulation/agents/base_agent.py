from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set
from collections import deque


@dataclass
class AgentState:
    """Mutable runtime state for an agent."""

    health: float = 1.0
    energy: float = 1.0
    resources: Dict[str, float] = field(default_factory=dict)
    status: str = "active"
    position: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class MemoryEntry:
    """A single memory entry."""

    data: Dict[str, Any]


class AgentMemory:
    """Bounded short-term and long-term agent memory."""

    def __init__(
        self,
        short_term_limit: int = 10,
        long_term_limit: int = 100,
    ):
        self.short_term: deque = deque(maxlen=short_term_limit)
        self.long_term: deque = deque(maxlen=long_term_limit)

    def add_short_term(self, memory: Dict[str, Any]) -> None:
        """Add an item to short-term memory."""
        self.short_term.append(memory)

    def add_long_term(self, memory: Dict[str, Any]) -> None:
        """Add an item to long-term memory."""
        self.long_term.append(memory)

    def get_recent(self, count: int = 10) -> List[Dict[str, Any]]:
        """Return the most recent short-term memories."""
        if count <= 0:
            return []
        return list(self.short_term)[-count:]

    def clear_short_term(self) -> None:
        """Clear short-term memory."""
        self.short_term.clear()


class BaseAgent:
    """Base class for agents participating in the simulation."""

    def __init__(
        self,
        agent_id: str,
        role: str,
        goals: Optional[List[str]] = None,
        resources: Optional[Dict[str, float]] = None,
        permissions: Optional[Set[str]] = None,
    ):
        self.agent_id = agent_id
        self.role = role
        self.goals = goals or []
        self.resources = resources or {}
        self.permissions = permissions or set()

        self.state = AgentState(
            resources=dict(self.resources),
        )

        self.memory = AgentMemory()

    def perceive(self, world) -> Dict[str, Any]:
        """Perceive the current state of the world.

        This is the legacy BaseAgent perception interface.
        Phase 1A will introduce role-scoped AgentView separately.
        """
        world_state = world.get_state()

        return {
            "world_state": world_state,
            "agent_id": self.agent_id,
            "role": self.role,
        }

    def act(self, world, action):
        """Execute an action through the existing agent interface.

        Authoritative simulation actions will be handled by the
        Phase 1A action/transition layer rather than by this method.
        """
        return None

    def step(self, world):
        """Advance the agent by one simulation step."""
        return None

    def receive_event(self, event):
        """Receive an authoritative simulation event and store it in memory."""

        self.memory.add_short_term(
            {
                "type": "event",
                "event": event.to_dict(),
                "world_time": event.tick,
            }
        )

    def update_state(self, **kwargs) -> None:
        """Update selected agent state fields."""
        for key, value in kwargs.items():
            if not hasattr(self.state, key):
                raise AttributeError(
                    f"Unknown AgentState field: {key}"
                )
            setattr(self.state, key, value)

    def has_permission(self, permission: str) -> bool:
        """Check whether the agent has a permission."""
        return permission in self.permissions

    def add_permission(self, permission: str) -> None:
        """Grant a permission to the agent."""
        self.permissions.add(permission)

    def remove_permission(self, permission: str) -> None:
        """Remove a permission from the agent."""
        self.permissions.discard(permission)

    def add_goal(self, goal: str) -> None:
        """Add a goal if it is not already present."""
        if goal not in self.goals:
            self.goals.append(goal)

    def remove_goal(self, goal: str) -> None:
        """Remove a goal if present."""
        if goal in self.goals:
            self.goals.remove(goal)

    def is_active(self) -> bool:
        """Return whether the agent is active."""
        return self.state.status == "active"

    def __repr__(self) -> str:
        return (
            f"Agent(id={self.agent_id}, "
            f"role={self.role}, "
            f"status={self.state.status})"
        )
