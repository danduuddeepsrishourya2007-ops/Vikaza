"""
Events Module
Implements event definitions and handling logic for NEXUS Core.
"""

from typing import Dict, Any, Optional
from dataclasses import dataclass
import json


@dataclass
class Event:
    """Base class for all simulation events."""

    timestamp: float
    event_type: str
    data: Dict[str, Any] = None

    def __post_init__(self):
        """Initialize data as empty dict if None."""
        if self.data is None:
            self.data = {}

    def process(self, world):
        """Process this event in the context of the world.

        Args:
            world (World): The world instance to process the event in
        """
        # Delegate to world's event processing
        world._apply_event(self)

    def to_dict(self) -> Dict[str, Any]:
        """Convert event to dictionary representation.

        Returns:
            dict: Dictionary representation of the event
        """
        return {
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "data": self.data.copy() if self.data else {}
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Event':
        """Create event from dictionary representation.

        Args:
            data (dict): Dictionary representation of the event

        Returns:
            Event: Reconstructed event instance
        """
        return cls(
            timestamp=data["timestamp"],
            event_type=data["event_type"],
            data=data.get("data", {}).copy()
        )

    def to_json(self) -> str:
        """Convert event to JSON string.

        Returns:
            str: JSON representation of the event
        """
        return json.dumps(self.to_dict())

    @classmethod
    def from_json(cls, json_str: str) -> 'Event':
        """Create event from JSON string.

        Args:
            json_str (str): JSON representation of the event

        Returns:
            Event: Reconstructed event instance
        """
        data = json.loads(json_str)
        return cls.from_dict(data)

    def __str__(self) -> str:
        """String representation of the event."""
        return f"Event(t={self.timestamp}, type={self.event_type}, data={self.data})"

    def __repr__(self) -> str:
        """Detailed string representation of the event."""
        return self.__str__()