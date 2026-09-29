from dataclasses import dataclass, field
from typing import Any, Literal
import json


EventType = Literal[
    "IntrusionDetected",
    "HostCompromised",
    "HostIsolated",
    "HostPatched",
    "HostInvestigated",
    "ConnectionBlocked",
    "ConnectionAllowed",
    "DataExfiltrated",
    "ServiceDown",
    "ServiceRestored",
    "PolicyChanged",
    "AgentActionTaken",
    "AgentActionRejected",
    "CustomerNotified",
    "ExecutiveBriefed",
    "TickCompleted",
]


@dataclass(frozen=True)
class Event:
    event_id: int
    tick: int
    event_type: EventType
    actor_id: str | None = None
    payload: dict[str, Any] = field(default_factory=dict)
    visibility_tags: frozenset[str] = field(default_factory=frozenset)

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "tick": self.tick,
            "event_type": self.event_type,
            "actor_id": self.actor_id,
            "payload": self.payload,
            "visibility_tags": sorted(self.visibility_tags),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Event":
        return cls(
            event_id=int(data["event_id"]),
            tick=int(data["tick"]),
            event_type=data["event_type"],
            actor_id=data.get("actor_id"),
            payload=dict(data.get("payload", {})),
            visibility_tags=frozenset(data.get("visibility_tags", [])),
        )

    def to_json(self) -> str:
        return json.dumps(
            self.to_dict(),
            sort_keys=True,
            separators=(",", ":"),
        )

    @classmethod
    def from_json(cls, value: str) -> "Event":
        return cls.from_dict(json.loads(value))