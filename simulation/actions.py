"""
Actions Module
Defines the action model for the NEXUS simulation engine.
"""

from enum import Enum
from dataclasses import dataclass
from typing import Dict, Any, Optional, List
import uuid


class ActionType(Enum):
    """Closed enum of action types available in the simulation."""
    SCAN_HOST = "SCAN_HOST"
    EXPLOIT_HOST = "EXPLOIT_HOST"
    LATERAL_MOVE = "LATERAL_MOVE"
    EXFILTRATE_DATA = "EXFILTRATE_DATA"
    ISOLATE_HOST = "ISOLATE_HOST"
    PATCH_HOST = "PATCH_HOST"
    INVESTIGATE_HOST = "INVESTIGATE_HOST"
    RESTORE_SERVICE = "RESTORE_SERVICE"
    NOTIFY_CUSTOMERS = "NOTIFY_CUSTOMERS"
    ESCALATE_INCIDENT = "ESCALATE_INCIDENT"
    NO_OP = "NO_OP"


@dataclass
class LegalAction:
    """Represents a legal action that an agent can take."""
    action_type: ActionType
    target: Optional[str]  # Target host/entity ID
    resource_cost: Dict[str, int]  # Resources required to perform action
    description: str  # Human-readable description
    

@dataclass
class AgentDecision:
    """Represents a decision made by an agent."""
    agent_id: str
    tick: int
    action_type: ActionType
    target: Optional[str]
    rationale: str  # Display/debug information only
    source: str  # "scripted", "fallback_heuristic", or "llm"
    
    def __post_init__(self):
        """Validate the decision after initialization."""
        if self.source not in ["scripted", "fallback_heuristic", "llm"]:
            raise ValueError(f"Invalid source: {self.source}. Must be 'scripted', 'fallback_heuristic', or 'llm'")


@dataclass
class AgentActionRejected:
    """Represents a rejected action with reason."""
    agent_id: str
    tick: int
    action_type: ActionType
    target: Optional[str]
    rationale: str
    source: str
    rejection_reason: str  # Why the action was rejected
    

@dataclass
class AgentActionTaken:
    """Represents an action that was successfully taken."""
    agent_id: str
    tick: int
    action_type: ActionType
    target: Optional[str]
    rationale: str
    source: str
    event_id: Optional[str] = None  # ID of the resulting event
