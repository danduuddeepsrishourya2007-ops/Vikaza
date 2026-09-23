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
    NETWORK_SCAN = "NETWORK_SCAN"
    PORT_SCAN = "PORT_SCAN"
    VULNERABILITY_SCAN = "VULNERABILITY_SCAN"
    CREDENTIAL_DUMP = "CREDENTIAL_DUMP"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    PERSISTENCE = "PERSISTENCE"
    LATERAL_MOVE = "LATERAL_MOVE"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    COMMAND_AND_CONTROL = "COMMAND_AND_CONTROL"
    DEFENSE_EVASION = "DEFENSE_EVASION"
    IMPACT = "IMPACT"


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
