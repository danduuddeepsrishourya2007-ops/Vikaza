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

    # Phase 1B: defender / coordination actions
    ISOLATE_HOST = "ISOLATE_HOST"
    RESTORE_SERVICE = "RESTORE_SERVICE"
    PATCH_HOST = "PATCH_HOST"
    INVESTIGATE_HOST = "INVESTIGATE_HOST"
    BLOCK_CONNECTION = "BLOCK_CONNECTION"
    ALLOW_CONNECTION = "ALLOW_CONNECTION"
    NOTIFY_CUSTOMERS = "NOTIFY_CUSTOMERS"
    ESCALATE_INCIDENT = "ESCALATE_INCIDENT"

    # Deterministic safe fallback.
    # Requires a valid actor but bypasses role permissions, policy allow-list,
    # targets and resource costs, and never mutates state.
    NO_OP = "NO_OP"


@dataclass
class LegalAction:
    """Represents a legal action that an agent can take."""
    action_type: ActionType
    target: Optional[str]
    resource_cost: Dict[str, int]
    description: str


@dataclass
class AgentDecision:
    """Represents a decision made by an agent."""
    agent_id: str
    tick: int
    action_type: ActionType
    target: Optional[str]
    rationale: str
    source: str
    failure_reason: Optional[str] = None

    def __post_init__(self):
        """Validate the decision after initialization."""
        if self.source not in ["scripted", "fallback_heuristic", "llm"]:
            raise ValueError(
                f"Invalid source: {self.source}. "
                "Must be 'scripted', 'fallback_heuristic', or 'llm'"
            )


@dataclass
class AgentActionRejected:
    """Represents a rejected action with reason."""
    agent_id: str
    tick: int
    action_type: ActionType
    target: Optional[str]
    rationale: str
    source: str
    rejection_reason: str


@dataclass
class AgentActionTaken:
    """Represents an action that was successfully taken."""
    agent_id: str
    tick: int
    action_type: ActionType
    target: Optional[str]
    rationale: str
    source: str
    event_id: Optional[int] = None