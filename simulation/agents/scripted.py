"""
Scripted Agent Module
Implements scripted agents for deterministic simulation in NEXUS.
"""

from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field

from .base import BaseAgent, AgentState, AgentMemory
from ..actions import ActionType, AgentDecision
from ..observe import observe
from ..world import WorldState


@dataclass
class ScriptedAgent(BaseAgent):
    """An agent that follows a predetermined script of actions."""

    script: List[Dict[str, Any]] = field(
        default_factory=list
    )

    script_index: int = 0

    def __init__(
        self,
        agent_id: Optional[str] = None,
        role: str = "agent",
        goals: Optional[List[str]] = None,
        resources: Optional[Dict[str, Any]] = None,
        permissions: Optional[List[str]] = None,
        script: Optional[List[Dict[str, Any]]] = None,
    ):
        """Initialize a scripted agent."""

        super().__init__(
            agent_id,
            role,
            goals,
            resources,
            permissions,
        )

        self.script = script or []
        self.script_index = 0

    def step(
        self,
        world: WorldState,
    ) -> Optional[AgentDecision]:
        """
        Get the next action from the script.

        The caller supplies WorldState, whose authoritative clock is
        world.tick.
        """

        # Exhausted script -> deterministic NO_OP at current tick.
        if self.script_index >= len(self.script):
            return AgentDecision(
                agent_id=self.agent_id,
                tick=world.tick,
                action_type=ActionType.NO_OP,
                target=None,
                rationale=(
                    "Script completed, performing no operation"
                ),
                source="scripted",
            )

        # Get and consume the next scripted action.
        script_action = self.script[
            self.script_index
        ]

        self.script_index += 1

        # Convert the action name into the closed ActionType enum.
        try:
            action_type = ActionType[
                script_action.get(
                    "action",
                    "NO_OP",
                )
            ]
        except KeyError:
            action_type = ActionType.NO_OP

        return AgentDecision(
            agent_id=self.agent_id,
            tick=world.tick,
            action_type=action_type,
            target=script_action.get(
                "target"
            ),
            rationale=script_action.get(
                "rationale",
                "Following scripted action",
            ),
            source="scripted",
        )


def create_attacker_agent(
    agent_id: str = "attacker_0",
) -> ScriptedAgent:
    """Create a basic attacker agent for testing."""

    return ScriptedAgent(
        agent_id=agent_id,
        role="attacker",
        goals=[
            "compromise_target_host",
            "exfiltrate_data",
        ],
        resources={
            "tools": 5,
            "exploits": 3,
        },
        permissions=[
            "scan_host",
            "exploit_host",
            "lateral_move",
            "exfiltrate_data",
        ],
        script=[
            {
                "action": "SCAN_HOST",
                "target": "edge_server_0",
                "rationale": "Initial reconnaissance",
            },
            {
                "action": "EXPLOIT_HOST",
                "target": "edge_server_0",
                "rationale": "Gain initial foothold",
            },
            {
                "action": "SCAN_HOST",
                "target": "workstation_0",
                "rationale": "Find lateral movement target",
            },
            {
                "action": "LATERAL_MOVE",
                "target": "workstation_0",
                "rationale": "Move to workstation",
            },
            {
                "action": "EXPLOIT_HOST",
                "target": "workstation_0",
                "rationale": "Compromise workstation",
            },
            {
                "action": "SCAN_HOST",
                "target": "database_server_0",
                "rationale": "Locate database",
            },
            {
                "action": "LATERAL_MOVE",
                "target": "database_server_0",
                "rationale": "Attempt to reach database",
            },
            {
                "action": "EXFILTRATE_DATA",
                "target": "database_server_0",
                "rationale": "Exfiltrate sensitive data",
            },
        ],
    )


def create_defender_agent(
    agent_id: str = "defender_0",
) -> ScriptedAgent:
    """Create a basic defender agent for testing."""

    return ScriptedAgent(
        agent_id=agent_id,
        role="security_engineer",
        goals=[
            "detect_intrusion",
            "contain_breach",
        ],
        resources={
            "analyst_hours": 10,
            "privileges": 5,
        },
        permissions=[
            "scan_host",
            "investigate_host",
            "isolate_host",
            "patch_host",
            "restore_service",
            "notify_customers",
            "escalate_incident",
        ],
        script=[
            {
                "action": "INVESTIGATE_HOST",
                "target": "edge_server_0",
                "rationale": "Investigate initial alert",
            },
            {
                "action": "ISOLATE_HOST",
                "target": "edge_server_0",
                "rationale": "Contain compromised host",
            },
            {
                "action": "NOTIFY_CUSTOMERS",
                "target": None,
                "rationale": "Inform customers of incident",
            },
            {
                "action": "ESCALATE_INCIDENT",
                "target": None,
                "rationale": "Escalate to management",
            },
        ],
    )


def create_executive_agent(
    agent_id: str = "executive_0",
) -> ScriptedAgent:
    """Create a basic executive agent for testing."""

    return ScriptedAgent(
        agent_id=agent_id,
        role="executive",
        goals=[
            "stay_informed",
            "approve_response",
        ],
        resources={
            "budget": 100000,
        },
        permissions=[
            "notify_customers",
            "escalate_incident",
        ],
        script=[
            {
                "action": "NOTIFY_CUSTOMERS",
                "target": None,
                "rationale": "Approve customer notification",
            },
            {
                "action": "ESCALATE_INCIDENT",
                "target": None,
                "rationale": "Authorize incident response budget",
            },
        ],
    )