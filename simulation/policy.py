"""
Policy Module
Implements typed PolicyConfig for the NEXUS simulation engine.
"""

from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional
from enum import Enum


class ContainmentStrategy(Enum):
    """Different containment strategies that policies can employ."""
    IMMEDIATE = "immediate"
    GRADUAL = "gradual"
    MONITOR_ONLY = "monitor_only"


@dataclass
class PolicyConfig:
    """Typed policy configuration that affects engine behavior."""
    name: str
    containment_strategy: ContainmentStrategy
    isolation_confidence_threshold: float  # 0.0 to 1.0
    allowed_actions: List[str]  # List of action type values that are allowed
    communication_delay_ticks: int  # Delay in ticks for agent communications
    resource_limits: Dict[str, int] = field(default_factory=dict)
    monitoring_enabled: bool = True
    auto_response_enabled: bool = False
    
    def __post_init__(self):
        """Validate policy configuration after initialization."""
        if not 0.0 <= self.isolation_confidence_threshold <= 1.0:
            raise ValueError("isolation_confidence_threshold must be between 0.0 and 1.0")
        if self.communication_delay_ticks < 0:
            raise ValueError("communication_delay_ticks must be non-negative")


def apply_policy_to_legal_actions(
    policy: PolicyConfig, 
    base_legal_actions: List['LegalAction'], 
    agent_role: str
) -> List['LegalAction']:
    """
    Apply policy constraints to determine which actions are legally available to an agent.
    
    Args:
        policy: Current policy configuration
        base_legal_actions: Actions that would be legal without policy constraints
        agent_role: Role of the agent requesting legal actions
        
    Returns:
        List of legally available actions after applying policy
    """
    # Start with base legal actions
    legal_actions = base_legal_actions.copy()
    
    # Filter by allowed actions in policy
    if policy.allowed_actions:
        legal_actions = [
            action for action in legal_actions 
            if action.action_type.value in policy.allowed_actions
        ]
    
    # Apply role-based restrictions
    legal_actions = _apply_role_based_restrictions(legal_actions, agent_role, policy)
    
    # Apply resource constraints
    legal_actions = _apply_resource_constraints(legal_actions, policy)
    
    return legal_actions


def _apply_role_based_restrictions(
    actions: List['LegalAction'], 
    agent_role: str, 
    policy: PolicyConfig
) -> List['LegalAction']:
    """Apply role-based restrictions to legal actions."""
    # Define what actions each role can perform
    role_permissions = {
        "attacker": [
            "SCAN_HOST", "EXPLOIT_HOST", "LATERAL_MOVE", "EXFILTRATE_DATA"
        ],
        "security_engineer": [
            "SCAN_HOST", "ISOLATE_HOST", "PATCH_HOST", "INVESTIGATE_HOST",
            "RESTORE_SERVICE", "NOTIFY_CUSTOMERS", "ESCALATE_INCIDENT"
        ],
        "it_administrator": [
            "ISOLATE_HOST", "PATCH_HOST", "RESTORE_SERVICE", 
            "NOTIFY_CUSTOMERS", "ESCALATE_INCIDENT"
        ],
        "developer": [
            "INVESTIGATE_HOST", "RESTORE_SERVICE"
        ],
        "executive": [
            "NOTIFY_CUSTOMERS", "ESCALATE_INCIDENT"
        ],
        "customer_proxy": []  # Customer proxy typically doesn't take direct actions
    }
    
    allowed_for_role = set(role_permissions.get(agent_role, []))
    
    # Filter actions to only those allowed for this role
    return [
        action for action in actions 
        if action.action_type.value in allowed_for_role
    ]


def _apply_resource_constraints(
    actions: List['LegalAction'], 
    policy: PolicyConfig
) -> List['LegalAction']:
    """Apply resource constraints to legal actions."""
    if not policy.resource_limits:
        return actions
    
    # This would check if agents have sufficient resources to perform actions
    # For now, we'll return all actions - resource checking happens elsewhere
    return actions


def get_policy_effects(policy: PolicyConfig) -> Dict[str, Any]:
    """
    Get the measurable effects of a policy for comparison purposes.
    
    Returns:
        Dictionary describing policy effects on engine behavior
    """
    return {
        "name": policy.name,
        "containment_strategy": policy.containment_strategy.value,
        "isolation_confidence_threshold": policy.isolation_confidence_threshold,
        "allowed_actions_count": len(policy.allowed_actions),
        "communication_delay_ticks": policy.communication_delay_ticks,
        "monitoring_enabled": policy.monitoring_enabled,
        "auto_response_enabled": policy.auto_response_enabled
    }


# Predefined policies as specified in the requirements
def get_immediate_containment_policy() -> PolicyConfig:
    """Get the immediate containment policy."""
    return PolicyConfig(
        name="Immediate Containment",
        containment_strategy=ContainmentStrategy.IMMEDIATE,
        isolation_confidence_threshold=0.7,  # Isolate at 70% confidence
        allowed_actions=[
            "SCAN_HOST", "EXPLOIT_HOST", "LATERAL_MOVE", "EXFILTRATE_DATA",
            "ISOLATE_HOST", "PATCH_HOST", "INVESTIGATE_HOST",
            "RESTORE_SERVICE", "NOTIFY_CUSTOMERS", "ESCALATE_INCIDENT"
        ],
        communication_delay_ticks=0,  # No delay for immediate response
        resource_limits={"isolation_units": 10, "patches": 5},
        monitoring_enabled=True,
        auto_response_enabled=True  # Auto-isolate when threshold reached
    )


def get_gradual_containment_policy() -> PolicyConfig:
    """Get the gradual containment policy.""" 
    return PolicyConfig(
        name="Gradual Containment",
        containment_strategy=ContainmentStrategy.GRADUAL,
        isolation_confidence_threshold=0.9,  # Isolate at 90% confidence (more gradual)
        allowed_actions=[
            "SCAN_HOST", "INVESTIGATE_HOST", "NOTIFY_CUSTOMERS", 
            "ESCALATE_INCIDENT"  # More limited actions initially
        ],
        communication_delay_ticks=2,  # Delayed response for gradual approach
        resource_limits={"isolation_units": 5, "patches": 3},
        monitoring_enabled=True,
        auto_response_enabled=False  # Manual response only
    )
