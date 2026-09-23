"""
Policy Module
Implements typed PolicyConfig for the NEXUS simulation engine.
"""

from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Tuple
from enum import Enum
from .actions import ActionType, AgentDecision, AgentActionRejected, AgentActionTaken
from .world import WorldState


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
    # New fields for Phase 1B
    role_priority: Dict[str, int] = field(default_factory=dict)  # Lower numbers = higher priority
    action_validation: Dict[str, List[str]] = field(default_factory=dict)  # action -> list of roles allowed
    resource_constraints: Dict[str, Any] = field(default_factory=dict)  # e.g., {"max_concurrent_isolations": 2}
    
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


# Decision validation functions for Phase 1B
def validate_decision(policy: PolicyConfig, decision: AgentDecision, world_state: WorldState) -> Tuple[bool, Optional[str]]:
    """
    Validate a single agent decision against policy and world state.
    
    Args:
        policy: Current policy configuration
        decision: The agent decision to validate
        world_state: Current world state
        
    Returns:
        Tuple of (is_valid, rejection_reason) where rejection_reason is None if valid
    """
    # Check if action is allowed by policy
    if policy.allowed_actions and decision.action_type.value not in policy.allowed_actions:
        return False, f"Action {decision.action_type.value} not allowed by policy"
    
    # Check if agent role is allowed to perform this action
    action_roles = policy.action_validation.get(decision.action_type.value, [])
    if action_roles and decision.agent_id not in action_roles:
        # We need to get the agent's role from world state
        agent_state = world_state.agents.get(decision.agent_id)
        if agent_state:
            agent_role = agent_state.role
            if agent_role not in action_roles:
                return False, f"Role {agent_role} not authorized to perform {decision.action_type.value}"
        else:
            return False, f"Agent {decision.agent_id} not found in world state"
    
    # Check resource constraints
    if "max_concurrent_actions" in policy.resource_constraints:
        # Count current actions of this type being performed
        # This would need to be tracked elsewhere - for now we'll skip detailed implementation
        pass
    
    # Additional validation could go here based on world state
    
    return True, None


def validate_decision_batch(world: WorldState, decisions: List[AgentDecision]) -> List[Tuple[bool, Optional[str]]]:
    """
    Validate a batch of agent decisions, resolving conflicts using role priority.
    
    Args:
        world: Current world state
        decisions: List of agent decisions to validate
        
    Returns:
        List of validation results (is_valid, rejection_reason) for each decision
    """
    # Group decisions by target to detect conflicts
    decisions_by_target: Dict[str, List[AgentDecision]] = {}
    for decision in decisions:
        target = decision.target or "unknown"
        if target not in decisions_by_target:
            decisions_by_target[target] = []
        decisions_by_target[target].append(decision)
    
    results = []
    
    # Process each target's decisions
    for target, target_decisions in decisions_by_target.items():
        if len(target_decisions) <= 1:
            # No conflict, validate individually
            for decision in target_decisions:
                is_valid, reason = validate_decision(world.active_policy or PolicyConfig(
                    name="Default", 
                    containment_strategy=ContainmentStrategy.MONITOR_ONLY,
                    isolation_confidence_threshold=0.5,
                    allowed_actions=[],
                    communication_delay_ticks=0
                ), decision, world)
                results.append((is_valid, reason))
        else:
            # Conflict detected - resolve using role priority
            # Sort by role priority (lower number = higher priority)
            def get_decision_priority(decision: AgentDecision) -> int:
                agent_state = world.agents.get(decision.agent_id)
                if agent_state and world.active_policy:
                    role_priority_map = world.active_policy.role_priority
                    return role_priority_map.get(agent_state.role, 999)  # Default low priority
                return 999
            
            sorted_decisions = sorted(target_decisions, key=get_decision_priority)
            
            # Validate each decision in priority order
            for i, decision in enumerate(sorted_decisions):
                is_valid, reason = validate_decision(world.active_policy or PolicyConfig(
                    name="Default", 
                    containment_strategy=ContainmentStrategy.MONITOR_ONLY,
                    isolation_confidence_threshold=0.5,
                    allowed_actions=[],
                    communication_delay_ticks=0
                ), decision, world)
                
                # If this is a conflicting action and not the highest priority, reject it
                if not is_valid and i > 0 and reason and "not allowed" in reason:
                    # Check if it's a conflict with higher priority decision
                    higher_priority_decision = sorted_decisions[0]
                    if (higher_priority_decision.action_type == decision.action_type and 
                        higher_priority_decision.target == decision.target):
                        reason = f"Conflict resolved: higher priority agent {higher_priority_decision.agent_id} wins"
                
                results.append((is_valid, reason))
    
    # Reorder results to match original decision order
    decision_to_result = {id(decision): result for decision, result in zip(decisions, results)}
    return [decision_to_result[id(decision)] for decision in decisions]


def get_role_priority(policy: PolicyConfig, role: str) -> int:
    """
    Get the priority number for a role (lower numbers = higher priority).
    
    Args:
        policy: Policy configuration
        role: Role name
        
    Returns:
        Priority number (default 999 if not specified)
    """
    return policy.role_priority.get(role, 999)


def validate_action_priority(policy: PolicyConfig, decisions: List[AgentDecision]) -> List[AgentDecision]:
    """
    Resolve conflicts in decisions using role priority, returning only the winning decisions.
    
    Args:
        policy: Policy configuration
        decisions: List of agent decisions
        
    Returns:
        List of decisions that won priority resolution
    """
    # Group by (action_type, target) to find conflicts
    conflict_groups: Dict[Tuple[str, Optional[str]], List[AgentDecision]] = {}
    for decision in decisions:
        key = (decision.action_type.value, decision.target)
        if key not in conflict_groups:
            conflict_groups[key] = []
        conflict_groups[key].append(decision)
    
    winning_decisions = []
    
    for key, group in conflict_groups.items():
        if len(group) == 1:
            # No conflict
            winning_decisions.extend(group)
        else:
            # Conflict - resolve by role priority
            def get_priority(decision: AgentDecision) -> int:
                return get_role_priority(policy, decision.agent_id)  # This needs agent state to get role
            
            # Actually, we need to get the agent's role from somewhere
            # For now, we'll sort by agent_id as a placeholder - this should be improved
            sorted_group = sorted(group, key=lambda d: d.agent_id)
            winning_decisions.append(sorted_group[0])  # First agent wins (placeholder)
    
    return winning_decisions


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
