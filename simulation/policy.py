"""
Policy Module
Implements typed PolicyConfig for the NEXUS simulation engine.
"""

from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Tuple
from enum import Enum

from .actions import ActionType, AgentDecision, AgentActionRejected, AgentActionTaken
from .transitions import has_sufficient_resources, precondition_failure


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
    isolation_confidence_threshold: float
    allowed_actions: List[str]
    communication_delay_ticks: int
    resource_limits: Dict[str, int] = field(default_factory=dict)
    monitoring_enabled: bool = True
    auto_response_enabled: bool = False

    # Phase 1B
    role_priority: Dict[str, int] = field(default_factory=dict)
    action_validation: Dict[str, List[str]] = field(default_factory=dict)
    resource_constraints: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        """Validate policy configuration after initialization."""
        if not 0.0 <= self.isolation_confidence_threshold <= 1.0:
            raise ValueError(
                "isolation_confidence_threshold must be between 0.0 and 1.0"
            )

        if self.communication_delay_ticks < 0:
            raise ValueError(
                "communication_delay_ticks must be non-negative"
            )


# Single source of truth for role authorization.
#
# NO_OP is deliberately absent. It is exempt from role and policy checks
# after the actor itself has been verified to exist.
ROLE_PERMISSIONS: Dict[str, frozenset] = {
    "attacker": frozenset(
        a.value
        for a in (
            ActionType.NETWORK_SCAN,
            ActionType.PORT_SCAN,
            ActionType.VULNERABILITY_SCAN,
            ActionType.CREDENTIAL_DUMP,
            ActionType.PRIVILEGE_ESCALATION,
            ActionType.PERSISTENCE,
            ActionType.LATERAL_MOVE,
            ActionType.DATA_EXFILTRATION,
            ActionType.COMMAND_AND_CONTROL,
            ActionType.DEFENSE_EVASION,
            ActionType.IMPACT,
        )
    ),

    "security_engineer": frozenset(
        a.value
        for a in (
            ActionType.NETWORK_SCAN,
            ActionType.ISOLATE_HOST,
            ActionType.PATCH_HOST,
            ActionType.INVESTIGATE_HOST,
            ActionType.RESTORE_SERVICE,
            ActionType.BLOCK_CONNECTION,
            ActionType.ALLOW_CONNECTION,
            ActionType.NOTIFY_CUSTOMERS,
            ActionType.ESCALATE_INCIDENT,
        )
    ),

    "it_administrator": frozenset(
        a.value
        for a in (
            ActionType.ISOLATE_HOST,
            ActionType.PATCH_HOST,
            ActionType.RESTORE_SERVICE,
            ActionType.BLOCK_CONNECTION,
            ActionType.ALLOW_CONNECTION,
            ActionType.NOTIFY_CUSTOMERS,
            ActionType.ESCALATE_INCIDENT,
        )
    ),

    "developer": frozenset(
        a.value
        for a in (
            ActionType.INVESTIGATE_HOST,
            ActionType.RESTORE_SERVICE,
        )
    ),

    "executive": frozenset(
        a.value
        for a in (
            ActionType.NOTIFY_CUSTOMERS,
            ActionType.ESCALATE_INCIDENT,
        )
    ),

    "customer_proxy": frozenset(),
}


def apply_policy_to_legal_actions(
    policy: PolicyConfig,
    base_legal_actions: List["LegalAction"],
    agent_role: str,
) -> List["LegalAction"]:
    """
    Apply policy constraints to determine which actions are legally
    available to an agent.
    """
    legal_actions = base_legal_actions.copy()

    if policy.allowed_actions:
        legal_actions = [
            action
            for action in legal_actions
            if (
                action.action_type == ActionType.NO_OP
                or action.action_type.value in policy.allowed_actions
            )
        ]

    legal_actions = _apply_role_based_restrictions(
        legal_actions,
        agent_role,
        policy,
    )

    legal_actions = _apply_resource_constraints(
        legal_actions,
        policy,
    )

    return legal_actions


def _apply_role_based_restrictions(
    actions: List["LegalAction"],
    agent_role: str,
    policy: PolicyConfig,
) -> List["LegalAction"]:
    """Apply role-based restrictions to legal actions."""
    allowed_for_role = ROLE_PERMISSIONS.get(
        agent_role,
        frozenset(),
    )

    return [
        action
        for action in actions
        if (
            action.action_type == ActionType.NO_OP
            or action.action_type.value in allowed_for_role
        )
    ]


def _apply_resource_constraints(
    actions: List["LegalAction"],
    policy: PolicyConfig,
) -> List["LegalAction"]:
    """Apply resource constraints to legal actions."""
    if not policy.resource_limits:
        return actions

    # Resource sufficiency is enforced during decision validation,
    # against the authoritative current WorldState.
    return actions


def get_policy_effects(policy: PolicyConfig) -> Dict[str, Any]:
    """
    Get the measurable effects of a policy for comparison purposes.
    """
    return {
        "name": policy.name,
        "containment_strategy": policy.containment_strategy.value,
        "isolation_confidence_threshold": (
            policy.isolation_confidence_threshold
        ),
        "allowed_actions_count": len(policy.allowed_actions),
        "communication_delay_ticks": policy.communication_delay_ticks,
        "monitoring_enabled": policy.monitoring_enabled,
        "auto_response_enabled": policy.auto_response_enabled,
    }


def validate_decision(
    policy: PolicyConfig,
    decision: AgentDecision,
    world_state: "WorldState",
) -> Tuple[bool, Optional[str]]:
    """
    Validate a single agent decision against policy and world state.

    Returns:
        Tuple of (is_valid, rejection_reason).
    """

    # 1. The actor must exist for every action, including NO_OP.
    agent_state = world_state.agents.get(decision.agent_id)

    if agent_state is None:
        return (
            False,
            f"Agent {decision.agent_id} not found in world state",
        )

    # 2. NO_OP is the deterministic safe fallback.
    # Once the actor exists, it bypasses role, policy, target and
    # resource validation.
    if decision.action_type == ActionType.NO_OP:
        return True, None

    # 3. Role authorization.
    agent_role = agent_state.role

    if decision.action_type.value not in ROLE_PERMISSIONS.get(
        agent_role,
        frozenset(),
    ):
        return (
            False,
            f"Role {agent_role} not authorized to perform "
            f"{decision.action_type.value}",
        )

    # 4. Policy allow-list.
    if (
        policy.allowed_actions
        and decision.action_type.value not in policy.allowed_actions
    ):
        return (
            False,
            f"Action {decision.action_type.value} not allowed by policy",
        )

    # 5. Optional policy-specific role restriction.
    action_roles = policy.action_validation.get(
        decision.action_type.value,
        [],
    )

    if action_roles and agent_role not in action_roles:
        return (
            False,
            f"Role {agent_role} not authorized to perform "
            f"{decision.action_type.value} under current policy",
        )

    # 6. Target and action-specific preconditions.
    reason = precondition_failure(
        world_state,
        decision,
    )

    if reason:
        return False, reason

    # 7. Resource sufficiency against CURRENT balance.
    if not has_sufficient_resources(
        world_state,
        decision.action_type,
    ):
        return (
            False,
            f"Insufficient resources for "
            f"{decision.action_type.value}",
        )

    return True, None


def validate_decision_batch(
    world: "WorldState",
    decisions: List[AgentDecision],
) -> List[Tuple[bool, Optional[str]]]:
    """
    Validate a batch of agent decisions, resolving conflicts
    using role priority.
    """
    from .world import WorldState

    decisions_by_target: Dict[str, List[AgentDecision]] = {}

    for decision in decisions:
        target = decision.target or "unknown"

        if target not in decisions_by_target:
            decisions_by_target[target] = []

        decisions_by_target[target].append(decision)

    results = []

    for target, target_decisions in decisions_by_target.items():
        if len(target_decisions) <= 1:
            for decision in target_decisions:
                is_valid, reason = validate_decision(
                    world.active_policy
                    or PolicyConfig(
                        name="Default",
                        containment_strategy=ContainmentStrategy.MONITOR_ONLY,
                        isolation_confidence_threshold=0.5,
                        allowed_actions=[],
                        communication_delay_ticks=0,
                    ),
                    decision,
                    world,
                )

                results.append((is_valid, reason))

        else:

            def get_decision_priority(
                decision: AgentDecision,
            ) -> int:
                agent_state = world.agents.get(
                    decision.agent_id
                )

                if agent_state and world.active_policy:
                    role_priority_map = (
                        world.active_policy.role_priority
                    )

                    return role_priority_map.get(
                        agent_state.role,
                        999,
                    )

                return 999

            sorted_decisions = sorted(
                target_decisions,
                key=get_decision_priority,
            )

            for i, decision in enumerate(sorted_decisions):
                is_valid, reason = validate_decision(
                    world.active_policy
                    or PolicyConfig(
                        name="Default",
                        containment_strategy=ContainmentStrategy.MONITOR_ONLY,
                        isolation_confidence_threshold=0.5,
                        allowed_actions=[],
                        communication_delay_ticks=0,
                    ),
                    decision,
                    world,
                )

                if (
                    not is_valid
                    and i > 0
                    and reason
                    and "not allowed" in reason
                ):
                    higher_priority_decision = (
                        sorted_decisions[0]
                    )

                    if (
                        higher_priority_decision.action_type
                        == decision.action_type
                        and higher_priority_decision.target
                        == decision.target
                    ):
                        reason = (
                            "Conflict resolved: higher priority "
                            f"agent {higher_priority_decision.agent_id} wins"
                        )

                results.append((is_valid, reason))

    decision_to_result = {
        id(decision): result
        for decision, result in zip(decisions, results)
    }

    return [
        decision_to_result[id(decision)]
        for decision in decisions
    ]


def get_role_priority(
    policy: PolicyConfig,
    role: str,
) -> int:
    """
    Get priority number for a role.
    Lower numbers mean higher priority.
    """
    return policy.role_priority.get(role, 999)


def order_decisions(
    policy: PolicyConfig,
    world_state: "WorldState",
    decisions: List[AgentDecision],
) -> List[AgentDecision]:
    """
    Deterministic total order for applying a batch of decisions.

    Key:
        role priority,
        agent_id,
        action value,
        target
    """

    def key(decision: AgentDecision):
        agent = world_state.agents.get(
            decision.agent_id
        )

        priority = (
            get_role_priority(policy, agent.role)
            if agent
            else 999
        )

        return (
            priority,
            decision.agent_id,
            decision.action_type.value,
            decision.target or "",
        )

    return sorted(
        decisions,
        key=key,
    )


def validate_action_priority(
    policy: PolicyConfig,
    decisions: List[AgentDecision],
    world_state: "WorldState",
) -> List[AgentDecision]:
    """
    Resolve conflicts in decisions using role priority.
    """
    from .world import WorldState

    conflict_groups: Dict[
        Tuple[str, Optional[str]],
        List[AgentDecision],
    ] = {}

    for decision in decisions:
        key = (
            decision.action_type.value,
            decision.target,
        )

        if key not in conflict_groups:
            conflict_groups[key] = []

        conflict_groups[key].append(decision)

    winning_decisions = []

    for key, group in conflict_groups.items():
        if len(group) == 1:
            winning_decisions.extend(group)

        else:

            def get_priority(
                decision: AgentDecision,
            ) -> int:
                agent_state = world_state.agents.get(
                    decision.agent_id
                )

                if agent_state:
                    return get_role_priority(
                        policy,
                        agent_state.role,
                    )

                return 999

            sorted_group = sorted(
                group,
                key=lambda d: (
                    get_priority(d),
                    d.agent_id,
                ),
            )

            winning_decisions.append(
                sorted_group[0]
            )

    return winning_decisions


def get_immediate_containment_policy() -> PolicyConfig:
    """Get the immediate containment policy."""
    return PolicyConfig(
        name="Immediate Containment",
        containment_strategy=ContainmentStrategy.IMMEDIATE,
        isolation_confidence_threshold=0.7,
        allowed_actions=[
            "NETWORK_SCAN",
            "LATERAL_MOVE",
            "DATA_EXFILTRATION",
            "ISOLATE_HOST",
            "PATCH_HOST",
            "INVESTIGATE_HOST",
            "RESTORE_SERVICE",
            "BLOCK_CONNECTION",
            "ALLOW_CONNECTION",
            "NOTIFY_CUSTOMERS",
            "ESCALATE_INCIDENT",
            "NO_OP",
        ],
        communication_delay_ticks=0,
        resource_limits={
            "isolation_units": 10,
            "patches": 5,
        },
        monitoring_enabled=True,
        auto_response_enabled=True,
    )


def get_gradual_containment_policy() -> PolicyConfig:
    """Get the gradual containment policy."""
    return PolicyConfig(
        name="Gradual Containment",
        containment_strategy=ContainmentStrategy.GRADUAL,
        isolation_confidence_threshold=0.9,
        allowed_actions=[
            "NETWORK_SCAN",
            "INVESTIGATE_HOST",
            "NOTIFY_CUSTOMERS",
            "ESCALATE_INCIDENT",
            "NO_OP",
        ],
        communication_delay_ticks=2,
        resource_limits={
            "isolation_units": 5,
            "patches": 3,
        },
        monitoring_enabled=True,
        auto_response_enabled=False,
    )