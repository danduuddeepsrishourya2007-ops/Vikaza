"""
Deterministic transition layer for NEXUS.

Applies an already-validated AgentDecision to WorldState.

No LLM logic.
No natural-language reasoning.
No randomness.

Same WorldState + same AgentDecision produces the same mutation
and event data every time.
"""

from typing import Any, Callable, Dict, Optional, Tuple

from .actions import ActionType, AgentDecision


EventData = Optional[Dict[str, Any]]

TransitionResult = Tuple[
    bool,
    EventData,
]


# ----------------------------------------------------------------------
# Resource costs
# ----------------------------------------------------------------------

ACTION_RESOURCE_COSTS: Dict[
    ActionType,
    Dict[str, float],
] = {
    ActionType.ISOLATE_HOST: {
        "analyst_hours": 2.0,
    },

    ActionType.RESTORE_SERVICE: {
        "analyst_hours": 1.0,
    },

    ActionType.PATCH_HOST: {
        "analyst_hours": 3.0,
    },

    ActionType.INVESTIGATE_HOST: {
        "analyst_hours": 1.0,
    },

    ActionType.BLOCK_CONNECTION: {
        "analyst_hours": 1.0,
    },

    ActionType.ALLOW_CONNECTION: {
        "analyst_hours": 1.0,
    },

    ActionType.NOTIFY_CUSTOMERS: {
        "analyst_hours": 0.5,
    },

    ActionType.ESCALATE_INCIDENT: {
        "analyst_hours": 0.5,
    },

    ActionType.NO_OP: {},
}


def get_action_cost(
    action_type: ActionType,
) -> Dict[str, float]:
    """Return the deterministic resource cost for an action."""
    return ACTION_RESOURCE_COSTS.get(
        action_type,
        {},
    )


def has_sufficient_resources(
    world_state,
    action_type: ActionType,
) -> bool:
    """Check whether the world has sufficient resources."""

    for key, amount in get_action_cost(
        action_type
    ).items():

        if (
            world_state.resource_pool.get(
                key,
                0.0,
            )
            < amount
        ):
            return False

    return True


def _deduct_resources(
    world_state,
    action_type: ActionType,
) -> None:
    """Deduct the exact deterministic cost of an action."""

    for key, amount in get_action_cost(
        action_type
    ).items():

        world_state.resource_pool[
            key
        ] = (
            world_state.resource_pool.get(
                key,
                0.0,
            )
            - amount
        )


# ----------------------------------------------------------------------
# Preconditions
# ----------------------------------------------------------------------

def _split_connection_target(
    target: Optional[str],
) -> Optional[Tuple[str, str]]:
    """Parse a connection target encoded as 'host_a,host_b'."""

    if not target or "," not in target:
        return None

    host_a, host_b = target.split(
        ",",
        1,
    )

    host_a = host_a.strip()
    host_b = host_b.strip()

    if not host_a or not host_b:
        return None

    return host_a, host_b


def precondition_failure(
    world_state,
    decision: AgentDecision,
) -> Optional[str]:
    """
    Check action-specific preconditions.

    Returns:
        None if the action's structural preconditions are satisfied,
        otherwise a deterministic rejection reason.
    """

    action = decision.action_type
    target = decision.target

    if action == ActionType.NO_OP:
        return None

    target_required = {
        ActionType.ISOLATE_HOST,
        ActionType.RESTORE_SERVICE,
        ActionType.PATCH_HOST,
        ActionType.INVESTIGATE_HOST,
        ActionType.BLOCK_CONNECTION,
        ActionType.ALLOW_CONNECTION,
    }

    if action in target_required and not target:
        return (
            f"{action.value} requires a target"
        )

    if action in {
        ActionType.BLOCK_CONNECTION,
        ActionType.ALLOW_CONNECTION,
    }:
        parts = _split_connection_target(
            target
        )

        if parts is None:
            return (
                f"{action.value} target must be "
                "'host_a,host_b'"
            )

        host_a, host_b = parts

        if host_a not in world_state.hosts:
            return (
                f"Unknown host: {host_a}"
            )

        if host_b not in world_state.hosts:
            return (
                f"Unknown host: {host_b}"
            )

        return None

    if action in target_required:
        if target not in world_state.hosts:
            return (
                f"Unknown host: {target}"
            )

    return None


# ----------------------------------------------------------------------
# Defender transitions
# ----------------------------------------------------------------------

def transition_isolate_host(
    world_state,
    decision: AgentDecision,
) -> TransitionResult:

    host = world_state.hosts.get(
        decision.target
    )

    if host is None:
        return False, None

    if host.isolated:
        return False, None

    if not has_sufficient_resources(
        world_state,
        ActionType.ISOLATE_HOST,
    ):
        return False, None

    host.isolated = True

    _deduct_resources(
        world_state,
        ActionType.ISOLATE_HOST,
    )

    return (
        True,
        {
            "type": "HostIsolated",
            "payload": {
                "host_id": decision.target,
            },
            "tags": [
                "security_team"
            ],
        },
    )


def transition_patch_host(
    world_state,
    decision: AgentDecision,
) -> TransitionResult:

    host = world_state.hosts.get(
        decision.target
    )

    if host is None:
        return False, None

    if not has_sufficient_resources(
        world_state,
        ActionType.PATCH_HOST,
    ):
        return False, None

    host.installed_patches.add(
        f"patch_tick_{world_state.tick}"
    )

    host.is_compromised = False

    _deduct_resources(
        world_state,
        ActionType.PATCH_HOST,
    )

    return (
        True,
        {
            "type": "HostPatched",
            "payload": {
                "host_id": decision.target,
            },
            "tags": [
                "security_team"
            ],
        },
    )


def transition_restore_service(
    world_state,
    decision: AgentDecision,
) -> TransitionResult:

    host = world_state.hosts.get(
        decision.target
    )

    if host is None:
        return False, None

    if not has_sufficient_resources(
        world_state,
        ActionType.RESTORE_SERVICE,
    ):
        return False, None

    for service in host.running_services:
        host.running_services[
            service
        ] = True

    _deduct_resources(
        world_state,
        ActionType.RESTORE_SERVICE,
    )

    return (
        True,
        {
            "type": "ServiceRestored",
            "payload": {
                "host_id": decision.target,
            },
            "tags": [
                "security_team"
            ],
        },
    )


def transition_investigate_host(
    world_state,
    decision: AgentDecision,
) -> TransitionResult:

    host = world_state.hosts.get(
        decision.target
    )

    if host is None:
        return False, None

    if not has_sufficient_resources(
        world_state,
        ActionType.INVESTIGATE_HOST,
    ):
        return False, None

    host.monitoring_alerts.append(
        (
            f"investigated_tick_"
            f"{world_state.tick}_"
            f"by_{decision.agent_id}"
        )
    )

    _deduct_resources(
        world_state,
        ActionType.INVESTIGATE_HOST,
    )

    return (
        True,
        {
            "type": "AgentActionTaken",
            "payload": {
                "host_id": decision.target,
                "action": "investigate",
            },
            "tags": [
                "security_team"
            ],
        },
    )


def transition_block_connection(
    world_state,
    decision: AgentDecision,
) -> TransitionResult:

    parts = _split_connection_target(
        decision.target
    )

    if parts is None:
        return False, None

    host_a, host_b = parts

    if host_a not in world_state.hosts:
        return False, None

    if host_b not in world_state.hosts:
        return False, None

    if not has_sufficient_resources(
        world_state,
        ActionType.BLOCK_CONNECTION,
    ):
        return False, None

    world_state.network.setdefault(
        host_a,
        set(),
    ).discard(host_b)

    world_state.network.setdefault(
        host_b,
        set(),
    ).discard(host_a)

    _deduct_resources(
        world_state,
        ActionType.BLOCK_CONNECTION,
    )

    return (
        True,
        {
            "type": "ConnectionBlocked",
            "payload": {
                "host_a": host_a,
                "host_b": host_b,
            },
            "tags": [
                "security_team"
            ],
        },
    )


def transition_allow_connection(
    world_state,
    decision: AgentDecision,
) -> TransitionResult:

    parts = _split_connection_target(
        decision.target
    )

    if parts is None:
        return False, None

    host_a, host_b = parts

    if host_a not in world_state.hosts:
        return False, None

    if host_b not in world_state.hosts:
        return False, None

    if not has_sufficient_resources(
        world_state,
        ActionType.ALLOW_CONNECTION,
    ):
        return False, None

    world_state.network.setdefault(
        host_a,
        set(),
    ).add(host_b)

    world_state.network.setdefault(
        host_b,
        set(),
    ).add(host_a)

    _deduct_resources(
        world_state,
        ActionType.ALLOW_CONNECTION,
    )

    return (
        True,
        {
            "type": "ConnectionAllowed",
            "payload": {
                "host_a": host_a,
                "host_b": host_b,
            },
            "tags": [
                "security_team"
            ],
        },
    )


def transition_notify_customers(
    world_state,
    decision: AgentDecision,
) -> TransitionResult:

    if not has_sufficient_resources(
        world_state,
        ActionType.NOTIFY_CUSTOMERS,
    ):
        return False, None

    _deduct_resources(
        world_state,
        ActionType.NOTIFY_CUSTOMERS,
    )

    return (
        True,
        {
            "type": "CustomerNotified",
            "payload": {},
            "tags": [
                "public"
            ],
        },
    )


def transition_escalate_incident(
    world_state,
    decision: AgentDecision,
) -> TransitionResult:

    if not has_sufficient_resources(
        world_state,
        ActionType.ESCALATE_INCIDENT,
    ):
        return False, None

    _deduct_resources(
        world_state,
        ActionType.ESCALATE_INCIDENT,
    )

    return (
        True,
        {
            "type": "ExecutiveBriefed",
            "payload": {},
            "tags": [
                "executive"
            ],
        },
    )


def transition_no_op(
    world_state,
    decision: AgentDecision,
) -> TransitionResult:
    """
    Deterministic safe fallback.

    No state mutation.
    No resource cost.
    No event.
    """
    return True, None


# ----------------------------------------------------------------------
# Dispatch
# ----------------------------------------------------------------------

TRANSITION_DISPATCH: Dict[
    ActionType,
    Callable[
        [Any, AgentDecision],
        TransitionResult,
    ],
] = {
    ActionType.ISOLATE_HOST:
        transition_isolate_host,

    ActionType.PATCH_HOST:
        transition_patch_host,

    ActionType.RESTORE_SERVICE:
        transition_restore_service,

    ActionType.INVESTIGATE_HOST:
        transition_investigate_host,

    ActionType.BLOCK_CONNECTION:
        transition_block_connection,

    ActionType.ALLOW_CONNECTION:
        transition_allow_connection,

    ActionType.NOTIFY_CUSTOMERS:
        transition_notify_customers,

    ActionType.ESCALATE_INCIDENT:
        transition_escalate_incident,

    ActionType.NO_OP:
        transition_no_op,
}