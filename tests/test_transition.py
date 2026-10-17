from copy import deepcopy

from simulation.actions import ActionType, AgentDecision
from simulation.transitions import (
    transition_allow_connection,
    transition_block_connection,
    transition_isolate_host,
    transition_no_op,
    transition_patch_host,
    transition_restore_service,
    transition_investigate_host,
    transition_notify_customers,
    transition_escalate_incident,
    precondition_failure,
)
from simulation.world import HostState, WorldState


def make_decision(
    action_type,
    target=None,
    agent_id="security_1",
):
    return AgentDecision(
        agent_id=agent_id,
        tick=0,
        action_type=action_type,
        target=target,
        rationale="test",
        source="scripted",
    )


def make_world():
    world = WorldState()

    world.hosts["host_a"] = HostState(
        host_id="host_a",
        hostname="host-a",
        os_type="Linux",
        os_version="1.0",
        ip_address="10.0.0.1",
        is_compromised=True,
        isolated=False,
        running_services={
            "web": False,
            "api": False,
        },
    )

    world.hosts["host_b"] = HostState(
        host_id="host_b",
        hostname="host-b",
        os_type="Linux",
        os_version="1.0",
        ip_address="10.0.0.2",
    )

    world.network["host_a"] = {"host_b"}
    world.network["host_b"] = {"host_a"}

    world.resource_pool["analyst_hours"] = 20.0

    return world


def test_isolate_host_changes_state_and_consumes_resources():
    world = make_world()

    decision = make_decision(
        ActionType.ISOLATE_HOST,
        "host_a",
    )

    success, event = transition_isolate_host(
        world,
        decision,
    )

    assert success is True
    assert world.hosts["host_a"].isolated is True
    assert world.resource_pool["analyst_hours"] == 18.0

    assert event is not None
    assert event["type"] == "HostIsolated"
    assert event["payload"]["host_id"] == "host_a"


def test_patch_host_clears_compromise_and_consumes_resources():
    world = make_world()

    decision = make_decision(
        ActionType.PATCH_HOST,
        "host_a",
    )

    success, event = transition_patch_host(
        world,
        decision,
    )

    assert success is True
    assert world.hosts["host_a"].is_compromised is False
    assert world.resource_pool["analyst_hours"] == 17.0

    assert event is not None
    assert event["type"] == "HostPatched"


def test_restore_service_restores_all_services():
    world = make_world()

    decision = make_decision(
        ActionType.RESTORE_SERVICE,
        "host_a",
    )

    success, event = transition_restore_service(
        world,
        decision,
    )

    assert success is True

    assert all(
        world.hosts["host_a"].running_services.values()
    )

    assert world.resource_pool["analyst_hours"] == 19.0

    assert event is not None
    assert event["type"] == "ServiceRestored"


def test_block_connection_removes_both_directions():
    world = make_world()

    decision = make_decision(
        ActionType.BLOCK_CONNECTION,
        "host_a,host_b",
    )

    success, event = transition_block_connection(
        world,
        decision,
    )

    assert success is True

    assert "host_b" not in world.network["host_a"]
    assert "host_a" not in world.network["host_b"]

    assert world.resource_pool["analyst_hours"] == 19.0

    assert event is not None
    assert event["type"] == "ConnectionBlocked"


def test_allow_connection_adds_both_directions():
    world = make_world()

    world.network["host_a"].discard("host_b")
    world.network["host_b"].discard("host_a")

    decision = make_decision(
        ActionType.ALLOW_CONNECTION,
        "host_a,host_b",
    )

    success, event = transition_allow_connection(
        world,
        decision,
    )

    assert success is True

    assert "host_b" in world.network["host_a"]
    assert "host_a" in world.network["host_b"]

    assert world.resource_pool["analyst_hours"] == 19.0

    assert event is not None
    assert event["type"] == "ConnectionAllowed"


def test_investigate_host_consumes_resources_and_records_alert():
    world = make_world()

    before = len(
        world.hosts["host_a"].monitoring_alerts
    )

    decision = make_decision(
        ActionType.INVESTIGATE_HOST,
        "host_a",
    )

    success, event = transition_investigate_host(
        world,
        decision,
    )

    assert success is True

    assert (
        len(world.hosts["host_a"].monitoring_alerts)
        == before + 1
    )

    assert world.resource_pool["analyst_hours"] == 19.0

    assert event is not None
    assert event["type"] == "AgentActionTaken"


def test_notify_customers_consumes_resources():
    world = make_world()

    decision = make_decision(
        ActionType.NOTIFY_CUSTOMERS,
    )

    success, event = transition_notify_customers(
        world,
        decision,
    )

    assert success is True
    assert world.resource_pool["analyst_hours"] == 19.5

    assert event is not None
    assert event["type"] == "CustomerNotified"


def test_escalate_incident_consumes_resources():
    world = make_world()

    decision = make_decision(
        ActionType.ESCALATE_INCIDENT,
    )

    success, event = transition_escalate_incident(
        world,
        decision,
    )

    assert success is True
    assert world.resource_pool["analyst_hours"] == 19.5

    assert event is not None
    assert event["type"] == "ExecutiveBriefed"


def test_no_op_does_not_mutate_world():
    world = make_world()

    before = deepcopy(world)

    decision = make_decision(
        ActionType.NO_OP,
    )

    success, event = transition_no_op(
        world,
        decision,
    )

    assert success is True
    assert event is None
    assert world == before


def test_insufficient_resources_reject_action_without_mutation():
    world = make_world()

    world.resource_pool["analyst_hours"] = 1.0

    before_isolated = world.hosts["host_a"].isolated
    before_resources = world.resource_pool["analyst_hours"]

    decision = make_decision(
        ActionType.ISOLATE_HOST,
        "host_a",
    )

    success, event = transition_isolate_host(
        world,
        decision,
    )

    assert success is False
    assert event is None
    assert (
        world.hosts["host_a"].isolated
        == before_isolated
    )
    assert (
        world.resource_pool["analyst_hours"]
        == before_resources
    )


def test_invalid_target_does_not_pass_preconditions():
    world = make_world()

    decision = make_decision(
        ActionType.ISOLATE_HOST,
        "does_not_exist",
    )

    failure = precondition_failure(
        world,
        decision,
    )

    assert failure == "Unknown host: does_not_exist"


def test_connection_target_requires_two_hosts():
    world = make_world()

    decision = make_decision(
        ActionType.BLOCK_CONNECTION,
        "host_a",
    )

    failure = precondition_failure(
        world,
        decision,
    )

    assert failure == (
        "BLOCK_CONNECTION target must be 'host_a,host_b'"
    )


def test_connection_target_with_more_than_one_comma_is_rejected():
    world = make_world()
    decision = make_decision(ActionType.BLOCK_CONNECTION, "host_a,host_b,host_c")
    assert precondition_failure(world, decision) == "BLOCK_CONNECTION target must be 'host_a,host_b'"
