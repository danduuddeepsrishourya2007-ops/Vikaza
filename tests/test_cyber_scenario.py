from scenarios.cyber_containment import (
    build_initial_world,
    compare_containment_policies,
    run_policy,
)
from simulation.policy import ContainmentStrategy


def test_initial_cyber_world_has_expected_topology_and_seed():
    world = build_initial_world(seed=11)
    assert world.state.rng_seed == 11
    assert set(world.state.hosts) == {
        "developer_workstation", "application_server", "customer_database"
    }
    assert "application_server" in world.state.network["developer_workstation"]
    assert world.state.hosts["developer_workstation"].is_compromised


def test_policy_comparison_uses_equivalent_initial_conditions():
    result = compare_containment_policies(seed=17)
    assert result["same_initial_host_ids"] is True
    immediate, gradual = result["comparison"]
    assert immediate["initial_state"] == gradual["initial_state"]
    assert immediate["seed"] == gradual["seed"] == 17


def test_immediate_policy_isolates_before_gradual_policy():
    immediate = run_policy("Immediate", ContainmentStrategy.IMMEDIATE, seed=3)
    gradual = run_policy("Gradual", ContainmentStrategy.GRADUAL, seed=3)
    assert immediate["metrics"]["first_isolation_tick"] == 0
    assert gradual["metrics"]["first_isolation_tick"] == 1
    assert immediate["metrics"]["analyst_hours_used"] == 7.0
    assert gradual["metrics"]["analyst_hours_used"] == 8.0


def test_same_policy_and_seed_are_reproducible():
    first = run_policy("Immediate", ContainmentStrategy.IMMEDIATE, seed=99)
    second = run_policy("Immediate", ContainmentStrategy.IMMEDIATE, seed=99)
    assert first == second
