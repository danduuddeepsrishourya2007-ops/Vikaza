
from simulation.experiment import (
    compare_providers,
    evaluate_provider,
)
from simulation.baselines import (
    DoNothingProvider,
    ScriptedDefensiveProvider,
)


def test_evaluation_provider_returns_replay_verified_metrics():
    result = evaluate_provider(
        ScriptedDefensiveProvider(),
        "scripted_test",
        seed=7,
        max_ticks=3,
    )
    assert result["replay_verified"] is True
    assert result["metrics"]["final_tick"] == 3
    assert result["trace"]["max_ticks"] == 3
    assert result["decision_provenance"]["source_counts"]["scripted"] > 0
    assert result["decision_provenance"]["source_counts"]["llm"] == 0
    assert result["decision_provenance"]["fallback_reason_counts"] == {}


def test_comparison_uses_each_seed_for_each_provider_and_aggregates_metrics():
    report = compare_providers(
        [
            (DoNothingProvider.policy_id, DoNothingProvider),
            (ScriptedDefensiveProvider.policy_id, ScriptedDefensiveProvider),
        ],
        seeds=[7, 17],
        max_ticks=2,
    )
    assert len(report["runs"]) == 4
    assert report["summaries"][DoNothingProvider.policy_id]["run_count"] == 2
    assert report["summaries"][ScriptedDefensiveProvider.policy_id]["run_count"] == 2
    assert (
        report["summaries"][DoNothingProvider.policy_id]["mean_metrics"]["final_tick"]
        == 2
    )


def test_evaluation_reports_fallback_provenance_from_recorded_decisions():
    from simulation.llm_provider import (
        FallbackProvider,
        OpenAICompatibleProvider,
        ProviderError,
    )

    def unavailable_transport(*args):
        raise ProviderError(
            "offline test",
            category="quota_exhausted",
            status_code=429,
        )

    primary = OpenAICompatibleProvider(
        "http://localhost:8000/v1",
        "offline-test",
        transport=unavailable_transport,
    )
    provider = FallbackProvider(primary, ScriptedDefensiveProvider())
    result = evaluate_provider(
        provider,
        "offline_fallback_test",
        seed=7,
        max_ticks=2,
    )

    provenance = result["decision_provenance"]
    assert result["replay_verified"] is True
    assert provenance["source_counts"]["fallback_heuristic"] > 0
    assert provenance["source_counts"]["llm"] == 0
    assert any(
        reason in {"quota_exhausted", "circuit open: quota_exhausted"}
        for reason in provenance["fallback_reason_counts"]
    )
    assert primary.calls == 1


def test_experiment_rejects_invalid_seed_ticks_and_provider_factory():
    import pytest

    with pytest.raises(ValueError, match="seed must be an integer"):
        evaluate_provider(
            DoNothingProvider(),
            "do_nothing_test",
            seed=True,
            max_ticks=1,
        )

    with pytest.raises(ValueError, match="max_ticks must be a positive integer"):
        evaluate_provider(
            DoNothingProvider(),
            "do_nothing_test",
            seed=1,
            max_ticks=True,
        )

    with pytest.raises(ValueError, match="callable factory"):
        compare_providers([("not_callable", None)], [1], max_ticks=1)


def test_stage5_decision_quality_metrics_are_deterministic_and_auditable():
    first = evaluate_provider(
        ScriptedDefensiveProvider(),
        "candidate",
        seed=71,
        max_ticks=5,
    )
    second = evaluate_provider(
        ScriptedDefensiveProvider(),
        "candidate",
        seed=71,
        max_ticks=5,
    )

    assert first["metrics"] == second["metrics"]
    metrics = first["metrics"]
    assert metrics["containment_achieved"] is True
    assert metrics["time_to_containment_ticks"] == 0
    assert metrics["final_compromised_hosts"] == 0
    assert metrics["data_exfiltrated_gb"] == 0.0
    assert metrics["final_services_running"] <= metrics["total_services"]
    assert (
        metrics["actions_proposed"]
        == metrics["actions_accepted"] + metrics["actions_rejected"]
    )
    assert 0.0 <= metrics["action_acceptance_rate"] <= 1.0
    assert first["replay_verified"] is True


def test_stage5_comparison_reports_paired_outcome_deltas_against_do_nothing():
    report = compare_providers(
        [
            (DoNothingProvider.policy_id, DoNothingProvider),
            (ScriptedDefensiveProvider.policy_id, ScriptedDefensiveProvider),
        ],
        seeds=[7, 17],
        max_ticks=5,
    )

    assert report["report_version"] == 2
    paired = report["paired_deltas_vs_do_nothing"][
        ScriptedDefensiveProvider.policy_id
    ]
    assert paired["baseline_policy_id"] == DoNothingProvider.policy_id
    assert [row["seed"] for row in paired["per_seed"]] == [7, 17]

    for row in paired["per_seed"]:
        assert row["delta_vs_do_nothing"]["final_compromised_hosts"] == -1
        # The baseline does not contain the incident, so its null containment
        # time is excluded from arithmetic deltas.
        assert "time_to_containment_ticks" not in row["delta_vs_do_nothing"]

    assert paired["containment_time_pairing"]["eligible_pairs"] == 0
    assert paired["containment_time_pairing"]["excluded_pairs"] == 2


def test_stage5_do_nothing_does_not_claim_containment():
    result = evaluate_provider(
        DoNothingProvider(),
        DoNothingProvider.policy_id,
        seed=7,
        max_ticks=5,
    )
    metrics = result["metrics"]

    assert metrics["containment_achieved"] is False
    assert metrics["time_to_containment_ticks"] is None
    assert metrics["actions_rejected"] == 0
    assert metrics["actions_proposed"] == metrics["actions_accepted"]


def test_stage5_summary_separates_containment_success_rate_from_time_to_containment():
    report = compare_providers(
        [
            (DoNothingProvider.policy_id, DoNothingProvider),
            (ScriptedDefensiveProvider.policy_id, ScriptedDefensiveProvider),
        ],
        seeds=[7, 17, 31],
        max_ticks=5,
    )

    do_nothing = report["summaries"][DoNothingProvider.policy_id]
    scripted = report["summaries"][ScriptedDefensiveProvider.policy_id]

    assert do_nothing["containment_success_rate"] == 0.0
    assert do_nothing["mean_time_to_containment_ticks_when_achieved"] is None
    assert scripted["containment_success_rate"] == 1.0
    assert scripted["mean_time_to_containment_ticks_when_achieved"] == 0.0


def test_empty_initial_compromise_set_does_not_claim_containment():
    from scenarios.cyber_containment import build_initial_world
    from simulation.evaluation import summarize_world

    world = build_initial_world(7)
    initial_world = build_initial_world(7)

    for host in world.state.hosts.values():
        host.is_compromised = False
    for host in initial_world.state.hosts.values():
        host.is_compromised = False

    metrics = summarize_world(
        world,
        dict(world.state.resource_pool),
        initial_world=initial_world,
        decisions_proposed=0,
    )

    assert metrics["initial_compromised_hosts"] == 0
    assert metrics["containment_achieved"] is False
    assert metrics["time_to_containment_ticks"] is None


def test_new_compromise_event_does_not_expand_initial_containment_targets():
    from scenarios.cyber_containment import build_initial_world
    from simulation.evaluation import summarize_world

    world = build_initial_world(7)
    initial_world = build_initial_world(7)

    initially_compromised = {
        host.host_id
        for host in initial_world.state.hosts.values()
        if host.is_compromised
    }
    newly_compromised = next(
        host.host_id
        for host in world.state.hosts.values()
        if host.host_id not in initially_compromised
    )

    # Record a new compromise event for a host that was clean initially.
    from simulation.events import Event

    world.state.events.append(
        Event(
            event_id=world.state.next_event_id,
            tick=1,
            event_type="HostCompromised",
            payload={"host_id": newly_compromised},
        )
    )
    world.state.next_event_id += 1

    metrics = summarize_world(
        world,
        dict(world.state.resource_pool),
        initial_world=initial_world,
        decisions_proposed=0,
    )

    assert metrics["initial_compromised_hosts"] == len(initially_compromised)


def test_provider_policy_ids_must_be_unique():
    import pytest

    with pytest.raises(ValueError, match="policy_ids must be unique"):
        compare_providers(
            [
                ("duplicate", DoNothingProvider),
                ("duplicate", ScriptedDefensiveProvider),
            ],
            seeds=[7],
            max_ticks=1,
        )
