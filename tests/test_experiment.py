from simulation.experiment import compare_providers, evaluate_provider
from simulation.baselines import DoNothingProvider, ScriptedDefensiveProvider


def test_evaluation_provider_returns_replay_verified_metrics():
    result = evaluate_provider(ScriptedDefensiveProvider(), "scripted_test", seed=7, max_ticks=3)
    assert result["replay_verified"] is True
    assert result["metrics"]["final_tick"] == 3
    assert result["trace"]["max_ticks"] == 3
    assert result["decision_provenance"]["source_counts"]["scripted"] > 0
    assert result["decision_provenance"]["source_counts"]["llm"] == 0
    assert result["decision_provenance"]["fallback_reason_counts"] == {}


def test_comparison_uses_each_seed_for_each_provider_and_aggregates_metrics():
    report = compare_providers(
        [(DoNothingProvider.policy_id, DoNothingProvider),
         (ScriptedDefensiveProvider.policy_id, ScriptedDefensiveProvider)],
        seeds=[7, 17], max_ticks=2,
    )
    assert len(report["runs"]) == 4
    assert report["summaries"][DoNothingProvider.policy_id]["run_count"] == 2
    assert report["summaries"][ScriptedDefensiveProvider.policy_id]["run_count"] == 2
    assert report["summaries"][DoNothingProvider.policy_id]["mean_metrics"]["final_tick"] == 2


def test_evaluation_reports_fallback_provenance_from_recorded_decisions():
    from simulation.llm_provider import FallbackProvider, OpenAICompatibleProvider, ProviderError

    def unavailable_transport(*args):
        raise ProviderError("offline test", category="quota_exhausted", status_code=429)

    primary = OpenAICompatibleProvider(
        "http://localhost:8000/v1", "offline-test", transport=unavailable_transport,
    )
    provider = FallbackProvider(primary, ScriptedDefensiveProvider())
    result = evaluate_provider(provider, "offline_fallback_test", seed=7, max_ticks=2)

    provenance = result["decision_provenance"]
    assert result["replay_verified"] is True
    assert provenance["source_counts"]["fallback_heuristic"] > 0
    assert provenance["source_counts"]["llm"] == 0
    assert any(reason in {"quota_exhausted", "circuit open: quota_exhausted"}
               for reason in provenance["fallback_reason_counts"])
    assert primary.calls == 1


def test_experiment_rejects_invalid_seed_ticks_and_provider_factory():
    import pytest

    with pytest.raises(ValueError, match="seed must be an integer"):
        evaluate_provider(DoNothingProvider(), "do_nothing_test", seed=True, max_ticks=1)
    with pytest.raises(ValueError, match="max_ticks must be a positive integer"):
        evaluate_provider(DoNothingProvider(), "do_nothing_test", seed=1, max_ticks=True)
    with pytest.raises(ValueError, match="provider.*callable factory"):
        compare_providers([("not_callable", None)], [1], max_ticks=1)
