from simulation.experiment import compare_providers, evaluate_provider
from simulation.baselines import DoNothingProvider, ScriptedDefensiveProvider


def test_evaluation_provider_returns_replay_verified_metrics():
    result = evaluate_provider(ScriptedDefensiveProvider(), "scripted_test", seed=7, max_ticks=3)
    assert result["replay_verified"] is True
    assert result["metrics"]["final_tick"] == 3
    assert result["trace"]["max_ticks"] == 3


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
