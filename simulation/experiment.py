
"""Comparable seeded experiments for baseline and model-backed decision providers."""
from __future__ import annotations

from typing import Any, Callable

from scenarios.cyber_containment import (
    SCENARIO_ID,
    build_attack_world,
    build_initial_world,
    policy_config,
)
from simulation.baselines import (
    AttackScenarioProvider, DoNothingProvider, ScriptedDefensiveProvider,
)
from simulation.evaluation import summarize_world
from simulation.policy import ContainmentStrategy
from simulation.replay import run_and_record, replay_trace


def configured_world(seed: int):
    """Build a fresh two-defender containment evaluation world."""
    world = build_initial_world(seed)
    world.state.active_policy = policy_config(
        "nexus_experiment",
        ContainmentStrategy.IMMEDIATE,
    )
    return world


def configured_attack_world(seed: int):
    """Build a fresh world with a simulated attacker and the same policy."""
    world = build_attack_world(seed)
    world.state.active_policy = policy_config(
        "nexus_attack_experiment",
        ContainmentStrategy.IMMEDIATE,
    )
    return world


def evaluate_provider(
    provider,
    policy_id: str,
    seed: int = 7,
    max_ticks: int = 5,
    verify_replay: bool = True,
    world_factory: Callable[[int], Any] | None = None,
) -> dict[str, Any]:
    """Run one provider with a fixed seed and return trace plus measured outcomes."""
    if not isinstance(policy_id, str) or not policy_id.strip():
        raise ValueError("policy_id must be a non-empty string")
    if not isinstance(seed, int) or isinstance(seed, bool):
        raise ValueError("seed must be an integer")
    if (
        not isinstance(max_ticks, int)
        or isinstance(max_ticks, bool)
        or max_ticks < 1
    ):
        raise ValueError("max_ticks must be a positive integer")
    if not isinstance(verify_replay, bool):
        raise ValueError("verify_replay must be a boolean")

    # Keep a separate initial world. The simulated world is mutated during the
    # run, whereas the initial world remains the authoritative initial snapshot.
    make_world = world_factory or configured_world
    world = make_world(seed)
    initial_world = make_world(seed)
    initial_resources = dict(world.state.resource_pool)

    trace = run_and_record(
        world,
        provider,
        policy_id,
        max_ticks=max_ticks,
    )

    if verify_replay:
        final_world = replay_trace(trace.to_json(), make_world)
    else:
        final_world = world

    decision_sources = {
        "llm": 0,
        "scripted": 0,
        "fallback_heuristic": 0,
    }
    fallback_reasons: dict[str, int] = {}

    for tick_decisions in trace.decisions_by_tick:
        for decision in tick_decisions:
            source = decision.get("source")
            if source in decision_sources:
                decision_sources[source] += 1

            if source == "fallback_heuristic":
                reason = decision.get("failure_reason") or "unspecified"
                fallback_reasons[reason] = (
                    fallback_reasons.get(reason, 0) + 1
                )

    return {
        "policy_id": policy_id,
        "scenario_id": world.state.scenario_id or SCENARIO_ID,
        "seed": seed,
        "max_ticks": max_ticks,
        "metrics": summarize_world(
            final_world,
            initial_resources,
            initial_world=initial_world,
            decisions_proposed=sum(
                len(row) for row in trace.decisions_by_tick
            ),
        ),
        "replay_verified": verify_replay,
        "trace": trace.to_dict(),
        "provider_stats": _provider_stats(provider),
        "decision_provenance": {
            "source_counts": decision_sources,
            "fallback_reason_counts": dict(sorted(fallback_reasons.items())),
        },
    }


def compare_providers(
    providers: list[tuple[str, Callable[[], Any]]],
    seeds: list[int],
    max_ticks: int = 5,
    world_factory: Callable[[int], Any] | None = None,
) -> dict[str, Any]:
    """Evaluate every provider on every seed using a fresh provider per run."""
    if not providers:
        raise ValueError("at least one provider is required")
    if not seeds:
        raise ValueError("at least one seed is required")
    if (
        not isinstance(max_ticks, int)
        or isinstance(max_ticks, bool)
        or max_ticks < 1
    ):
        raise ValueError("max_ticks must be a positive integer")
    if any(
        not isinstance(seed, int) or isinstance(seed, bool)
        for seed in seeds
    ):
        raise ValueError("all seeds must be integers")
    if any(
        not isinstance(policy_id, str)
        or not policy_id.strip()
        or not callable(factory)
        for policy_id, factory in providers
    ):
        raise ValueError(
            "each provider must have a non-empty policy_id "
            "and callable factory"
        )
    if len(set(seeds)) != len(seeds):
        raise ValueError("seeds must be unique")

    policy_ids = [policy_id for policy_id, _ in providers]
    if len(set(policy_ids)) != len(policy_ids):
        raise ValueError("provider policy_ids must be unique")

    runs = []
    for seed in seeds:
        for policy_id, factory in providers:
            runs.append(
                evaluate_provider(
                    factory(),
                    policy_id,
                    seed,
                    max_ticks,
                    world_factory=world_factory,
                )
            )

    grouped: dict[str, dict[str, Any]] = {}
    for run in runs:
        row = grouped.setdefault(
            run["policy_id"],
            {"run_count": 0, "metrics": {}},
        )
        row["run_count"] += 1

        for key, value in run["metrics"].items():
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                row["metrics"].setdefault(key, []).append(value)

    summaries: dict[str, dict[str, Any]] = {}
    for policy_id, row in grouped.items():
        policy_runs = [
            run for run in runs
            if run["policy_id"] == policy_id
        ]
        containment_runs = [
            run for run in policy_runs
            if run["metrics"].get("containment_achieved") is True
        ]
        containment_times = [
            run["metrics"]["time_to_containment_ticks"]
            for run in containment_runs
            if isinstance(
                run["metrics"].get("time_to_containment_ticks"),
                (int, float),
            )
            and not isinstance(
                run["metrics"].get("time_to_containment_ticks"),
                bool,
            )
        ]

        source_totals = {"llm": 0, "scripted": 0, "fallback_heuristic": 0}
        fallback_reasons: dict[str, int] = {}
        provider_call_totals = {"calls": 0, "failures": 0, "total_latency_seconds": 0.0}
        provider_stats_available = False
        for policy_run in policy_runs:
            provenance = policy_run.get("decision_provenance", {})
            for source, count in provenance.get("source_counts", {}).items():
                if source in source_totals and isinstance(count, int) and not isinstance(count, bool):
                    source_totals[source] += count
            for reason, count in provenance.get("fallback_reason_counts", {}).items():
                if isinstance(count, int) and not isinstance(count, bool):
                    fallback_reasons[reason] = fallback_reasons.get(reason, 0) + count
            stats = policy_run.get("provider_stats") or {}
            primary_stats = stats.get("primary", {}) if isinstance(stats, dict) else {}
            for stat_key in provider_call_totals:
                value = primary_stats.get(stat_key) if isinstance(primary_stats, dict) else None
                if isinstance(value, (int, float)) and not isinstance(value, bool):
                    provider_call_totals[stat_key] += value
                    provider_stats_available = True

        total_decisions = sum(source_totals.values())
        fallback_count = source_totals["fallback_heuristic"]
        summaries[policy_id] = {
            "run_count": row["run_count"],
            "containment_success_rate": round(
                len(containment_runs) / len(policy_runs),
                4,
            ),
            "contained_run_count": len(containment_runs),
            "mean_time_to_containment_ticks_when_achieved": (
                round(
                    sum(containment_times) / len(containment_times),
                    4,
                )
                if containment_times
                else None
            ),
            "mean_metrics": {
                key: round(sum(values) / len(values), 4)
                for key, values in sorted(row["metrics"].items())
                if values
            },
            "decision_provenance": {
                "source_counts": source_totals,
                "total_decisions": total_decisions,
                "fallback_decision_rate": round(fallback_count / total_decisions, 4) if total_decisions else 0.0,
                "fallback_reason_counts": dict(sorted(fallback_reasons.items())),
            },
            "provider_stats": (
                {
                    "total_calls": int(provider_call_totals["calls"]),
                    "total_failures": int(provider_call_totals["failures"]),
                    "total_latency_seconds": round(provider_call_totals["total_latency_seconds"], 4),
                }
                if provider_stats_available else None
            ),
        }

    paired_deltas: dict[str, dict[str, Any]] = {}
    baseline_id = DoNothingProvider.policy_id
    baseline_by_seed = {
        run["seed"]: run["metrics"]
        for run in runs
        if run["policy_id"] == baseline_id
    }

    lower_is_better = {
        "final_compromised_hosts",
        "final_compromised_host_fraction",
        "time_to_containment_ticks",
        "data_exfiltrated_gb",
        "exfiltrated_stores",
        "final_services_down",
        "service_down_events",
        "analyst_hours_used",
        "actions_rejected",
    }

    for policy_id in summaries:
        if policy_id == baseline_id:
            continue

        comparisons = []
        containment_time_eligible_pairs = 0
        containment_time_excluded_pairs = 0

        for run in runs:
            if (
                run["policy_id"] != policy_id
                or run["seed"] not in baseline_by_seed
            ):
                continue

            candidate_metrics = run["metrics"]
            baseline_metrics = baseline_by_seed[run["seed"]]
            deltas: dict[str, float] = {}

            for key, value in candidate_metrics.items():
                base_value = baseline_metrics.get(key)

                if key == "time_to_containment_ticks":
                    both_contained = (
                        candidate_metrics.get("containment_achieved") is True
                        and baseline_metrics.get("containment_achieved") is True
                        and isinstance(value, (int, float))
                        and not isinstance(value, bool)
                        and isinstance(base_value, (int, float))
                        and not isinstance(base_value, bool)
                    )
                    if both_contained:
                        deltas[key] = round(value - base_value, 4)
                        containment_time_eligible_pairs += 1
                    else:
                        containment_time_excluded_pairs += 1
                    continue

                if (
                    isinstance(value, (int, float))
                    and not isinstance(value, bool)
                    and isinstance(base_value, (int, float))
                    and not isinstance(base_value, bool)
                ):
                    deltas[key] = round(value - base_value, 4)

            comparisons.append({
                "seed": run["seed"],
                "delta_vs_do_nothing": deltas,
            })

        paired_deltas[policy_id] = {
            "baseline_policy_id": baseline_id,
            "interpretation": {
                key: (
                    "negative is improvement"
                    if key in lower_is_better
                    else "inspect raw metric"
                )
                for key in sorted(lower_is_better)
            },
            "containment_time_pairing": {
                "eligible_pairs": containment_time_eligible_pairs,
                "excluded_pairs": containment_time_excluded_pairs,
                "rule": (
                    "A containment-time delta is included only when both "
                    "the candidate and do-nothing baseline achieved "
                    "containment and both times are numeric."
                ),
            },
            "per_seed": comparisons,
        }

    # The decision-quality question is whether a candidate improves on the
    # scripted defender, not only on doing nothing. Keep raw paired deltas and
    # omit containment-time arithmetic whenever either arm fails containment.
    scripted_id = ScriptedDefensiveProvider.policy_id
    scripted_by_seed = {
        run["seed"]: run["metrics"]
        for run in runs
        if run["policy_id"] == scripted_id
    }
    paired_deltas_vs_scripted: dict[str, dict[str, Any]] = {}
    for policy_id in summaries:
        if policy_id == scripted_id:
            continue
        per_seed = []
        metric_deltas_by_key: dict[str, list[float]] = {}
        containment_success_deltas: list[float] = []
        eligible_containment_pairs = 0
        excluded_containment_pairs = 0
        for run in runs:
            if run["policy_id"] != policy_id or run["seed"] not in scripted_by_seed:
                continue
            candidate_metrics = run["metrics"]
            scripted_metrics = scripted_by_seed[run["seed"]]
            deltas: dict[str, float] = {}
            for key, value in candidate_metrics.items():
                reference_value = scripted_metrics.get(key)
                if key == "time_to_containment_ticks":
                    both_contained = (
                        candidate_metrics.get("containment_achieved") is True
                        and scripted_metrics.get("containment_achieved") is True
                        and isinstance(value, (int, float)) and not isinstance(value, bool)
                        and isinstance(reference_value, (int, float)) and not isinstance(reference_value, bool)
                    )
                    if both_contained:
                        deltas[key] = round(value - reference_value, 4)
                        eligible_containment_pairs += 1
                    else:
                        excluded_containment_pairs += 1
                    continue
                if (
                    isinstance(value, (int, float)) and not isinstance(value, bool)
                    and isinstance(reference_value, (int, float)) and not isinstance(reference_value, bool)
                ):
                    deltas[key] = round(value - reference_value, 4)
            candidate_contained = candidate_metrics.get("containment_achieved") is True
            scripted_contained = scripted_metrics.get("containment_achieved") is True
            containment_delta = float(candidate_contained) - float(scripted_contained)
            containment_success_deltas.append(containment_delta)
            for metric_key, metric_delta in deltas.items():
                metric_deltas_by_key.setdefault(metric_key, []).append(metric_delta)
            per_seed.append({
                "seed": run["seed"],
                "candidate_containment_achieved": candidate_contained,
                "scripted_containment_achieved": scripted_contained,
                "containment_success_delta": int(containment_delta),
                "delta_vs_scripted_defense": deltas,
            })
        if per_seed:
            paired_deltas_vs_scripted[policy_id] = {
                "baseline_policy_id": scripted_id,
                "interpretation": {
                    "raw_deltas": "candidate minus scripted defense; inspect each metric independently",
                    "containment_success_rate": "positive is better",
                    "harm_or_cost_metrics": "negative is generally better",
                },
                "aggregate_deltas": {
                    "containment_success_rate_delta": round(
                        sum(containment_success_deltas) / len(containment_success_deltas), 4
                    ),
                    "mean_metric_deltas": {
                        key: round(sum(values) / len(values), 4)
                        for key, values in sorted(metric_deltas_by_key.items()) if values
                    },
                },
                "containment_time_pairing": {
                    "eligible_pairs": eligible_containment_pairs,
                    "excluded_pairs": excluded_containment_pairs,
                    "rule": "Containment-time deltas require both candidate and scripted defense to achieve containment.",
                },
                "per_seed": per_seed,
            }

    return {
        "report_version": 3,
        "scenario_id": (runs[0]["scenario_id"] if runs else SCENARIO_ID),
        "seeds": list(seeds),
        "max_ticks": max_ticks,
        "summaries": summaries,
        "paired_deltas_vs_do_nothing": paired_deltas,
        "paired_deltas_vs_scripted_defense": paired_deltas_vs_scripted,
        "runs": runs,
    }


def baseline_provider_factories():
    """Return the standard baseline providers as fresh-instance factories."""
    return [
        (DoNothingProvider.policy_id, DoNothingProvider),
        (ScriptedDefensiveProvider.policy_id, ScriptedDefensiveProvider),
    ]


def _provider_stats(provider) -> dict[str, Any] | None:
    """Expose safe numeric counters without leaking URLs or credentials."""
    result: dict[str, Any] = {}

    stats = getattr(provider, "stats", None)
    if stats is not None and hasattr(stats, "__dict__"):
        result["wrapper"] = dict(vars(stats))

    primary = getattr(provider, "primary", None)
    if primary is not None:
        result["primary"] = {
            key: getattr(primary, key)
            for key in ("calls", "failures", "total_latency_seconds")
            if isinstance(getattr(primary, key, None), (int, float))
            and not isinstance(getattr(primary, key, None), bool)
        }

    return result or None


def evaluate_baselines(
    seed: int = 7,
    max_ticks: int = 5,
) -> dict[str, Any]:
    """Run both baselines from equivalent initial conditions and return traces."""
    if not isinstance(seed, int) or isinstance(seed, bool):
        raise ValueError("seed must be an integer")
    if (
        not isinstance(max_ticks, int)
        or isinstance(max_ticks, bool)
        or max_ticks < 1
    ):
        raise ValueError("max_ticks must be a positive integer")

    providers = [
        (DoNothingProvider.policy_id, DoNothingProvider()),
        (ScriptedDefensiveProvider.policy_id, ScriptedDefensiveProvider()),
    ]
    results = []
    initial_host_ids = sorted(build_evaluation_world(seed).state.hosts)

    for policy_id, provider in providers:
        world = build_evaluation_world(seed)
        initial_resources = dict(world.state.resource_pool)
        initial_world = build_evaluation_world(seed)

        trace = run_and_record(
            world,
            provider,
            policy_id,
            max_ticks=max_ticks,
        )

        replayed = replay_trace(trace.to_json(), build_evaluation_world)
        results.append({
            "policy_id": policy_id,
            "seed": seed,
            "scenario_id": SCENARIO_ID,
            "initial_host_ids": initial_host_ids,
            "metrics": summarize_world(
                replayed,
                initial_resources,
                initial_world=initial_world,
                decisions_proposed=sum(
                    len(row) for row in trace.decisions_by_tick
                ),
            ),
            "trace": trace.to_dict(),
        })

    return {
        "evaluation_version": 2,
        "scenario_id": SCENARIO_ID,
        "seed": seed,
        "max_ticks": max_ticks,
        "same_initial_host_ids": all(
            item["initial_host_ids"] == initial_host_ids
            for item in results
        ),
        "results": results,
    }


def build_evaluation_world(seed: int):
    """Build the standard evaluation world with the fixed immediate policy."""
    world = build_initial_world(seed)
    world.state.active_policy = policy_config(
        "baseline_evaluation",
        ContainmentStrategy.IMMEDIATE,
    )
    return world


def attack_provider_factories() -> list[tuple[str, Callable[[], Any]]]:
    """Return comparable attacker-plus-defender providers for the active-attack mode."""
    return [
        (DoNothingProvider.policy_id, lambda: AttackScenarioProvider(DoNothingProvider())),
        (ScriptedDefensiveProvider.policy_id, lambda: AttackScenarioProvider(ScriptedDefensiveProvider())),
    ]
