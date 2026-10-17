# NEXUS Stage 5 — Decision-Quality Evaluation

## Purpose

Stage 5 evaluates cyber-response outcomes rather than execution speed. It builds on the existing deterministic world, decision-provider boundary, baseline providers, replay traces, and seeded experiment runner.

## Evaluation arms

- `do_nothing_v1`: no intervention baseline.
- `scripted_defensive_v1`: deterministic isolate-then-patch response baseline.
- Candidate policy: pass its provider factory to `simulation.experiment.compare_providers`.
- LLM-driven provider: include its factory as a separate arm when the provider is configured. The report records decision-source counts and fallback reasons; a run that used fallback decisions must not be described as fully LLM-driven.

All arms are run against a fresh world constructed from the same scenario builder, with the same seed and tick horizon. Each run records a decision trace and verifies deterministic replay by default.

## Metrics

- `containment_achieved`: whether every host compromised in the initial world was isolated during the measured horizon.
- `time_to_containment_ticks`: tick of the event that completes containment; `null` if containment is not achieved.
- `final_compromised_hosts` and `final_compromised_host_fraction`.
- `data_exfiltrated_gb` and `exfiltrated_stores`: sums the sizes of stores marked exfiltrated. The current scenario models whole-store exfiltration, not partial byte-level transfer; do not present this as measured bytes.
- `service_availability_fraction`, `final_services_available`, `final_services_down`, `service_down_events`, and `service_restored_events`. A running service on an isolated host is not counted as externally available.
- `analyst_hours_used` and remaining resource pool.
- `actions_proposed`, `actions_accepted`, `actions_rejected`, and `action_acceptance_rate`.

The current world model does not represent service downtime duration as a per-tick time series. The report therefore exposes final availability and explicit down/restore event counts, not service-outage service-ticks. Add a state timeline before claiming duration-weighted service disruption.

## Comparison method

`compare_providers` reports mean numeric metrics across seeds and paired per-seed deltas versus `do_nothing_v1`. Deltas are raw (`candidate - baseline`), not a weighted aggregate score. For harm/cost metrics such as compromised hosts, exfiltrated GB, service outages, analyst-hours, and rejected actions, negative deltas are generally improvements. Containment tick is only comparable when both policies achieve containment; a `null` value means not contained within the horizon and must not be treated as zero.

## Reproducible run

```python
from simulation.experiment import compare_providers, baseline_provider_factories

report = compare_providers(
    baseline_provider_factories(),
    seeds=[7, 17, 31, 71, 101],
    max_ticks=5,
)
```

For candidate or LLM providers, append `(stable_policy_id, ProviderClass)` to the provider list. The factory must create a fresh provider for each run. Save the returned JSON report as an artifact and preserve its seeds, horizon, scenario ID, replay status, provider provenance, and fallback counts.

## Interpretation limits

- Do not claim LLM superiority from a single seed or from latency alone.
- Compare paired outcomes at identical seeds and tick horizons.
- Report per-seed outcomes and variability, not only means.
- Keep the baseline, scenario, and scoring semantics fixed for a comparison series.
- This version deliberately does not invent a weighted scalar quality score; outcome dimensions remain independently inspectable.


## Active-attack evaluation mode (CPU-only)

The dashboard and experiment runner also support `mode="active_attack"`, using `configured_attack_world` and `AttackScenarioProvider`. The attacker follows a deterministic in-memory sequence across seven ticks: credential access, lateral movement to the application host, command-and-control, lateral movement to the database, command-and-control, whole-store data exfiltration, and service impact. The security engineer has higher action priority than the attacker, so isolation can interrupt the sequence before the attack transition applies. The scripted response then patches the isolated host, unisolates it after remediation, and restores the service.

Example:

```python
from backend.api.main import run_experiment

report = run_experiment({
    "seeds": [7, 17, 42],
    "ticks": 7,
    "mode": "active_attack",
})
```

The unmitigated arm is expected to compromise all three hosts, exfiltrate the modeled 50 GB customer-records store, and take the database service down. The scripted defensive arm should isolate the initial workstation before lateral movement, patch it, reconnect it, and restore its service, preventing that attack sequence. These are model outcomes for this defined scenario, not empirical estimates of real incidents. Exfiltration is all-or-nothing at the data-store level; service availability is measured at the final tick, with explicit down/restore events, not duration-weighted outage time.
