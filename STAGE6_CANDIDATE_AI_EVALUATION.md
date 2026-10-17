# NEXUS Stage 6 — Candidate AI Decision Quality

## Status

**The evaluation harness is implemented and tested. A genuine LLM-vs-scripted result is not yet available.** This workspace has no `NEXUS_LLM_BASE_URL` or `NEXUS_LLM_MODEL` configured, so I did not substitute a mock model or describe fallback decisions as LLM decisions.

The experiment runner now reports paired, per-seed deltas for every candidate against `scripted_defensive_v1`, alongside the existing deltas against `do_nothing_v1`. It also aggregates decision-source counts, fallback rate/reasons, and model-provider call/failure/latency counters. Containment-time deltas are omitted unless both policies achieve containment on the same seed.

## Baseline results (measured)

Artifact: [`artifacts/nexus-stage6-baselines.json`](artifacts/nexus-stage6-baselines.json)

Scenario: `active_attack`, 7 ticks, seeds `7, 17, 31, 71, 101`.

| Metric | Do nothing | Scripted defense |
|---|---:|---:|
| Containment success | 0/5 (0%) | 5/5 (100%) |
| Mean final compromised hosts | 3.0 | 0.0 |
| Mean exfiltrated data | 50 GB | 0 GB |
| Mean final services down | 1.0 | 0.0 |
| Mean service availability fraction | 0.75 | 1.0 |
| Mean analyst-hours used | 0.0 | 7.0 |
| Mean time to containment when achieved | Not achieved | Tick 0 |

These are outcomes of NEXUS's defined in-memory scenario, not estimates of real-world incident rates. The scripted policy is a strong baseline; the AI policy must be evaluated against it, not merely against doing nothing.

## Run the real candidate model

Start an OpenAI-compatible inference endpoint, then configure its address and model in PowerShell. Example values below are placeholders; use your actual endpoint/model:

```powershell
$env:NEXUS_LLM_BASE_URL = "http://127.0.0.1:8000/v1"
$env:NEXUS_LLM_MODEL = "YOUR_MODEL_ID"
# Optional, only if the endpoint requires a key:
$env:NEXUS_LLM_API_KEY = "YOUR_API_KEY"

python -m simulation.cli `
  --mode active_attack `
  --seeds 7,17,31,71,101 `
  --ticks 7 `
  --with-llm `
  --timeout 8 `
  --output artifacts/nexus-stage6-candidate.json
```

Do not commit API keys or endpoint credentials. The provider does not include credentials or response bodies in experiment diagnostics.

## Interpretation rules

1. Compare the candidate's `paired_deltas_vs_scripted_defense` entries for the same seeds.
2. Inspect each outcome independently: containment, compromised hosts, exfiltration, service availability, and analyst-hours. There is no weighted scalar score.
3. A candidate run that has any `fallback_heuristic` decisions is a mixed LLM/fallback run, not a pure LLM run. Check `decision_provenance` at both run and summary level.
4. Claim improvement only when the measured outcomes support it across the paired seeds. Five seeds are an initial evaluation set, not broad statistical evidence.
5. This scenario models whole-store exfiltration; it does not measure partial bytes transferred or duration-weighted outage service-ticks.

## Verification performed in this workspace

- `python -m pytest -q`: **166 passed**.
- Active-attack baseline experiment completed for all five seeds and both baseline policies.
- The candidate LLM arm was not executed because no endpoint/model configuration was available.
- This uploaded snapshot has no `.git` directory or configured remote, so these changes have not been committed or pushed to GitHub.
