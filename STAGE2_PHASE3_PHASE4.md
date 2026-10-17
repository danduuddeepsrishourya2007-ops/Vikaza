# NEXUS Stage 2 — Phase 3 + Phase 4 (Completed Patch)

This patch implements deterministic baseline decision providers, decision-trace recording, replay verification, and a reproducible cyber-containment evaluation runner. The authoritative world engine remains the source of truth; replay feeds recorded decisions back through the engine rather than restoring a final state.

## Files

- `simulation/baselines.py` — `DoNothingProvider`, `ScriptedDefensiveProvider`, and `build_baseline`.
- `simulation/replay.py` — versioned JSON traces, strict trace validation, decision serialization, stable snapshots, scheduler/policy/RNG capture, and deterministic replay verification.
- `simulation/evaluation.py` — compares both baselines from equivalent initial conditions and returns serializable metrics and traces.
- `tests/test_baselines.py` — determinism, observation-only behavior, non-mutation, role validation, and per-tick decision recording.
- `tests/test_replay.py` — JSON round-trip, provider-free replay, malformed-trace and scenario/seed mismatch rejection, reproducibility, policy/RNG/scheduler snapshot coverage, and fail-closed handling of non-portable callbacks.

## Verification performed

On the supplied Phase 2 source archive with this patch applied:

```text
python -m compileall -q simulation scenarios tests
# passed
python -m pytest -q
81 passed
```

The test count is specific to that supplied archive. Run the commands below in the target checkout and use its actual count as the authoritative result.

## Run evaluation

```python
from simulation.evaluation import evaluate_baselines

result = evaluate_baselines(seed=7, max_ticks=5)
print(result)
```

The result contains `do_nothing_v1` and `scripted_defensive_v1` metrics and JSON-compatible traces. The scripted policy is a transparent rule-based comparator, not an optimal policy. No universal superiority claim is made.

## Apply on Windows PowerShell

Extract the ZIP into a temporary folder. From `C:\Users\dandu\NEXUS`, copy the files under `simulation\` and `tests\` into their matching repository folders. This patch does not replace the engine, scenario, or policy implementation.

Then run each command separately:

```powershell
python -m compileall -q simulation scenarios tests
python -m pytest -q
git diff --check
git status --short
```

Review the diff before committing. Do not stage unrelated files. Replay recording requires a fresh world at tick 0; replay factories must reconstruct the same scenario, seed, and policy configuration. Pending scheduler callbacks are intentionally rejected because arbitrary Python callbacks cannot be serialized portably.
