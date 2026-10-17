# NEXUS Stage 4D — Reliability and Benchmark Integrity

## Scope

Stage 4D tightens reliability checks around the deterministic benchmark and comparison tools. It does not change the cyber scenario's intended transitions, introduce an LLM dependency, or claim GPU/production performance.

## Changes

- Benchmark comparison now rejects malformed result objects, boolean/fractional/string workload identifiers, invalid workload dimensions, and non-finite or boolean throughput values instead of coercing or silently accepting them.
- The stateful scaling benchmark validates direct API inputs (including booleans masquerading as integers, duplicate workload sizes, and duplicate seeds).
- Each stateful run checks its accounting contract before emitting a report: final tick equals requested ticks; accepted plus rejected decisions equals agents × ticks; analyst hours never go negative; isolated plus still-unisolated compromised hosts equals the workload host count.
- Deterministic state hashing now includes the active policy configuration, since policy changes can alter future transitions even when the current host/resource state is unchanged.
- Regression tests cover invalid report data, malformed configuration, decision/resource accounting, and policy-sensitive state hashes.

## Validation

- `python -m compileall -q simulation tests` — passed.
- `python -m pytest -q` — **132 passed**.
- Stateful scaling benchmark smoke run at 2/10/50 agents, 3/10/50 hosts, seeds 7/17/42, 20 ticks, 3 repeats, 1 warmup — all reported deterministic; resource use remained non-negative; 50-agent cases rejected attempts after analyst-hour exhaustion.

## Limitations

- This remains a local CPU benchmark; external LLM inference and GPU execution are excluded.
- Timing is environment-dependent and should not be compared across machines without recording environment details.
- This audit does not establish production capacity or prove every possible simulation path correct.
