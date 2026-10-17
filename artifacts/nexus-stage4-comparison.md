# NEXUS Stage 4C — Benchmark Comparison

Local simulation benchmark comparison. External LLM inference and GPU execution are excluded. The two workloads have different state-transition behavior; throughput ratios describe this workload difference, not a pure engine overhead measurement.

## Summary

- Matched workload/seed configurations: 9
- All no-op runs deterministic: True
- All stateful runs deterministic: True
- Resource-exhaustion cases: 3

## Results

| Agents | Hosts | Seed | No-op ticks/s | Stateful ticks/s | Ratio | Isolated | Rejected | Hours left |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 2 | 3 | 7 | 23932.03 | 20725.39 | 0.866x | 3 | 0 | 14.00 |
| 2 | 3 | 17 | 24166.26 | 21477.66 | 0.889x | 3 | 0 | 14.00 |
| 2 | 3 | 42 | 24163.34 | 16486.69 | 0.682x | 3 | 0 | 14.00 |
| 10 | 10 | 7 | 2594.98 | 2485.40 | 0.958x | 10 | 0 | 0.00 |
| 10 | 10 | 17 | 2609.77 | 2498.50 | 0.957x | 10 | 0 | 0.00 |
| 10 | 10 | 42 | 2629.09 | 2027.82 | 0.771x | 10 | 0 | 0.00 |
| 50 | 50 | 7 | 125.57 | 129.06 | 1.028x | 10 | 10 | 0.00 |
| 50 | 50 | 17 | 132.66 | 131.62 | 0.992x | 10 | 10 | 0.00 |
| 50 | 50 | 42 | 130.06 | 119.23 | 0.917x | 10 | 10 | 0.00 |

## Interpretation and limitations

- The no-op workload emphasizes observation, decision validation, and tick advancement with minimal state change.
- The stateful workload performs containment attempts and enforces the existing analyst-hour budget.
- A ratio below 1 means the stateful workload processes fewer ticks per second than the matched no-op workload.
- Rejected actions and remaining compromised hosts are operational outcomes, not performance errors by themselves.
- Final-state hashes are workload-specific. Different workload hashes are expected and must not be treated as a determinism failure.
- These measurements exclude external LLM inference and do not establish GPU performance or production capacity.
