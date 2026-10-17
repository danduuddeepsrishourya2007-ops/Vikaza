# NEXUS: AI Decision-Rehearsal Platform

## Core Thesis
"NEXUS lets organizations test high-stakes decisions inside large-scale simulated environments before deploying them in reality."

## What NEXUS Is
NEXUS is an AI decision-rehearsal platform focused on:
- Decision rehearsal
- Scenario exploration
- Policy stress testing
- Measurable consequences of competing decisions

## What NEXUS Is NOT
- A chatbot
- Generic AI assistant
- Simple multi-agent framework
- A system claiming to predict reality

## Architecture Overview
```
NEXUS
├── Nexus Core
│   └── General-purpose large-scale simulation and decision-rehearsal engine
│
└── Nexus Cyber
    └── Flagship cyber-incident simulation environment
```

## Documentation
- [PROJECT_SPEC.md](PROJECT_SPEC.md) - Detailed project specification
- [ARCHITECTURE.md](ARCHITECTURE.md) - Technical architecture and design principles
- [DECISIONS.md](DECISIONS.md) - Key architectural and product decisions
- [BENCHMARKS.md](BENCHMARKS.md) - Performance benchmarks and testing methodology
- [DASHBOARD.md](DASHBOARD.md) - Dashboard startup and API details
- [GPU_INDEPENDENT_MILESTONE.md](GPU_INDEPENDENT_MILESTONE.md) - CPU-only scope and verification boundary

## Getting Started

Run the deterministic cyber containment comparison from the repository root:

```powershell
python -m pytest -q
python -c "from scenarios.cyber_containment import compare_containment_policies; import json; print(json.dumps(compare_containment_policies(seed=7), indent=2))"
```

The current executable scenario compares immediate and gradual containment from
equivalent initial host/network states and a shared seed. The timeline and
resource metrics are derived from the simulation's state and event log.

## NEXUS Cyber Dashboard

A local browser dashboard connects to the Python simulation engine for seeded baseline comparisons and an active, deterministic red-team scenario. It displays measured outcomes, the network topology, recorded decisions/events, replay status, and JSON report exports. See [DASHBOARD.md](DASHBOARD.md) for startup and API details.

Start it from the repository root with:

```powershell
python -m backend.api.main
```

Then open <http://127.0.0.1:8765>. Choose **Containment baseline** or **Active simulated attack** from the scenario selector. Both modes run on CPU; neither claims that an LLM or GPU was used.

## Current MVP status

Implemented and testable without GPU hardware:
- Deterministic world state, event log, scheduler, action validation, role permissions, resource accounting, and replay.
- Defender containment, patching, service isolation/recovery, and explicit service-down events.
- In-memory simulated red-team actions: scans, credential access, privilege escalation, persistence, lateral movement, command-and-control, data-store exfiltration, defense evasion, and service impact. These actions never touch real networks or hosts.
- A seven-tick active-attack comparison: do-nothing versus scripted defense, with state-derived compromise, exfiltration, service availability, resource, and action metrics.
- Local dashboard and HTTP API, input validation, JSON export, seeded comparisons, and replay verification.
- Optional OpenAI-compatible inference adapter and deterministic fallback boundary; a reachable model endpoint is not bundled.

Still outside the GPU-independent completion boundary:
- Hosted/production dashboard deployment, authentication, multi-user persistence, and deployment hardening.
- Real model-backed decision-quality evaluation requires a reachable compatible inference endpoint and must be run separately from deterministic baselines.
- AMD MI300X/ROCm/vLLM integration and GPU throughput/latency claims require access to that hardware and serving stack.
- The cyber model is an illustrative discrete simulation, not a validated prediction of real-world incidents; exfiltration is whole-store rather than byte-by-byte, and service downtime is not duration-weighted.


## License
[To be determined]
## Local-first experiment runner

Run reproducible baseline comparisons without an LLM, API key, or GPU:

```powershell
python -m compileall -q simulation scenarios tests
python -m pytest -q
python -m simulation --seeds 7,17,42 --ticks 5 --output artifacts/nexus-evaluation.json
python -m simulation --mode active_attack --seeds 7,17,42 --ticks 7 --output artifacts/nexus-active-attack-evaluation.json
```

The JSON report includes each seed's trace, replay verification, state-derived metrics, and mean numeric metrics by policy. `artifacts/nexus-active-attack-evaluation.json` is the checked-in example for the active-attack path. See [GPU_INDEPENDENT_MILESTONE.md](GPU_INDEPENDENT_MILESTONE.md) for exact measurement boundaries.

### Optional OpenAI-compatible inference endpoint

The LLM provider is deliberately optional and uses only Python's standard library. Configure a model endpoint you already have access to:

```powershell
$env:NEXUS_LLM_BASE_URL = "http://127.0.0.1:8000/v1"
$env:NEXUS_LLM_MODEL = "YOUR_SERVED_MODEL_ID"
# Set only if the endpoint requires authentication; do not commit secrets.
$env:NEXUS_LLM_API_KEY = "YOUR_KEY_IF_REQUIRED"
python -m simulation --with-llm --seeds 7 --ticks 5 --output artifacts/nexus-llm-evaluation.json
```

No model server or GPU is provisioned automatically. If the endpoint fails or emits malformed decisions, the optional fallback provider uses a marked heuristic proposal; inspect `provider_stats` before interpreting results as model performance. See [STAGE3_LOCAL_CHECKPOINT.md](STAGE3_LOCAL_CHECKPOINT.md) for architecture boundaries, limitations, and criteria for considering GPU compute.
