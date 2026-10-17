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

## Getting Started

Run the deterministic cyber containment comparison from the repository root:

```powershell
python -m pytest -q
python -c "from scenarios.cyber_containment import compare_containment_policies; import json; print(json.dumps(compare_containment_policies(seed=7), indent=2))"
```

The current executable scenario compares immediate and gradual containment from
equivalent initial host/network states and a shared seed. The timeline and
resource metrics are derived from the simulation's state and event log.

## Current MVP status

Implemented in this repository:
- Deterministic world state, event log, scheduler, action validation, and transitions.
- Cyber containment scenario with immediate-versus-gradual policy execution.
- State/event-derived comparison output and scenario regression tests.

Not yet implemented or verified:
- Browser UI and visual topology/timeline.
- LLM inference integration.
- Execution on AMD MI300X hardware, ROCm, or vLLM.
- Multi-host attacker propagation and modeled data exfiltration. Do not present these as implemented capabilities.


## License
[To be determined]
## Local-first experiment runner

Run reproducible baseline comparisons without an LLM, API key, or GPU:

```powershell
python -m compileall -q simulation scenarios tests
python -m pytest -q
python -m simulation --seeds 7,17,42 --ticks 5 --output artifacts/nexus-evaluation.json
```

The JSON report includes each seed's trace, replay verification, state-derived metrics, and mean numeric metrics by policy. This is the current CPU-only evaluation path.

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
