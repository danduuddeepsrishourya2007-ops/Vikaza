NEXUS — Cyber Incident Simulation & Evaluation
NEXUS is a reproducible cyber-incident simulation and decision-evaluation prototype. It lets you run controlled containment and simulated-attack scenarios, compare defensive policies on the same seeds, inspect recorded decisions and events, and optionally evaluate decisions proposed by a local LLM.
Design principle: the Python simulation engine owns the authoritative world state. Decision providers propose actions; the engine validates and applies them. An LLM is optional and never directly mutates simulation state.

NEXUS is a research/demo prototype. It does not connect to real hosts, perform live penetration testing, or predict real-world incidents.
What you can do
- Run deterministic cyber-containment and active simulated-attack scenarios.
- Compare do_nothing_v1, scripted_defensive_v1, and (optionally) an OpenAI-compatible LLM provider with fallback behavior.
- Repeat experiments across explicit seeds and tick limits.
- Inspect hosts, services, data stores, resources, decisions, events, and state-derived outcome metrics.
- Verify replay behavior and run automated tests.
- Use the local browser dashboard and HTTP API.
- Run deterministic engine benchmarks, workload-scaling benchmarks, and state-changing scaling benchmarks.
- Export experiment and benchmark reports as JSON, with a Markdown comparison report for benchmark comparisons.
Quick start — Windows PowerShell
Run these commands from the repository root (C:\Users\dandu\NEXUS in the original development setup):
cd C:\Users\dandu\NEXUS

# Activate the existing environment
.\.venv\Scripts\Activate.ps1

# Install dependencies (the simulation uses Python's standard library;
# pytest is needed for the test suite)
python -m pip install -r requirements.txt

# Run all tests
python -m pytest -q

# Run the default deterministic containment comparison
python -m simulation.cli --seeds 7,17,42 --ticks 5 --output artifacts/nexus-evaluation.json
If you do not have a virtual environment yet, create it first:
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
The default evaluation does not require Ollama, an API key, or a GPU.
Run NEXUS in the browser
NEXUS includes a local dashboard served by a Python standard-library HTTP server. From the repository root:
python -m backend.api.main
Open http://127.0.0.1:8765. Stop the server with Ctrl+C.
To use another local port:
$env:NEXUS_PORT = "8766"
python -m backend.api.main
The dashboard provides two modes:
- Containment: compares the do-nothing and scripted-defensive baselines.
- Active simulated attack: runs a deterministic, in-memory attack sequence through the simulated topology and measures whether defensive actions interrupt it.
The dashboard currently runs deterministic baseline comparisons; it does not call the optional LLM provider. Use the CLI below for model-backed evaluation.
Local API routes
Method and route	Purpose
GET /api/health	Health check and scenario identifier
GET /api/scenario	Initial scenario topology, hosts, services, data stores, agents, and resources
POST /api/run	Run a seeded baseline comparison and return the evaluation report


Example JSON body for POST /api/run:
{
  "seeds": [7, 17, 42],
  "ticks": 5,
  "mode": "containment"
}
Set mode to active_attack to select the active-attack scenario. The API accepts 1–20 unique non-negative integer seeds and 1–100 ticks per request.
Security note: the API has no authentication and is intended for localhost development only. Do not expose it to an untrusted network.
Run an evaluation from the CLI
1. Baseline comparison (no LLM)
python -m simulation.cli --seeds 7,17,42 --ticks 5 --output artifacts/nexus-baseline-evaluation.json
By default, the CLI runs the containment scenario and compares the do-nothing and scripted-defensive baselines.
2. Active simulated attack (no LLM)
python -m simulation.cli --mode active_attack --seeds 7,17,42 --ticks 7 --output artifacts/nexus-active-attack-evaluation.json
This mode models an attacker as a deterministic in-memory sequence. It does not send traffic to real hosts or networks. Use enough ticks for the configured attack sequence; seven or more ticks are suggested for the full sequence.
CLI options
Option	Description	Default
--mode	containment or active_attack	containment
--seeds	Comma-separated unique integer seeds	7,17,42
--ticks	Maximum ticks per run; must be positive	5
--output	Path for the JSON report	artifacts/nexus-evaluation.json
--with-llm	Add the configured OpenAI-compatible LLM provider	Off
--timeout	Per-decision request timeout in seconds	8


Each output path is created if necessary. Use the same seed list and tick limit when comparing providers so the comparison is as fair as possible.
Optional: use a local LLM with Ollama
The LLM provider talks to an OpenAI-compatible chat-completions endpoint. Ollama is one supported local option.
1. Install and start Ollama.
2. Pull a model, for example:
   ollama pull qwen2.5:7b
3. Configure the endpoint and model in the same PowerShell session where you will run NEXUS:
   $env:NEXUS_LLM_BASE_URL = "http://127.0.0.1:11434/v1"
   $env:NEXUS_LLM_MODEL = "qwen2.5:7b"
4. Run a short smoke test:
   python -m simulation.cli --with-llm --seeds 7 --ticks 2 --timeout 30 --output artifacts/nexus-ollama-smoke.json
5. If the smoke test is healthy, evaluate containment over multiple seeds:
   python -m simulation.cli --mode containment --with-llm --seeds 7,17,31,42,71,101,202,303,404,505 --ticks 7 --timeout 30 --output artifacts/nexus-llm-containment.json
6. Run the active-attack scenario separately:
   python -m simulation.cli --mode active_attack --with-llm --seeds 7,17,31,42,71,101,202,303,404,505 --ticks 7 --timeout 30 --output artifacts/nexus-llm-active-attack.json
The CLI does not start Ollama automatically. If the server or model is unavailable, fix that before interpreting model results. PowerShell environment variables set with $env: apply only to the current terminal session. Never commit credentials or private endpoint details to the repository.
Understand the results
The CLI writes a JSON report to the path passed to --output. Open it in VS Code or inspect it in PowerShell:
Get-Content .\artifacts\nexus-evaluation.json
Review metrics together rather than relying on a single headline number:
- Containment result: whether the scenario's current containment condition was met.
- Final compromised hosts: whether any host remains compromised at the end.
- Service availability: how many services remain available under the scenario's availability rules.
- Resources: defensive analyst-hours or other tracked resources consumed.
- Exfiltration: data exfiltrated, when reported for the selected scenario.
- Decision quality and reliability: proposed and accepted actions, rejected decisions, provider failures, fallback use, and latency where available.
- Replay and determinism: whether the recorded run can be verified against the expected state.
Interpret metrics carefully. A run can satisfy the simulator's containment condition while a host remains compromised—for example, if isolation is sufficient for the containment rule. Always inspect the final host state and service availability alongside containment. A run completed using fallback decisions is not the same as a fully model-driven run. NEXUS does not assume that the LLM outperforms the scripted baseline; use the generated results to determine that.
Benchmarks
The benchmark modules measure different aspects of the deterministic engine. They are separate from the LLM evaluation: engine throughput does not demonstrate LLM quality or GPU acceleration.
Deterministic engine benchmark
python -m simulation.benchmark --seeds 7,17,42 --ticks 20 --repeats 5 --warmups 1 --output artifacts/nexus-stage4-benchmark.json
Workload scaling benchmark
python -m simulation.scaling_benchmark --sizes 2:3,10:10,50:50 --seeds 7,17,42 --ticks 20 --repeats 3 --warmups 1 --output artifacts/nexus-scaling-benchmark.json
Here each workload size is written as AGENTS:HOSTS.
State-changing workload scaling benchmark
python -m simulation.stateful_scaling_benchmark --sizes 2:3,10:10,50:50 --seeds 7,17,42 --ticks 50 --repeats 3 --warmups 1 --output artifacts/nexus-stateful-scaling.json
Compare benchmark reports
After the no-op and stateful scaling reports exist:
python -m simulation.compare_benchmarks --noop artifacts/nexus-scaling-benchmark.json --stateful artifacts/nexus-stateful-scaling.json --output artifacts/nexus-stage4-comparison.json --markdown-output artifacts/nexus-stage4-comparison.md
Record the hardware, Python version, configuration, seeds, tick count, warm-ups, and repetitions when sharing benchmark numbers. Do not present engine-only throughput as model inference throughput or make GPU claims without measurements on the stated hardware and runtime.
Repository map
NEXUS/
├── backend/
│   ├── __init__.py                 # Backend package
│   └── api/
│       ├── __init__.py             # API package
│       └── main.py                 # Local HTTP API and dashboard server
├── dashboard/
│   └── index.html                  # Browser-based cyber simulation dashboard
├── scenarios/
│   ├── __init__.py                 # Scenario package
│   └── cyber_containment.py        # Scenario setup and initial world builders
├── simulation/
│   ├── agents/
│   │   ├── base_agent.py           # Base agent abstraction
│   │   └── scripted.py             # Scripted agent behavior
│   ├── __main__.py                 # Enables: python -m simulation
│   ├── __init__.py                 # Simulation package
│   ├── actions.py                  # Action and decision structures
│   ├── baselines.py                # Do-nothing and scripted policy baselines
│   ├── benchmark.py                # Deterministic engine benchmark
│   ├── cli.py                      # Main evaluation CLI
│   ├── compare_benchmarks.py       # Compare benchmark output files
│   ├── decision_provider.py        # Decision-provider contract
│   ├── evaluation.py               # Evaluation metrics and summaries
│   ├── events.py                   # Simulation event records
│   ├── experiment.py               # Seeded runs and policy comparisons
│   ├── llm_provider.py             # OpenAI-compatible model integration and fallback
│   ├── observations.py             # Scoped agent observations
│   ├── policy.py                   # Policy/action validation and permissions
│   ├── replay.py                   # Trace serialization and replay verification
│   ├── scaling_benchmark.py        # Engine workload scaling benchmark
│   ├── scheduler.py                # Agent scheduling and action application
│   ├── stateful_scaling_benchmark.py # State-changing scaling benchmark
│   ├── transitions.py              # Authoritative world-state transitions
│   ├── workloads.py                # Benchmark workload construction
│   └── world.py                    # Core world state and simulation model
├── tests/                          # Automated tests for engine, API, replay, and benchmarks
├── artifacts/                      # Saved JSON/Markdown reports; new outputs are generated here
├── ARCHITECTURE.md                 # System architecture and data flow
├── BENCHMARKS.md                   # Benchmark methodology and interpretation
├── DASHBOARD.md                    # Dashboard setup, API routes, and scope
├── DECISIONS.md                    # Architecture decision records
├── GPU_INDEPENDENT_MILESTONE.md    # GPU-independent milestone notes
├── NEXUS_STAGE3_SAFETY_PATCH.md    # Safety-related patch notes
├── PROJECT_SPEC.md                 # Project requirements and scope
├── STAGE2_PHASE3_PHASE4.md         # Stage 2 implementation notes
├── STAGE3_LOCAL_CHECKPOINT.md      # Local checkpoint notes
├── STAGE3_RELIABILITY_PATCH.md     # Reliability patch notes
├── STAGE4D_RELIABILITY_AUDIT.md    # Reliability audit notes
├── STAGE5_DECISION_QUALITY.md      # Decision-quality evaluation notes
├── STAGE6_CANDIDATE_AI_EVALUATION.md # Candidate model-evaluation notes, if present
├── requirements.txt                # Minimal development dependency list
└── .gitignore
artifacts/ contains generated or retained experiment outputs. These JSON files are evidence for the specific configurations that produced them, not universal performance guarantees. The .venv/, cache directories, and other machine-specific files are intentionally not listed above.
Key modules
Module	Responsibility
simulation/world.py	Authoritative world state, hosts, agents, network, resources, and simulation state
simulation/transitions.py	Applies validated state transitions and records their effects
simulation/scheduler.py	Coordinates agents and simulation ticks
simulation/observations.py	Builds scoped observations for agents without granting direct state mutation
simulation/decision_provider.py	Defines the decision-provider interface
simulation/llm_provider.py	Calls an OpenAI-compatible model endpoint and handles provider/fallback behavior
simulation/experiment.py	Runs seeded experiments and compares providers
simulation/evaluation.py	Derives run-level and aggregate evaluation metrics
simulation/replay.py	Serializes traces and checks replay consistency
backend/api/main.py	Serves the local API and dashboard assets


Troubleshooting
No module named pytest
Activate .venv and run python -m pip install -r requirements.txt, then retry python -m pytest -q.
--with-llm says environment variables are required
Set both NEXUS_LLM_BASE_URL and NEXUS_LLM_MODEL in the current PowerShell session before running the CLI.
Connection refused or timeout
Verify Ollama is running and the model is installed with ollama list. Confirm the base URL ends in /v1 and try the two-tick smoke test before the longer evaluation.
Unexpected fallback decisions
Inspect the output JSON for provider failures, invalid/rejected actions, and fallback counts. Do not interpret fallback-only behavior as successful model inference.
Dashboard does not load
Start the server from the repository root with python -m backend.api.main, then open http://127.0.0.1:8765. Check whether NEXUS_PORT was changed in the current shell.
Documentation guide
- Start here for installation and run commands: README.md.
- Read PROJECT_SPEC.md for scope and requirements.
- Read ARCHITECTURE.md for the engine/provider separation and data flow.
- Read DASHBOARD.md for dashboard and API details.
- Read BENCHMARKS.md for benchmark methodology.
- Read DECISIONS.md for recorded design decisions.
- Read the stage/checkpoint documents for implementation history and audit notes.
Scope and limitations
- NEXUS is a controlled simulation and evaluation prototype, not a production SOC platform.
- The active attacker is simulated in memory; no real network is contacted.
- The dashboard uses deterministic baselines and is not an LLM benchmark.
- Results depend on scenario rules, seed selection, tick limits, model configuration, and fallback behavior.
- Local inference latency depends on the model, quantization, runtime, and machine.
- GPU acceleration does not make the simulation's deterministic transitions more correct by itself.
- Publish performance claims only with repeatable, configuration-specific measurements.
License
Add or link the project's chosen license before public distribution or accepting external contributions.
