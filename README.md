# NEXUS — Cyber Simulation & Decision Evaluation

**NEXUS** is a cyber simulation platform that lets organizations evaluate security decisions in a controlled, repeatable environment before applying them in the real world.

It models cyber incidents, attacker and defender actions, system availability, resource constraints, and incident outcomes. It supports deterministic baselines and LLM-driven decisions so their behavior can be compared using measurable simulation results.

> **Core principle:** The simulation engine is authoritative. AI proposes decisions; the engine validates and applies them.

## Table of Contents

- [Key Features](#key-features)
- [Architecture](#architecture)
- [Project Structure](#project-structure)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Running the LLM](#running-the-llm)
- [Simulation Modes](#simulation-modes)
- [Evaluation and Benchmarks](#evaluation-and-benchmarks)
- [Tests](#tests)
- [Understanding Results](#understanding-results)
- [Documentation](#documentation)
- [Limitations](#limitations)

## Key Features

- **Deterministic simulation:** Reproducible scenarios using controlled seeds and simulation state transitions.
- **Cyber incident scenarios:** Containment and active-attack simulation modes.
- **Multiple decision providers:** Do-nothing, scripted defensive, and LLM-driven strategies.
- **LLM integration:** Supports a locally hosted model through an OpenAI-compatible API, including Ollama.
- **Action validation:** Proposed actions are checked against role permissions and simulation rules.
- **Resource-aware decisions:** Models constrained defensive resources, including analyst-hours.
- **Event logging and replay:** Records simulation activity to support debugging and reproducibility.
- **Evaluation framework:** Compares strategies using outcomes, service availability, resource use, and decision metrics.
- **Automated tests:** Tests the simulation engine, action transitions, observations, providers, and evaluation behavior.
- **Dashboard and API:** Provides supporting interfaces for interacting with and inspecting the simulation, where configured.

## Architecture

NEXUS separates simulation correctness from AI reasoning.

```text
                 NEXUS
                   |
       +-----------+-----------+
       |                       |
 Simulation Engine       Decision Providers
       |                       |
 World State             Scripted Policies
 Scheduler               Local LLM
 Action Validation       OpenAI-Compatible API
       |                       |
       +-----------+-----------+
                   |
           Validated Decisions
                   |
           State Transitions
                   |
          Events and Metrics
                   |
        Replay and Evaluation
```

### Simulation Engine

The engine owns the authoritative world state, schedules agent decisions, validates actions, applies transitions, tracks resources, and records events.

Given the same initial state, random seed, and accepted decisions, the deterministic engine is designed to reproduce the same simulation outcome.

### Decision Providers

Decision providers propose actions for simulated agents. These may be deterministic policies or an LLM.

LLM output is not permitted to directly mutate the world state. Proposed actions must pass the engine's validation rules before they can affect the simulation.

### Evaluation Layer

The evaluation layer runs scenarios and collects metrics so different decision strategies can be compared under consistent conditions.

## Project Structure

The following is a logical guide to the major project areas. Exact files may vary by checkout.

```text
NEXUS/
├── backend/
│   └── api/                 # Backend API entry points
├── simulation/
│   ├── agents/              # Agent-related abstractions, if present
│   ├── world.py             # World state
│   ├── policy.py            # Policy configuration
│   ├── policies.py          # Policy implementations, if present
│   ├── scheduler.py         # Simulation scheduling
│   ├── transitions.py       # Validated state transitions
│   ├── observations.py      # Agent-specific observations
│   ├── decision_provider.py # Decision provider interfaces
│   ├── llm_provider.py      # LLM integration
│   ├── baselines.py         # Baseline strategies
│   ├── evaluation.py        # Evaluation utilities
│   ├── replay.py             # Replay and trace utilities
│   └── cli.py               # Command-line interface
├── scenarios/
│   └── cyber_containment.py # Cyber scenario definitions
├── tests/                   # Automated tests
├── artifacts/               # Generated evaluation outputs
├── dashboard/               # Dashboard files, if present
├── README.md
├── ARCHITECTURE.md
├── PROJECT_SPEC.md
├── DECISIONS.md
└── BENCHMARKS.md
```

Some modules and folders are optional or may have different names across development stages. Check the actual repository before relying on a particular path.

## Requirements

- Windows, Linux, or macOS
- Python version supported by the project's dependencies
- Git
- Python virtual environment
- Optional: [Ollama](https://ollama.com/) and a compatible local language model for LLM-driven simulation

For the Windows commands below, run PowerShell from the NEXUS repository root.

## Installation

### 1. Open the repository

```powershell
cd C:\Users\dandu\NEXUS
```

### 2. Activate the virtual environment

If `.venv` already exists:

```powershell
.\.venv\Scripts\Activate.ps1
```

If it does not exist, create it using an installed Python version compatible with the project's dependencies:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```powershell
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

If PowerShell blocks environment activation, use the virtual environment interpreter directly:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

## Quick Start

### Run a simulation without an LLM

Start with a small, reproducible containment run:

```powershell
python -m simulation.cli --seeds 7 --ticks 5 --output artifacts/nexus-smoke.json
```

This exercises the configured default simulation mode and writes its results to the specified JSON file.

### Run a containment simulation

```powershell
python -m simulation.cli --mode containment --seeds 7,17,31 --ticks 5 --output artifacts/nexus-containment.json
```

### Run an active-attack simulation

```powershell
python -m simulation.cli --mode active_attack --seeds 7,17,31 --ticks 5 --output artifacts/nexus-active-attack.json
```

The seed list controls which initial random conditions are evaluated. Increasing the number of seeds helps reveal whether results are consistent across different initial conditions.

Use the CLI help to verify the options supported by your current checkout:

```powershell
python -m simulation.cli --help
```

## Running the LLM

NEXUS can use an OpenAI-compatible local inference endpoint. For the local Ollama configuration, first install Ollama and download the desired model.

For example:

```powershell
ollama pull qwen2.5:7b
```

Configure the endpoint and model in PowerShell:

```powershell
$env:NEXUS_LLM_BASE_URL = "http://127.0.0.1:11434/v1"
$env:NEXUS_LLM_MODEL = "qwen2.5:7b"
```

Verify that Ollama is running and that the model is available:

```powershell
ollama list
```

Then run a small LLM-enabled test:

```powershell
python -m simulation.cli --with-llm --seeds 7 --ticks 2 --timeout 30 --output artifacts/nexus-llm-smoke.json
```

If the LLM provider is unavailable, check the endpoint, model name, server status, and timeout configuration.

**Important:** LLM inference may be substantially slower than deterministic policies. The actual latency depends on the model, hardware, prompt size, concurrency, and inference configuration.

## Simulation Modes

### Containment

The containment mode evaluates defensive decisions in a cyber incident. Depending on the scenario and policy, defensive actions may isolate affected hosts, patch vulnerabilities, or preserve system availability.

### Active Attack

The active-attack mode evaluates behavior under an ongoing attack scenario. It can help investigate defensive responses, attack progression, service impact, and resource trade-offs.

The exact actions and metrics depend on the scenario implementation. Consult the scenario code and generated evaluation artifacts for the authoritative definitions.

## Evaluation and Benchmarks

NEXUS supports comparisons between decision strategies, including:

| Strategy | Purpose |
|---|---|
| Do-nothing baseline | Establishes an inactive-response reference |
| Scripted defensive baseline | Provides a deterministic defensive reference |
| LLM-driven strategy | Evaluates model-generated decisions under the same simulation framework |

For a fair comparison, keep scenario configuration, seeds, tick limits, and resource constraints consistent.

### Example evaluation

```powershell
python -m simulation.cli --mode containment --seeds 7,17,31,42,71 --ticks 7 --output artifacts/nexus-containment-evaluation.json
```

Run the same configuration with LLM inference enabled:

```powershell
python -m simulation.cli --mode containment --with-llm --seeds 7,17,31,42,71 --ticks 7 --timeout 30 --output artifacts/nexus-containment-llm.json
```

Repeat for `active_attack` when comparing both scenario modes.

These commands illustrate evaluation runs; they do not, by themselves, guarantee that every baseline is included in each output. Confirm the actual provider and comparison behavior in the current CLI implementation.

### Metrics to examine

- **Containment success:** Whether the implementation's containment criterion was satisfied.
- **Compromised hosts:** The number of hosts that remain compromised at the end of a run.
- **Service availability:** How many services remain operational.
- **Analyst-hours:** Defensive resources consumed.
- **Action acceptance rate:** The proportion of proposed actions accepted by validation.
- **Fallback rate:** How frequently fallback behavior replaces an LLM decision.
- **Decision latency:** Time spent waiting for model responses.
- **Exfiltrated data:** Data exfiltration recorded by the scenario, where applicable.

Interpret metrics together. For example, a run can satisfy the implementation's containment criterion while a host remains compromised. Containment success alone should not be interpreted as proof that all compromised hosts were remediated.

Do not claim that the LLM outperforms scripted defense unless repeated, comparable runs support that conclusion.

## Tests

Run the full test suite from the repository root:

```powershell
python -m pytest -q
```

Run a syntax compilation check:

```powershell
python -m compileall -q simulation scenarios tests
```

Check for whitespace errors in Git changes:

```powershell
git diff --check
```

Tests validate implemented behavior; they do not substitute for performance measurements on the target hardware.

## Understanding Results

Generated JSON files are written to the path specified by `--output`.

Inspect a result file in PowerShell:

```powershell
Get-Content .\artifacts\nexus-smoke.json
```

For larger artifacts, use an editor or JSON viewer.

When reviewing a run, verify:

1. The scenario mode and seed configuration.
2. The number of completed ticks.
3. Which provider generated the decisions.
4. Whether actions were accepted or rejected.
5. Whether any timeouts or fallback decisions occurred.
6. Final compromise and service-availability metrics.
7. Resource consumption and decision latency.
8. Whether the reported result is consistent across multiple seeds.

Keep generated benchmark outputs with their configuration so results can be reproduced and audited.

## Documentation

Consult the documentation files present in your checkout for additional detail:

- `ARCHITECTURE.md` — architecture and module responsibilities.
- `PROJECT_SPEC.md` — project scope and requirements.
- `DECISIONS.md` — recorded design decisions.
- `BENCHMARKS.md` — benchmark methodology and results.
- `DASHBOARD.md` — dashboard usage, if included.
- Stage-specific notes — implementation history, reliability audits, and evaluation findings.

Not every development note is intended as a public-facing project guide. Keep this README as the main entry point and use the detailed documents for implementation-specific information.

## Limitations

- This is a simulation, not a production cyber-defense system.
- Simulated outcomes do not establish real-world security effectiveness.
- LLM decisions may be invalid, inconsistent, slow, or dependent on the selected model.
- Fallback behavior improves operational resilience but can affect comparisons.
- Results depend on scenario design, initial conditions, model configuration, and evaluation methodology.
- Hardware acceleration benefits must be established through measurements rather than assumed.
- A successful test suite does not prove that all scenarios or edge cases are correct.

## Project Goal

NEXUS aims to make high-stakes decision evaluation measurable and reproducible by combining a controlled simulation engine with interchangeable decision-making strategies.

The objective is not merely to generate AI recommendations. It is to evaluate what those recommendations actually do inside a simulation, what they cost, and how their outcomes compare against explicit baselines.
