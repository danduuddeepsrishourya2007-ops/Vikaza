# NEXUS Technical Architecture

## Core Architectural Principles

### 1. Deterministic Simulation vs. LLM Reasoning Separation
Deterministic code handles:
- World state management
- Time progression
- System/service state
- Dependencies and resource changes
- Attack propagation and recovery
- Accounting and state transitions

LLM inference is used selectively for:
- Agent decisions
- Communication between agents
- Classification and prioritization
- Strategic/high-impact decisions

**Important**: Do NOT make every simulated entity an LLM agent.

### 2. Scalability
The architecture must support hundreds of simulated agents simultaneously.

### 3. Reproducibility
Simulation runs must support deterministic seeds for reproducible results.

### 4. Planned Inference Infrastructure
- AMD Instinct MI300X GPUs
- ROCm software stack
- vLLM for efficient inference serving
- Batched and concurrent inference capabilities

## System Components

### Nexus Core (General-Purpose Simulation Engine)
Provides the foundational simulation capabilities:
- Deterministic world simulation
- Event scheduling and processing
- State management systems
- Dependency tracking
- Resource modeling

### Nexus Cyber (Flagship Simulation Environment)
Specialized cyber-incident simulation built on Nexus Core:
- Cyber-specific entities and behaviors
- Attack modeling and propagation
- Network and infrastructure simulation
- Security team and attacker agent roles
- Incident response simulation

### Supporting Modules
- **Backend**: API services and server-side logic
- **Agents**: Agent definitions, populations, memory systems, and roles
- **Inference**: LLM client interfaces, routing, and prompt management
- **Scenarios**: Scenario definitions, with initial focus on cyber scenarios
- **Evaluation**: Metrics calculation and benchmarking tools
- **Frontend**: Local browser dashboard in `dashboard/index.html`, served by the standard-library HTTP API in `backend/api/main.py`
- **Tests**: Test suite for all components

## Data Flow
1. Simulation engine progresses deterministic state
2. At decision points, agents may query LLM for guidance
3. LLM responses inform agent actions within deterministic constraints
4. Simulation continues with updated agent behaviors
5. Outcomes are measured and recorded for evaluation

## Security and Isolation
- Deterministic simulation prevents unpredictable AI behavior from corrupting core mechanics
- LLM interactions are sandboxed and monitored
- Simulation boundaries ensure AI decisions affect only the simulated environment

## GPU-independent completion boundary

The deterministic simulation, baseline experiment runner, active simulated attack scenario, replay verification, and localhost dashboard can run on CPU with the Python standard library. The optional OpenAI-compatible provider is an adapter only; it does not provision a model server. GPU inference, ROCm/vLLM setup, and MI300X benchmarks remain separate integration work and must not be claimed without measurements on the actual serving hardware. The current cyber scenario is a discrete illustrative model, not a validated operational cyber range.
