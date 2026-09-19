# Key Decisions in NEXUS Design

## Architectural Decisions

### Separation of Deterministic and LLM Components
**Decision**: Strict separation between deterministic simulation mechanics and LLM-based reasoning.
**Rationale**: 
- Ensures simulation reproducibility and reliability
- Prevents LLM non-determinism from affecting core simulation integrity
- Allows deterministic validation and testing of simulation engine
- Makes it possible to run simulations without LLM components for baseline testing

### Selective LLM Usage
**Decision**: LLM inference is used only for specific high-value functions, not for every agent action.
**Rationale**:
- Computational efficiency (LLM calls are expensive)
- Maintains simulation performance at scale
- Focuses AI resources where they provide maximum value
- Reduces potential for AI-induced simulation instability

### Agent Design Philosophy
**Decision**: Not every simulated entity will be an LLM agent.
**Rationale**:
- Enables scaling to hundreds or thousands of agents
- Most agent behaviors can be modeled deterministically
- LLM agents reserved for decision-makers and strategic roles
- Hybrid approach balances realism with computational feasibility

## Product Decisions

### Initial Focus on Cybersecurity
**Decision**: Nexus Cyber as the first flagship environment focusing on cyber-incident simulation.
**Rationale**:
- High-stakes decisions with clear, measurable outcomes
- Well-defined domain with established frameworks (MITRE ATT&CK, etc.)
- Clear separation between attackers and defenders
- Quantifiable impact metrics (downtime, data loss, recovery time)
- Immediate applicability to enterprise risk management

### Policy Comparison Focus
**Decision**: Platform design emphasizes comparing competing policies/decisions.
**Rationale**:
- Addresses core organizational need: "What should we do in situation X?"
- Enables evidence-based decision making
- Supports regulatory compliance and due diligence
- Provides measurable ROI for simulation investment
- Aligns with decision-rehearsal thesis

### Deterministic Seeds for Reproducibility
**Decision**: All simulation runs must support deterministic seeding.
**Rationale**:
- Enables scientific approach to policy testing
- Allows apples-to-apples comparison of different decisions
- Facilitates debugging and validation
- Supports audit requirements and traceability
- Essential for benchmarking and performance testing

## Technical Decisions

### Python as Primary Implementation Language
**Decision**: Use Python for initial implementation.
**Rationale**:
- Rich ecosystem for scientific computing and simulation
- Good ML/AI library integration (PyTorch, TensorFlow, etc.)
- Strong community and tooling
- Suitable for both simulation engine and API layers
- Performance can be addressed through optimization and inference offloading

### Modular Package Structure
**Decision**: Organize code into clearly defined modules with strict interfaces.
**Rationale**:
- Maintainability as project grows
- Clear separation of concerns
- Enables independent development and testing
- Supports potential future language diversification per module
- Facilitates team-based development

## Open Questions (For Future Resolution)
- Exact LLM integration patterns and interfaces
- Specific database/storage requirements for simulation state
- Network simulation fidelity levels
- Visualization and frontend technology choices
- Deployment and scaling architecture details