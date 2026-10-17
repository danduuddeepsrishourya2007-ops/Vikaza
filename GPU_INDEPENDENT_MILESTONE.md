# NEXUS GPU-Independent Milestone

## Status

The local NEXUS Cyber milestone is executable and testable on CPU. Runtime code uses the Python standard library; `pytest` is needed only for tests. No API key, hosted LLM, CUDA/ROCm installation, vLLM server, or GPU is needed for the deterministic paths below.

## Implemented

- Deterministic world state, scheduler, event log, role permissions, decision validation, resource accounting, and decision-driven replay.
- Defensive lifecycle: investigate, isolate, patch, unisolate after remediation, and restore service. Patching a compromised host requires isolation; service restoration requires the host to be unisolated.
- In-memory attacker lifecycle: network/port/vulnerability scans, credential access, privilege escalation, persistence, lateral movement, command-and-control, defense evasion, whole-store data exfiltration, and service impact.
- Defender actions are applied before attacker actions by policy priority. The scripted defender can interrupt the attack sequence, remediate, reconnect, and restore the affected host.
- State-derived evaluation metrics, paired comparisons, decision provenance, JSON traces, and deterministic replay checks.
- Local browser dashboard + HTTP API with containment and active-attack modes, seed/tick controls, live topology state from the selected run, event/decision timeline, metrics, and JSON export.
- CLI for CPU-only containment and active-attack reports.

## Reproducible verification

From the repository root on Python 3.10+:

```powershell
python -m compileall -q simulation scenarios backend tests
python -m pytest -q
python -m simulation --seeds 7,17,42 --ticks 5 --output artifacts/nexus-evaluation.json
python -m simulation --mode active_attack --seeds 7,17,42 --ticks 7 --output artifacts/nexus-active-attack-evaluation.json
python -m backend.api.main
```

The active-attack report in `artifacts/nexus-active-attack-evaluation.json` contains six runs across three seeds and replay verification for each run. In this defined scenario, the unmitigated arm compromises all three hosts, exfiltrates the modeled 50 GB store, and takes the database service down; scripted defense prevents lateral movement and restores the workstation service.

## Measurement boundaries

- Exfiltration is whole-store, not byte-by-byte throughput.
- Service availability counts services on non-isolated hosts; a running process on an isolated host is not externally available. Final availability and down/restore events are measured, not duration-weighted downtime.
- The simulated attack has no real network access and is not a validated cyber range or prediction of real-world outcomes.
- The optional OpenAI-compatible provider is an integration boundary only. Model quality/latency measurements require a reachable endpoint.
- MI300X, ROCm, vLLM, batching, VRAM, throughput, and GPU latency claims are outside this milestone and require actual target hardware/serving access.
- Production hosting, authentication, multi-user persistence, and deployment hardening are also outside this local milestone.
