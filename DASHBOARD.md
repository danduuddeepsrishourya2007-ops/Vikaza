# NEXUS Cyber Dashboard

The dashboard is a local-first browser interface over the actual Python simulation. It supports two modes:

- **Containment baseline** compares `do_nothing_v1` with `scripted_defensive_v1` against the initial compromised endpoint.
- **Active simulated attack** runs a deterministic red-team sequence through the in-memory workstation → application → database topology. It models credential access, lateral movement, command-and-control, whole-store exfiltration, and service impact. The defensive policy can interrupt this sequence. It never connects to real hosts or networks.

Both modes report state-derived metrics, recorded decisions/events, replay status, and JSON export. No fabricated dashboard fixture results are used.

## Run locally (Windows PowerShell)

From the repository root, activate the project virtual environment if you use one, then run:

```powershell
python -m pytest -q
python -m backend.api.main
```

Run a CPU-only active-attack evaluation from PowerShell without opening the dashboard:

```powershell
python -m simulation --mode active_attack --seeds 7,17,42 --ticks 7 --output artifacts/nexus-active-attack-evaluation.json
```

Open <http://127.0.0.1:8765> in your browser. Stop the server with `Ctrl+C`.

To choose another port:

```powershell
$env:NEXUS_PORT = "8766"
python -m backend.api.main
```

## API

- `GET /api/health` — process health and scenario identifier.
- `GET /api/scenario` — authoritative initial hosts, links, services, data stores, agents, and resources.
- `POST /api/run` — execute seeded comparisons and return metrics, paired deltas, decision traces, and replay verification. Accepts `mode: "containment"` (default) or `mode: "active_attack"`.

Example request:

```json
{"seeds": [7, 17, 42], "ticks": 5, "mode": "containment"}
```

Run the full deterministic attack sequence with:

```json
{"seeds": [7, 17, 42], "ticks": 7, "mode": "active_attack"}
```

Limits: 1–20 unique non-negative integer seeds and 1–100 ticks per run. The server binds to `127.0.0.1` by default and has no authentication; **do not expose it to an untrusted network**. The dashboard is intentionally standard-library-only, so the core dependencies and inference stack are not required to start it.

## Scope and interpretation

The topology starts from the authoritative initial state for the selected mode and updates to the selected run's final host/network state. Service availability counts services on non-isolated hosts; a running process on an isolated host is not treated as externally available. Timeline entries come from recorded trace decisions and events. The active-attack scenario uses a deterministic scripted attacker, not an LLM. Neither mode is an LLM quality benchmark or a prediction of real-world incident outcomes. Model inference is not called by the dashboard; configure and validate the optional inference provider separately before comparing model-backed decisions. The server is unauthenticated and intended for localhost development only.
