# NEXUS Stage 3–5: Local-First Integration Checkpoint

## Implemented in this local checkpoint

- `simulation/llm_provider.py`: standard-library-only OpenAI Chat Completions-compatible provider, structured JSON parsing, action enum validation, timeout configuration, and optional API-key environment variable.
- `FallbackProvider`: if the endpoint fails or returns invalid output, produces a marked `fallback_heuristic` decision. The authoritative engine still validates and applies/rejects it.
- `simulation/experiment.py`: same-seed provider comparisons, numeric metric aggregation, and deterministic replay verification for each run.
- `simulation/cli.py` and `simulation/__main__.py`: command-line evaluation and JSON report generation.
- Tests use a fake transport; they do not require an API key, internet, a running model, or a GPU.

## Local verification

```powershell
python -m compileall -q simulation scenarios tests
python -m pytest -q
python -m simulation --seeds 7,17,42 --ticks 5 --output artifacts/nexus-evaluation.json
```

Expected baseline policies: `do_nothing_v1` and `scripted_defensive_v1`. Exact values and test counts may change as the simulation evolves; use actual command output as the source of truth.

## Optional real endpoint (not required for local development)

Set the endpoint/model for a server you already operate or a service you are authorized to use. Do not commit API keys.

```powershell
$env:NEXUS_LLM_BASE_URL = "http://127.0.0.1:8000/v1"
$env:NEXUS_LLM_MODEL = "YOUR_SERVED_MODEL_ID"
$env:NEXUS_LLM_API_KEY = "YOUR_KEY_IF_REQUIRED"
python -m simulation --with-llm --seeds 7 --ticks 5 --output artifacts/nexus-llm-evaluation.json
```

The endpoint is expected to support `POST /chat/completions` (or be the full `/chat/completions` URL), Chat Completions response shape, and JSON-object response mode. No server is started automatically. A fake transport is used in unit tests; no real-model result is claimed by those tests.

## Important limitations

- Requests are currently synchronous and sequential, one per active agent per tick. This is an integration baseline, not a high-throughput inference scheduler.
- Fallback is observable in each run's `provider_stats`; do not report a fallback-heavy run as successful LLM performance.
- `source="llm"` indicates a parsed model proposal, not an authorized or accepted world action. The engine remains authoritative.
- The current cyber scenario is a small containment benchmark with an initially compromised host. It does not yet model realistic attack propagation or prove real-world predictive validity.
- Replay verifies deterministic execution of recorded decisions. It does not make stochastic remote model calls deterministic; replay does not call the model again.
- Do not add RAG, fine-tuning, distributed orchestration, or GPU-specific dependencies until a measured requirement justifies them.

## GPU / cloud checkpoint criteria

Do not rent a GPU just to continue developing. Consider a local or cloud model runtime only when all of the following are true:

1. The CPU-only simulation and test suite are stable.
2. A real model-backed run has been measured on a fixed seed set.
3. We have recorded end-to-end decision latency, failure/fallback rate, throughput, and outcome metrics against both baselines.
4. The chosen model cannot meet the target latency/throughput on available CPU or an existing hosted inference API.
5. There is a specific benchmark and budget for the next experiment.

For MI300X claims, benchmark with the intended ROCm/vLLM setup on actual hardware and report measured p50/p95 latency, decisions per second, VRAM, GPU utilization, failure rate, and outcome equivalence. Do not infer performance from the GPU specifications alone.
