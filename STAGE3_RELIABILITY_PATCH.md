# NEXUS Stage 3 Reliability Patch — No API Credits Required

This patch improves diagnostics and avoids repeated hosted API calls after a non-recoverable configuration/quota response.

## Files to replace

- `simulation/llm_provider.py`
- `tests/test_llm_provider.py`

## Changes

- Classifies HTTP failures into safe categories such as `quota_exhausted`, `authentication_error`, `permission_error`, `rate_limited`, `invalid_request`, `endpoint_or_model_not_found`, and `server_error`.
- Reads the API error code from the HTTP response body without persisting or exposing the raw error body, request headers, or API key.
- Exposes `last_error_category` and `last_error_status_code` in experiment `provider_stats`.
- Opens a per-provider circuit after quota exhaustion, authentication/permission failure, rate limiting, or clearly invalid endpoint/request configuration. Subsequent decisions use the scripted fallback without another network request.
- Preserves engine authority: fallback decisions are still proposals and must pass the normal simulation validation path.
- Adds tests for quota classification, safe error reporting, and no repeated requests after quota exhaustion.

## Apply in Windows PowerShell

Extract this patch ZIP to a temporary folder. From the NEXUS repository root, copy the two files into the matching paths, then run:

```powershell
python -m compileall -q simulation scenarios tests
python -m pytest -q
python -m simulation --seeds 7,17,42 --ticks 5 --output artifacts/nexus-evaluation.json
```

The tests use mocked responses and make no real API calls. The baseline experiment does not require an API key or cloud GPU. Do not rerun `--with-llm` until API credits are available.
