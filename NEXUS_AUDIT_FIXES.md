# NEXUS Audit Fixes

## Scope and provenance

This package is based on the uploaded `NEXUS-GPU-independent.zip` snapshot. It is not connected to or automatically applied to the live working tree at `C:\Users\dandu\NEXUS`. Copy or apply the patch to that repository only after reviewing it.

## Fixes implemented

1. **Fail closed on incomplete LLM decisions** (`simulation/llm_provider.py`): a model response must contain all three schema fields: `action_type`, `target`, and `rationale`. Missing fields raise a categorized `ProviderError` (`invalid_decision`), allowing the configured fallback provider to take over instead of silently accepting an incomplete decision. `target` may explicitly be JSON `null` where permitted by the schema.
2. **Correct tick-zero containment accounting** (`simulation/evaluation.py`): initially compromised hosts already isolated in the initial world are counted as isolated from tick 0. If every initially compromised host is already isolated, containment time is `0`. An empty initial compromise set remains unsuccessful rather than passing by vacuous truth.
3. **Reject boolean trace versions** (`simulation/replay.py`): trace versions must be integers but not booleans. This avoids Python's `True == 1` behavior accepting `true` as trace version 1.

## Regression coverage added

- Three parameterized LLM-provider cases: missing `action_type`, `target`, or `rationale`; each verifies fallback behavior and failure accounting.
- Replay trace rejects `trace_version: true`.
- Evaluation reports tick-zero containment when the initially compromised host is already isolated.

## Verification performed

Commands run from the project root:

```text
python -m compileall -q simulation scenarios tests
python -m pytest -q
164 passed in 1.30s
```

The full test suite increased from 159 passing tests in the supplied snapshot to 164 passing tests after these fixes. The compile check completed successfully.

## Remaining limitations

- Tests exercise the local deterministic suite; they do not prove real GPU/vLLM throughput or production endpoint reliability.
- No live model endpoint or MI300X hardware benchmark was run as part of this audit.
- The archive is a snapshot-based deliverable and does not create a Git commit or alter your local checkout.
