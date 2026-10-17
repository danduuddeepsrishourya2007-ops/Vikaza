# NEXUS Stage 3 — Decision Safety and Offline Evaluation Patch

## Scope

This patch tightens the authoritative decision boundary and improves offline provenance/evaluation reporting.

- Rejects malformed, stale, future-tick, oversized, or incorrectly typed decisions before sorting or executing them.
- Makes rejection-event recording robust to malformed decision fields.
- Enforces exactly two host identifiers in connection targets (`host_a,host_b`).
- Adds optional structured `failure_reason` provenance to fallback decisions and replay traces.
- Reports recorded decision-source counts and fallback reasons in experiment results.
- Treats quota/auth/configuration failures as circuit-opening failures, while transient HTTP 429 rate limiting remains recoverable.
- Avoids echoing an untrusted unknown action name in provider error messages.
- Validates experiment seed/tick/provider configuration.
- Adds offline regression tests for these behaviors.

## Verification performed on the available project snapshot

Commands:

```powershell
python -m compileall -q simulation scenarios tests
python -m pytest -q
```

Result: **102 passed**.

The patch was tested against the previously uploaded `NEXUS-local-first-stage3.zip` snapshot with the committed Stage 3 reliability provider patch applied. It was not executed inside the user's live `C:\Users\dandu\NEXUS` checkout; run the same commands there before committing.

## Apply on Windows PowerShell

1. Back up the repository or ensure the working tree is clean. Keep `artifacts/` untouched.
2. Extract `NEXUS-stage3-safety-patch.zip` to a temporary folder.
3. From `C:\Users\dandu\NEXUS`, copy the `simulation` and `tests` files from the extracted `nexus_stage3_safety_patch` folder into the matching repository folders, preserving relative paths.
4. Run:

```powershell
python -m compileall -q simulation scenarios tests
python -m pytest -q
git diff --check
git status --short
git diff --stat
```

Do not stage `artifacts/`. Review the diff before committing. The patch intentionally does not commit anything.
