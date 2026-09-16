# ADR-0005: Authorization outcome and execution outcome are separate

**Status:** accepted (v0.2.0; replaces v0.1.0 behaviour)

## Context
v0.1.0 returned `{"decision": "ALLOW", "reason": "TARGET_SYSTEM_FAILURE"}` for every target-side
problem and recorded `target_status: FAILURE` in evidence even when the outcome was unknown (e.g. a
read timeout after the target had committed).

## Decision
- API responses carry `authorization` and `execution` objects; legacy top-level fields remain for v0.1 clients.
- `execution.status ∈ {SUCCEEDED, FAILED, UNKNOWN, NOT_ATTEMPTED}`. `FAILED` is used only when the
  failure is knowable (request never reached the target, or the target answered 4xx). Timeouts,
  dropped connections and 5xx are ambiguous: C6 attempts reconciliation by `ecc_id` and otherwise
  records `UNKNOWN`.
- Evidence gains `execution_status` and `claims_verified`.

## Consequences
- The evidence log never asserts an outcome C6 could not observe.
- Consumers must read `execution.status`, not infer it from `reason`.
