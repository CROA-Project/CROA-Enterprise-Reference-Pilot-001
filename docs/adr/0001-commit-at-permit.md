# ADR-0001: Trajectory budget is reserved at permit time

**Status:** accepted (v0.1.0), reaffirmed v0.2.0

## Context
C4 must guarantee that the cumulative effect of *authorized* operations never exceeds an invariant.
Budget could be consumed when the ECC is issued or when the target confirms execution.

## Decision
Consume at permit (ECC issuance), atomically with the check.

## Consequences
- Simple and safe: no path exists where two outstanding ECCs together exceed the limit.
- Unused or failed ECCs still consume budget until the session ends. Acceptable for the pilot; a
  production design may release budget on `EXECUTION_FAILED (NOT_REACHED)` or expiry, never on `UNKNOWN`.
