# ADR-0003: Evidence fails closed, and C5 is a single writer

**Status:** accepted (v0.2.0; replaces v0.1.0 behaviour)

## Context
v0.1.0 returned the genesis hash when the evidence file could not be read, so a corrupted, truncated
or deleted log silently began a new chain. Meanwhile C6 already refused to execute without a
pre-execution evidence record. The two behaviours were inconsistent.

## Decision
- C5 verifies the whole chain at startup and keeps the head hash as an in-process anchor.
- Every append first checks that the file still ends with the anchored record; otherwise it raises
  `EvidenceIntegrityError` and the control plane returns 503 with no decision.
- `/evidence/verify` reports malformed content as `{"valid": false, "reason": …}` rather than failing.
- Exactly one process may write a given evidence file.

## Consequences
- Unreadable or externally modified history stops the plane. This is the intended posture for a
  component whose purpose is undeniable history.
- Tests that spawn a second control-plane process must give it its own `CROA_EVIDENCE_FILE`.
- C6's execution depends on C5 availability; production separates C5 from C7 (see PRODUCTION-MAPPING).
