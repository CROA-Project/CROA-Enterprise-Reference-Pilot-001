# ADR-0002: The nonce is burned before execution

**Status:** accepted

## Context
If the target executes and the response is lost, C6 must choose between allowing a retry (at-least-once)
and refusing it (at-most-once).

## Decision
At-most-once. The nonce is reserved atomically before the authorization evidence is written and is
marked redeemed before the target is called. A lost response is reconciled by `ecc_id`, never retried.

## Consequences
- An ECC can never produce two executions.
- A genuinely failed execution requires a new proposal (and, per ADR-0001, new budget).
- The target must be idempotent on `ecc_id` so that reconciliation is possible.
