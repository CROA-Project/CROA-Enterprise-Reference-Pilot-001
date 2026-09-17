# Changelog

## v0.2.0 — hardening release (unreleased)

Findings from two independent reviews of v0.1.1 (see PR description). Behavioural changes:

### Enforcement
- **C4** evaluate-and-commit is one atomic step under a lock; every applicable invariant is evaluated
  and committed all-or-nothing (`reserve_trajectory`). Previously check and commit were separate and
  only the first invariant was evaluated.
- **C6** nonce redemption is an explicit atomic reservation (`RESERVED → REDEEMED`), released if the
  pre-execution evidence write fails. Evidence calls are now `await`ed with explicit timeouts.
- **C6** refuses ECCs issued before its own boot (`ECC_PREDATES_FIREWALL_EPOCH`), closing the
  restart-replay window without persistent state.
- **ECC envelope**: `iss`, `aud`, `jti`, `kid`, `ecc_schema_version`, optional `policy_id`; C6 validates
  issuer, audience, required claims, key id and schema, and refuses `crit` headers. Expected invariant
  version is configuration, not a literal.
- **AcmeOps** requires the internal service secret on `/internal/*` and is idempotent on `ecc_id`;
  new `GET /internal/executions/{ecc_id}` for reconciliation.

### Evidence and API
- Execution outcome is `SUCCEEDED | FAILED | UNKNOWN | NOT_ATTEMPTED`, separate from the authorization
  decision. C6 reconciles ambiguous outcomes by `ecc_id` and records `EXECUTION_UNKNOWN` when it cannot.
  Previously a lost response was recorded as `FAILURE`.
- C5 verifies the chain at startup, anchors its head hash, refuses to extend a truncated, replaced or
  externally appended log, and `fsync`s each record. `/evidence/verify` returns structured results
  instead of 500 on malformed content.
- Evidence records carry `execution_status` and `claims_verified`. Timestamps are valid ISO-8601 `Z`
  (v0.1 emitted `+00:00Z` in ECC issuance records).

### Operations
- Keys live in `./keys/` and are mounted read-only; images no longer contain the private key.
- Placeholder or short secrets are rejected at startup; comparisons are constant-time.
- Containers run non-root with read-only root filesystems, dropped capabilities, health checks and
  resource limits; compose uses health-based `depends_on`. `ECC_TTL_SECONDS`, `ECC_ISSUER`,
  `ECC_AUDIENCE` and `C6_TARGET_TIMEOUT_SECONDS` are explicit configuration.
- Dependencies bumped (PyJWT 2.14, cryptography 50, FastAPI 0.141, httpx 0.28); `pip-audit` runs in CI.

### Repository
- Removed ~113 MB of GitHub CLI binaries and ~60 scratch scripts committed in `32ff22a`, a credential
  helper, and a hardcoded local secret. Fixed UI mojibake and stripped BOMs.
- Added GitHub Actions CI (lint, unit suite, dependency audit, compose harness), `CODEOWNERS`,
  `SECURITY.md`, `CONTRIBUTING.md`, `docs/` (architecture, trust boundaries, threat model, ECC spec,
  failure modes, production mapping) and five ADRs.
- Added an in-process pytest suite (43 tests) covering concurrency, cryptographic forgery, replay,
  lost responses, evidence corruption and canonicalization.

### Compatibility
- `/execute` responses keep the legacy top-level `decision`/`reason` fields.
- ECCs issued by v0.1 are rejected (`MALFORMED_ECC`: missing `iss`/`aud`/`jti`/schema).
- `tests/test_ttl_enforcement.py` must run inside `croa_plane` (it spawns a control plane).

## v0.1.1
UI reset fix. Tree includes transient workspace artifacts (removed in v0.2.0).

## v0.1.0
First public release: eight demonstration scenarios; execution-authority separation, context
grounding, policy enforcement, cumulative trajectory constraints, signed ECCs, replay and mutation
protection, tamper-evident evidence.
