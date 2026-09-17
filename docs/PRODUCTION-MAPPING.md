# Production Mapping

Each pilot simplification, what it stands in for, and what changes.

| Pilot | Enterprise realization | Notes |
|---|---|---|
| In-memory C4 state, one process | Transactional store with conditional update (compare-and-add) or a single-writer reservation service | The atomic reserve contract in `c4_trajectory.reserve_trajectory` is the interface to preserve |
| `session_id`/`subject` from the request body | Session minted by an authenticated agent surface; subject from workload/user identity | Budgets keyed on trusted identifiers; optionally per-subject budgets across sessions |
| PEM signing key on disk, mounted read-only | KMS/HSM-backed signing; JWKS endpoint with `kid` rotation | C6 already requires `kid`; add a JWKS fetch with pinned key set |
| Shared `INTERNAL_SERVICE_SECRET` | mTLS / SPIFFE workload identity | Applies to plane↔C6 and C6↔target |
| Target trusts network + secret | Target verifies the ECC signature itself | Defense in depth; removes C6 as the only verifier |
| In-memory nonce registry, one worker | Distributed replay registry (e.g. Redis `SET NX PX`) keyed on `jti` with TTL = `exp` | Keep the reserve→authorize-evidence→redeem state machine |
| Restart epoch (`iat >= BOOT_TIME`) | Not needed once the registry is durable; keep as belt-and-braces | |
| JSONL evidence, self-anchored | Append-only/WORM evidence service with external anchoring (e.g. periodic head-hash publication) | C6 could retain the last head hash it saw and refuse execution on regression |
| C5 co-located with C7 | Separate evidence service with its own availability | Breaks the coupling "control plane down ⇒ no execution" into an explicit dependency |
| `invariant_set_version` label | Content hash of a signed policy bundle | Enables revocation-by-rotation at C6 |
| First-match policy list | Deny-overrides evaluation with explicit ordering and signed distribution | |
| Docker `internal` network | Private network / service mesh with egress control | |
| Compose healthchecks, non-root, read-only rootfs | Same, plus digest-pinned images, SBOM, image signing | |
| Zero clock leeway | Small leeway (seconds) with monitored clock sync | |
| `python json.dumps` canonicalization | RFC 8785 (JCS) under a new `ecc_schema_version` | |
