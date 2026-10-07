# Failure Modes

What the pilot does when something goes wrong, and which test proves it.

| Scenario | Behaviour | Proof |
|---|---|---|
| Concurrent proposals in one session | C4 reserves under a lock; total never exceeds the limit | `test_c4_trajectory.py::test_concurrent_*` |
| Several invariants apply, one denies | none is committed (all-or-nothing) | `test_multiple_invariants_all_evaluated_and_committed` |
| Concurrent redemption of one ECC | exactly one `ALLOW`, one target execution | `test_simultaneous_redemption_executes_exactly_once` |
| C5 unavailable before execution | `BLOCK / EVIDENCE_UNAVAILABLE`; reservation released; ECC still usable later | `test_evidence_unavailable_fails_closed_and_releases_reservation` |
| C5 unavailable after execution | outcome evidence is lost (best effort); `ecc_id` remains queryable at the target | documented gap |
| Target unreachable (connect error) | `execution.status = FAILED`, `target_status = NOT_REACHED` — a knowable failure | `test_target_unreachable_is_a_knowable_failure` |
| Target executed, response lost | C6 reconciles via `GET /internal/executions/{ecc_id}` → `SUCCEEDED (RECONCILED_SUCCESS)` | `test_lost_response_reconciles_to_succeeded` |
| Response lost and reconciliation impossible | `execution.status = UNKNOWN`; evidence `EXECUTION_UNKNOWN`; ECC spent | `test_lost_response_and_no_reconciliation_is_unknown_not_failure` |
| Target returns 5xx | treated as ambiguous → reconcile | code path `_execute_on_target` |
| Evidence file truncated | next write raises `EvidenceIntegrityError` (503); `/evidence/verify` reports the line | `test_truncated_tail_fails_closed_on_write_and_reports_on_verify` |
| Evidence file deleted while running | refused (anchor mismatch) | `test_deleted_log_is_not_silently_restarted` |
| Evidence file corrupt at startup | control plane refuses to start | `test_startup_refuses_corrupt_history` |
| Evidence file appended by another process | refused (single-writer invariant) | by design; see ADR-0003 |
| C6 restart within ECC TTL | ECCs issued before boot are refused (`ECC_PREDATES_FIREWALL_EPOCH`) | `test_ecc_issued_before_firewall_boot_rejected` |
| croa_plane restart | trajectory budgets reset (documented pilot limitation) | — |
| croa_plane unavailable | C6 cannot execute anything (fail-closed evidence dependency) | ADR-0003 |
| C6 unavailable during a denial | denial returned to caller; boundary-side evidence of the denial is lost | code path `forward_to_c6_refusal_gateway` |
| Placeholder or short secret | service refuses to start | `test_placeholder_secret_refused_at_startup` |
| Signing key missing | control plane refuses to start (lifespan) | — |
| Denial storm | possible thread-pool stall through the refuse/evidence cycle; bounded by 5 s timeouts | not tested; out of scope |
