# Execution Change Contract (ECC) — Schema Version 1

An ECC is a JWS (RFC 7515) compact-serialized JWT signed with **RS256**. It is a bearer capability
bound to exactly one operation and redeemable exactly once at C6.

## Header

| Field | Value |
|---|---|
| `alg` | `RS256` (C6 accepts nothing else) |
| `typ` | `JWT` |
| `kid` | first 16 hex chars of SHA-256 over the DER SubjectPublicKeyInfo of the signing key's public half |
| `crit` | must be absent |

## Claims (all mandatory)

| Claim | Type | Meaning | Verified by C6 |
|---|---|---|---|
| `iss` | string | control-plane identity (`ECC_ISSUER`) | exact match |
| `aud` | string | firewall identity (`ECC_AUDIENCE`) | exact match |
| `jti` | string | contract id (== `ecc_id` == `nonce`) | equality of the three |
| `iat` | int | issue time (Unix seconds) | not in the future; `>= C6 BOOT_TIME` |
| `exp` | int | expiry | `> now`, zero leeway |
| `ecc_schema_version` | string | `"1"` | exact match |
| `ecc_id` | string | contract id; the target's idempotency key | — |
| `nonce` | string | retained for v0.1 compatibility; identical to `jti` | replay registry key |
| `request_id` | string | proposal correlation id | recorded in evidence |
| `session_id` | string | trajectory scope (trusted input in the pilot) | recorded |
| `subject` | string | proposer identity string | must equal request body |
| `action` | string | operation | must equal request body |
| `target` | string | resource | must equal request body |
| `parameters_hash` | hex | canonical hash of the operation parameters | must equal hash of request body parameters |
| `invariant_set_version` | string | policy set the decision was made under | must equal C6's expected version |
| `policy_id` | string | optional; matched C1 rule | — |

## Canonicalization of `parameters`

`sha256( json.dumps(parameters, sort_keys=True, separators=(",", ":"), ensure_ascii=True) )`

Consequences (tested in `tests/unit/test_ecc_and_c6.py::test_parameter_canonicalization`):
- key order is irrelevant, recursively;
- array order is significant;
- `40` and `40.0` are different values;
- non-ASCII is escaped (`\uXXXX`), so NFC and NFD forms of a string are different values;
- both C7 and C6 must use this exact function. A future schema version may adopt RFC 8785 (JCS).

## Verification order at C6

1. Signature, algorithm pin, `iss`, `aud`, `exp`, `iat`, required claims (library).
2. `kid` matches the mounted public key; `crit` absent; schema version; `jti == ecc_id == nonce`; integer times; restart epoch.
3. Evidence: `EXECUTION_ATTEMPT`.
4. Early replay check.
5. Binding: subject, action, target, `parameters_hash`, invariant-set version.
6. Atomic nonce reservation.
7. Evidence: `EXECUTION_AUTHORIZED` — mandatory; failure releases the reservation and blocks.
8. Nonce marked redeemed; execute; reconcile if ambiguous; record `EXECUTION_{SUCCEEDED|FAILED|UNKNOWN}`.

## Block reasons

`MISSING_ECC`, `INVALID_SIGNATURE`, `ECC_EXPIRED`, `MALFORMED_ECC`, `ISSUER_OR_AUDIENCE_MISMATCH`,
`UNKNOWN_KEY_ID`, `UNSUPPORTED_ECC_SCHEMA`, `ECC_PREDATES_FIREWALL_EPOCH`, `ECC_ALREADY_REDEEMED`,
`SUBJECT_MISMATCH`, `ACTION_MISMATCH`, `TARGET_MISMATCH`, `OPERATION_MISMATCH`,
`INVARIANT_VERSION_MISMATCH`, `EVIDENCE_UNAVAILABLE`.

## Response model

```json
{
  "authorization": {"decision": "ALLOW|BLOCK", "reason": "…", "ecc_id": "…"},
  "execution":     {"status": "SUCCEEDED|FAILED|UNKNOWN|NOT_ATTEMPTED", "target_status": "…", "execution_id": "…"},
  "decision": "ALLOW|BLOCK", "reason": "…"            // legacy v0.1 fields
}
```
