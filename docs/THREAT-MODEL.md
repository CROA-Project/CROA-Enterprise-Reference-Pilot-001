# Threat Model — Pilot #001

## Security objective

No operation reaches the protected target unless the control plane issued a valid ECC for **that
operation**, the ECC is unexpired and unredeemed, and the authorization was recorded before execution.
Cumulative limits are enforced per `(session_id, subject)` **within one control-plane process**.

## In scope (the pilot is expected to resist)

| Adversary | Capability | Controls |
|---|---|---|
| Rogue/compromised agent | Sends arbitrary `/propose` and `/execute` requests | C3 grounding, C2 default-deny, C4 reservation, ECC required at C6 |
| Agent with a valid ECC | Presents it for a different operation | subject/action/target/`parameters_hash`/invariant-version binding |
| Agent with a valid ECC | Presents it twice, or concurrently | atomic nonce reservation; burned before execution |
| Agent with a spent ECC after C6 restart | Replays within TTL | restart epoch: `iat < BOOT_TIME` refused |
| Forger | Wrong key, `alg=none`, HS256 with public key, unknown `crit`, wrong `iss`/`aud`/`kid` | algorithm pin, issuer/audience/required-claims validation, `kid` match, `crit` refusal |
| Concurrent legitimate requests | Exceed a cumulative limit by racing | C4 reserve under lock; all invariants all-or-nothing |
| Operator error / disk fault | Truncated or replaced evidence file | anchored, fail-closed C5; `/evidence/verify` reports rather than crashes |
| Anyone on `governed_network` | Calls AcmeOps directly | service secret required; only C6 holds it |

## Out of scope (documented, not defended)

- **Session and subject spoofing.** `session_id`/`subject` in `/propose` are unauthenticated. An agent
  can reset its trajectory budget by choosing a new `session_id`. The invariant is real; the *scope*
  is trusted input. Enterprise realizations mint sessions server-side and/or budget per authenticated
  subject.
- Distributed or multi-process state: C4 state and the C6 replay registry are per-process, in-memory.
  Run one worker per service.
- Immutability of evidence. C5 is tamper-evident and self-anchored; it cannot prove that a file
  replaced *between process restarts* is the original without an external anchor.
- Compromise of the Docker host, of the C6 container, or of the control-plane container (which holds
  the signing key).
- Denial of service, including thread-pool exhaustion through the `/propose → /refuse → /evidence`
  call cycle under a denial storm.
- Confidentiality: no TLS anywhere in the pilot.
- Policy signing, distribution and revocation (`invariant_set_version` is a label, not a content hash).

## Residual risks accepted for the pilot

- Shared secrets instead of workload identity.
- Zero clock leeway (single host).
- Nonce registry bounded only by TTL-based purge.
