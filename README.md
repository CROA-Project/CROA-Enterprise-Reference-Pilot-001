# CROA Enterprise Reference Pilot #001

[![CI](https://github.com/CROA-Project/CROA-Enterprise-Reference-Pilot-001/actions/workflows/ci.yml/badge.svg)](https://github.com/CROA-Project/CROA-Enterprise-Reference-Pilot-001/actions/workflows/ci.yml)

## Purpose
A small, fully local, reproducible demonstration of the **Constrained Reachability Orchestration
Architecture (CROA)**. An AI agent may *propose* actions; execution authority remains entirely outside
the agent. Within its modeled scenarios and the trust assumptions documented below, the pilot
demonstrates that legitimate actions are permitted, prohibited actions are denied, cumulative
trajectories are enforced *before* execution, and no operation reaches the protected target without a
cryptographically valid Execution Change Contract (ECC).

This is an **author-operated reference pilot**: it is not a production implementation, a formal
verification, or an independent validation of CROA.

## Architecture
Four containers model the enterprise boundaries:

- **ui** — demonstration interface (`localhost:8080`).
- **croa_plane** — C1 Policy, C2 Governor, C3 Context Grounding, C4 Trajectory Invariants,
  C5 Evidence, C7 Contract Compiler. Issues RS256 ECCs. Holds the private key (runtime-mounted).
- **c6_firewall** — the Execution Firewall on the governed-network boundary. Verifies ECCs
  independently (signature, issuer, audience, key id, expiry, bindings, single redemption) and never
  asks the control plane whether to execute.
- **acmeops_api** — a simulated protected target on an isolated internal network. It authenticates
  its firewall and is idempotent on `ecc_id`.

Co-locating C1–C5 and C7 in one container is a pilot choice, not a CROA requirement.
Details: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md), [`docs/TRUST-BOUNDARIES.md`](docs/TRUST-BOUNDARIES.md).

## Quick start
```bash
cp .env.example .env            # then replace BOTH secrets (≥12 chars; placeholders are rejected)
python scripts/generate_pilot_keys.py   # writes ./keys/ (gitignored) and ./evidence_data/
docker compose up --build --wait
open http://localhost:8080
```
Demo-control functions (Reset, evidence view) prompt for `DEMO_CONTROL_SECRET`. This is a local
operator convenience, not a security boundary.

## Demo scenarios
| | Scenario | Stops at |
|---|---|---|
| A | Legitimate action | executes through C6 |
| B | Unknown target | C3 (not registered) |
| C | Forbidden action | C2 (policy) |
| D | Cumulative trajectory — 3 × 40 records under a 100-record session limit | C4 blocks the third *before* an ECC exists |
| E | Missing ECC | C6 |
| F | Structurally invalid ECC | C6 (`INVALID_SIGNATURE`) — cryptographic forgeries are covered by the unit suite |
| G | Mutated operation — authorized 40, execute 400 | C6 (`OPERATION_MISMATCH`) |
| H | Replay | C6 (`ECC_ALREADY_REDEEMED`) |

## What the pilot demonstrates
- Proposal and execution authority are separated by a cryptographic contract.
- C6 admits only a valid, unexpired, unredeemed ECC whose signed commitment matches the presented
  operation; the check is atomic under concurrent redemption.
- Trajectory limits are reserved atomically at permit time, so concurrent proposals cannot
  collectively exceed an invariant within one control-plane process.
- The pre-execution authorization record is mandatory; if C5 cannot record it, nothing executes.
- Execution outcomes are reported as `SUCCEEDED`, `FAILED` or `UNKNOWN`. C6 reconciles ambiguous
  outcomes with the target by `ecc_id` and never records an outcome it did not observe.
- Evidence is a hash-chained, self-anchored log that fails closed on corruption.

## What the pilot does NOT demonstrate
- **Authenticated proposers.** `/propose` has no AuthN. `session_id` and `subject` are trusted inputs:
  the C4 limit is enforced faithfully within the scope the caller names, and a caller can name a new
  session. Subject binding in the ECC is a string match, not identity.
- Distributed or multi-process safety. C4 state and the C6 replay registry are per-process, in memory;
  run one worker per service. A C6 restart is handled by refusing pre-boot ECCs (ADR-0004); a
  control-plane restart resets budgets.
- Immutable evidence. C5 is tamper-evident and self-anchored while running; a file replaced between
  restarts is not detectable without an external anchor.
- Workload identity. Services authenticate with a shared secret; there is no TLS.
- Signed policy lifecycle, policy conflict resolution, AQL, or a live LLM.
- C6 independence *of availability*: C6 needs the control plane's evidence endpoint to execute.

Full list and rationale: [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md); production replacements:
[`docs/PRODUCTION-MAPPING.md`](docs/PRODUCTION-MAPPING.md); failure behaviour with the test that
proves each: [`docs/FAILURE-MODES.md`](docs/FAILURE-MODES.md); contract format:
[`docs/ECC-SPEC.md`](docs/ECC-SPEC.md); decisions: [`docs/adr/`](docs/adr/).

## Security model (pilot)
- **Network isolation:** `acmeops_api` is on an `internal` Docker network with no published ports.
  Only `c6_firewall` is dual-homed.
- **Target authentication:** AcmeOps rejects any `/internal/*` call without the internal service secret.
- **Key custody:** `keys/private.pem` is mounted read-only into `croa_plane`; `keys/public.pem` into
  `c6_firewall`. Neither is committed or built into an image. This is local pilot custody, not KMS/HSM.
- **Containers:** non-root, read-only root filesystem, all capabilities dropped, health-checked,
  memory/CPU limited, single worker.

## Evidence
`evidence_data/evidence.jsonl` is a SHA-256 hash-chained JSONL log written by C5 alone. The UI
live-tails it through the API and shows chain validity. `decision` is the *authorization* outcome;
`execution_status` is the *target* outcome; `claims_verified: false` marks records whose ECC claims
could not be authenticated.

## Reset
**Reset Demo** in the UI clears trajectory counters, the replay registry and AcmeOps history, and
writes a `DEMO_RESET` record to the evidence chain (the reset itself is auditable).

## Tests
```bash
pip install -r requirements-dev.txt
pytest -q                     # in-process suite: concurrency, forgery, replay, lost responses, corruption
scripts/run_regression.sh     # scenario harness against the compose stack (normal + test mode)
```
The in-process suite needs no Docker. The compose harness pipes the scripts in `tests/` into the running
containers; `docker-compose.test.yml` enables clock/TTL overrides and fault injection and must never be
used for demonstrations. CI runs both.

## Versioning
See [`CHANGELOG.md`](CHANGELOG.md). `v0.1.x` releases predate the hardening described there.
