# CROA Enterprise Reference Pilot #001

## Purpose
Build a small, fully local, reproducible enterprise-style demonstration of the **Constrained Reachability Orchestration Architecture (CROA)**. 
The objective is to demonstrate that an AI agent may propose actions, but execution authority remains completely outside the agent. This pilot proves that legitimate actions are permitted, prohibited actions are denied, cumulative trajectories are enforced *before* execution, and that operations cannot execute without a cryptographically valid Execution Change Contract (ECC).

## Architecture
The pilot consists of four distinct containers simulating enterprise boundaries:
- **ui**: Interactive HTML/JS demonstration interface (`localhost:8080`).
- **croa_plane**: Houses C1 (Policy), C2 (Governor), C3 (Context Grounding), C4 (Trajectory Invariants), C5 (Evidence Logger), and C7 (Contract Compiler). Issues RS256 JWTs upon valid proposals.
- **c6_firewall**: The Execution Firewall that sits on the boundary of the governed network. It evaluates ECCs independently, validates signatures, parameters, and protects against replays.
- **acmeops_api**: A completely isolated fictitious enterprise system that represents the actual execution target.

*Note: C1, C2, C3, C4, C5, and C7 are co-located in one pilot container for implementation simplicity. This is a pilot deployment choice, not a CROA architectural requirement.*

## Quick Start
From a clean local environment, simply run:
```bash
python scripts/generate_pilot_keys.py
docker compose build
docker compose up -d
```
Then navigate your browser to:
[http://localhost:8080](http://localhost:8080)

## Demo Scenarios
The UI provides 8 pre-configured scenarios that interact directly with the live pilot containers:
- **A â€” Legitimate Action**: Normal operation generating a valid ECC and executing.
- **B â€” Unknown Target**: Fails at C3 context grounding (resource not registered).
- **C â€” Forbidden Action**: Fails at C2 static policy check.
- **D â€” Cumulative Trajectory**: Attempting 3 exports of 40 records under a 100-record session limit. The third request is blocked by C4 *before* an ECC is issued.
- **E â€” Missing ECC**: Direct call to C6 without a contract is blocked.
- **F â€” Forged ECC**: Invalidly signed contract is blocked by C6.
- **G â€” Mutated Operation**: ECC issued for 40 records, but C6 is asked to execute 400. Blocked by payload binding mismatch.
- **H â€” Replay Attempt**: Re-submitting an already redeemed valid ECC is blocked.

## What the Pilot Demonstrates
- Agent proposals are decoupled from execution.
- Within the pilot's modeled scenarios and trust assumptions, C6 admits only operations carrying a valid, unexpired and unredeemed ECC whose signed commitment matches the requested operation.
- Trajectory constraints (e.g. rate limits) are checked protectively on the control plane, preventing the generation of an ECC that would breach limits.
- The C6 execution firewall is strictly stateless (except for replay caches) and does not rely on calling the control plane to make enforcement decisions.
- A cryptographic tamper-evident C5 evidence hash chain logs all critical decisions.

## What the Pilot Does NOT Demonstrate
This is an author-operated reference pilot. It is not:
- C1 is a static pilot realization of policy content, not full signed-policy lifecycle.
- Agent Surface / AuthN / AQL are out of scope.
- Subject binding is not identity authentication.
- C5 is tamper-evident, not immutable.
- C5 provenance is protected in the pilot by internal service authentication.
- Replay cache is in-memory, single-node only.
- C4 commit-at-permit simplification.
- Cross-agent distributed trajectory safety is not demonstrated.
- Distributed concurrency safety is not demonstrated.

## Security Model
- **Network Isolation**: `acmeops_api` is on an internal docker network and publishes no ports. It cannot be reached directly by the UI or the `croa_plane`. Only `c6_firewall` has dual-network membership.
- **Key Hygiene**: The `croa_plane` holds `private.pem`. `c6_firewall` only holds `public.pem`. The UI never sees the private key.
- **Key Provisioning**: Keys are strictly local pilot artifacts. `private.pem` is never committed to version control. They are generated locally via `scripts/generate_pilot_keys.py`. This mechanism represents local pilot custody, not a production KMS/HSM.

## Known Limitations
- The C5 hash chain is a simplified local JSONL implementation.
- Pilot simplification: trajectory budget is reserved/committed at permit time rather than target commit time. As a result, unused ECCs may still consume trajectory budget.
- Replay protection (Nonces) are currently kept in memory within C6; production would require distributed caching (e.g., Redis).
- Live LLM dependencies are omitted in favor of predetermined demonstration payloads.

## Evidence
The pilot implements C5 using a persistent SHA-256 hash-chained JSONL evidence log. This provides tamper-evidence for demonstration purposes; it is not a production immutable ledger. Evidence of governance is written chronologically to `evidence_data/evidence.jsonl`. The UI live-tails this file and automatically verifies the chain validity.

## How to Reset
In the UI, click **Reset Demo**. This will:
1. Reset the in-memory trajectory counters on `croa_plane`.
2. Clear the used-nonce cache on `c6_firewall`.
3. Clear the execution history on `acmeops_api`.
4. Log a `DEMO_RESET` event to the `evidence_data/evidence.jsonl` log to maintain audibility of the reset operation.

## How to Run Tests
The automated test scripts are stored in the 	ests/ directory. They can be executed by piping them directly into the Python environment of the c6_firewall container, which has the correct network resolution.

### Normal Runtime Tests
These tests assert behavior in the standard environment:
`ash
# Phase 5 Automated UI Scenarios
cat tests/test_phase5.py | docker exec -i croa-pilot-001-c6_firewall-1 python -

# Hardening / Adversarial Scenarios
cat tests/test_hardening.py | docker exec -i croa-pilot-001-c6_firewall-1 python -

# Prove TTL manipulation is blocked
cat tests/test_ttl_enforcement.py | docker exec -i croa-pilot-001-c6_firewall-1 python -
`

### Test Mode Execution
To run tests that require internal clock/TTL overrides (like the expiration test), you must explicitly restart the plane in test mode:
`ash
docker compose -f docker-compose.yml -f docker-compose.test.yml up -d
cat tests/test_phase4.py | docker exec -i croa-pilot-001-c6_firewall-1 python -
docker compose up -d # Reverts to normal mode
`