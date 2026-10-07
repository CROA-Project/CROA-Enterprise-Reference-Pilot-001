# Security Policy

This repository is an **author-operated reference pilot**, not a production system. It intentionally
uses local key custody, in-memory state and shared secrets. See `docs/THREAT-MODEL.md` for what is in
and out of scope, and `docs/PRODUCTION-MAPPING.md` for what an enterprise realization replaces.

## Reporting

If you find a way for an operation to reach the protected target without a valid, unexpired,
unredeemed ECC whose commitment matches the operation, or a way to exceed a trajectory invariant
within a single control-plane process, please report it privately through GitHub's
"Report a vulnerability" (Security → Advisories) rather than a public issue. Include the commit hash,
a reproduction (the `tests/unit` harness is the easiest vehicle), and the CROA claim you believe is
undermined.

## Known, documented limitations (not vulnerabilities)

- `session_id` and `subject` are trusted inputs to C4 scoping (README → "What the Pilot Does NOT Demonstrate").
- Replay registry and trajectory state are per-process and in-memory.
- C5 is tamper-evident, not immutable; an unanchored chain cannot detect whole-file replacement by itself.
- Shared secrets, not workload identity, authenticate C6 to C5 and to AcmeOps.
