# Contributing

Pilot #001 exists to demonstrate CROA's enforcement claims in a form other architects can inspect and
run. Contributions that make a claim *more verifiable* (tests, failure-mode coverage, documentation of
trust assumptions) are the most valuable.

## Workflow

1. Branch from `main`; open a pull request. `main` is protected: CI must pass and a maintainer must review.
2. Run locally before pushing:
   ```bash
   pip install -r requirements-dev.txt
   ruff check . && ruff format --check croa_plane c6_firewall acmeops_api scripts tests/unit
   pytest -q                      # in-process suite, no Docker needed
   python scripts/generate_pilot_keys.py && docker compose up --build --wait   # full stack
   ```
3. Any change to `c6_firewall/`, `croa_plane/c4_trajectory.py`, `croa_plane/c5_evidence.py`, `croa_plane/c7_compiler.py`
   or `docs/ECC-SPEC.md` must include a test that fails without the change, and an ADR in `docs/adr/` if it
   changes a design decision.
4. Do not commit keys, `.env`, evidence files, binaries, or scratch scripts. `.gitignore` covers the first three;
   the last two are a review criterion.

## Conventions

- Python 3.12, `ruff` for lint/format, type hints on public functions.
- Evidence vocabulary: `decision` is an *authorization* outcome; `execution_status` is a *target* outcome. Never conflate them.
- Every fail path must be fail-closed unless an ADR says otherwise.
