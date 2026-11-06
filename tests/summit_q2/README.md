# Summit Q2 VALIDATE — modelled CROA run

Test material for the modelled CROA run of the Q2 VALIDATE stage of the TMG × CROA pilot, carried out on 26 October 2026. As with `tests/summit_q1/`, this folder holds the frozen test definition, the test code and the adjudication of the results.

## Important differences from `tests/summit_q1/`

- This material does **not** run against the code in this repository. It runs against the [CROA Minimal Reference Harness](https://github.com/CROA-Project/croa-reference-harness) at commit `10ad6da5fd0f717cf8e7cbfe18ffbb223bb4b21b`, unmodified.
- The harness is a demonstrator. Results show how the CROA design behaves in this mock. They do not establish the properties of any real deployment or a CROA conformance level.
- The roles, targets and invariants INV-Q2-01..07 are evaluation-team policy, not CROA requirements.

## Contents

| Path | Content |
|---|---|
| `Q2_TEST_PLAN_FREEZE.md` | Test plan and acceptance criteria, fixed before execution |
| `Q2_FINAL_ADJUDICATION.md` | Results, observations and claim boundary |
| `inputs/finance_ai_report_payload.json` | Structured transcription of the fictitious Finance AI report used in TC-15 |
| `q2fixture/` | Enterprise model, control payloads, independent oracle, test cases |
| `tools/` | Harness tree digest and determinism comparison |
| `docker/Dockerfile` | Offline image, no `RUN` step |
| `SHA256SUMS.txt` | Digests of the files in this folder |

## Replaying the run

```bash
docker build --pull=false --network=none -t q2-croa-run:v0.1 docker/
docker run --rm --network none --read-only --tmpfs /tmp:rw,size=64m \
  --cap-drop ALL --security-opt no-new-privileges --user 10001:10001 \
  -v "$MRH:/opt/mrh:ro" -v "$PWD:/opt/fixture:ro" -v "$PWD/inputs:/opt/inputs:ro" -v "$OUT:/out" \
  -w /out q2-croa-run:v0.1 \
  python -m q2fixture --out /out --finance-payload /opt/inputs/finance_ai_report_payload.json
```

`$MRH` is a harness checkout at the commit above and `$OUT` an empty directory. Later harness commits refuse the OBS-2 delivery, so OBS-2 reproduces only at that commit.

## Differences from the code that was executed

Text was changed in three files for this copy. No control logic changed, and a replay of this copy gave the same 50 decisions as the original run:

- `q2fixture/model.py`: the module docstring and one comment no longer use internal names.
- `q2fixture/payloads.py`: the `source` label of the synthetic control payload now reads "evaluation team". The digests of the control payloads therefore differ from those of the original run.
- `inputs/finance_ai_report_payload.json`: the provenance block was removed. Its digest therefore differs from the one in the adjudication; the report fields are unchanged.

The driver script of the original run is omitted because it contained local paths. The commands above replace it.
