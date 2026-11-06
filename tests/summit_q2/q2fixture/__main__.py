"""Entry point: python -m q2fixture --out <run dir> --finance-payload <json>

Runs TC-01..TC-18 (+ OBS-1, OBS-2) in one process against one MRH Harness and writes
c5_log.jsonl, results.json, decision_trace.json, env.json and verify_output.json.
Exit code 0 iff every scored case in this run passed.
"""
import argparse
import json
import os
import sys

from . import __version__
from .cases import Run, environment


def main(argv=None):
    p = argparse.ArgumentParser(prog="q2fixture")
    p.add_argument("--out", required=True)
    p.add_argument("--finance-payload", required=True)
    args = p.parse_args(argv)
    os.makedirs(args.out, exist_ok=True)

    env = dict(environment(), fixture_version=__version__)
    with open(os.path.join(args.out, "env.json"), "w", encoding="utf-8") as fh:
        json.dump(env, fh, indent=2)
    print("q2fixture %s | mrh %s at %s" % (__version__, env["mrh_version"], env["mrh_file"]))
    print("network interfaces: %s" % env["network_interfaces"])
    print("-" * 72)

    run = Run(args.out, args.finance_payload)
    results = run.run()

    with open(os.path.join(args.out, "results.json"), "w", encoding="utf-8") as fh:
        json.dump({"results": results, "payload_hashes": run.payload_hashes}, fh, indent=2,
                  default=str)
    with open(os.path.join(args.out, "decision_trace.json"), "w", encoding="utf-8") as fh:
        json.dump(run.trace, fh, indent=1, sort_keys=True)

    scored = [r for r in results if r["scored"]]
    passed = sum(r["status"] == "PASS" for r in scored)
    print("-" * 72)
    print("%d/%d scored cases passed in this run (TC-01..TC-18); %d C5 events"
          % (passed, len(scored), len(run.h.c5.events)))
    return 0 if passed == len(scored) else 1


if __name__ == "__main__":
    sys.exit(main())
