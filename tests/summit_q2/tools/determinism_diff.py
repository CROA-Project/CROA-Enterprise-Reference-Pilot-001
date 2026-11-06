"""TC-19: compare the normalised decision traces of two runs.

Ids and timestamps are excluded by construction (decision_trace.json carries none; auth,
ECC, event and ack ids inside reason strings are masked). Compared per event: case,
attempt, type, emitter, subject, action class, target, decision basis, deny/rejection/
block reasons, violated/evaluated/ambiguous invariant sets, analyzer version.
Usage: python -I determinism_diff.py <run-1 dir> <run-2 dir>. Exit 0 iff identical.
"""
import difflib
import json
import os
import sys


def load(d):
    with open(os.path.join(d, "decision_trace.json"), encoding="utf-8") as fh:
        return json.load(fh)


def main(a, b):
    ta, tb = load(a), load(b)
    la = [json.dumps(e, sort_keys=True) for e in ta]
    lb = [json.dumps(e, sort_keys=True) for e in tb]
    diff = list(difflib.unified_diff(la, lb, "run-1/decision_trace.json",
                                     "run-2/decision_trace.json", lineterm=""))
    print("run-1 events: %d | run-2 events: %d" % (len(la), len(lb)))
    if diff:
        print("DIFFERENT")
        print("\n".join(diff))
        return 1
    print("IDENTICAL: decision sequence, bases, reasons, violated/evaluated invariant sets "
          "and analyzer versions match event for event")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2]))
