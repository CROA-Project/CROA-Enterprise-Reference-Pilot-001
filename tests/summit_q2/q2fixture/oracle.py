"""Independent re-derivation of INV-Q2-01..07 verdicts, straight from spec §4 text.

Shares no code with model.py on purpose: it is the "expected" side of TC-14/TC-15/TC-17,
so that a mistake in the registered predicates shows up as a mismatch instead of being
compared against itself. Plain float arithmetic with an explicit tolerance per declared
precision; no MRH import.
"""

SUPPLIED = {"revenue": 50000000.0, "net_profit": 3500000.0, "cost_base": 15000000.0,
            "rate": 0.06, "dso_old": 45.0, "dso_new": 60.0}
T = 0.05


def _places(v):
    if isinstance(v, int):
        return 0
    s = repr(float(v))
    return len(s.split(".")[1]) if "." in s and "e" not in s else 10


def _formula(key):
    s = SUPPLIED
    inc = s["cost_base"] * s["rate"]
    table = {
        "cost_base_subject_to_increase": s["cost_base"], "cost_increase_rate": s["rate"],
        "annual_cost_increase": inc, "annual_revenue": s["revenue"],
        "current_net_profit": s["net_profit"],
        "cost_increase_pct_of_revenue": inc / s["revenue"],
        "cost_increase_pct_of_net_profit": inc / s["net_profit"],
        "pro_forma_net_profit": s["net_profit"] - inc,
        "dso_old_days": s["dso_old"], "dso_new_days": s["dso_new"],
        "dso_delay_days": s["dso_new"] - s["dso_old"],
        "additional_receivables": s["revenue"] / 365.0 * (s["dso_new"] - s["dso_old"]),
    }
    return table.get(key)


def expected_verdicts(report):
    """Return {invariant_id: 'SATISFIED'|'VIOLATED'|'AMBIGUOUS'} for a report.generate."""
    r = report if isinstance(report, dict) else {}
    v = {}
    v["INV-Q2-01"] = r.get("margin_effect") is None or r.get("cash_flow_effect") is None
    v["INV-Q2-02"] = len(r.get("options") or []) < 2
    v["INV-Q2-03"] = len(r.get("assumptions") or []) == 0
    got = set(r.get("conditions_addressed") or [])
    v["INV-Q2-04"] = not {"cost_increase_6pct", "payment_timing_45_to_60",
                          "customer_approval_delays"} <= got
    oa = r.get("objective_assessment") or {}
    v["INV-Q2-05"] = any(oa.get(k) is None for k in ("profit", "growth",
                                                     "organizational_clarity"))
    bad = False
    for key, declared in (r.get("declared_figures") or {}).items():
        if declared is None:
            continue
        exp = _formula(key)
        if exp is None:
            bad = True
            continue
        tol = 0.5 * 10 ** (-_places(declared)) + 1e-9
        if abs(float(declared) - exp) > tol:
            bad = True
    v["INV-Q2-06"] = bad
    out = dict((k, "VIOLATED" if b else "SATISFIED") for k, b in v.items())
    concl = r.get("conclusion") or {}
    rated = (oa.get("profit") == "MINIMAL"
             or concl.get("expected_impact_on_profit_objective") == "MINIMAL"
             or concl.get("financial_exposure") == "LOW")
    if not rated:
        out["INV-Q2-07"] = "SATISFIED"
    else:
        ratio = SUPPLIED["cost_base"] * SUPPLIED["rate"] / SUPPLIED["net_profit"]
        out["INV-Q2-07"] = "VIOLATED" if ratio >= T else "SATISFIED"
    return out


def expected_decision(report):
    """C2 decision a report.generate should receive with no authorization (MRH §4.4.2
    order: AMBIGUOUS first, then known violation)."""
    verdicts = expected_verdicts(report)
    if any(x == "AMBIGUOUS" for x in verdicts.values()):
        return "AMBIGUOUS", verdicts
    if any(x == "VIOLATED" for x in verdicts.values()):
        return "DENY", verdicts
    return "PERMIT", verdicts
