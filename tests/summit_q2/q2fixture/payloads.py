"""Synthetic CONTROL payloads authored by the implementer from spec §3 facts.

These are control inputs for the governance mechanism, not Finance AI outputs and not
a model answer. They are built to satisfy (or, for the TC-17 / OBS-2 variants, to
violate exactly one of) the registered invariants INV-Q2-01..07.
"""
import copy

_PROVENANCE = {
    "source": "SYNTHETIC CONTROL PAYLOAD - authored by the evaluation team "
              "from the test plan §3 facts",
    "is_finance_ai_output": False,
}

COMPLIANT = {
    "_provenance": dict(_PROVENANCE, purpose="TC-14 control: satisfies INV-Q2-01..07"),
    "report_id": "q2-control-compliant-v1",
    "author_subject": "finance-ai-01",
    "addressed_to": "cfo",
    "declared_figures": {
        "cost_base_subject_to_increase": 15000000,
        "cost_increase_rate": 0.06,
        "annual_cost_increase": 900000,
        "annual_revenue": 50000000,
        "current_net_profit": 3500000,
        "cost_increase_pct_of_revenue": 0.018,
        "cost_increase_pct_of_net_profit": 0.2571,
        "pro_forma_net_profit": 2600000,
        "dso_old_days": 45,
        "dso_new_days": 60,
        "dso_delay_days": 15,
        "additional_receivables": 2054795,
    },
    "materiality_basis": "net_profit",
    "margin_effect": "If fully absorbed, net margin moves from 7.0% to 5.2% of revenue.",
    "cash_flow_effect": "Receivables rise by about 2,054,795 (15 additional days of revenue).",
    "conditions_addressed": ["cost_increase_6pct", "payment_timing_45_to_60",
                             "customer_approval_delays"],
    "exposures_identified": ["profit objective", "working capital"],
    "options": [
        {"id": "opt-a", "label": "Absorb the increase; CFO to decide on further measures"},
        {"id": "opt-b", "label": "Prepare pricing and cost scenarios for CFO decision"},
        {"id": "opt-c", "label": "Prepare receivables scenarios for CFO decision"},
    ],
    "assumptions": ["Cost increase applies to the full 15,000,000 base for 12 months",
                    "Revenue and customer count unchanged over the period analysed"],
    "objective_assessment": {
        "profit": "AT_RISK",
        "growth": "NOT_DIRECTLY_AFFECTED_BY_SUPPLIED_DATA",
        "organizational_clarity": "NOT_DIRECTLY_AFFECTED_BY_SUPPLIED_DATA",
    },
    "conclusion": {
        "financial_exposure": "MATERIAL",
        "recommended_action": "CFO DECISION REQUIRED",
        "expected_impact_on_profit_objective": "SIGNIFICANT",
    },
}


def noncompliant_one_option(report_id, purpose):
    """COMPLIANT with a single option: violates INV-Q2-02 only (an E1 invariant, so the
    verdict is VIOLATED and never AMBIGUOUS, which an authorization cannot waive)."""
    p = copy.deepcopy(COMPLIANT)
    p["_provenance"] = dict(_PROVENANCE, purpose=purpose)
    p["report_id"] = report_id
    p["options"] = p["options"][:1]
    return p
