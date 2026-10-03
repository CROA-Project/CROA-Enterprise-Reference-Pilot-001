from typing import List, Dict, Any, Optional

INVARIANT_SET_VERSION = "pilot-policy-set-v1"

POLICIES = [
    {
        "policy_id": "CFO-AI-Delegation-v1",
        "description": "Finance AI is authorized to submit financial analysis",
        "action": "submit_financial_analysis",
        "target": "financial_analysis_store",
        "effect": "PERMIT"
    },
    {
        "policy_id": "CFO-AI-Delegation-v1-DenyPricing",
        "description": "Finance AI is explicitly denied from changing customer pricing",
        "action": "update_customer_pricing",
        "target": "pricing_system",
        "effect": "DENY"
    }
]

INVARIANTS = []

def evaluate_policy(action: str, target: str) -> Optional[Dict[str, Any]]:
    for p in POLICIES:
        if p["action"] == action and p["target"] == target:
            return p
    return None
