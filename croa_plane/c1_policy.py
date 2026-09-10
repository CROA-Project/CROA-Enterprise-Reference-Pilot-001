from typing import List, Dict, Any, Optional

INVARIANT_SET_VERSION = "pilot-policy-set-v1"

POLICIES = [
    {
        "policy_id": "POLICY-001",
        "description": "get_customer is allowed for registered customer targets",
        "action": "get_customer",
        "target_prefix": "customer:",
        "effect": "PERMIT"
    },
    {
        "policy_id": "POLICY-002",
        "description": "export_customers is allowed for the registered analytics endpoint",
        "action": "export_customers",
        "target": "endpoint:analytics.internal",
        "effect": "PERMIT"
    },
    {
        "policy_id": "POLICY-003",
        "description": "change_config is allowed for environment:dev",
        "action": "change_config",
        "target": "environment:dev",
        "effect": "PERMIT"
    },
    {
        "policy_id": "POLICY-004",
        "description": "change_config is denied for environment:prod",
        "action": "change_config",
        "target": "environment:prod",
        "effect": "DENY"
    },
    {
        "policy_id": "POLICY-005",
        "description": "deploy_service is allowed for service:billing and service:notifications",
        "action": "deploy_service",
        "target_in": ["service:billing", "service:notifications"],
        "effect": "PERMIT"
    },
    {
        "policy_id": "POLICY-006",
        "description": "delete_environment is always denied",
        "action": "delete_environment",
        "effect": "DENY"
    }
]

INVARIANTS = [
    {
        "invariant_id": "INVARIANT-TRAJ-001",
        "name": "Maximum Customer Export Per Session",
        "description": "Limits the total number of customer records exported in a single session",
        "profile": "TP-C",
        "action": "export_customers",
        "accumulation_parameter": "count",
        "limit": 100,
        "scope": "session_subject",
        "version": "1"
    }
]

def evaluate_policy(action: str, target: str) -> Optional[Dict[str, Any]]:
    for p in POLICIES:
        if p["action"] == action:
            match = True
            if "target" in p and p["target"] != target:
                match = False
            if "target_prefix" in p and not target.startswith(p["target_prefix"]):
                match = False
            if "target_in" in p and target not in p["target_in"]:
                match = False
            if match:
                return p
    return None
