from typing import Dict, Tuple

FEDERATED_CONTEXT_REGISTRY = {
    "financial_analysis_store": "analysis_store",
    "pricing_system": "operational_system"
}

ACTION_TARGET_TYPES = {
    "submit_financial_analysis": "analysis_store",
    "update_customer_pricing": "operational_system"
}

def resolve_target(action: str, target: str) -> Tuple[bool, str]:
    if target not in FEDERATED_CONTEXT_REGISTRY:
        return False, "TARGET_NOT_REGISTERED"
    
    expected_type = ACTION_TARGET_TYPES.get(action)
    actual_type = FEDERATED_CONTEXT_REGISTRY[target]
    
    if expected_type and actual_type != expected_type:
        return False, "TARGET_TYPE_MISMATCH"
        
    return True, "GROUNDED"
