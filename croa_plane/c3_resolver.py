from typing import Dict, Tuple

FEDERATED_CONTEXT_REGISTRY = {
    "customer:342": "customer",
    "customer:871": "customer",
    "service:billing": "service",
    "service:notifications": "service",
    "environment:dev": "environment",
    "environment:prod": "environment",
    "endpoint:analytics.internal": "endpoint"
}

ACTION_TARGET_TYPES = {
    "get_customer": "customer",
    "export_customers": "endpoint",
    "change_config": "environment",
    "deploy_service": "service",
    "delete_environment": "environment"
}

def resolve_target(action: str, target: str) -> Tuple[bool, str]:
    if target not in FEDERATED_CONTEXT_REGISTRY:
        return False, "TARGET_NOT_REGISTERED"
    
    expected_type = ACTION_TARGET_TYPES.get(action)
    actual_type = FEDERATED_CONTEXT_REGISTRY[target]
    
    if expected_type and actual_type != expected_type:
        return False, "TARGET_TYPE_MISMATCH"
        
    return True, "GROUNDED"
