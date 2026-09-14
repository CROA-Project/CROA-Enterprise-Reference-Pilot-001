from typing import Dict, Any, Tuple, Optional
from c1_policy import INVARIANTS

trajectory_state: Dict[str, Dict[str, int]] = {}

def get_trajectory_state(session_subject_key: str, inv_id: str) -> int:
    return trajectory_state.get(session_subject_key, {}).get(inv_id, 0)

def evaluate_trajectory(session_id: str, subject: str, action: str, parameters: Dict[str, Any]) -> Tuple[str, Optional[Dict[str, Any]]]:
    applicable_invariants = [inv for inv in INVARIANTS if inv["action"] == action]
    
    if not applicable_invariants:
        return "PERMIT", None
        
    session_subject_key = f"{session_id}:{subject}"
        
    for inv in applicable_invariants:
        inv_id = inv["invariant_id"]
        limit = inv["limit"]
        param_name = inv["accumulation_parameter"]
        
        if param_name not in parameters:
            return "DENY", {"reason": "INVALID_ACCUMULATION_PARAMETER"}
            
        count_val = parameters[param_name]
        if type(count_val) is not int or count_val <= 0:
            return "DENY", {"reason": "INVALID_ACCUMULATION_PARAMETER"}
            
        current = get_trajectory_state(session_subject_key, inv_id)
        projected = current + count_val
        
        result_data = {
            "invariant_id": inv_id,
            "profile": inv["profile"],
            "current_value": current,
            "requested_increment": count_val,
            "projected_value": projected,
            "limit": limit
        }
        
        if projected > limit:
            result_data["trajectory_decision"] = "DENY"
            result_data["reason"] = "TRAJECTORY_LIMIT_EXCEEDED"
            return "DENY", result_data
            
        result_data["trajectory_decision"] = "ALLOW"
        return "PERMIT", result_data
        
    return "PERMIT", None

def commit_trajectory(session_id: str, subject: str, inv_id: str, increment: int):
    session_subject_key = f"{session_id}:{subject}"
    if session_subject_key not in trajectory_state:
        trajectory_state[session_subject_key] = {}
    if inv_id not in trajectory_state[session_subject_key]:
        trajectory_state[session_subject_key][inv_id] = 0
    trajectory_state[session_subject_key][inv_id] += increment
