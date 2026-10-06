"""
CROA Reference Harness — C2 Governor Engine
Normative Reference: CROA Framework v1.0.1 §4.3 / §4.4 / §4.6

Evaluates requests across admission parameters, governed exception artifacts,
policy rules, and trajectory limits.
"""

from typing import Dict, Any
from datetime import datetime, timezone
from c1_policy import evaluate_policy, INVARIANT_SET_VERSION, validate_action_parameters, verify_authorization_artifact
from c4_trajectory import evaluate_trajectory
from c5_evidence import record_event

def evaluate_request(request_data: Dict[str, Any]) -> Dict[str, Any]:
    req_id = request_data.get("request_id")
    subject = request_data.get("subject")
    action = request_data.get("action")
    target = request_data.get("target")
    session_id = request_data.get("session_id")
    parameters = request_data.get("parameters", {})
    auth_artifact = request_data.get("authorization_artifact")
    
    timestamp = datetime.now(timezone.utc).isoformat()

    # Defense-in-depth: Strict parameter contract check
    is_valid_param, param_reason = validate_action_parameters(action, parameters)
    if not is_valid_param:
        record_event(req_id, session_id, subject, action, target, "DENY", "DENY", param_reason, "C2", None, INVARIANT_SET_VERSION)
        return {"request_id": req_id, "subject": subject, "action": action, "target": target, "decision": "DENY", "reason": param_reason, "decision_stage": "C2", "policy_id": None, "invariant_set_version": INVARIANT_SET_VERSION, "timestamp": timestamp}

    # Governed Exception Path (§4.3.1 / §4.4.1)
    if auth_artifact:
        is_valid_auth, auth_reason, exception_scope = verify_authorization_artifact(
            auth_artifact, subject, action, target, parameters
        )
        if not is_valid_auth:
            record_event(req_id, session_id, subject, action, target, "DENY", "DENY", auth_reason, "C2", None, INVARIANT_SET_VERSION)
            return {"request_id": req_id, "subject": subject, "action": action, "target": target, "decision": "DENY", "reason": auth_reason, "decision_stage": "C2", "policy_id": None, "invariant_set_version": INVARIANT_SET_VERSION, "timestamp": timestamp}
        
        # Valid C1 Authorization Artifact waives registered invariant within bounded exception scope
        exception_policy_id = f"EXCEPTION:{auth_artifact['invariant_reference']}"

        record_event(req_id, session_id, subject, action, target, "PERMIT_WITH_AUTHORIZATION", "PERMIT", "POLICY_ALLOWED_UNDER_AUTHORIZATION", "C2", exception_policy_id, INVARIANT_SET_VERSION)
        return {
            "request_id": req_id,
            "subject": subject,
            "action": action,
            "target": target,
            "decision": "PERMIT_WITH_AUTHORIZATION",
            "reason": "POLICY_ALLOWED_UNDER_AUTHORIZATION",
            "decision_stage": "C2",
            "policy_id": exception_policy_id,
            "invariant_set_version": INVARIANT_SET_VERSION,
            "timestamp": timestamp,
            "auth_id": auth_artifact["auth_id"],
            "exception_scope": exception_scope
        }

    policy_match = evaluate_policy(action, target)
    
    if not policy_match:
        record_event(req_id, session_id, subject, action, target, "DENY", "DENY", "NO_POLICY_MATCH", "C2", None, INVARIANT_SET_VERSION)
        return {"request_id": req_id, "subject": subject, "action": action, "target": target, "decision": "DENY", "reason": "NO_POLICY_MATCH", "decision_stage": "C2", "policy_id": None, "invariant_set_version": INVARIANT_SET_VERSION, "timestamp": timestamp}
        
    if policy_match["effect"] == "DENY":
        record_event(req_id, session_id, subject, action, target, "DENY", "DENY", "POLICY_DENIED", "C2", policy_match["policy_id"], INVARIANT_SET_VERSION)
        return {"request_id": req_id, "subject": subject, "action": action, "target": target, "decision": "DENY", "reason": "POLICY_DENIED", "decision_stage": "C2", "policy_id": policy_match["policy_id"], "invariant_set_version": INVARIANT_SET_VERSION, "timestamp": timestamp}
        
    c4_decision, c4_data = evaluate_trajectory(session_id, subject, action, parameters, target)
    
    if c4_decision == "DENY":
        reason = c4_data.get("reason")
        if reason in ("INVALID_ACCUMULATION_PARAMETER", "INVALID_ACCUMULATION_DIMENSION"):
            record_event(req_id, session_id, subject, action, target, "DENY", "DENY", reason, "C4", policy_match["policy_id"], INVARIANT_SET_VERSION)
            return {"request_id": req_id, "subject": subject, "action": action, "target": target, "decision": "DENY", "reason": reason, "decision_stage": "C4", "policy_id": policy_match["policy_id"], "invariant_set_version": INVARIANT_SET_VERSION, "timestamp": timestamp}
        else:
            record_event(req_id, session_id, subject, action, target, "TRAJECTORY_ALERT", "DENY", reason, "C4", policy_match["policy_id"], INVARIANT_SET_VERSION, c4_data)
            record_event(req_id, session_id, subject, action, target, "DENY", "DENY", reason, "C4", policy_match["policy_id"], INVARIANT_SET_VERSION, c4_data)
            resp = {"request_id": req_id, "subject": subject, "action": action, "target": target, "decision": "DENY", "reason": reason, "decision_stage": "C4", "policy_id": policy_match["policy_id"], "invariant_set_version": INVARIANT_SET_VERSION, "timestamp": timestamp}
            for k, v in c4_data.items():
                resp[k] = v
            return resp
            
    if c4_data:
        record_event(req_id, session_id, subject, action, target, "TRAJECTORY_CHECK", "PERMIT", "TRAJECTORY_ALLOWED", "C4", policy_match["policy_id"], INVARIANT_SET_VERSION, c4_data)

    record_event(req_id, session_id, subject, action, target, "PERMIT", "PERMIT", "POLICY_ALLOWED", "C2", policy_match["policy_id"], INVARIANT_SET_VERSION)
    
    resp = {"request_id": req_id, "subject": subject, "action": action, "target": target, "decision": "PERMIT", "reason": "POLICY_ALLOWED", "decision_stage": "C2", "policy_id": policy_match["policy_id"], "invariant_set_version": INVARIANT_SET_VERSION, "timestamp": timestamp}
    if c4_data:
        for k, v in c4_data.items():
            resp[k] = v
    return resp
