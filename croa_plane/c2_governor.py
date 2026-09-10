from typing import Dict, Any
from datetime import datetime
from c1_policy import evaluate_policy, INVARIANT_SET_VERSION
from c4_trajectory import evaluate_trajectory, commit_trajectory
from c5_evidence import record_event

def evaluate_request(request_data: Dict[str, Any]) -> Dict[str, Any]:
    req_id = request_data.get("request_id")
    subject = request_data.get("subject")
    action = request_data.get("action")
    target = request_data.get("target")
    session_id = request_data.get("session_id")
    parameters = request_data.get("parameters", {})
    
    timestamp = datetime.utcnow().isoformat() + "Z"
    policy_match = evaluate_policy(action, target)
    
    if not policy_match:
        record_event(req_id, session_id, subject, action, target, "DENY", "DENY", "NO_POLICY_MATCH", "C2", None, INVARIANT_SET_VERSION)
        return {"request_id": req_id, "subject": subject, "action": action, "target": target, "decision": "DENY", "reason": "NO_POLICY_MATCH", "decision_stage": "C2", "policy_id": None, "invariant_set_version": INVARIANT_SET_VERSION, "timestamp": timestamp}
        
    if policy_match["effect"] == "DENY":
        record_event(req_id, session_id, subject, action, target, "DENY", "DENY", "POLICY_DENIED", "C2", policy_match["policy_id"], INVARIANT_SET_VERSION)
        return {"request_id": req_id, "subject": subject, "action": action, "target": target, "decision": "DENY", "reason": "POLICY_DENIED", "decision_stage": "C2", "policy_id": policy_match["policy_id"], "invariant_set_version": INVARIANT_SET_VERSION, "timestamp": timestamp}
        
    # Static allowed, now evaluate trajectory
    c4_decision, c4_data = evaluate_trajectory(session_id, subject, action, parameters)
    
    if c4_decision == "DENY":
        reason = c4_data.get("reason")
        if reason == "INVALID_ACCUMULATION_PARAMETER":
            record_event(req_id, session_id, subject, action, target, "DENY", "DENY", reason, "C4", policy_match["policy_id"], INVARIANT_SET_VERSION)
            return {"request_id": req_id, "subject": subject, "action": action, "target": target, "decision": "DENY", "reason": reason, "decision_stage": "C4", "policy_id": policy_match["policy_id"], "invariant_set_version": INVARIANT_SET_VERSION, "timestamp": timestamp}
        else:
            # TRAJECTORY_ALERT
            record_event(req_id, session_id, subject, action, target, "TRAJECTORY_ALERT", "DENY", reason, "C4", policy_match["policy_id"], INVARIANT_SET_VERSION, c4_data)
            # DENY
            record_event(req_id, session_id, subject, action, target, "DENY", "DENY", reason, "C4", policy_match["policy_id"], INVARIANT_SET_VERSION, c4_data)
            resp = {"request_id": req_id, "subject": subject, "action": action, "target": target, "decision": "DENY", "reason": reason, "decision_stage": "C4", "policy_id": policy_match["policy_id"], "invariant_set_version": INVARIANT_SET_VERSION, "timestamp": timestamp}
            # Append C4 data to response for assertions
            for k, v in c4_data.items():
                resp[k] = v
            return resp
            
    if c4_data:
        commit_trajectory(session_id, c4_data["invariant_id"], c4_data["requested_increment"])
        record_event(req_id, session_id, subject, action, target, "TRAJECTORY_CHECK", "PERMIT", "TRAJECTORY_ALLOWED", "C4", policy_match["policy_id"], INVARIANT_SET_VERSION, c4_data)

    # Final C2 PERMIT
    record_event(req_id, session_id, subject, action, target, "PERMIT", "PERMIT", "POLICY_ALLOWED", "C2", policy_match["policy_id"], INVARIANT_SET_VERSION)
    
    resp = {"request_id": req_id, "subject": subject, "action": action, "target": target, "decision": "PERMIT", "reason": "POLICY_ALLOWED", "decision_stage": "C2", "policy_id": policy_match["policy_id"], "invariant_set_version": INVARIANT_SET_VERSION, "timestamp": timestamp}
    if c4_data:
        for k, v in c4_data.items():
            resp[k] = v
    return resp
