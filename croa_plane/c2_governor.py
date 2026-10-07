"""
CROA Reference Harness — C2 Execution Governor
Normative Reference: CROA Framework v1.0.1 §4.3 Governor / §4.6 Trajectory / §4.9 Admission

Orchestrates access decisions:
1. Evaluates governed Authorization Artifact exceptions (§4.3 / §4.9).
2. Evaluates static policy definitions (C1).
3. Evaluates and commits trajectory accumulation atomically (C4).
Logs all governance decisions to tamper-evident evidence log (C5).
"""

from __future__ import annotations

from typing import Dict, Any, Optional
from c1_policy import INVARIANT_SET_VERSION, evaluate_policy, validate_action_parameters, verify_authorization_artifact
from c4_trajectory import evaluate_trajectory
from c5_evidence import record_event, utc_now_iso


def _response(req: Dict[str, Any], decision: str, reason: str, stage: str, policy_id: Optional[str]) -> Dict[str, Any]:
    return {
        "request_id": req.get("request_id"),
        "session_id": req.get("session_id"),
        "subject": req.get("subject"),
        "action": req.get("action"),
        "target": req.get("target"),
        "decision": decision,
        "reason": reason,
        "decision_stage": stage,
        "policy_id": policy_id,
        "invariant_set_version": INVARIANT_SET_VERSION,
        "timestamp": utc_now_iso(),
    }


def evaluate_request(request_data: Dict[str, Any]) -> Dict[str, Any]:
    req_id = request_data.get("request_id")
    subject = request_data.get("subject")
    action = request_data.get("action")
    target = request_data.get("target")
    session_id = request_data.get("session_id")
    parameters = request_data.get("parameters") or {}

    # Check for Governed Authorization Artifact (CROA §4.3 / §4.9)
    auth_artifact = request_data.get("authorization_artifact")
    if auth_artifact:
        is_valid_auth, auth_reason, exception_scope = verify_authorization_artifact(
            auth_artifact, subject, action, target, parameters
        )
        if not is_valid_auth:
            record_event(req_id, session_id, subject, action, target, "DENY", "DENY", auth_reason, "C2", None, INVARIANT_SET_VERSION)
            return _response(request_data, "DENY", auth_reason, "C2", None)

        # Valid C1 Authorization Artifact waives registered invariant within bounded exception scope
        # Invariant reference is strictly required; no fallback to auth_id
        inv_ref = auth_artifact.get("invariant_reference")
        exception_policy_id = f"EXCEPTION:{inv_ref}"

        record_event(req_id, session_id, subject, action, target, "PERMIT_WITH_AUTHORIZATION", "PERMIT", "POLICY_ALLOWED_UNDER_AUTHORIZATION", "C2", exception_policy_id, INVARIANT_SET_VERSION)
        resp = _response(request_data, "PERMIT_WITH_AUTHORIZATION", "POLICY_ALLOWED_UNDER_AUTHORIZATION", "C2", exception_policy_id)
        resp["auth_id"] = auth_artifact["auth_id"]
        resp["exception_scope"] = exception_scope
        return resp

    policy_match = evaluate_policy(action, target)

    if not policy_match:
        record_event(req_id, session_id, subject, action, target, "DENY", "DENY", "NO_POLICY_MATCH", "C2", None, INVARIANT_SET_VERSION)
        return _response(request_data, "DENY", "NO_POLICY_MATCH", "C2", None)

    policy_id = policy_match["policy_id"]
    if policy_match["effect"] == "DENY":
        record_event(req_id, session_id, subject, action, target, "DENY", "DENY", "POLICY_DENIED", "C2", policy_id, INVARIANT_SET_VERSION)
        return _response(request_data, "DENY", "POLICY_DENIED", "C2", policy_id)

    # Parameter admission contract check (CROA §4.5.1 / §4.9.1)
    is_valid_param, param_reason = validate_action_parameters(action, parameters)
    if not is_valid_param:
        record_event(req_id, session_id, subject, action, target, "DENY", "DENY", param_reason, "AGENT_SURFACE_ADMISSION", policy_id, INVARIANT_SET_VERSION)
        return _response(request_data, "DENY", param_reason, "AGENT_SURFACE_ADMISSION", policy_id)

    # C4: evaluate-and-reserve is a single atomic step (see c4_trajectory.evaluate_trajectory).
    c4_decision, c4_data = evaluate_trajectory(session_id, subject, action, parameters, target)

    if c4_decision == "DENY":
        reason = c4_data.get("reason") if c4_data else "TRAJECTORY_LIMIT_EXCEEDED"
        if reason in ("INVALID_ACCUMULATION_PARAMETER", "INVALID_ACCUMULATION_DIMENSION"):
            record_event(req_id, session_id, subject, action, target, "DENY", "DENY", reason, "C4", policy_id, INVARIANT_SET_VERSION)
            resp = _response(request_data, "DENY", reason, "C4", policy_id)
            if c4_data:
                resp.update(c4_data)
            return resp

        record_event(
            req_id, session_id, subject, action, target, "TRAJECTORY_ALERT", "DENY", reason, "C4", policy_id, INVARIANT_SET_VERSION, c4_data
        )
        record_event(req_id, session_id, subject, action, target, "DENY", "DENY", reason, "C4", policy_id, INVARIANT_SET_VERSION, c4_data)
        resp = _response(request_data, "DENY", reason, "C4", policy_id)
        if c4_data:
            resp.update(c4_data)
        return resp

    if c4_data:
        record_event(
            req_id,
            session_id,
            subject,
            action,
            target,
            "TRAJECTORY_CHECK",
            "PERMIT",
            "TRAJECTORY_ALLOWED",
            "C4",
            policy_id,
            INVARIANT_SET_VERSION,
            c4_data,
        )

    record_event(req_id, session_id, subject, action, target, "PERMIT", "PERMIT", "POLICY_ALLOWED", "C2", policy_id, INVARIANT_SET_VERSION)

    resp = _response(request_data, "PERMIT", "POLICY_ALLOWED", "C2", policy_id)
    if c4_data:
        resp.update(c4_data)
    return resp
