"""C2 — Execution Governor: static policy (C1) then trajectory reservation (C4)."""

from __future__ import annotations

from typing import Any

from c1_policy import INVARIANT_SET_VERSION, evaluate_policy
from c4_trajectory import reserve_trajectory
from c5_evidence import record_event, utc_now_iso


def _response(req: dict[str, Any], decision: str, reason: str, stage: str, policy_id: str | None) -> dict[str, Any]:
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


def evaluate_request(request_data: dict[str, Any]) -> dict[str, Any]:
    req_id = request_data.get("request_id")
    subject = request_data.get("subject")
    action = request_data.get("action")
    target = request_data.get("target")
    session_id = request_data.get("session_id")
    parameters = request_data.get("parameters") or {}

    policy_match = evaluate_policy(action, target)

    if not policy_match:
        record_event(req_id, session_id, subject, action, target, "DENY", "DENY", "NO_POLICY_MATCH", "C2", None, INVARIANT_SET_VERSION)
        return _response(request_data, "DENY", "NO_POLICY_MATCH", "C2", None)

    policy_id = policy_match["policy_id"]
    if policy_match["effect"] == "DENY":
        record_event(req_id, session_id, subject, action, target, "DENY", "DENY", "POLICY_DENIED", "C2", policy_id, INVARIANT_SET_VERSION)
        return _response(request_data, "DENY", "POLICY_DENIED", "C2", policy_id)

    # C4: evaluate-and-reserve is a single atomic step (see c4_trajectory.reserve_trajectory).
    c4_decision, c4_data = reserve_trajectory(session_id, subject, action, parameters)

    if c4_decision == "DENY":
        reason = c4_data.get("reason")
        if reason == "INVALID_ACCUMULATION_PARAMETER":
            record_event(req_id, session_id, subject, action, target, "DENY", "DENY", reason, "C4", policy_id, INVARIANT_SET_VERSION)
            return _response(request_data, "DENY", reason, "C4", policy_id)
        record_event(
            req_id, session_id, subject, action, target, "TRAJECTORY_ALERT", "DENY", reason, "C4", policy_id, INVARIANT_SET_VERSION, c4_data
        )
        record_event(req_id, session_id, subject, action, target, "DENY", "DENY", reason, "C4", policy_id, INVARIANT_SET_VERSION, c4_data)
        resp = _response(request_data, "DENY", reason, "C4", policy_id)
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
