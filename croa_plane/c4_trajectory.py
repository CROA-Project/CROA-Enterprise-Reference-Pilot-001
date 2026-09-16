"""C4 — Trajectory Invariants.

Cumulative-authority enforcement. The pilot keeps trajectory state in process
memory (documented limitation); what this module guarantees is that, within
one process, the check of the current state and the commit of the projected
state happen as ONE atomic step under a lock, and that every invariant that
applies to an action is evaluated and committed together (all-or-nothing).
"""

from __future__ import annotations

import threading
from typing import Any

from c1_policy import INVARIANTS

# session_subject_key -> invariant_id -> accumulated value
trajectory_state: dict[str, dict[str, int]] = {}
_state_lock = threading.Lock()


def get_trajectory_state(session_subject_key: str, inv_id: str) -> int:
    with _state_lock:
        return trajectory_state.get(session_subject_key, {}).get(inv_id, 0)


def reset_trajectory_state() -> None:
    with _state_lock:
        trajectory_state.clear()


def _validate_increment(parameters: dict[str, Any], param_name: str) -> int | None:
    if param_name not in parameters:
        return None
    value = parameters[param_name]
    # bool is a subclass of int; reject it explicitly. Floats are rejected too:
    # the accumulation parameter must be a positive integer.
    if type(value) is not int or value <= 0:
        return None
    return value


def reserve_trajectory(session_id: str, subject: str, action: str, parameters: dict[str, Any]) -> tuple[str, dict[str, Any] | None]:
    """Evaluate every applicable invariant and, if all pass, commit them atomically.

    Returns ("PERMIT", data) or ("DENY", data). `data` is None when no invariant
    applies. On PERMIT the budget has already been reserved when this returns —
    there is no separate commit step for callers to forget or reorder.
    """
    applicable = [inv for inv in INVARIANTS if inv["action"] == action]
    if not applicable:
        return "PERMIT", None

    key = f"{session_id}:{subject}"

    with _state_lock:
        per_session = trajectory_state.setdefault(key, {})
        evaluations: list[dict[str, Any]] = []
        for inv in applicable:
            inv_id = inv["invariant_id"]
            increment = _validate_increment(parameters, inv["accumulation_parameter"])
            if increment is None:
                return "DENY", {"reason": "INVALID_ACCUMULATION_PARAMETER", "invariant_id": inv_id}
            current = per_session.get(inv_id, 0)
            projected = current + increment
            evaluations.append(
                {
                    "invariant_id": inv_id,
                    "profile": inv["profile"],
                    "current_value": current,
                    "requested_increment": increment,
                    "projected_value": projected,
                    "limit": inv["limit"],
                    "trajectory_decision": "DENY" if projected > inv["limit"] else "ALLOW",
                }
            )

        denied = [e for e in evaluations if e["trajectory_decision"] == "DENY"]
        # Top-level fields mirror the first (or first denied) invariant so the existing
        # API/evidence shape is preserved; `invariants` carries the full set.
        primary = denied[0] if denied else evaluations[0]
        result: dict[str, Any] = dict(primary)
        result["invariants"] = evaluations

        if denied:
            result["reason"] = "TRAJECTORY_LIMIT_EXCEEDED"
            return "DENY", result

        # All passed: commit every invariant inside the same critical section.
        for e in evaluations:
            per_session[e["invariant_id"]] = e["projected_value"]
        return "PERMIT", result
