"""
CROA Reference Harness — C4 Trajectory Invariants Engine
Normative Reference: CROA Framework v1.0.1 §4.6 / §4.6.1 / §4.6.3

Cumulative-authority enforcement under atomic concurrency lock.
Evaluates both TP-C (session-bounded) and TP-X (cross-session) invariants.
Guarantees all-or-nothing multi-invariant evaluation and atomic commit.
Provides reserve_trajectory(...) compatibility API delegating directly to canonical engine.
"""

import threading
from typing import Dict, Any, Optional, Tuple, List
import c1_policy

# Module-level invariants override (for monkeypatching in unit tests)
INVARIANTS: Optional[List[Dict[str, Any]]] = None


class InMemoryTrajectoryStore:
    """
    Thread-safe in-memory store for trajectory accumulation state.
    Reference harness single-process implementation only.
    """
    def __init__(self):
        self._state: Dict[str, int] = {}
        self._lock = threading.RLock()

    @property
    def lock(self) -> threading.RLock:
        return self._lock

    @property
    def state(self) -> Dict[str, int]:
        return self._state

    def get(self, key: str, default: int = 0) -> int:
        with self._lock:
            return self._state.get(key, default)

    def set(self, key: str, value: int) -> None:
        with self._lock:
            self._state[key] = value

    def clear(self) -> None:
        with self._lock:
            self._state.clear()


# Global default store instance for reference harness
default_trajectory_store = InMemoryTrajectoryStore()
trajectory_state: Dict[str, int] = default_trajectory_store.state
_trajectory_lock: threading.RLock = default_trajectory_store.lock


def reset_trajectory_state() -> None:
    """Explicitly reset trajectory accumulation state."""
    default_trajectory_store.clear()


def _validate_increment(parameters: Dict[str, Any], param_name: str) -> Optional[int]:
    """
    Strict increment validation:
    - Must be present in parameters
    - Type must be int (bool is rejected as bool is a subclass of int)
    - Must be positive (> 0)
    """
    if not isinstance(parameters, dict) or param_name not in parameters:
        return None
    value = parameters[param_name]
    if type(value) is not int or value <= 0:
        return None
    return value


def build_accumulation_key(inv: Dict[str, Any], context: Dict[str, Any]) -> str:
    """
    Constructs an accumulation key from the invariant's declared dimensions.
    Enforces CROA Framework v1.0.1 §4.6.3 requirements:
    - TP-C invariants include session boundary in accumulation key.
    - TP-X invariants aggregate cross-session for declared governance dimensions (e.g. subject).
    - Fails closed on unresolvable or unknown dimensions.
    """
    profile = inv.get("trajectory_profile", inv.get("profile", "TP-C"))
    scope_dims = inv.get("accumulation_key_dimensions", inv.get("scope_dimensions"))
    
    if scope_dims is None:
        scope_str = inv.get("scope")
        if scope_str == "session_subject":
            scope_dims = ["session", "subject"]
        elif scope_str == "subject":
            scope_dims = ["subject"]
        else:
            scope_dims = ["session", "subject"] if profile == "TP-C" else ["subject"]

    inv_id = inv["invariant_id"]
    parts = [f"inv:{inv_id}"]

    for dim in scope_dims:
        if dim == "session":
            if profile == "TP-X":
                raise ValueError("INVALID_DIMENSION: session dimension not permitted in TP-X profile")
            sess_val = context.get("session_id")
            if not sess_val:
                raise ValueError("MISSING_DIMENSION: session_id is required")
            parts.append(f"session:{sess_val}")
        elif dim == "subject":
            subj_val = context.get("subject")
            if not subj_val:
                raise ValueError("MISSING_DIMENSION: subject is required")
            parts.append(f"subject:{subj_val}")
        elif dim == "target":
            target_val = context.get("target")
            if not target_val:
                raise ValueError("MISSING_DIMENSION: target is required")
            parts.append(f"target:{target_val}")
        elif dim == "action":
            action_val = context.get("action")
            if not action_val:
                raise ValueError("MISSING_DIMENSION: action is required")
            parts.append(f"action:{action_val}")
        else:
            raise ValueError(f"UNRESOLVED_DIMENSION: {dim}")

    return ":".join(parts)


def get_trajectory_state(session_subject_or_key: str, inv_id: Optional[str] = None) -> int:
    """
    Returns current accumulated value for given accumulation key or (session_subject_key, inv_id).
    """
    with _trajectory_lock:
        if inv_id is not None:
            if not session_subject_or_key.startswith("inv:"):
                sess, _, subj = session_subject_or_key.partition(":")
                candidate_keys = [
                    f"inv:{inv_id}:session:{sess}:subject:{subj}",
                    f"inv:{inv_id}:session:{session_subject_or_key}",
                    f"inv:{inv_id}:subject:{session_subject_or_key}",
                    f"{session_subject_or_key}:{inv_id}",
                ]
                for ck in candidate_keys:
                    if ck in trajectory_state:
                        return trajectory_state[ck]
                return trajectory_state.get(session_subject_or_key, 0)
        return trajectory_state.get(session_subject_or_key, 0)


def evaluate_trajectory(
    session_id: str,
    subject: str,
    action: str,
    parameters: Dict[str, Any],
    target: str = "",
    auto_commit: bool = True
) -> Tuple[str, Optional[Dict[str, Any]]]:
    """
    Canonical atomic trajectory evaluation and commitment mechanism.
    Evaluates cumulative trajectory limits and atomically commits valid increments
    under a single continuous _trajectory_lock critical section.
    Iterates over all applicable invariants for the action.
    """
    with _trajectory_lock:
        # Check invariants from module globals (supports monkeypatching in unit tests) or c1_policy
        active_invariants = globals().get("INVARIANTS")
        if active_invariants is None:
            active_invariants = getattr(c1_policy, "INVARIANTS", [])
        applicable_invariants = [inv for inv in active_invariants if inv.get("action") == action]
        
        if not applicable_invariants:
            return "PERMIT", None
            
        context = {
            "session_id": session_id,
            "subject": subject,
            "action": action,
            "target": target
        }
        
        evaluations: List[Dict[str, Any]] = []
        to_commit: List[Tuple[str, int]] = []

        for inv in applicable_invariants:
            inv_id = inv["invariant_id"]
            limit = inv["limit"]
            param_name = inv.get("accumulation_parameter")
            
            count_val = _validate_increment(parameters, param_name)
            if count_val is None:
                return "DENY", {
                    "reason": "INVALID_ACCUMULATION_PARAMETER",
                    "invariant_id": inv_id,
                    "trajectory_decision": "DENY"
                }
                
            try:
                acc_key = build_accumulation_key(inv, context)
            except Exception as e:
                return "DENY", {
                    "reason": "INVALID_ACCUMULATION_DIMENSION",
                    "error": str(e),
                    "invariant_id": inv_id,
                    "trajectory_decision": "DENY"
                }
                
            current = trajectory_state.get(acc_key, 0)
            projected = current + count_val
            profile = inv.get("profile", inv.get("trajectory_profile", "TP-C"))
            
            evaluation = {
                "invariant_id": inv_id,
                "profile": profile,
                "accumulation_key": acc_key,
                "current_value": current,
                "requested_increment": count_val,
                "projected_value": projected,
                "limit": limit,
                "trajectory_decision": "DENY" if projected > limit else "ALLOW"
            }
            evaluations.append(evaluation)
            to_commit.append((acc_key, count_val))

        denied = [e for e in evaluations if e["trajectory_decision"] == "DENY"]
        primary = denied[0] if denied else evaluations[0]
        result: Dict[str, Any] = dict(primary)
        result["applicable_keys"] = [e["accumulation_key"] for e in evaluations]
        result["invariants"] = evaluations

        if denied:
            result["reason"] = "TRAJECTORY_LIMIT_EXCEEDED"
            result["trajectory_decision"] = "DENY"
            return "DENY", result

        if auto_commit:
            for acc_key, inc in to_commit:
                trajectory_state[acc_key] = trajectory_state.get(acc_key, 0) + inc

        result["trajectory_decision"] = "ALLOW"
        return "PERMIT", result


def reserve_trajectory(
    session_id: str,
    subject: str,
    action: str,
    parameters: Dict[str, Any]
) -> Tuple[str, Optional[Dict[str, Any]]]:
    """
    Compatibility API delegating directly to canonical evaluate_trajectory with auto_commit=True.
    """
    return evaluate_trajectory(
        session_id=session_id,
        subject=subject,
        action=action,
        parameters=parameters,
        target="",
        auto_commit=True
    )


def commit_trajectory(acc_key_or_session: str, increment_or_subject: Any = None, inv_id: Optional[str] = None, increment: Optional[int] = None, **kwargs):
    """
    Commits trajectory increment atomically under _trajectory_lock.
    Supports both accumulation_key and legacy parameter signatures.
    """
    with _trajectory_lock:
        if inv_id is not None and increment is not None:
            session_id = acc_key_or_session
            subject = str(increment_or_subject)
            legacy_key = f"inv:{inv_id}:session:{session_id}:subject:{subject}"
            trajectory_state[legacy_key] = trajectory_state.get(legacy_key, 0) + increment
        elif isinstance(increment_or_subject, int):
            acc_key = acc_key_or_session
            inc_val = increment_or_subject
            trajectory_state[acc_key] = trajectory_state.get(acc_key, 0) + inc_val
