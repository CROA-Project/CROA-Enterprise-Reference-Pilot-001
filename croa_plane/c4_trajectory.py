"""
CROA Reference Harness — C4 Trajectory State and Evaluator
Normative Reference: CROA Framework v1.0.1 §4.6.3 / §4.6.4

Maintains cumulative trajectory states and evaluates requests against cumulative invariant limits.
Atomically evaluates and commits valid increments.

================================================================================
DISCLAIMER: SINGLE-PROCESS REFERENCE HARNESS IMPLEMENTATION ONLY
This in-memory trajectory store is designed exclusively for local reference harness
execution, unit testing, and single-process demonstration. It relies on in-memory
Python dictionary state protected by a threading lock. It is NOT designed for
multi-node, distributed, or production enterprise deployment, which requires an
external transactional consensus datastore.
================================================================================
"""

import threading
from typing import Dict, Any, Tuple, Optional, List
import c1_policy

class InMemoryTrajectoryStore:
    """
    In-memory reference storage mechanism for cumulative trajectory state.
    Reference harness single-process implementation only.
    """
    def __init__(self):
        self._state: Dict[str, int] = {}
        self._lock = threading.Lock()

    @property
    def lock(self) -> threading.Lock:
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
_trajectory_lock: threading.Lock = default_trajectory_store.lock

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

def get_trajectory_state(acc_key: str, inv_id: Optional[str] = None) -> int:
    with _trajectory_lock:
        if inv_id is not None and not acc_key.startswith("inv:"):
            # Legacy fallback: session_subject_key + inv_id
            legacy_key = f"inv:{inv_id}:session:{acc_key}"
            return trajectory_state.get(legacy_key, trajectory_state.get(acc_key, 0))
        return trajectory_state.get(acc_key, 0)

def evaluate_trajectory(session_id: str, subject: str, action: str, parameters: Dict[str, Any], target: str = "", auto_commit: bool = True) -> Tuple[str, Optional[Dict[str, Any]]]:
    """
    Evaluates cumulative trajectory limits and atomically commits valid increments
    under a single continuous _trajectory_lock critical section.
    Iterates over all applicable invariants for the action.
    """
    with _trajectory_lock:
        applicable_invariants = [inv for inv in c1_policy.INVARIANTS if inv.get("action") == action]
        
        if not applicable_invariants:
            return "PERMIT", None
            
        context = {
            "session_id": session_id,
            "subject": subject,
            "action": action,
            "target": target
        }
        
        applicable_keys = []
        for inv in applicable_invariants:
            inv_id = inv["invariant_id"]
            limit = inv["limit"]
            param_name = inv["accumulation_parameter"]
            
            if param_name not in parameters:
                return "DENY", {"reason": "INVALID_ACCUMULATION_PARAMETER"}
                
            count_val = parameters[param_name]
            if type(count_val) is not int or count_val <= 0:
                return "DENY", {"reason": "INVALID_ACCUMULATION_PARAMETER"}
                
            try:
                acc_key = build_accumulation_key(inv, context)
            except Exception as e:
                return "DENY", {"reason": "INVALID_ACCUMULATION_DIMENSION", "error": str(e)}
                
            applicable_keys.append(acc_key)
            current = trajectory_state.get(acc_key, 0)
            projected = current + count_val
            
            result_data = {
                "invariant_id": inv_id,
                "profile": inv.get("profile", inv.get("trajectory_profile", "TP-C")),
                "accumulation_key": acc_key,
                "applicable_keys": applicable_keys,
                "current_value": current,
                "requested_increment": count_val,
                "projected_value": projected,
                "limit": limit
            }
            
            if projected > limit:
                result_data["trajectory_decision"] = "DENY"
                result_data["reason"] = "TRAJECTORY_LIMIT_EXCEEDED"
                return "DENY", result_data

        primary_inv = applicable_invariants[0]
        acc_key = applicable_keys[0]
        current = trajectory_state.get(acc_key, 0)
        param_name = primary_inv["accumulation_parameter"]
        count_val = parameters[param_name]
        
        # Atomically commit all applicable accumulation keys within the critical section
        if auto_commit:
            for k in applicable_keys:
                trajectory_state[k] = trajectory_state.get(k, 0) + count_val

        result_data = {
            "invariant_id": primary_inv["invariant_id"],
            "profile": primary_inv.get("profile", primary_inv.get("trajectory_profile", "TP-C")),
            "accumulation_key": acc_key,
            "applicable_keys": applicable_keys,
            "current_value": current,
            "requested_increment": count_val,
            "projected_value": current + count_val,
            "limit": primary_inv["limit"],
            "trajectory_decision": "ALLOW"
        }
        return "PERMIT", result_data

def commit_trajectory(acc_key_or_session: str, increment_or_subject: Any = None, inv_id: str = None, increment: int = None, **kwargs):
    """
    Commits trajectory increment atomically under _trajectory_lock.
    Supports both new accumulation_key and legacy parameter signatures.
    """
    with _trajectory_lock:
        if inv_id is not None and increment is not None:
            # Legacy signature: commit_trajectory(session_id, subject, inv_id, increment)
            session_id = acc_key_or_session
            subject = str(increment_or_subject)
            legacy_key = f"inv:{inv_id}:session:{session_id}:subject:{subject}"
            trajectory_state[legacy_key] = trajectory_state.get(legacy_key, 0) + increment
        elif isinstance(increment_or_subject, int):
            # New signature: commit_trajectory(acc_key, increment)
            acc_key = acc_key_or_session
            inc_val = increment_or_subject
            trajectory_state[acc_key] = trajectory_state.get(acc_key, 0) + inc_val
