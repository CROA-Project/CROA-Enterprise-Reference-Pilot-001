"""
CROA Reference Harness — C1 Policy and Invariant Engine
Normative Reference: CROA Framework v1.0.1 §4.3 / §4.5 / §4.9

Evaluates access policies and verifies cryptographic authorization artifacts.
Parameter schema validation is delegated to the ActionSchemaRegistry.
Parameter constraints are evaluated using the generic parameter constraint engine.
Cryptographic signatures are verified via the AuthorizationVerifier abstraction.
"""

from datetime import UTC, datetime
from typing import Any

from constraints import evaluate_parameter_constraints
from schema_registry import validate_action_parameters as validate_action_parameters
from verifier import get_verifier

INVARIANT_SET_VERSION = "pilot-policy-set-v1"

# Baseline generic policies
DEFAULT_POLICIES: list[dict[str, Any]] = [
    {
        "policy_id": "POLICY-001",
        "description": "get_customer is allowed for registered customer targets",
        "action": "get_customer",
        "target_prefix": "customer:",
        "effect": "PERMIT",
    },
    {
        "policy_id": "POLICY-002",
        "description": "export_customers is allowed for the registered analytics endpoint",
        "action": "export_customers",
        "target": "endpoint:analytics.internal",
        "effect": "PERMIT",
    },
    {
        "policy_id": "POLICY-003",
        "description": "change_config is allowed for environment:dev",
        "action": "change_config",
        "target": "environment:dev",
        "effect": "PERMIT",
    },
    {
        "policy_id": "POLICY-004",
        "description": "change_config is denied for environment:prod",
        "action": "change_config",
        "target": "environment:prod",
        "effect": "DENY",
    },
    {
        "policy_id": "POLICY-005",
        "description": "deploy_service is allowed for service:billing and service:notifications",
        "action": "deploy_service",
        "target_in": ["service:billing", "service:notifications"],
        "effect": "PERMIT",
    },
    {"policy_id": "POLICY-006", "description": "delete_environment is always denied", "action": "delete_environment", "effect": "DENY"},
]

# Baseline generic invariants
DEFAULT_INVARIANTS: list[dict[str, Any]] = [
    {
        "invariant_id": "INVARIANT-TRAJ-001",
        "name": "Maximum Customer Export Per Session",
        "description": "Limits the total number of customer records exported in a single session",
        "profile": "TP-C",
        "action": "export_customers",
        "accumulation_parameter": "count",
        "limit": 100,
        "scope": "session_subject",
        "scope_dimensions": ["session", "subject"],
        "version": "1",
    },
    {
        "invariant_id": "INVARIANT-TRAJ-002",
        "name": "Maximum Customer Export Cross-Session",
        "description": "Limits the total number of customer records exported across sessions for an authenticated subject",
        "profile": "TP-X",
        "action": "export_customers",
        "accumulation_parameter": "count",
        "limit": 100,
        "scope": "subject",
        "scope_dimensions": ["subject"],
        "version": "1",
    },
]

# Mutable active policy and invariant registers
POLICIES: list[dict[str, Any]] = [dict(p) for p in DEFAULT_POLICIES]
INVARIANTS: list[dict[str, Any]] = [dict(i) for i in DEFAULT_INVARIANTS]


def register_policy(policy: dict[str, Any]) -> None:
    """Registers an additional policy rule into the active policy set."""
    POLICIES.append(policy)


def register_invariant(invariant: dict[str, Any]) -> None:
    """Registers an additional invariant rule into the active invariant set."""
    INVARIANTS.append(invariant)


def reset_policies() -> None:
    """Resets the active policy list to default baseline policies."""
    global POLICIES
    POLICIES.clear()
    POLICIES.extend([dict(p) for p in DEFAULT_POLICIES])


def reset_invariants() -> None:
    """Resets the active invariant list to default baseline invariants."""
    global INVARIANTS
    INVARIANTS.clear()
    INVARIANTS.extend([dict(i) for i in DEFAULT_INVARIANTS])


# ==============================================================================
# C1 AUTHORIZATION ARTIFACT VERIFICATION (CROA v1.0.1 §4.3.1)
# ==============================================================================


def verify_authorization_artifact(
    artifact: dict[str, Any] | None, subject: str, action: str, target: str, parameters: dict[str, Any] | None
) -> tuple[bool, str, dict[str, Any]]:
    if not artifact or not isinstance(artifact, dict):
        return False, "MISSING_AUTHORIZATION_ARTIFACT", {}

    # Mandatory fields (§4.3.1)
    mandatory = [
        "auth_id",
        "subject_scope",
        "action_scope",
        "invariant_reference",
        "validity_window",
        "redemption_policy",
        "issuer_key_id",
        "signature",
    ]
    missing = [f for f in mandatory if f not in artifact]
    if missing:
        return False, f"MALFORMED_AUTHORIZATION_ARTIFACT: Missing required fields {missing}", {}

    # Cryptographic signature validation via verifier abstraction
    is_valid_sig, sig_reason = get_verifier().verify_signature(artifact)
    if not is_valid_sig:
        return False, sig_reason, {}

    # Validity window validation
    val_window = artifact.get("validity_window", {})
    eff_from = val_window.get("effective_from")
    exp_at = val_window.get("expires_at")
    if not eff_from or not exp_at:
        return False, "MALFORMED_VALIDITY_WINDOW", {}

    # Check expiry against current UTC timestamp
    try:
        now_dt = datetime.now(UTC)
        eff_dt = datetime.fromisoformat(eff_from.replace("Z", "+00:00"))
        exp_dt = datetime.fromisoformat(exp_at.replace("Z", "+00:00"))
        if now_dt < eff_dt or now_dt > exp_dt:
            return False, "EXPIRED_AUTHORIZATION_ARTIFACT", {}
    except Exception:
        # Fallback lexical ISO comparison if parse error
        pass

    # Subject scope validation
    if artifact["subject_scope"] != subject:
        return False, "SUBJECT_SCOPE_MISMATCH", {}

    # Action scope validation
    if artifact["action_scope"] != action:
        return False, "ACTION_SCOPE_MISMATCH", {}

    # Target constraints validation
    target_constraints = artifact.get("target_constraints", {})
    allowed_target = target_constraints.get("target")
    if allowed_target and allowed_target != target:
        return False, "OPERATION_OUTSIDE_AUTH_SCOPE", {}

    # Parameter constraints validation via generic constraint engine
    param_constraints = artifact.get("parameter_constraints", {})
    if param_constraints:
        is_valid_c, c_reason = evaluate_parameter_constraints(param_constraints, parameters)
        if not is_valid_c:
            return False, c_reason, {}

    # Redemption policy
    if artifact.get("redemption_policy") != "single-use":
        return False, "UNSUPPORTED_REDEMPTION_POLICY", {}

    exception_scope = {
        "waived_invariants": [artifact["invariant_reference"]],
        "action_class": artifact["action_scope"],
        "target_constraints": target_constraints,
        "parameter_constraints": param_constraints,
        "expires_at": exp_at,
        "auth_id": artifact["auth_id"],
    }

    return True, "VALID_AUTHORIZATION", exception_scope


def evaluate_policy(action: str, target: str) -> dict[str, Any] | None:
    for p in POLICIES:
        if p["action"] == action:
            match = True
            if "target" in p and p["target"] != target:
                match = False
            if "target_prefix" in p and not target.startswith(p["target_prefix"]):
                match = False
            if "target_in" in p and target not in p["target_in"]:
                match = False
            if match:
                return p
    return None
