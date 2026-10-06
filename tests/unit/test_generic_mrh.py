"""
CROA Reference Harness — Generic Component Unit Tests
Normative Reference: CROA Framework v1.0.1 §4.2, §4.3, §4.5, §4.6, §4.9

Verifies declarative parameter constraints, schema registry fail-closed semantics,
pluggable subject authenticator, authorization verifier abstraction,
context resolver grounding, and trajectory evaluation.
"""

import sys
import os
import pytest
from fastapi import HTTPException

# Ensure croa_plane is importable
repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
croa_plane_path = os.path.join(repo_root, "croa_plane")
if croa_plane_path not in sys.path:
    sys.path.insert(0, croa_plane_path)

from constraints import evaluate_parameter_constraints
from schema_registry import ActionSchemaRegistry
from auth import TokenRegistryAuthenticator
from verifier import MockAuthorizationVerifier
from c3_resolver import ContextRegistry
from c4_trajectory import InMemoryTrajectoryStore, build_accumulation_key

# ==============================================================================
# 1. PARAMETER CONSTRAINT ENGINE TESTS
# ==============================================================================

def test_constraints_all_supported_operators_pass():
    constraints = {
        "count": {"type": "int", "min": 1, "max": 100, "required": True},
        "mode": {"type": "str", "equals": "fast", "not_equals": "slow"},
        "status": {"in": ["active", "pending"], "not_in": ["deleted", "archived"]}
    }
    params = {
        "count": 50,
        "mode": "fast",
        "status": "active"
    }
    valid, reason = evaluate_parameter_constraints(constraints, params)
    assert valid is True
    assert reason == "VALID"

def test_constraints_fail_closed_unknown_operator():
    constraints = {
        "count": {"regex": ".*"}
    }
    params = {"count": 10}
    valid, reason = evaluate_parameter_constraints(constraints, params)
    assert valid is False
    assert "UNKNOWN_OPERATOR" in reason

def test_constraints_fail_closed_missing_required():
    constraints = {
        "mandatory_field": {"required": True}
    }
    params = {"other_field": 123}
    valid, reason = evaluate_parameter_constraints(constraints, params)
    assert valid is False
    assert "REQUIRED_PARAMETER_MISSING" in reason

def test_constraints_fail_closed_type_mismatch():
    constraints = {
        "count": {"type": "int"}
    }
    # String passed instead of int
    valid, reason = evaluate_parameter_constraints(constraints, {"count": "50"})
    assert valid is False
    assert "TYPE_MISMATCH" in reason

    # Boolean passed instead of int (bool is subclass of int in Python)
    valid, reason = evaluate_parameter_constraints(constraints, {"count": True})
    assert valid is False
    assert "TYPE_MISMATCH" in reason

def test_constraints_fail_closed_numeric_bounds():
    constraints = {
        "discount": {"max": 20, "min": 5}
    }
    # Exceeds max
    valid, reason = evaluate_parameter_constraints(constraints, {"discount": 25})
    assert valid is False
    assert "CONSTRAINT_VIOLATION" in reason
    assert "exceeds upper bound" in reason

    # Below min
    valid, reason = evaluate_parameter_constraints(constraints, {"discount": 2})
    assert valid is False
    assert "CONSTRAINT_VIOLATION" in reason
    assert "below lower bound" in reason

    # Non-numeric candidate for max/min fails closed
    valid, reason = evaluate_parameter_constraints(constraints, {"discount": "ten"})
    assert valid is False
    assert "COMPARISON_ERROR" in reason

    # Boolean candidate for max/min fails closed
    valid, reason = evaluate_parameter_constraints(constraints, {"discount": True})
    assert valid is False
    assert "COMPARISON_ERROR" in reason

def test_constraints_fail_closed_in_and_not_in():
    constraints = {
        "color": {"in": ["red", "blue"], "not_in": ["yellow"]}
    }
    # Not in allowed set
    valid, reason = evaluate_parameter_constraints(constraints, {"color": "green"})
    assert valid is False
    assert "CONSTRAINT_VIOLATION" in reason

    # In disallowed set
    valid, reason = evaluate_parameter_constraints(constraints, {"color": "yellow"})
    assert valid is False
    assert "CONSTRAINT_VIOLATION" in reason

def test_constraints_fail_closed_malformed_spec():
    valid, reason = evaluate_parameter_constraints("not-a-dict", {})
    assert valid is False
    assert "MALFORMED_CONSTRAINTS" in reason

    valid, reason = evaluate_parameter_constraints({"field": "not-a-rule-dict"}, {})
    assert valid is False
    assert "MALFORMED_RULE" in reason

# ==============================================================================
# 2. SCHEMA REGISTRY TESTS
# ==============================================================================

def test_schema_registry_contract_validation():
    reg = ActionSchemaRegistry()
    reg.register_schema("deploy", allowed_keys={"version", "env"}, required_keys={"version"})

    # Valid
    valid, reason = reg.validate_action_parameters("deploy", {"version": "1.0", "env": "dev"})
    assert valid is True

    # Unregistered action fails closed
    valid, reason = reg.validate_action_parameters("unknown_action", {})
    assert valid is False
    assert "UNREGISTERED_ACTION_SCHEMA" in reason

    # Missing required parameter fails closed
    valid, reason = reg.validate_action_parameters("deploy", {"env": "dev"})
    assert valid is False
    assert "SCHEMA_VIOLATION" in reason
    assert "Missing required parameters" in reason

    # Unexpected parameter fails closed
    valid, reason = reg.validate_action_parameters("deploy", {"version": "1.0", "unexpected": True})
    assert valid is False
    assert "SCHEMA_VIOLATION" in reason
    assert "Unexpected parameters" in reason

# ==============================================================================
# 3. PLUGGABLE AUTHENTICATOR TESTS
# ==============================================================================

def test_authenticator_intake_validation():
    auth = TokenRegistryAuthenticator()
    auth.register_token("tok-123", "agent_worker_1")

    # Valid Bearer header
    subject = auth.authenticate("Bearer tok-123", None)
    assert subject == "agent_worker_1"

    # Valid X-Subject-Token header
    subject = auth.authenticate(None, "tok-123")
    assert subject == "agent_worker_1"

    # Missing credential fails closed with 401
    with pytest.raises(HTTPException) as excinfo:
        auth.authenticate(None, None)
    assert excinfo.value.status_code == 401
    assert "MISSING_AUTHENTICATION_CREDENTIAL" in excinfo.value.detail

    # Unknown credential fails closed with 401
    with pytest.raises(HTTPException) as excinfo:
        auth.authenticate("Bearer unknown-token", None)
    assert excinfo.value.status_code == 401
    assert "INVALID_AUTHENTICATION_CREDENTIAL" in excinfo.value.detail

# ==============================================================================
# 4. AUTHORIZATION VERIFIER TESTS
# ==============================================================================

def test_verifier_signature_validation():
    ver = MockAuthorizationVerifier()
    ver.register_trusted_key("key-auth-2026")
    ver.set_expected_signature_proof("attested_proof_sig")

    valid_artifact = {
        "issuer_key_id": "key-auth-2026",
        "signature": "attested_proof_sig"
    }
    is_valid, reason = ver.verify_signature(valid_artifact)
    assert is_valid is True

    # Untrusted key fails closed
    untrusted = {
        "issuer_key_id": "key-evil",
        "signature": "attested_proof_sig"
    }
    is_valid, reason = ver.verify_signature(untrusted)
    assert is_valid is False
    assert "Untrusted or unregistered issuer key" in reason

    # Invalid signature fails closed
    bad_sig = {
        "issuer_key_id": "key-auth-2026",
        "signature": "wrong_proof"
    }
    is_valid, reason = ver.verify_signature(bad_sig)
    assert is_valid is False
    assert "Cryptographic proof does not match" in reason

# ==============================================================================
# 5. CONTEXT RESOLVER TESTS
# ==============================================================================

def test_context_resolver_grounding():
    resolver = ContextRegistry()
    # Baseline defaults include environment:dev -> environment
    is_grounded, reason = resolver.resolve_target("change_config", "environment:dev")
    assert is_grounded is True
    assert reason == "GROUNDED"

    # Unregistered target fails closed
    is_grounded, reason = resolver.resolve_target("change_config", "unknown:env")
    assert is_grounded is False
    assert reason == "TARGET_NOT_REGISTERED"

    # Target type mismatch fails closed
    # deploy_service expects 'service', given 'environment:dev'
    is_grounded, reason = resolver.resolve_target("deploy_service", "environment:dev")
    assert is_grounded is False
    assert reason == "TARGET_TYPE_MISMATCH"

# ==============================================================================
# 6. TRAJECTORY ACCUMULATION KEY TESTS
# ==============================================================================

def test_trajectory_accumulation_key_construction():
    inv_tpc = {
        "invariant_id": "INV-01",
        "profile": "TP-C",
        "scope_dimensions": ["session", "subject"]
    }
    ctx = {"session_id": "sess-1", "subject": "subj-1"}
    key = build_accumulation_key(inv_tpc, ctx)
    assert key == "inv:INV-01:session:sess-1:subject:subj-1"

    inv_tpx = {
        "invariant_id": "INV-02",
        "profile": "TP-X",
        "scope_dimensions": ["subject"]
    }
    key_x = build_accumulation_key(inv_tpx, ctx)
    assert key_x == "inv:INV-02:subject:subj-1"

    # Session in TP-X must fail closed
    inv_tpx_invalid = {
        "invariant_id": "INV-03",
        "profile": "TP-X",
        "scope_dimensions": ["session", "subject"]
    }
    with pytest.raises(ValueError) as excinfo:
        build_accumulation_key(inv_tpx_invalid, ctx)
    assert "INVALID_DIMENSION" in str(excinfo.value)
