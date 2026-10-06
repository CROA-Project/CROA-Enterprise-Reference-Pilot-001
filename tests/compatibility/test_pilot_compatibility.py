"""
CROA Reference Test Apparatus — Pilot Domain Compatibility Tests
Normative Reference: CROA Framework v1.0.1 §4.3, §4.4, §4.5, §4.9

Verifies that the generic Reference Harness cleanly supports the enterprise pilot
workloads, policies, and authorization exceptions when configured via external fixtures,
without requiring domain hardcoding inside the core engine.
Also verifies hermetic fixture isolation post-teardown.
"""

import sys
import os
import datetime
import pytest
from fastapi import HTTPException

# Ensure croa_plane and tests are importable
repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
croa_plane_path = os.path.join(repo_root, "croa_plane")
if croa_plane_path not in sys.path:
    sys.path.insert(0, croa_plane_path)

from fixtures.pilot_fixtures import pilot_fixtures, PILOT_TEST_ISSUER_KEY, PILOT_TEST_SIGNATURE_PROOF
from c2_governor import evaluate_request
from c1_policy import validate_action_parameters
from c3_resolver import resolve_target, default_context_registry
from auth import get_authenticator
from verifier import get_verifier
import c4_trajectory

def test_pilot_workload_lifecycle_and_exception_path():
    with pilot_fixtures():
        # 1. Action schema verification
        valid, _ = validate_action_parameters("update_customer_pricing", {"product": "sku-1", "discount_pct": 10})
        assert valid is True

        valid_bad_param, _ = validate_action_parameters("update_customer_pricing", {"unknown_param": 123})
        assert valid_bad_param is False

        # 2. Context resolution verification
        grounded, _ = resolve_target("update_customer_pricing", "pricing_system")
        assert grounded is True

        # 3. Default autonomous denial under pilot policy
        unauth_req = {
            "request_id": "req-pilot-01",
            "session_id": "sess-pilot-01",
            "subject": "finance_ai",
            "action": "update_customer_pricing",
            "target": "pricing_system",
            "parameters": {"product": "sku-1", "discount_pct": 10}
        }
        res_unauth = evaluate_request(unauth_req)
        assert res_unauth["decision"] == "DENY"
        assert res_unauth["reason"] == "POLICY_DENIED"

        # 4. Governed exception path with valid C1 authorization artifact
        now = datetime.datetime.now(datetime.timezone.utc)
        eff_from = (now - datetime.timedelta(minutes=5)).isoformat()
        exp_at = (now + datetime.timedelta(minutes=15)).isoformat()

        valid_artifact = {
            "auth_id": "AUTH-PILOT-2026-001",
            "subject_scope": "finance_ai",
            "action_scope": "update_customer_pricing",
            "invariant_reference": "INVARIANT-PRICING-001",
            "validity_window": {
                "effective_from": eff_from,
                "expires_at": exp_at
            },
            "redemption_policy": "single-use",
            "issuer_key_id": PILOT_TEST_ISSUER_KEY,
            "signature": PILOT_TEST_SIGNATURE_PROOF,
            "target_constraints": {
                "target": "pricing_system"
            },
            "parameter_constraints": {
                "discount_pct": {"type": "int", "max": 15, "min": 0}
            }
        }

        # Submitting with discount_pct = 10 (Within authorized bounds)
        auth_req_valid = dict(unauth_req)
        auth_req_valid["authorization_artifact"] = valid_artifact

        res_auth = evaluate_request(auth_req_valid)
        assert res_auth["decision"] == "PERMIT_WITH_AUTHORIZATION"
        assert res_auth["policy_id"] == "EXCEPTION:INVARIANT-PRICING-001"
        assert res_auth["auth_id"] == "AUTH-PILOT-2026-001"

        # Submitting with discount_pct = 20 (Violates parameter constraint max = 15)
        auth_req_exceeded = dict(unauth_req)
        auth_req_exceeded["parameters"] = {"product": "sku-1", "discount_pct": 20}
        auth_req_exceeded["authorization_artifact"] = valid_artifact

        res_exceeded = evaluate_request(auth_req_exceeded)
        assert res_exceeded["decision"] == "DENY"
        assert "exceeds upper bound" in res_exceeded["reason"]

    # 5. Direct hermetic isolation assertions proving clean state after exiting pilot_fixtures:
    # A. Pilot action schemas are absent
    valid_after, reason_after = validate_action_parameters("update_customer_pricing", {})
    assert valid_after is False
    assert "UNREGISTERED_ACTION_SCHEMA" in reason_after

    # B. Pilot context targets are absent
    grounded_after, _ = resolve_target("update_customer_pricing", "pricing_system")
    assert grounded_after is False
    assert "pricing_system" not in default_context_registry.registry
    assert "customer:342" not in default_context_registry.registry

    # C. Pilot credentials are absent
    auth = get_authenticator()
    with pytest.raises(HTTPException) as excinfo:
        auth.authenticate("Bearer valid_token_finance_ai", None)
    assert excinfo.value.status_code == 401

    # D. Pilot authorization verifier material is absent
    ver = get_verifier()
    valid_sig, sig_reason = ver.verify_signature({
        "issuer_key_id": PILOT_TEST_ISSUER_KEY,
        "signature": PILOT_TEST_SIGNATURE_PROOF
    })
    assert valid_sig is False
    assert "Untrusted or unregistered issuer key" in sig_reason

    # E. Trajectory store is clean
    assert len(c4_trajectory.trajectory_state) == 0

    # F. Redemption store is clean
    if repo_root not in sys.path:
        sys.path.insert(0, repo_root)
    import c6_firewall.main as c6_main
    assert len(c6_main.default_redemption_store.redeemed_nonces) == 0
    assert len(c6_main.default_redemption_store.redeemed_auth_ids) == 0

def test_missing_invariant_reference_fails_closed():
    """Verifies that missing invariant_reference fails closed at C1 and cannot grant exception."""
    with pilot_fixtures():
        now = datetime.datetime.now(datetime.timezone.utc)
        eff_from = (now - datetime.timedelta(minutes=5)).isoformat()
        exp_at = (now + datetime.timedelta(minutes=15)).isoformat()

        # Artifact deliberately missing 'invariant_reference'
        artifact_missing_inv = {
            "auth_id": "AUTH-TEST-NO-INV",
            "subject_scope": "finance_ai",
            "action_scope": "update_customer_pricing",
            # invariant_reference omitted
            "validity_window": {
                "effective_from": eff_from,
                "expires_at": exp_at
            },
            "redemption_policy": "single-use",
            "issuer_key_id": PILOT_TEST_ISSUER_KEY,
            "signature": PILOT_TEST_SIGNATURE_PROOF,
            "target_constraints": {"target": "pricing_system"}
        }

        req = {
            "request_id": "req-missing-inv-01",
            "session_id": "sess-missing-inv-01",
            "subject": "finance_ai",
            "action": "update_customer_pricing",
            "target": "pricing_system",
            "parameters": {"product": "sku-1", "discount_pct": 5},
            "authorization_artifact": artifact_missing_inv
        }

        res = evaluate_request(req)
        assert res["decision"] == "DENY"
        assert "MALFORMED_AUTHORIZATION_ARTIFACT" in res["reason"]
        assert "invariant_reference" in res["reason"]
