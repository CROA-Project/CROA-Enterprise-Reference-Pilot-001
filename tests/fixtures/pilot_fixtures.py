"""
CROA Reference Test Apparatus — Pilot Domain Fixtures and Registrations
Authoritative Normative Baseline: CROA Framework v1.0.1
Scope: External Test Apparatus and Fixture Configuration Only
Does NOT modify or pollute generic reference harness source code.

Encapsulates all domain-specific Summit / Enterprise Pilot identities,
schemas, context targets, test policies, invariants, and authorization keys.
"""

import os
import shutil
import sys
import tempfile
from contextlib import contextmanager

# Ensure croa_plane is importable
repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
croa_plane_path = os.path.join(repo_root, "croa_plane")
if croa_plane_path not in sys.path:
    sys.path.insert(0, croa_plane_path)

import c1_policy  # noqa: E402
import c3_resolver  # noqa: E402
import c5_evidence  # noqa: E402
from auth import TokenRegistryAuthenticator, get_authenticator  # noqa: E402
from schema_registry import default_schema_registry  # noqa: E402
from verifier import MockAuthorizationVerifier, get_verifier  # noqa: E402

# Domain-specific pilot actions and parameter schemas
PILOT_SCHEMAS = {
    "update_customer_pricing": {"allowed_keys": {"product", "discount_pct"}, "required_keys": set()},
    "submit_financial_analysis": {"allowed_keys": {"analytical_model"}, "required_keys": set()},
}

# Domain-specific pilot context registry entries
PILOT_TARGETS = {
    "customer:342": "customer",
    "pricing_system": "pricing",
    "customer_database": "database",
    "financial_analysis_store": "store",
}

PILOT_ACTION_TARGET_TYPES = {
    "update_customer_pricing": "pricing",
    "revenue_optimization_discount": "pricing",
    "submit_financial_analysis": "store",
}

# Domain-specific pilot policies
PILOT_POLICIES = [
    {
        "policy_id": "POLICY-007",
        "description": "update_customer_pricing is denied without exception authorization",
        "action": "update_customer_pricing",
        "target": "pricing_system",
        "effect": "DENY",
    }
]

# Domain-specific pilot invariants
PILOT_INVARIANTS = [
    {
        "invariant_id": "INVARIANT-PRICING-001",
        "name": "Customer Pricing Mutation Restricted",
        "description": "Mutations to pricing_system require governed C1 exception authority",
        "profile": "INVARIANT_RULE",
        "action": "update_customer_pricing",
        "target": "pricing_system",
        "effect": "DENY",
        "version": "1",
    }
]

# Domain-specific test tokens
PILOT_TEST_TOKENS = {
    "valid_token_finance_ai": "finance_ai",
    "valid_token_finance_ai_refreshed": "finance_ai",
    "valid_token_finance_ai_alt": "finance_ai_alt",
    "valid_token_billing_worker": "billing_worker",
    "valid_token_calib_agent": "calib_agent",
    "valid_token_test_agent": "test_agent",
}

PILOT_TEST_ISSUER_KEY = "key-c1-policy-auth-2026"
PILOT_TEST_SIGNATURE_PROOF = "c1_attested_cryptographic_signature_proof"

_orig_evidence_file: str | None = None
_temp_dir: str | None = None


def setup_pilot_fixtures():
    """Registers pilot domain schemas, targets, policies, tokens, and verification keys."""
    global _orig_evidence_file, _temp_dir

    # Redirect evidence file for host test execution
    _orig_evidence_file = c5_evidence.EVIDENCE_FILE
    _temp_dir = tempfile.mkdtemp(prefix="croa_evidence_")
    c5_evidence.EVIDENCE_FILE = os.path.join(_temp_dir, "evidence.jsonl")
    c5_evidence.reset_anchor_for_tests()

    # Register schemas
    for action, schema in PILOT_SCHEMAS.items():
        default_schema_registry.register_schema(action, allowed_keys=schema["allowed_keys"], required_keys=schema["required_keys"])

    # Register targets
    for target, target_type in PILOT_TARGETS.items():
        c3_resolver.default_context_registry.register_target(target, target_type)

    for action, target_type in PILOT_ACTION_TARGET_TYPES.items():
        c3_resolver.default_context_registry.register_action_target_type(action, target_type)

    # Register policies & invariants
    for p in PILOT_POLICIES:
        c1_policy.register_policy(p)

    for inv in PILOT_INVARIANTS:
        c1_policy.register_invariant(inv)

    # Register tokens in active authenticator
    auth = get_authenticator()
    if isinstance(auth, TokenRegistryAuthenticator):
        for token, subject in PILOT_TEST_TOKENS.items():
            auth.register_token(token, subject)

    # Register mock verifier credentials
    ver = get_verifier()
    if isinstance(ver, MockAuthorizationVerifier):
        ver.register_trusted_key(PILOT_TEST_ISSUER_KEY)
        ver.set_expected_signature_proof(PILOT_TEST_SIGNATURE_PROOF)


def teardown_pilot_fixtures():
    """Cleans up registered pilot fixtures and resets core registries to defaults."""
    global _orig_evidence_file, _temp_dir

    for action in PILOT_SCHEMAS:
        default_schema_registry.unregister_schema(action)

    c3_resolver.default_context_registry.reset_to_defaults()
    c1_policy.reset_policies()
    c1_policy.reset_invariants()

    auth = get_authenticator()
    if isinstance(auth, TokenRegistryAuthenticator):
        auth.clear()

    ver = get_verifier()
    if isinstance(ver, MockAuthorizationVerifier):
        ver.clear()

    # Explicitly clear trajectory store
    import c4_trajectory

    c4_trajectory.default_trajectory_store.clear()
    c4_trajectory.trajectory_state.clear()

    # Explicitly clear C6 redemption store
    try:
        if repo_root not in sys.path:
            sys.path.insert(0, repo_root)
        if "DEMO_CONTROL_SECRET" not in os.environ:
            os.environ["DEMO_CONTROL_SECRET"] = "test-secret-unit-test"
        if "INTERNAL_SERVICE_SECRET" not in os.environ:
            os.environ["INTERNAL_SERVICE_SECRET"] = "test-internal-secret"
        import c6_firewall.main as c6_main

        c6_main.default_redemption_store.clear()
    except Exception:
        pass

    if _orig_evidence_file:
        c5_evidence.EVIDENCE_FILE = _orig_evidence_file
        c5_evidence.reset_anchor_for_tests()
        _orig_evidence_file = None

    if _temp_dir and os.path.exists(_temp_dir):
        shutil.rmtree(_temp_dir, ignore_errors=True)
        _temp_dir = None


@contextmanager
def pilot_fixtures():
    """Context manager for running tests under pilot fixture configuration."""
    setup_pilot_fixtures()
    try:
        yield
    finally:
        teardown_pilot_fixtures()
