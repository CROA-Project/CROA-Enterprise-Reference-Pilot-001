"""
Prospective Conformance Test Policy and Invariant Fixtures
Authoritative Normative Baseline: CROA Framework v1.0.1
Scope: Test Apparatus Only (Does NOT modify SUT source code)
"""

# Existing Preserved TP-C Invariant
INVARIANT_TRAJ_001 = {
    "invariant_id": "INVARIANT-TRAJ-001",
    "name": "Maximum Customer Export Per Session",
    "description": "Limits the total number of customer records exported in a single session",
    "profile": "TP-C",
    "action": "export_customers",
    "accumulation_parameter": "count",
    "limit": 100,
    "scope_dimensions": ["session", "subject"],
    "version": "1"
}

# Prospective TP-X Invariant for Summit Business Requirement
INVARIANT_TRAJ_002 = {
    "invariant_id": "INVARIANT-TRAJ-002",
    "name": "Maximum Customer Export Cross-Session",
    "description": "Limits the total number of customer records exported across sessions for an authenticated subject",
    "profile": "TP-X",
    "action": "export_customers",
    "accumulation_parameter": "count",
    "limit": 100,
    "scope_dimensions": ["subject"],
    "version": "1"
}

# Prospective Generic Non-Summit TP-X Invariant
INVARIANT_TEST_GENERIC = {
    "invariant_id": "INVARIANT-TEST-GENERIC",
    "name": "Generic Cross-Session Limit",
    "description": "Limits the total deployment units across sessions for an authenticated subject",
    "profile": "TP-X",
    "action": "deploy_service",
    "accumulation_parameter": "units",
    "limit": 50,
    "scope_dimensions": ["subject"],
    "version": "1"
}

# MRH Test Identity Tokens for §4.9 Subject Authentication Verification
# NOTE: This is strictly an MRH TEST IDENTITY MECHANISM, NOT a production IAM architecture.
TEST_SUBJECT_TOKENS = {
    "valid_token_finance_ai": "finance_ai",
    "valid_token_finance_ai_refreshed": "finance_ai",
    "valid_token_finance_ai_alt": "finance_ai_alt",
    "valid_token_billing_worker": "billing_worker"
}
