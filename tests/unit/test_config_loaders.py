"""
CROA Reference Harness — Config Loaders and Authentication Unit Tests
Normative Reference: CROA Framework v1.0.1 §4.3, §4.9

Verifies fail-closed startup configuration parsing for:
- CROA_SUBJECT_TOKENS
- CROA_CONTEXT_TARGETS
And verifies §4.9 fail-closed subject authentication negative cases:
- Missing credential -> HTTP 401
- Invalid credential -> HTTP 401
- Subject mismatch -> HTTP 403
"""

import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi import HTTPException

repo_root = Path(__file__).resolve().parents[2]
croa_plane_path = repo_root / "croa_plane"
if str(croa_plane_path) not in sys.path:
    sys.path.insert(0, str(croa_plane_path))

from auth import TokenRegistryAuthenticator  # noqa: E402
from c3_resolver import ContextRegistry  # noqa: E402

# ==============================================================================
# 1. CROA_SUBJECT_TOKENS CONFIG LOADER TESTS
# ==============================================================================


def test_subject_tokens_unset_or_empty():
    with patch.dict(os.environ, {}, clear=True):
        auth = TokenRegistryAuthenticator()
        assert auth._registry == {}

    with patch.dict(os.environ, {"CROA_SUBJECT_TOKENS": "  "}):
        auth = TokenRegistryAuthenticator()
        assert auth._registry == {}


def test_subject_tokens_valid_json():
    valid_json = '{"token-alpha": "agent:1", "token-beta": "alice"}'
    with patch.dict(os.environ, {"CROA_SUBJECT_TOKENS": valid_json}):
        auth = TokenRegistryAuthenticator()
        assert auth.authenticate("Bearer token-alpha", None) == "agent:1"
        assert auth.authenticate("Bearer token-beta", None) == "alice"
        with pytest.raises(HTTPException) as exc_info:
            auth.authenticate("Bearer unknown", None)
        assert exc_info.value.status_code == 401


@pytest.mark.parametrize(
    "malformed_val",
    [
        "{not valid json",
        '{"unterminated": ',
        "true",
        "123",
        '"string_value"',
        '["token1", "token2"]',
        '{"valid_key": 123}',
        '{"": "agent:1"}',
        '{"token1": ""}',
        '{"token1": null}',
    ],
)
def test_subject_tokens_malformed_fails_closed(malformed_val):
    with patch.dict(os.environ, {"CROA_SUBJECT_TOKENS": malformed_val}):
        with pytest.raises(ValueError, match="MALFORMED_SUBJECT_TOKENS_CONFIG"):
            TokenRegistryAuthenticator()


# ==============================================================================
# 2. CROA_CONTEXT_TARGETS CONFIG LOADER TESTS
# ==============================================================================


def test_context_targets_unset_or_empty():
    with patch.dict(os.environ, {}, clear=True):
        reg = ContextRegistry()
        # Default targets should remain untouched
        assert "environment:dev" in reg.registry
        assert "environment:prod" in reg.registry

    with patch.dict(os.environ, {"CROA_CONTEXT_TARGETS": "  "}):
        reg = ContextRegistry()
        assert "environment:dev" in reg.registry


def test_context_targets_valid_json():
    valid_json = '{"customer:999": "customer", "custom:system": "environment"}'
    with patch.dict(os.environ, {"CROA_CONTEXT_TARGETS": valid_json}):
        reg = ContextRegistry()
        assert reg.registry.get("customer:999") == "customer"
        assert reg.registry.get("custom:system") == "environment"
        grounded, reason = reg.resolve_target("get_customer", "customer:999")
        assert grounded is True
        assert reason == "GROUNDED"
        # Standard defaults preserved
        assert reg.registry.get("environment:dev") == "environment"


@pytest.mark.parametrize(
    "malformed_val",
    [
        "{invalid json",
        "42",
        "false",
        '["item1", "item2"]',
        '{"key": 99}',
        '{"": "customer"}',
        '{"customer:123": ""}',
        '{"customer:123": null}',
    ],
)
def test_context_targets_malformed_fails_closed(malformed_val):
    with patch.dict(os.environ, {"CROA_CONTEXT_TARGETS": malformed_val}):
        with pytest.raises(ValueError, match="MALFORMED_CONTEXT_TARGETS_CONFIG"):
            ContextRegistry()


# ==============================================================================
# 3. NEGATIVE AUTHENTICATION GATE TESTS (CROA SURFACE)
# ==============================================================================


def test_propose_missing_auth_header(croa_client):
    body = {
        "request_id": "auth-test-1",
        "session_id": "sess-auth",
        "subject": "agent:1",
        "action": "get_customer",
        "target": "customer:342",
        "parameters": {},
    }
    resp = croa_client.post("/propose", json=body)
    assert resp.status_code == 401
    assert "MISSING_AUTHENTICATION_CREDENTIAL" in resp.json().get("detail", "")


def test_propose_invalid_token(croa_client):
    body = {
        "request_id": "auth-test-2",
        "session_id": "sess-auth",
        "subject": "agent:1",
        "action": "get_customer",
        "target": "customer:342",
        "parameters": {},
    }
    resp = croa_client.post("/propose", json=body, headers={"Authorization": "Bearer invalid-unknown-token"})
    assert resp.status_code == 401
    assert "INVALID_AUTHENTICATION_CREDENTIAL" in resp.json().get("detail", "")


def test_propose_subject_mismatch(croa_client):
    from auth import get_authenticator

    get_authenticator().register_token("alice-valid-token", "alice")

    body = {
        "request_id": "auth-test-3",
        "session_id": "sess-auth",
        "subject": "bob",  # Mismatch: Token is for alice, declared subject is bob
        "action": "get_customer",
        "target": "customer:342",
        "parameters": {},
    }
    resp = croa_client.post("/propose", json=body, headers={"Authorization": "Bearer alice-valid-token"})
    assert resp.status_code == 403
    assert "SUBJECT_AUTHENTICATION_MISMATCH" in resp.json().get("detail", "")
