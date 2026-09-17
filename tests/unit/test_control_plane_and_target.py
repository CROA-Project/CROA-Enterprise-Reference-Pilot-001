"""Control-plane and target behaviours that are cheap to prove in-process."""

import jwt
from conftest import propose

H = {"X-Demo-Control-Secret": "unit-test-demo-control-secret"}
INT = {"X-Internal-Service-Secret": "unit-test-internal-service-secret"}


def test_ecc_envelope_contains_standard_claims(croa_client, services):
    r = propose(croa_client)
    header = jwt.get_unverified_header(r["ecc"])
    p = jwt.decode(r["ecc"], options={"verify_signature": False}, audience="c6-firewall-pilot")
    assert header["kid"] == services["c6"].PUBLIC_KID
    assert p["iss"] == "croa-plane-pilot" and p["aud"] == "c6-firewall-pilot" and p["jti"] == p["ecc_id"] == p["nonce"]
    assert p["ecc_schema_version"] == "1" and p["policy_id"] == "POLICY-001"
    assert r["expires_at"].endswith("Z") and "+00:00" not in r["expires_at"]


def test_default_deny_and_policy_deny(croa_client):
    assert propose(croa_client, action="bogus_action")["reason"] == "NO_POLICY_MATCH"
    assert propose(croa_client, action="change_config", target="environment:prod")["reason"] == "POLICY_DENIED"
    assert propose(croa_client, target="customer:999")["reason"] == "TARGET_NOT_REGISTERED"


def test_secrets_are_required_and_placeholders_rejected(croa_client):
    assert croa_client.post("/reset", json={"demo_run_id": "x"}).status_code == 403
    assert croa_client.post("/reset", json={"demo_run_id": "x"}, headers={"X-Demo-Control-Secret": "wrong"}).status_code == 403
    assert croa_client.post("/reset", json={"demo_run_id": "x"}, headers=H).status_code == 200


def test_placeholder_secret_refused_at_startup(services, monkeypatch):
    import pytest

    monkeypatch.setenv("DEMO_CONTROL_SECRET", "replace-me")
    with pytest.raises(RuntimeError):
        services["croa"]._require_secret("DEMO_CONTROL_SECRET")
    monkeypatch.setenv("DEMO_CONTROL_SECRET", "short")
    with pytest.raises(RuntimeError):
        services["croa"]._require_secret("DEMO_CONTROL_SECRET")


def test_ttl_not_caller_controllable_outside_test_mode(croa_client, services, monkeypatch):
    monkeypatch.setattr(services["croa"], "TEST_MODE", False)
    r = propose(croa_client, expiry_seconds=999999)
    p = jwt.decode(r["ecc"], options={"verify_signature": False}, audience="c6-firewall-pilot")
    assert p["exp"] - p["iat"] == 300


def test_acmeops_requires_firewall_identity_and_is_idempotent(services):
    from fastapi.testclient import TestClient

    c = TestClient(services["acme"].app)
    body = {"ecc_id": "e1", "action": "get_customer", "target": "customer:342", "parameters": {}}
    assert c.post("/internal/execute", json=body).status_code == 403
    assert c.get("/internal/history").status_code == 403
    first = c.post("/internal/execute", json=body, headers=INT).json()
    dup = c.post("/internal/execute", json=body, headers=INT).json()
    assert first["status"] == "executed" and dup["status"] == "duplicate"
    assert first["execution_id"] == dup["execution_id"]
    assert len(c.get("/internal/history", headers=INT).json()) == 1
    assert c.get("/internal/executions/e1", headers=INT).status_code == 200
    assert c.get("/internal/executions/nope", headers=INT).status_code == 404
