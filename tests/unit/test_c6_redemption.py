"""
CROA Reference Harness — C6 Execution Firewall Redemption Unit Tests
Normative Reference: CROA Framework v1.0.1 §4.8, §4.9; NT-007

Tests single-use capability token (ECC nonce) redemption,
authorization artifact (auth_id) sequential and concurrent redemption,
and positive controls on independent nonces.
Scope: In-memory single-process Reference Harness (InMemoryRedemptionStore).
"""

import os
import sys
import threading
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
croa_plane_path = os.path.join(repo_root, "croa_plane")

if repo_root not in sys.path:
    sys.path.insert(0, repo_root)
if croa_plane_path not in sys.path:
    sys.path.insert(0, croa_plane_path)

os.environ["DEMO_CONTROL_SECRET"] = "test-secret-unit-test"
os.environ["INTERNAL_SERVICE_SECRET"] = "test-internal-secret"

import c7_compiler  # noqa: E402

c6_mod: Any = None
c6_app: Any = None
default_redemption_store: Any = None


@pytest.fixture(autouse=True)
def setup_c6_environment(services, monkeypatch):
    """
    Hermetic test fixture for in-process C6 firewall testing:
    - Obtains C6 module/app/store from hermetic ephemeral-key services fixture
    - Resets default redemption store
    - Mocks evidence logging to avoid external HTTP dependency
    - Instruments upstream execution POST calls to track upstream execution count
    """
    global c6_mod, c6_app, default_redemption_store

    c6_mod = services["c6"]
    c6_app = c6_mod.app
    default_redemption_store = c6_mod.default_redemption_store

    default_redemption_store.clear()

    upstream_calls = []
    call_lock = threading.Lock()

    async def mock_async_post(self, url, *args, **kwargs):
        if "/internal/execute" in str(url):
            with call_lock:
                upstream_calls.append(kwargs.get("json"))
                call_index = len(upstream_calls)
            req = httpx.Request("POST", url)
            return httpx.Response(200, json={"execution_id": f"exec-{call_index}", "status": "SUCCESS"}, request=req)
        req = httpx.Request("POST", url)
        return httpx.Response(200, json={"status": "ok"}, request=req)

    monkeypatch.setattr(c6_mod, "log_evidence", lambda *args, **kwargs: None)
    monkeypatch.setattr(httpx.AsyncClient, "post", mock_async_post)

    yield upstream_calls

    default_redemption_store.clear()


def test_c6_auth_id_sequential_replay(setup_c6_environment):
    """
    AUTH_ID_SEQUENTIAL_REPLAY_TEST (CROA §4.8, NT-007):
    A valid ECC containing a valid authorization auth_ref may execute once.
    A second presentation attempting to redeem the same auth_ref must fail closed.
    """
    upstream_calls = setup_c6_environment
    client = TestClient(c6_app)

    auth_id = "AUTH-TEST-SEQUENTIAL-001"
    ecc1 = c7_compiler.generate_ecc(
        request_id="req-seq-1",
        session_id="sess-seq-1",
        subject="alice",
        action="export_customers",
        target="endpoint:analytics.internal",
        parameters={"count": 10},
        invariant_set_version="pilot-policy-set-v1",
        decision_basis="PERMIT_WITH_AUTHORIZATION",
        auth_id=auth_id,
        exception_scope={"action_class": "export_customers", "target_constraints": {"target": "endpoint:analytics.internal"}},
    )
    ecc2 = c7_compiler.generate_ecc(
        request_id="req-seq-2",
        session_id="sess-seq-2",
        subject="alice",
        action="export_customers",
        target="endpoint:analytics.internal",
        parameters={"count": 10},
        invariant_set_version="pilot-policy-set-v1",
        decision_basis="PERMIT_WITH_AUTHORIZATION",
        auth_id=auth_id,
        exception_scope={"action_class": "export_customers", "target_constraints": {"target": "endpoint:analytics.internal"}},
    )

    body1 = {
        "ecc": ecc1["ecc"],
        "subject": "alice",
        "action": "export_customers",
        "target": "endpoint:analytics.internal",
        "parameters": {"count": 10},
    }
    body2 = {
        "ecc": ecc2["ecc"],
        "subject": "alice",
        "action": "export_customers",
        "target": "endpoint:analytics.internal",
        "parameters": {"count": 10},
    }

    resp1 = client.post("/execute", json=body1).json()
    resp2 = client.post("/execute", json=body2).json()

    assert resp1.get("decision") == "ALLOW", f"Expected ALLOW for first presentation, got {resp1}"
    assert resp2.get("decision") == "BLOCK", f"Expected BLOCK for second presentation, got {resp2}"
    assert resp2.get("reason") == "AUTH_TOKEN_ALREADY_REDEEMED", f"Expected AUTH_TOKEN_ALREADY_REDEEMED, got {resp2.get('reason')}"
    assert len(upstream_calls) == 1, f"Expected UPSTREAM_EXECUTION_COUNT == 1, got {len(upstream_calls)}"
    assert auth_id in default_redemption_store.redeemed_auth_ids


def test_c6_auth_id_concurrent_double_redemption(setup_c6_environment):
    """
    AUTH_ID_CONCURRENT_REDEMPTION_TEST:
    Deterministic concurrency test for two simultaneous presentations using
    distinct otherwise-valid ECC presentations bound to the SAME authorization auth_ref.
    Classification: TESTED_SINGLE_PROCESS_CONCURRENT_REDEMPTION
    """
    upstream_calls = setup_c6_environment
    client = TestClient(c6_app)

    auth_id = "AUTH-TEST-CONCURRENT-001"
    ecc1 = c7_compiler.generate_ecc(
        request_id="req-conc-1",
        session_id="sess-conc-1",
        subject="alice",
        action="export_customers",
        target="endpoint:analytics.internal",
        parameters={"count": 10},
        invariant_set_version="pilot-policy-set-v1",
        decision_basis="PERMIT_WITH_AUTHORIZATION",
        auth_id=auth_id,
        exception_scope={"action_class": "export_customers", "target_constraints": {"target": "endpoint:analytics.internal"}},
    )
    ecc2 = c7_compiler.generate_ecc(
        request_id="req-conc-2",
        session_id="sess-conc-2",
        subject="alice",
        action="export_customers",
        target="endpoint:analytics.internal",
        parameters={"count": 10},
        invariant_set_version="pilot-policy-set-v1",
        decision_basis="PERMIT_WITH_AUTHORIZATION",
        auth_id=auth_id,
        exception_scope={"action_class": "export_customers", "target_constraints": {"target": "endpoint:analytics.internal"}},
    )

    barrier = threading.Barrier(2)
    results = {}

    def worker(worker_id: str, ecc_payload: dict):
        body = {
            "ecc": ecc_payload["ecc"],
            "subject": "alice",
            "action": "export_customers",
            "target": "endpoint:analytics.internal",
            "parameters": {"count": 10},
        }
        barrier.wait()
        results[worker_id] = client.post("/execute", json=body).json()

    t1 = threading.Thread(target=worker, args=("W1", ecc1))
    t2 = threading.Thread(target=worker, args=("W2", ecc2))

    t1.start()
    t2.start()
    t1.join()
    t2.join()

    decisions = [results["W1"].get("decision"), results["W2"].get("decision")]
    reasons = [results["W1"].get("reason"), results["W2"].get("reason")]

    successful_auth_redemptions = decisions.count("ALLOW")
    blocked_auth_redemptions = decisions.count("BLOCK")

    assert successful_auth_redemptions == 1, f"Expected 1 ALLOW, got {successful_auth_redemptions} (results: {results})"
    assert blocked_auth_redemptions == 1, f"Expected 1 BLOCK, got {blocked_auth_redemptions} (results: {results})"
    assert "AUTH_TOKEN_ALREADY_REDEEMED" in reasons, f"Expected AUTH_TOKEN_ALREADY_REDEEMED in {reasons}"
    assert len(upstream_calls) == 1, f"Expected UPSTREAM_EXECUTION_COUNT == 1, got {len(upstream_calls)}"
    assert auth_id in default_redemption_store.redeemed_auth_ids


def test_c6_ecc_nonce_replay(setup_c6_environment):
    """
    ECC_NONCE_REPLAY_TEST (CROA §4.8):
    Direct post-genericization C6 test proving capability nonce single-use semantics.
    Presenting the same valid ECC twice must allow the first and block the second.
    """
    upstream_calls = setup_c6_environment
    client = TestClient(c6_app)

    ecc = c7_compiler.generate_ecc(
        request_id="req-nonce-1",
        session_id="sess-nonce-1",
        subject="alice",
        action="export_customers",
        target="endpoint:analytics.internal",
        parameters={"count": 10},
        invariant_set_version="pilot-policy-set-v1",
    )

    body = {
        "ecc": ecc["ecc"],
        "subject": "alice",
        "action": "export_customers",
        "target": "endpoint:analytics.internal",
        "parameters": {"count": 10},
    }

    resp1 = client.post("/execute", json=body).json()
    resp2 = client.post("/execute", json=body).json()

    assert resp1.get("decision") == "ALLOW", f"Expected ALLOW for first presentation, got {resp1}"
    assert resp2.get("decision") == "BLOCK", f"Expected BLOCK for second presentation, got {resp2}"
    assert resp2.get("reason") == "ECC_ALREADY_REDEEMED", f"Expected ECC_ALREADY_REDEEMED, got {resp2.get('reason')}"
    assert len(upstream_calls) == 1, f"Expected UPSTREAM_EXECUTION_COUNT == 1, got {len(upstream_calls)}"


def test_c6_independent_ecc_positive_control(setup_c6_environment):
    """
    NEGATIVE CONTROL / INDEPENDENT POSITIVE CONTROL:
    Two independent valid ECCs with different nonces and no conflicting authorization
    redemption state must both be allowed.
    Prevents false PASS caused by any firewall logic improperly blocking subsequent calls.
    """
    upstream_calls = setup_c6_environment
    client = TestClient(c6_app)

    ecc1 = c7_compiler.generate_ecc(
        request_id="req-indep-1",
        session_id="sess-indep-1",
        subject="alice",
        action="export_customers",
        target="endpoint:analytics.internal",
        parameters={"count": 10},
        invariant_set_version="pilot-policy-set-v1",
    )
    ecc2 = c7_compiler.generate_ecc(
        request_id="req-indep-2",
        session_id="sess-indep-2",
        subject="alice",
        action="export_customers",
        target="endpoint:analytics.internal",
        parameters={"count": 10},
        invariant_set_version="pilot-policy-set-v1",
    )

    body1 = {
        "ecc": ecc1["ecc"],
        "subject": "alice",
        "action": "export_customers",
        "target": "endpoint:analytics.internal",
        "parameters": {"count": 10},
    }
    body2 = {
        "ecc": ecc2["ecc"],
        "subject": "alice",
        "action": "export_customers",
        "target": "endpoint:analytics.internal",
        "parameters": {"count": 10},
    }

    resp1 = client.post("/execute", json=body1).json()
    resp2 = client.post("/execute", json=body2).json()

    assert resp1.get("decision") == "ALLOW", f"Expected ALLOW for first execution, got {resp1}"
    assert resp2.get("decision") == "ALLOW", f"Expected ALLOW for second execution, got {resp2}"
    assert len(upstream_calls) == 2, f"Expected UPSTREAM_EXECUTION_COUNT == 2, got {len(upstream_calls)}"
