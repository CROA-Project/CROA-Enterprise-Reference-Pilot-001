import httpx
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

class MockResponse:
    def __init__(self):
        self.status_code = 200

captured_evidence = []

def mock_post(*args, **kwargs):
    if "json" in kwargs:
        captured_evidence.append(kwargs["json"])
    return MockResponse()

httpx.post = mock_post

def test_1_missing_ecc_block_with_request_id():
    captured_evidence.clear()
    resp = client.post("/execute", json={
        "ecc": "",
        "subject": "finance_ai",
        "action": "update_customer_pricing",
        "target": "pricing_system",
        "parameters": {},
        "request_id": "test-req-123"
    })
    assert resp.status_code == 200
    assert resp.json() == {"decision": "BLOCK", "reason": "MISSING_ECC"}

    assert len(captured_evidence) == 1
    ev = captured_evidence[0]
    assert ev["request_id"] == "test-req-123"
    assert ev["decision"] == "BLOCK"
    assert ev["reason"] == "MISSING_ECC"
    assert ev["event_type"] == "EXECUTION_BLOCKED"
    assert ev.get("ecc_id") is None

def test_3_missing_ecc_no_request_id():
    captured_evidence.clear()
    resp = client.post("/execute", json={
        "ecc": "",
        "subject": "finance_ai",
        "action": "update_customer_pricing",
        "target": "pricing_system",
        "parameters": {}
    })
    assert resp.status_code == 200
    assert resp.json() == {"decision": "BLOCK", "reason": "MISSING_ECC"}

    assert len(captured_evidence) == 1
    ev = captured_evidence[0]
    assert ev["request_id"] == "unknown"
    assert ev["decision"] == "BLOCK"
    assert ev["reason"] == "MISSING_ECC"
    assert ev["event_type"] == "EXECUTION_BLOCKED"

def test_4_arbitrary_request_id_cannot_grant_authority():
    captured_evidence.clear()
    resp = client.post("/execute", json={
        "ecc": "",
        "subject": "finance_ai",
        "action": "update_customer_pricing",
        "target": "pricing_system",
        "parameters": {},
        "request_id": "admin-override"
    })
    assert resp.status_code == 200
    assert resp.json()["decision"] == "BLOCK"
    ev = captured_evidence[0]
    assert ev["request_id"] == "admin-override"
    assert ev["decision"] == "BLOCK"

def test_6_valid_looking_request_id_cannot_substitute():
    captured_evidence.clear()
    resp = client.post("/execute", json={
        "ecc": "",
        "subject": "finance_ai",
        "action": "update_customer_pricing",
        "target": "pricing_system",
        "parameters": {},
        "request_id": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.dummy.dummy"
    })
    assert resp.status_code == 200
    assert resp.json()["decision"] == "BLOCK"
    ev = captured_evidence[0]
    assert ev["decision"] == "BLOCK"
    assert ev["reason"] == "MISSING_ECC"

if __name__ == "__main__":
    test_1_missing_ecc_block_with_request_id()
    test_3_missing_ecc_no_request_id()
    test_4_arbitrary_request_id_cannot_grant_authority()
    test_6_valid_looking_request_id_cannot_substitute()
    print("ALL C6 CORRELATION TESTS PASSED")
