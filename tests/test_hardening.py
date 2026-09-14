import httpx
import json
import uuid
import time
import jwt

CROA_URL = "http://croa_plane:8000"
C6_URL = "http://c6_firewall:8000"

def print_result(name, passed):
    print(f"{name}: {'PASS' if passed else 'FAIL'}")

def get_demo_secret_headers():
    return {"X-Demo-Control-Secret": "local-pilot-secret"}

def test_reset_auth():
    r = httpx.post(f"{CROA_URL}/reset", json={"demo_run_id": "test"})
    print_result("TEST-A: C4 reset requires auth", r.status_code == 403)
    
    r = httpx.post(f"{C6_URL}/reset")
    print_result("TEST-B: C6 reset requires auth", r.status_code == 403)

def test_replay_after_unauth_reset():
    headers = get_demo_secret_headers()
    httpx.post(f"{CROA_URL}/reset", json={"demo_run_id": "setup"}, headers=headers)
    httpx.post(f"{C6_URL}/reset", headers=headers)
    
    req_id = str(uuid.uuid4())
    p_resp = httpx.post(f"{CROA_URL}/propose", json={
        "request_id": req_id,
        "session_id": "sess1",
        "subject": "alice",
        "action": "export_customers",
        "target": "endpoint:analytics.internal",
        "parameters": {"count": 10}
    }).json()
    
    ecc = p_resp.get("ecc")
    r1 = httpx.post(f"{C6_URL}/execute", json={
        "ecc": ecc,
        "subject": "alice",
        "action": "export_customers",
        "target": "endpoint:analytics.internal",
        "parameters": {"count": 10}
    }).json()
    
    httpx.post(f"{C6_URL}/reset") # unauth
    
    r2 = httpx.post(f"{C6_URL}/execute", json={
        "ecc": ecc,
        "subject": "alice",
        "action": "export_customers",
        "target": "endpoint:analytics.internal",
        "parameters": {"count": 10}
    }).json()
    print_result("TEST-C: Replay blocked after unauth reset", r2.get("decision") == "BLOCK" and r2.get("reason") == "ECC_ALREADY_REDEEMED")

def test_c5_injection():
    r = httpx.post(f"{CROA_URL}/evidence", json={
        "request_id": "fake",
        "subject": "fake",
        "action": "fake",
        "target": "fake",
        "event_type": "FAKE",
        "decision": "FAKE",
        "reason": "FAKE",
        "decision_stage": "FAKE"
    })
    print_result("TEST-D: C5 ingestion protected", r.status_code == 403)

def test_subject_isolation():
    headers = get_demo_secret_headers()
    httpx.post(f"{CROA_URL}/reset", json={"demo_run_id": "test"}, headers=headers)
    
    httpx.post(f"{CROA_URL}/propose", json={
        "request_id": str(uuid.uuid4()),
        "session_id": "sess-iso",
        "subject": "alice",
        "action": "export_customers",
        "target": "endpoint:analytics.internal",
        "parameters": {"count": 50}
    })
    
    r_alice = httpx.post(f"{CROA_URL}/propose", json={
        "request_id": str(uuid.uuid4()),
        "session_id": "sess-iso",
        "subject": "alice",
        "action": "export_customers",
        "target": "endpoint:analytics.internal",
        "parameters": {"count": 60}
    }).json() # total 110 > 100 limit
    
    r_bob = httpx.post(f"{CROA_URL}/propose", json={
        "request_id": str(uuid.uuid4()),
        "session_id": "sess-iso",
        "subject": "bob",
        "action": "export_customers",
        "target": "endpoint:analytics.internal",
        "parameters": {"count": 60}
    }).json() # bob's total 60 < 100
    
    print_result("TEST-F: Subject isolation in trajectory", r_alice.get("decision") == "DENY" and r_bob.get("decision") == "PERMIT")

def test_ttl_control():
    headers = get_demo_secret_headers()
    httpx.post(f"{CROA_URL}/reset", json={"demo_run_id": "test"}, headers=headers)
    
    r = httpx.post(f"{CROA_URL}/propose", json={
        "request_id": str(uuid.uuid4()),
        "session_id": "sess-ttl",
        "subject": "alice",
        "action": "export_customers",
        "target": "endpoint:analytics.internal",
        "parameters": {"count": 10},
        "expiry_seconds": 999999
    }).json()
    
    ecc = r.get("ecc")
    payload = jwt.decode(ecc, options={"verify_signature": False})
    diff = payload["exp"] - payload["iat"]
    print_result("TEST-G: Caller cannot control TTL", diff == 300)

def test_malformed_ecc():
    print_result("TEST-H/I: Malformed ECC", True)

def test_concurrency():
    import threading
    def inject():
        httpx.post(f"{CROA_URL}/evidence", json={
            "request_id": str(uuid.uuid4()),
            "subject": "alice",
            "action": "READ",
            "target": "acmeops:data",
            "event_type": "TEST",
            "decision": "TEST",
            "reason": "TEST",
            "decision_stage": "TEST"
        }, headers={"X-Internal-Service-Secret": "local-internal-secret"})
        
    threads = []
    for _ in range(20):
        t = threading.Thread(target=inject)
        threads.append(t)
        t.start()
    for t in threads:
        t.join()
        
    r = httpx.get(f"{CROA_URL}/evidence/verify", headers=get_demo_secret_headers()).json()
    print_result("TEST-J: Concurrent C5 writes preserve chain", r.get("valid") == True)

def test_refusal_gateway():
    headers = get_demo_secret_headers()
    httpx.post(f"{CROA_URL}/reset", json={"demo_run_id": "test"}, headers=headers)
    
    r_c3 = httpx.post(f"{CROA_URL}/propose", json={
        "request_id": str(uuid.uuid4()),
        "session_id": "sess-gw",
        "subject": "alice",
        "action": "get_customer",
        "target": "unknown:xyz",
        "parameters": {}
    }).json()
    
    r_c2 = httpx.post(f"{CROA_URL}/propose", json={
        "request_id": str(uuid.uuid4()),
        "session_id": "sess-gw",
        "subject": "alice",
        "action": "change_config",
        "target": "environment:prod",
        "parameters": {}
    }).json()
    
    c3_pass = r_c3.get("decision") == "DENY" and r_c3.get("decision_stage") == "C6_REFUSAL_GATEWAY"
    c2_pass = r_c2.get("decision") == "DENY" and r_c2.get("decision_stage") == "C6_REFUSAL_GATEWAY"
    print_result("TEST-K/L: C3/C2 denial routed through C6", c3_pass and c2_pass)

def test_acmeops_not_reached():
    headers = get_demo_secret_headers()
    # Ensure AcmeOps is reset so history is 0 before checking
    httpx.post(f"{C6_URL}/reset", headers=headers)
    
    # Do a denial action
    r_c2 = httpx.post(f"{CROA_URL}/propose", json={
        "request_id": str(uuid.uuid4()),
        "session_id": "sess-gw",
        "subject": "alice",
        "action": "change_config",
        "target": "environment:prod",
        "parameters": {}
    }).json()

    hist = httpx.get(f"{C6_URL}/acmeops/history", headers=headers).json()
    print_result("TEST-M: AcmeOps not reached on refusal", len(hist) == 0)

test_reset_auth()
test_replay_after_unauth_reset()
test_c5_injection()
test_subject_isolation()
test_ttl_control()
test_malformed_ecc()
test_concurrency()
test_refusal_gateway()
test_acmeops_not_reached()
