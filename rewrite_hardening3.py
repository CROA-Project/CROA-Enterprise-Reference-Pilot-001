import httpx
import json
import os
import uuid
import time
import jwt
import threading

CROA_URL = "http://localhost:8000"
C6_URL = "http://c6_firewall:8000"

results = {}
passed_all = True

def report(name, passed, diagnostics=""):
    global passed_all
    if passed:
        results[name] = "PASS"
    else:
        results[name] = f"FAIL {diagnostics}"
        passed_all = False

def get_demo_secret_headers():
    return {"X-Demo-Control-Secret": os.environ.get("DEMO_CONTROL_SECRET", "")}

def test_c4_reset_auth():
    r = httpx.post(f"{CROA_URL}/reset", json={"demo_run_id": "test"})
    report("TEST-A: C4 reset requires auth", r.status_code == 403)

def test_c6_reset_auth():
    r = httpx.post(f"{C6_URL}/reset", json={"demo_run_id": "test"})
    report("TEST-B: C6 reset requires auth", r.status_code == 403)

def test_replay_after_unauth_reset():
    headers = get_demo_secret_headers()
    httpx.post(f"{C6_URL}/reset", json={"demo_run_id": "test"}, headers=headers)
    
    p_resp = httpx.post(f"{CROA_URL}/propose", json={
        "request_id": str(uuid.uuid4()),
        "session_id": "sess-replay",
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
    report("TEST-C: Replay blocked after unauth reset", r2.get("decision") == "BLOCK" and r2.get("reason") == "ECC_ALREADY_REDEEMED")

def test_c5_auth():
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
    report("TEST-D: C5 ingestion protected", r.status_code == 403)

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
    
    report("TEST-F: Subject isolation in trajectory", r_alice.get("decision") == "DENY" and r_bob.get("decision") == "PERMIT")

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
    report("TEST-G: Caller cannot control TTL", diff == 300)

def test_malformed_ecc():
    h_before = len(httpx.get(f"{C6_URL}/acmeops/history", headers={"X-Demo-Control-Secret": os.environ["DEMO_CONTROL_SECRET"]}).json())
    # A. missing nonce
    # Generate a valid token without nonce
    import jwt
    with open('private.pem', 'rb') as kf:
        private_key = kf.read()
    
    payload_a = {
        "ecc_id": str(uuid.uuid4()),
        "request_id": "malformed-1",
        "session_id": "sess-malformed",
        "subject": "agent:1",
        "action": "get_customer",
        "target": "customer:342",
        "parameters_hash": "dummy",
        "invariant_set_version": "pilot-policy-set-v1",
        "iat": int(time.time()),
        "exp": int(time.time()) + 300
    }
    ecc_a = jwt.encode(payload_a, private_key, algorithm="RS256")
    
    r_a = httpx.post(f"{C6_URL}/execute", json={
        "ecc": ecc_a,
        "subject": "agent:1",
        "action": "get_customer",
        "target": "customer:342",
        "parameters": {}
    })
    
    if r_a.json().get("decision") == "BLOCK" and r_a.json().get("reason") == "MALFORMED_ECC" and len(httpx.get(f"{C6_URL}/acmeops/history", headers={"X-Demo-Control-Secret": os.environ["DEMO_CONTROL_SECRET"]}).json()) == h_before:
        pass
    else:
        report("TEST-H/I: Malformed ECC", False, f"Missing nonce failed: {r_a.json()}")
        return
        
    payload_b = payload_a.copy()
    payload_b["nonce"] = str(uuid.uuid4())
    del payload_b["ecc_id"]
    ecc_b = jwt.encode(payload_b, private_key, algorithm="RS256")
    
    r_b = httpx.post(f"{C6_URL}/execute", json={
        "ecc": ecc_b,
        "subject": "agent:1",
        "action": "get_customer",
        "target": "customer:342",
        "parameters": {}
    })
    
    if r_b.json().get("decision") == "BLOCK" and r_b.json().get("reason") == "MALFORMED_ECC" and len(httpx.get(f"{C6_URL}/acmeops/history", headers={"X-Demo-Control-Secret": os.environ["DEMO_CONTROL_SECRET"]}).json()) == h_before:
        report("TEST-H/I: Malformed ECC", True)
    else:
        report("TEST-H/I: Malformed ECC", False, f"Missing ecc_id failed: {r_b.json()}")

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
        }, headers={"X-Internal-Service-Secret": os.environ["INTERNAL_SERVICE_SECRET"]})
        
    threads = []
    for _ in range(20):
        t = threading.Thread(target=inject)
        threads.append(t)
        t.start()
    for t in threads:
        t.join()
        
    r = httpx.get(f"{CROA_URL}/evidence/verify", headers=get_demo_secret_headers()).json()
    report("TEST-J: Concurrent C5 writes preserve chain", r.get("valid") == True)

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
    report("TEST-K/L: C3/C2 denial routed through C6", c3_pass and c2_pass)

def test_acmeops_not_reached():
    headers = get_demo_secret_headers()
    httpx.post(f"{C6_URL}/reset", headers=headers)
    
    r_c2 = httpx.post(f"{CROA_URL}/propose", json={
        "request_id": str(uuid.uuid4()),
        "session_id": "sess-gw",
        "subject": "alice",
        "action": "change_config",
        "target": "environment:prod",
        "parameters": {}
    }).json()

    hist = httpx.get(f"{C6_URL}/acmeops/history", headers=headers).json()
    report("TEST-M: AcmeOps not reached on refusal", len(hist) == 0)

def test_c5_fail_closed():
    # A. Obtain valid ECC
    r = httpx.post(f"{CROA_URL}/propose", json={"request_id": "c5-1", "session_id": "sess-c5", "subject": "agent:1", "action": "get_customer", "target": "customer:342", "parameters": {}}).json()
    
    # B. Make C5 unavailable via Demo Control
    httpx.post(f"{CROA_URL}/demo-control/c5-fail", json={"unavailable": True}, headers=get_demo_secret_headers())
    
    # C. Submit ECC to C6
    h_before = len(httpx.get(f"{C6_URL}/acmeops/history", headers=get_demo_secret_headers()).json())
    x = httpx.post(f"{C6_URL}/execute", json={"ecc": r["ecc"], "subject": "agent:1", "action": "get_customer", "target": "customer:342", "parameters": {}}).json()
    h_after = len(httpx.get(f"{C6_URL}/acmeops/history", headers=get_demo_secret_headers()).json())
    
    # D & E. Assert BLOCK, reason EVIDENCE_UNAVAILABLE, history unchanged
    passed = (x.get("decision") == "BLOCK" and x.get("reason") == "EVIDENCE_UNAVAILABLE" and h_before == h_after)
    
    # F. Restore C5
    httpx.post(f"{CROA_URL}/demo-control/c5-fail", json={"unavailable": False}, headers=get_demo_secret_headers())
    
    report("TEST-N: C5 Fail-Closed Execution", passed, f"Failed with {x}")

def run_tests():
    test_c4_reset_auth()
    test_c6_reset_auth()
    test_replay_after_unauth_reset()
    test_c5_auth()
    test_subject_isolation()
    test_ttl_control()
    test_malformed_ecc()
    test_concurrency()
    test_refusal_gateway()
    test_acmeops_not_reached()
    test_c5_fail_closed()
    
    print(json.dumps(results, indent=2))
    return passed_all

if __name__ == "__main__":
    if not run_tests():
        exit(1)
