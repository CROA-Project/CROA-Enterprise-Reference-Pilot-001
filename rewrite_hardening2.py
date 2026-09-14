import os

code = """import httpx
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

def get_history():
    return httpx.get(f"{C6_URL}/acmeops/history", headers={"X-Demo-Control-Secret": os.environ.get("DEMO_CONTROL_SECRET", "")}).json()

def test_c4_reset_auth():
    r = httpx.post(f"{CROA_URL}/reset", json={"demo_run_id": "test"})
    report("TEST-A: C4 reset requires auth", r.status_code == 403)

def test_c6_reset_auth():
    r = httpx.post(f"{C6_URL}/reset", json={"demo_run_id": "test"})
    report("TEST-B: C6 reset requires auth", r.status_code == 403)

def test_replay_after_unauth_reset():
    r1 = httpx.post(f"{CROA_URL}/propose", json={"request_id": "replay1", "session_id": "sess-replay", "subject": "agent:1", "action": "get_customer", "target": "customer:342", "parameters": {}}).json()
    httpx.post(f"{C6_URL}/execute", json={"ecc": r1["ecc"], "subject": "agent:1", "action": "get_customer", "target": "customer:342", "parameters": {}})
    httpx.post(f"{C6_URL}/reset", json={"demo_run_id": "test"}) # unauth
    r2 = httpx.post(f"{C6_URL}/execute", json={"ecc": r1["ecc"], "subject": "agent:1", "action": "get_customer", "target": "customer:342", "parameters": {}}).json()
    report("TEST-C: Replay blocked after unauth reset", r2.get("decision") == "BLOCK" and r2.get("reason") == "ECC_ALREADY_REDEEMED")

def test_c5_auth():
    r = httpx.post(f"{CROA_URL}/evidence", json={})
    report("TEST-D: C5 ingestion protected", r.status_code == 403)

def test_subject_isolation():
    r1 = httpx.post(f"{CROA_URL}/propose", json={"request_id": "s1", "session_id": "sess-sub-iso", "subject": "agent:1", "action": "export_customers", "target": "endpoint:analytics.internal", "parameters": {"count": 100}}).json()
    r_alice = httpx.post(f"{CROA_URL}/propose", json={"request_id": "s2", "session_id": "sess-sub-iso", "subject": "agent:alice", "action": "export_customers", "target": "endpoint:analytics.internal", "parameters": {"count": 1}}).json()
    r_bob = httpx.post(f"{CROA_URL}/propose", json={"request_id": "s3", "session_id": "sess-sub-iso-bob", "subject": "agent:bob", "action": "export_customers", "target": "endpoint:analytics.internal", "parameters": {"count": 1}}).json()
    report("TEST-F: Subject isolation in trajectory", r_alice.get("decision") == "DENY" and r_bob.get("decision") == "PERMIT")

def test_ttl_control():
    r = httpx.post(f"{CROA_URL}/propose", headers={"X-Test-Expiry-Seconds": "9999"}, json={"request_id": "ttl1", "session_id": "sess-ttl", "subject": "agent:1", "action": "get_customer", "target": "customer:342", "parameters": {}, "expiry_seconds": 9999}).json()
    token = r["ecc"]
    payload = jwt.decode(token, options={"verify_signature": False})
    diff = payload["exp"] - payload["iat"]
    report("TEST-G: Caller cannot control TTL", diff == 300)

def test_malformed_ecc():
    h_before = len(get_history())
    with open('private.pem', 'rb') as kf:
        private_key = kf.read()
    
    payload_a = {
        "ecc_id": str(uuid.uuid4()), "request_id": "malformed-1", "session_id": "sess-malformed", "subject": "agent:1", "action": "get_customer", "target": "customer:342", "parameters_hash": "dummy", "invariant_set_version": "pilot-policy-set-v1", "iat": int(time.time()), "exp": int(time.time()) + 300
    }
    ecc_a = jwt.encode(payload_a, private_key, algorithm="RS256")
    r_a = httpx.post(f"{C6_URL}/execute", json={"ecc": ecc_a, "subject": "agent:1", "action": "get_customer", "target": "customer:342", "parameters": {}})
    
    if not (r_a.json().get("decision") == "BLOCK" and r_a.json().get("reason") == "MALFORMED_ECC" and len(get_history()) == h_before):
        report("TEST-H/I: Malformed ECC (Missing nonce)", False, f"Missing nonce failed: {r_a.json()}")
        return
        
    payload_b = payload_a.copy()
    payload_b["nonce"] = str(uuid.uuid4())
    del payload_b["ecc_id"]
    ecc_b = jwt.encode(payload_b, private_key, algorithm="RS256")
    r_b = httpx.post(f"{C6_URL}/execute", json={"ecc": ecc_b, "subject": "agent:1", "action": "get_customer", "target": "customer:342", "parameters": {}})
    
    if r_b.json().get("decision") == "BLOCK" and r_b.json().get("reason") == "MALFORMED_ECC" and len(get_history()) == h_before:
        report("TEST-H/I: Malformed ECC", True)
    else:
        report("TEST-H/I: Malformed ECC", False, f"Missing ecc_id failed: {r_b.json()}")

def test_concurrency():
    sid = "sess-conc"
    reqs = []
    for i in range(5):
        reqs.append({"request_id": f"c{i}", "session_id": sid, "subject": "agent:1", "action": "export_customers", "target": "endpoint:analytics.internal", "parameters": {"count": 20}})
    
    def fire(req, out, idx):
        out[idx] = httpx.post(f"{CROA_URL}/propose", json=req).json()
        
    threads = []
    out = [None] * 5
    for i in range(5):
        t = threading.Thread(target=fire, args=(reqs[i], out, i))
        threads.append(t)
        t.start()
        
    for t in threads:
        t.join()
        
    r = httpx.get(f"{CROA_URL}/evidence/verify")
    report("TEST-J: Concurrent C5 writes preserve chain", r.json().get("valid") == True)

def test_c3_c2_denial():
    r = httpx.post(f"{CROA_URL}/propose", json={"request_id": "c3", "session_id": "sess-c3", "subject": "agent:1", "action": "get_customer", "target": "customer:999", "parameters": {}}).json()
    c3_pass = (r.get("decision") == "DENY" and r.get("decision_stage") == "C6_REFUSAL_GATEWAY" and "ecc" in r)
    r2 = httpx.post(f"{CROA_URL}/propose", json={"request_id": "c2", "session_id": "sess-c2", "subject": "agent:1", "action": "delete_environment", "target": "environment:dev", "parameters": {}}).json()
    c2_pass = (r2.get("decision") == "DENY" and r2.get("decision_stage") == "C6_REFUSAL_GATEWAY" and "ecc" in r2)
    report("TEST-K/L: C3/C2 denial routed through C6", c3_pass and c2_pass)

def test_acmeops_unreached():
    r = httpx.post(f"{CROA_URL}/propose", json={"request_id": "u1", "session_id": "sess-u1", "subject": "agent:1", "action": "delete_environment", "target": "environment:dev", "parameters": {}}).json()
    httpx.post(f"{C6_URL}/execute", json={"ecc": r["ecc"], "subject": "agent:1", "action": "delete_environment", "target": "environment:dev", "parameters": {}})
    hist = get_history()
    report("TEST-M: AcmeOps not reached on refusal", not any(x.get("request_id") == "u1" for x in hist))

def test_c5_fail_closed():
    r = httpx.post(f"{CROA_URL}/propose", json={"request_id": "c5-1", "session_id": "sess-c5", "subject": "agent:1", "action": "get_customer", "target": "customer:342", "parameters": {}}).json()
    httpx.post(f"{CROA_URL}/demo-control/c5-fail", json={"unavailable": True}, headers={"X-Demo-Control-Secret": os.environ.get("DEMO_CONTROL_SECRET", "")})
    
    h_before = len(get_history())
    x = httpx.post(f"{C6_URL}/execute", json={"ecc": r["ecc"], "subject": "agent:1", "action": "get_customer", "target": "customer:342", "parameters": {}}).json()
    h_after = len(get_history())
    
    passed = (x.get("decision") == "BLOCK" and x.get("reason") == "EVIDENCE_UNAVAILABLE" and h_before == h_after)
    httpx.post(f"{CROA_URL}/demo-control/c5-fail", json={"unavailable": False}, headers={"X-Demo-Control-Secret": os.environ.get("DEMO_CONTROL_SECRET", "")})
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
    test_c3_c2_denial()
    test_acmeops_unreached()
    test_c5_fail_closed()
    
    print(json.dumps(results, indent=2))
    return passed_all

if __name__ == "__main__":
    if not run_tests():
        exit(1)
"""

with open('tests/test_hardening.py', 'w', encoding='utf-8') as f:
    f.write(code)
