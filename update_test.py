import os

with open('tests/test_hardening.py', 'r', encoding='utf-8') as f:
    text = f.read()

bad = """def test_c5_fail_closed():
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
    
    report("TEST-N: C5 Fail-Closed Execution", passed, f"Failed with {x}")"""

good = """def test_c5_fault_injection_modes():
    # 1. NORMAL RUNTIME (test by launching a temporary instance without test mode)
    import subprocess, time
    env = os.environ.copy()
    if "ENABLE_TEST_MODE" in env:
        del env["ENABLE_TEST_MODE"]
    p = subprocess.Popen(["uvicorn", "main:app", "--port", "8005", "--host", "127.0.0.1"], env=env, cwd="/app")
    time.sleep(2)
    try:
        r_norm = httpx.post("http://127.0.0.1:8005/demo-control/c5-fail", json={"unavailable": True}, headers=get_demo_secret_headers())
        report("Normal-runtime fault-injection endpoint unavailable", r_norm.status_code == 404, f"Got {r_norm.status_code}")
    finally:
        p.terminate()
        p.wait()

    # 2. TEST MODE WITHOUT DEMO SECRET
    r_unauth = httpx.post(f"{CROA_URL}/demo-control/c5-fail", json={"unavailable": True})
    report("Test-mode fault-injection requires secret", r_unauth.status_code in [401, 403], f"Got {r_unauth.status_code}")

    # 3. TEST MODE WITH VALID DEMO SECRET (TEST-N)
    r_auth = httpx.post(f"{CROA_URL}/demo-control/c5-fail", json={"unavailable": True}, headers=get_demo_secret_headers())
    success = (r_auth.status_code == 200)
    
    try:
        r = httpx.post(f"{CROA_URL}/propose", json={"request_id": "c5-1", "session_id": "sess-c5", "subject": "agent:1", "action": "get_customer", "target": "customer:342", "parameters": {}}).json()
        h_before = len(httpx.get(f"{C6_URL}/acmeops/history", headers=get_demo_secret_headers()).json())
        x = httpx.post(f"{C6_URL}/execute", json={"ecc": r["ecc"], "subject": "agent:1", "action": "get_customer", "target": "customer:342", "parameters": {}}).json()
        h_after = len(httpx.get(f"{C6_URL}/acmeops/history", headers=get_demo_secret_headers()).json())
        passed = (x.get("decision") == "BLOCK" and x.get("reason") == "EVIDENCE_UNAVAILABLE" and h_before == h_after)
        report("TEST-N: C5 Fail-Closed Execution", success and passed, f"Failed with {x}")
    finally:
        httpx.post(f"{CROA_URL}/demo-control/c5-fail", json={"unavailable": False}, headers=get_demo_secret_headers())"""

text = text.replace(bad, good)
text = text.replace("test_c5_fail_closed()", "test_c5_fault_injection_modes()")

with open('tests/test_hardening.py', 'w', encoding='utf-8') as f:
    f.write(text)
print("Replaced test_c5_fail_closed")
