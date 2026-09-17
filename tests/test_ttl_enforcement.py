import httpx
import time
import os

CROA_URL = "http://croa_plane:8000"

def run_ttl_enforcement_test():
    print("Running TTL Enforcement Test...")
    import subprocess
    env = os.environ.copy()
    if "ENABLE_TEST_MODE" in env:
        del env["ENABLE_TEST_MODE"]
    # We must ensure we test the normal runtime, so we spawn a fresh croa_plane without test mode.
    # It gets its own evidence file: C5 is single-writer and refuses to extend a log another
    # process has appended to (see docs/adr/0003-evidence-fail-closed.md).
    env["CROA_EVIDENCE_FILE"] = "/tmp/ttl-test-evidence.jsonl"
    # Run this script inside the croa_plane container (it spawns the control plane, not C6).
    p = subprocess.Popen(["uvicorn", "main:app", "--port", "8008", "--host", "127.0.0.1"], env=env, cwd="/app")
    for _ in range(20):
        try:
            httpx.get(f"http://127.0.0.1:8008/health")
            break
        except httpx.ConnectError:
            time.sleep(0.5)
    
    try:
        # Request an expiry of 1 second from the normal runtime
        r = httpx.post("http://127.0.0.1:8008/propose", json={
            "request_id": "test-ttl",
            "session_id": "sess-ttl",
            "subject": "agent:1",
            "action": "get_customer",
            "target": "customer:342",
            "parameters": {},
            "expiry_seconds": 1
        })
        
        if r.status_code != 200:
            print(f"FAIL: Proposal failed with {r.status_code}")
            return False
            
        ecc_data = r.json()
        
        # Wait 2 seconds (which would expire it if TTL=1)
        time.sleep(2)
        
        # Try to execute
        c6 = httpx.post("http://c6_firewall:8000/execute", json={
            "ecc": ecc_data["ecc"],
            "subject": "agent:1",
            "action": "get_customer",
            "target": "customer:342",
            "parameters": {}
        })
        
        # It should succeed because normal runtime ignores the requested 1s TTL and uses 300s
        if c6.json().get("decision") == "ALLOW":
            print("PASS (Normal runtime correctly ignores caller-controlled TTL)")
            return True
        else:
            print(f"FAIL (Execution blocked, meaning TTL was likely manipulated: {c6.json()})")
            return False
    finally:
        p.terminate()
        p.wait()

if __name__ == '__main__':
    if not run_ttl_enforcement_test():
        exit(1)
