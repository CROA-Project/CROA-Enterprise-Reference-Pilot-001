import httpx
import time
import os

CROA_URL = "http://croa_plane:8000"

def run_ttl_enforcement_test():
    print("Running TTL Enforcement Test...")
    # Request an expiry of 1 second
    r = httpx.post(f"{CROA_URL}/propose", json={
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
    c6 = httpx.post("http://localhost:8000/execute", json={
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

if __name__ == '__main__':
    if not run_ttl_enforcement_test():
        exit(1)
