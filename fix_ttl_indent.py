import os

with open('tests/test_ttl_enforcement.py', 'r', encoding='utf-8') as f:
    text = f.read()

bad = """    try:
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
        p.terminate()
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
        p.terminate()
        return True
    else:
        print(f"FAIL (Execution blocked, meaning TTL was likely manipulated: {c6.json()})")
        p.terminate()
        return False"""

good = """    try:
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
        p.wait()"""

text = text.replace(bad, good)

with open('tests/test_ttl_enforcement.py', 'w', encoding='utf-8') as f:
    f.write(text)
print("Fixed indent in test_ttl_enforcement.py")
