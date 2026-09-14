import os

with open('tests/test_ttl_enforcement.py', 'r', encoding='utf-8') as f:
    text = f.read()

bad = """    # Request an expiry of 1 second
    r = httpx.post(f"{CROA_URL}/propose", json={"""

good = """    import subprocess
    env = os.environ.copy()
    if "ENABLE_TEST_MODE" in env:
        del env["ENABLE_TEST_MODE"]
    # We must ensure we test the normal runtime, so we spawn a fresh croa_plane without test mode
    p = subprocess.Popen(["uvicorn", "main:app", "--port", "8008", "--host", "127.0.0.1"], env=env, cwd="/app")
    time.sleep(2)
    
    try:
        # Request an expiry of 1 second from the normal runtime
        r = httpx.post("http://127.0.0.1:8008/propose", json={"""

bad2 = """    if not run_ttl_enforcement_test():
        exit(1)"""

good2 = """    try:
        if not run_ttl_enforcement_test():
            exit(1)
    finally:
        # ensure we cleanup if it throws exception
        pass"""

text = text.replace(bad, good)
text = text.replace("    if r.status_code != 200:\n        print(f\"FAIL: Proposal failed with {r.status_code}\")\n        return False", "    if r.status_code != 200:\n        print(f\"FAIL: Proposal failed with {r.status_code}\")\n        p.terminate()\n        return False")
text = text.replace("        return True\n    else:\n        print(f\"FAIL (Execution blocked, meaning TTL was likely manipulated: {c6.json()})\")\n        return False", "        p.terminate()\n        return True\n    else:\n        print(f\"FAIL (Execution blocked, meaning TTL was likely manipulated: {c6.json()})\")\n        p.terminate()\n        return False")

with open('tests/test_ttl_enforcement.py', 'w', encoding='utf-8') as f:
    f.write(text)
print("Updated test_ttl_enforcement.py")
