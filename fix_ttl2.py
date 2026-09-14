import os

with open('tests/test_ttl_enforcement.py', 'r', encoding='utf-8') as f:
    text = f.read()

bad = """        # Wait 2 seconds (which would expire it if TTL=1)
        for _ in range(20):
        try:
            httpx.get(f"http://127.0.0.1:8008/health")
            break
        except httpx.ConnectError:
            time.sleep(0.5)"""

good = """        # Wait 2 seconds (which would expire it if TTL=1)
        time.sleep(2)"""

text = text.replace(bad, good)

bad2 = """    p = subprocess.Popen(["uvicorn", "main:app", "--port", "8008", "--host", "127.0.0.1"], env=env, cwd="/app")
    time.sleep(2)"""
    
good2 = """    p = subprocess.Popen(["uvicorn", "main:app", "--port", "8008", "--host", "127.0.0.1"], env=env, cwd="/app")
    for _ in range(20):
        try:
            httpx.get("http://127.0.0.1:8008/health")
            break
        except httpx.ConnectError:
            time.sleep(0.5)"""

text = text.replace(bad2, good2)

with open('tests/test_ttl_enforcement.py', 'w', encoding='utf-8') as f:
    f.write(text)

print("Fixed test_ttl_enforcement.py")
