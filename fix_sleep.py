import re

def fix_file(filename, port):
    with open(filename, 'r', encoding='utf-8') as f:
        text = f.read()
    
    # replace time.sleep(2) with a polling loop
    bad = "time.sleep(2)"
    good = f"""for _ in range(20):
        try:
            httpx.get(f"http://127.0.0.1:{port}/health")
            break
        except httpx.ConnectError:
            time.sleep(0.5)"""
            
    text = text.replace(bad, good)
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(text)

fix_file('tests/test_hardening.py', 8005)
fix_file('tests/test_ttl_enforcement.py', 8008)
print("Added polling")
