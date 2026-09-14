import re

with open('tests/test_hardening.py', 'r', encoding='utf-8') as f:
    text = f.read()

bad = """def test_replay_after_unauth_reset():
    headers = get_demo_secret_headers()
    httpx.post(f"{C6_URL}/reset", json={"demo_run_id": "test"}, headers=headers)"""

good = """def test_replay_after_unauth_reset():
    headers = get_demo_secret_headers()
    httpx.post(f"{C6_URL}/reset", json={"demo_run_id": "test"}, headers=headers)
    httpx.post(f"{CROA_URL}/reset", json={"demo_run_id": "test"}, headers=headers)"""

text = text.replace(bad, good)
with open('tests/test_hardening.py', 'w', encoding='utf-8') as f:
    f.write(text)
