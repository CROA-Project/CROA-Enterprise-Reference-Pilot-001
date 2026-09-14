import os

with open('tests/test_ttl_enforcement.py', 'r', encoding='utf-8') as f:
    text = f.read()

text = text.replace('http://localhost:8000/execute', 'http://c6_firewall:8000/execute')

with open('tests/test_ttl_enforcement.py', 'w', encoding='utf-8') as f:
    f.write(text)

with open('run_reg3.py', 'r', encoding='utf-8') as f:
    text2 = f.read()

text2 = text2.replace('run_test("tests/test_ttl_enforcement.py", "croa-pilot-001-c6_firewall-1")', 'run_test("tests/test_ttl_enforcement.py", "croa-pilot-001-croa_plane-1")')

with open('run_reg3.py', 'w', encoding='utf-8') as f:
    f.write(text2)

print("Updated hostnames and run_reg3")
