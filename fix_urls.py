import os

for filename in ['tests/test_phase4.py', 'tests/test_phase5.py']:
    with open(filename, 'r', encoding='utf-8') as f:
        text = f.read()

    text = text.replace('C6_URL = "http://localhost:8000"', 'C6_URL = "http://c6_firewall:8000"')
    
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(text)

print("Updated C6_URL in test_phase4 and test_phase5")
