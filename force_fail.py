import re

with open('tests/test_hardening.py', 'r', encoding='utf-8') as f:
    text = f.read()

text = text.replace('print(json.dumps(results, indent=2))', 'results["TEST-FORCED-FAILURE"] = "FAIL"\n        passed_all = False\n        print(json.dumps(results, indent=2))')

with open('tests/test_hardening.py', 'w', encoding='utf-8') as f:
    f.write(text)
print("Added forced failure")
