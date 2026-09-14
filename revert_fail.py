import re

with open('tests/test_hardening.py', 'r', encoding='utf-8') as f:
    text = f.read()

text = text.replace('        passed_all = False\n        print(json.dumps(results, indent=2))', '        print(json.dumps(results, indent=2))')
text = text.replace('results["TEST-FORCED-FAILURE"] = "FAIL"\n', '')

with open('tests/test_hardening.py', 'w', encoding='utf-8') as f:
    f.write(text)
print("Reverted forced failure")
