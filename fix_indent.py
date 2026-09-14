import re

with open('tests/test_hardening.py', 'r', encoding='utf-8') as f:
    text = f.read()

text = text.replace('            print(json.dumps(results, indent=2))', '    print(json.dumps(results, indent=2))')

with open('tests/test_hardening.py', 'w', encoding='utf-8') as f:
    f.write(text)
print("Fixed indent")
