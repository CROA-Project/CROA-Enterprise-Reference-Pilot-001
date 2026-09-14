import os
with open('tests/test_phase5.py', 'r', encoding='utf-8') as f:
    text = f.read()

text = text.replace('results["Scenario A"] = f"FAIL ({traceback.format_exc()})"', 'results["Scenario A"] = f"FAIL (x={x})"')
text = text.replace('results["Scenario E"] = f"FAIL ({traceback.format_exc()})"', 'results["Scenario E"] = f"FAIL (x={x})"')

with open('tests/test_phase5.py', 'w', encoding='utf-8') as f:
    f.write(text)
print("Modified test_phase5.py to print x")
