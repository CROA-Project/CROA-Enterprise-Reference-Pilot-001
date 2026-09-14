import os
with open('tests/test_phase5.py', 'r', encoding='utf-8') as f:
    text = f.read()

text = text.replace('except Exception as e:\n            results["Scenario A"] = f"FAIL ({e})"', 'except Exception as e:\n            import traceback\n            results["Scenario A"] = f"FAIL ({traceback.format_exc()})"')
text = text.replace('except Exception as e:\n            results["Scenario D"] = f"FAIL ({e})"', 'except Exception as e:\n            import traceback\n            results["Scenario D"] = f"FAIL ({traceback.format_exc()})"')
text = text.replace('except Exception as e:\n            results["Scenario E"] = f"FAIL ({e})"', 'except Exception as e:\n            import traceback\n            results["Scenario E"] = f"FAIL ({traceback.format_exc()})"')

with open('tests/test_phase5.py', 'w', encoding='utf-8') as f:
    f.write(text)
print("Modified test_phase5.py to print tracebacks")
