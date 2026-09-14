import re

with open('croa_plane/main.py', 'r', encoding='utf-8') as f:
    text = f.read()

text = text.replace('if os.environ.get("ENABLE_TEST_MODE", "0") == "1":', 'print("IS_TEST:", os.environ.get("ENABLE_TEST_MODE", "0") == "1")\nif os.environ.get("ENABLE_TEST_MODE", "0") == "1":')

with open('croa_plane/main.py', 'w', encoding='utf-8') as f:
    f.write(text)
print("Added print")
