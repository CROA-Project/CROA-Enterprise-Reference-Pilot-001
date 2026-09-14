import re

with open('croa_plane/main.py', 'r', encoding='utf-8') as f:
    text = f.read()

text = text.replace('app = FastAPI()', 'app = FastAPI()\n_test_c5_unavailable = False')

with open('croa_plane/main.py', 'w', encoding='utf-8') as f:
    f.write(text)
print("Fixed _test_c5_unavailable for real")
