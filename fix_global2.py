import re

with open('croa_plane/main.py', 'r', encoding='utf-8') as f:
    text = f.read()

text = re.sub(r'trajectory_state: Dict\[str, int\] = \{\}', 'trajectory_state: Dict[str, int] = {}\n_test_c5_unavailable = False', text)

with open('croa_plane/main.py', 'w', encoding='utf-8') as f:
    f.write(text)
print("Fixed _test_c5_unavailable")
