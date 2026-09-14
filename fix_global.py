import re

with open('croa_plane/main.py', 'r', encoding='utf-8') as f:
    text = f.read()

bad = """trajectory_state = {}"""
good = """trajectory_state = {}
_test_c5_unavailable = False"""

if good not in text:
    text = text.replace(bad, good)
    with open('croa_plane/main.py', 'w', encoding='utf-8') as f:
        f.write(text)
    print("Fixed _test_c5_unavailable")
