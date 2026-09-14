import os
import re

def fix_hyphens(path):
    with open(path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    original = content
    content = re.sub(r'A [-—–] Legitimate Action', 'A — Legitimate Action', content)
    content = re.sub(r'B [-—–] Unknown Target', 'B — Unknown Target', content)
    content = re.sub(r'C [-—–] Forbidden Action', 'C — Forbidden Action', content)
    content = re.sub(r'D [-—–] Cumulative Trajectory', 'D — Cumulative Trajectory', content)
    content = re.sub(r'E [-—–] Missing ECC', 'E — Missing ECC', content)
    content = re.sub(r'F [-—–] Forged ECC', 'F — Forged ECC', content)
    content = re.sub(r'G [-—–] Mutated Operation', 'G — Mutated Operation', content)
    content = re.sub(r'H [-—–] Replay Attempt', 'H — Replay Attempt', content)
    
    if content != original:
        with open(path, 'w', encoding='utf-8') as f:
            f.write(content)
        print(f"Fixed scenarios in {path}")

fix_hyphens("README.md")
fix_hyphens("ui/index.html")
