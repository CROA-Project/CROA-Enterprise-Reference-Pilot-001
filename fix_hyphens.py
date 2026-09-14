import os

def fix_hyphens(path):
    with open(path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    original = content
    content = content.replace("A - Legitimate Action", "A \u2014 Legitimate Action")
    content = content.replace("B - Unknown Target", "B \u2014 Unknown Target")
    content = content.replace("C - Forbidden Action", "C \u2014 Forbidden Action")
    content = content.replace("D - Cumulative Trajectory", "D \u2014 Cumulative Trajectory")
    content = content.replace("E - Missing ECC", "E \u2014 Missing ECC")
    content = content.replace("F - Forged ECC", "F \u2014 Forged ECC")
    content = content.replace("G - Mutated Operation", "G \u2014 Mutated Operation")
    content = content.replace("H - Replay Attempt", "H \u2014 Replay Attempt")
    
    if content != original:
        with open(path, 'w', encoding='utf-8') as f:
            f.write(content)
        print(f"Fixed scenarios in {path}")

fix_hyphens("README.md")
fix_hyphens("ui/index.html")
