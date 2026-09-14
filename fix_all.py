import os
import re

def fix_all(path):
    with open(path, 'r', encoding='utf-8', errors='replace') as f:
        content = f.read()
    
    original = content
    
    # We replace any garbage between the letter and the word
    content = re.sub(r'A .*? Legitimate Action', 'A \u2014 Legitimate Action', content)
    content = re.sub(r'B .*? Unknown Target', 'B \u2014 Unknown Target', content)
    content = re.sub(r'C .*? Forbidden Action', 'C \u2014 Forbidden Action', content)
    content = re.sub(r'D .*? Cumulative Trajectory', 'D \u2014 Cumulative Trajectory', content)
    content = re.sub(r'E .*? Missing ECC', 'E \u2014 Missing ECC', content)
    content = re.sub(r'F .*? Forged ECC', 'F \u2014 Forged ECC', content)
    content = re.sub(r'G .*? Mutated Operation', 'G \u2014 Mutated Operation', content)
    content = re.sub(r'H .*? Replay Attempt', 'H \u2014 Replay Attempt', content)
    
    # Check for other single quotes etc.
    content = content.replace('\ufffd', '')
    content = content.replace('\u00e2\u20ac\u201c', '\u2013') # en dash
    content = content.replace('\u00e2\u20ac\u2122', '\u2019') # right single quote
    content = content.replace('\u00e2\u20ac\u0153', '\u201c') # left double quote
    content = content.replace('\u00e2\u20ac\u009d', '\u201d') # right double quote
    content = content.replace('\u00e2\u20ac', '\u201d') # fallback
    content = content.replace('\u00c2\u00a0', ' ')
    content = content.replace('\u00c2', ' ')
    
    if content != original:
        with open(path, 'w', encoding='utf-8') as f:
            f.write(content)
        print(f"Fixed scenarios in {path}")

fix_all("README.md")
fix_all("ui/index.html")
