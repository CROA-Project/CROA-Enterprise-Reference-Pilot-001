import os

replacements = {
    "\u00e2\u20ac\u201d": "—", # em dash
    "\u00e2\u20ac\u201c": "–", # en dash
    "\u00e2\u20ac\u2122": "’", # right single quote
    "\u00e2\u20ac\u0153": "“", # left double quote
    "\u00e2\u20ac\u009d": "”", # right double quote (assuming 9d, but wait, maybe just \u00e2\u20ac ?)
    "\u00c2\u00a0": " ",       # non-breaking space
    "\u00c2": " ",             # fallback Â
}

def fix_file(path):
    with open(path, 'rb') as f:
        content = f.read().decode('utf-8')
    
    original = content
    # Handle the specific sequences
    content = content.replace("â€”", "—")
    content = content.replace("â€“", "–")
    content = content.replace("â€™", "’")
    content = content.replace("â€œ", "“")
    content = content.replace("â€\u009d", "”")
    content = content.replace("â€", "”") # fallback for leftover â€
    content = content.replace("Â\u00a0", " ")
    content = content.replace("Â", " ")
    content = content.replace("", "")
    
    if content != original:
        with open(path, 'wb') as f:
            f.write(content.encode('utf-8'))
        print(f"Fixed {path}")

fix_file("README.md")
fix_file("ui/index.html")
