import os
import glob

search_strings = ["â€”", "â€“", "â€™", "â€œ", "â€", "Â", ""]
replacements = {
    "â€”": "—", # em dash
    "â€“": "–", # en dash
    "â€™": "’", # right single quote
    "â€œ": "“", # left double quote
    "â€": "”",  # right double quote (or sometimes part of others)
    "Â": " ",   # often a non-breaking space Â
    "": ""
}

def scan_files():
    found_files = set()
    for root, dirs, files in os.walk("."):
        if ".git" in root or "__pycache__" in root:
            continue
        for file in files:
            path = os.path.join(root, file)
            try:
                with open(path, "r", encoding="utf-8") as f:
                    content = f.read()
                    
                for s in search_strings:
                    if s in content:
                        found_files.add(path)
                        print(f"Found '{s}' in {path}")
                        
            except UnicodeDecodeError:
                pass
                
scan_files()
