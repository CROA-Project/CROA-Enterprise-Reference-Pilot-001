import os

def scan_files():
    mojibake = ["â€”", "â€“", "â€™", "â€œ", "â€", "Â", ""]
    # We write it with escape sequences to avoid PowerShell mangling
    mojibake = [
        "\u00e2\u20ac\u201d", # â€”
        "\u00e2\u20ac\u201c", # â€“
        "\u00e2\u20ac\u2122", # â€™
        "\u00e2\u20ac\u0153", # â€œ
        "\u00e2\u20ac",       # â€
        "\u00c2",             # Â
        "\ufffd"              # 
    ]
    
    found_in = {}
    for root, dirs, files in os.walk("."):
        if ".git" in root or "__pycache__" in root:
            continue
        for file in files:
            path = os.path.join(root, file)
            # Only check known text extensions
            if not path.endswith((".py", ".md", ".yml", ".html", ".sh", ".json", ".txt")):
                if file not in [".env", ".env.example", ".gitignore"]:
                    continue
            
            try:
                with open(path, "r", encoding="utf-8") as f:
                    content = f.read()
                    
                matches = set()
                for seq in mojibake:
                    if seq in content:
                        matches.add(seq.encode('unicode_escape').decode())
                
                if matches:
                    found_in[path] = matches
                    
            except UnicodeDecodeError:
                pass
                
    for path, matches in found_in.items():
        print(f"{path}: {matches}")

scan_files()
