import os

def scan_files():
    mojibake = [
        "\u00e2\u20ac\u201d", # â€”
        "\u00e2\u20ac\u201c", # â€“
        "\u00e2\u20ac\u2122", # â€™
        "\u00e2\u20ac\u0153", # â€œ
        "\u00e2\u20ac\u009d", # â€
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
            
            # Skip untracked python scripts created by me during testing
            if file.endswith('.py') and file not in [
                'main.py', 'test_hardening.py', 'test_phase5.py', 'test_ttl_enforcement.py',
                'generate_pilot_keys.py', 'c1_policy.py', 'c2_governor.py', 'c3_resolver.py',
                'c4_trajectory.py', 'c5_evidence.py', 'c7_compiler.py', 'test_phase2.py',
                'test_phase3.py', 'test_phase4.py'
            ]:
                continue
                
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
                
    if not found_in:
        print("No mojibake found!")
    for path, matches in found_in.items():
        print(f"{path}: {matches}")

scan_files()
