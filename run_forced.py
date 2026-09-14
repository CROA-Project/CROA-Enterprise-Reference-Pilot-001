import subprocess

def run_test():
    with open("tests/test_hardening.py", 'r', encoding='utf-8') as f:
        code = f.read()
    
    code = code.replace(
        'results["TEST-A: C4 reset requires auth"] = "PASS"', 
        'results["TEST-A: C4 reset requires auth"] = "FAIL (FORCED)"\n        passed_all = False'
    )
    
    p = subprocess.Popen(
        f"docker exec -i croa-pilot-001-croa_plane-1 python -", 
        shell=True, 
        stdin=subprocess.PIPE, 
        stdout=subprocess.PIPE, 
        stderr=subprocess.PIPE
    )
    out, err = p.communicate(input=code.encode('utf-8'))
    print(out.decode())
    print(err.decode())
    print(f"EXIT CODE: {p.returncode}")

run_test()
