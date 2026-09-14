import subprocess
import time
import sys
import os

def run_test(file_path, container):
    with open(file_path, 'r', encoding='utf-8') as f:
        p = subprocess.Popen(
            f"docker exec -i {container} python -", 
            shell=True, 
            stdin=f, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE
        )
        out, err = p.communicate()
        print(out.decode())
        print(err.decode())
        print(f"EXIT CODE: {p.returncode}")
        return p.returncode

def run(cmd):
    p = subprocess.Popen(cmd, shell=True)
    p.communicate()

print("Running test_phase4.py")
run("docker compose -f docker-compose.yml -f docker-compose.test.yml up -d")
time.sleep(3)
run_test("tests/test_phase4.py", "croa-pilot-001-c6_firewall-1")
run("docker compose down")
run("docker compose up -d")

time.sleep(5)
print("\nRunning test_phase5.py")
run_test("tests/test_phase5.py", "croa-pilot-001-c6_firewall-1")

print("\nRunning test_ttl_enforcement.py")
run_test("tests/test_ttl_enforcement.py", "croa-pilot-001-c6_firewall-1")

print("\nRunning test_hardening.py")
run_test("tests/test_hardening.py", "croa-pilot-001-croa_plane-1")

