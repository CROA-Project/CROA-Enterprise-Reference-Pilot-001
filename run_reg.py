import subprocess
import time
import sys

def run(cmd):
    p = subprocess.Popen(cmd, shell=True)
    p.communicate()
    print(f"EXIT CODE: {p.returncode}")
    return p.returncode

print("Running test_phase4.py")
run("docker compose -f docker-compose.yml -f docker-compose.test.yml up -d")
time.sleep(3)
run("cat tests/test_phase4.py | docker exec -i croa-pilot-001-c6_firewall-1 python -")
run("docker compose down")
run("docker compose up -d")

time.sleep(5)
print("\nRunning test_phase5.py")
run("cat tests/test_phase5.py | docker exec -i croa-pilot-001-c6_firewall-1 python -")

print("\nRunning test_ttl_enforcement.py")
run("cat tests/test_ttl_enforcement.py | docker exec -i croa-pilot-001-c6_firewall-1 python -")

print("\nRunning test_hardening.py")
run("cat tests/test_hardening.py | docker exec -i croa-pilot-001-croa_plane-1 python -")

