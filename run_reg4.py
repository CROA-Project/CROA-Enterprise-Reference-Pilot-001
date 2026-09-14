import subprocess
import time

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

def run(cmd):
    p = subprocess.Popen(cmd, shell=True)
    p.communicate()

run("docker compose down")
run("docker compose -f docker-compose.yml -f docker-compose.test.yml up -d")
time.sleep(3)
run_test("tests/test_phase4.py", "croa-pilot-001-c6_firewall-1")
