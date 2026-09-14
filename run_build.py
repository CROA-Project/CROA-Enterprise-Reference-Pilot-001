import subprocess

def run(cmd):
    p = subprocess.Popen(cmd, shell=True)
    p.communicate()

run("docker compose down")
run("docker compose build")
run("docker compose -f docker-compose.yml -f docker-compose.test.yml up -d")
