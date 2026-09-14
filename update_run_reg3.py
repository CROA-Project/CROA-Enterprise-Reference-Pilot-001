import os

with open('run_reg3.py', 'r', encoding='utf-8') as f:
    text = f.read()

text = text.replace('run("docker compose up -d")', 'run("docker compose -f docker-compose.yml -f docker-compose.test.yml up -d")')

with open('run_reg3.py', 'w', encoding='utf-8') as f:
    f.write(text)
print("Updated run_reg3.py")
