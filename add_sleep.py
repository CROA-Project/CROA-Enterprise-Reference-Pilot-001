import os

with open('run_reg3.py', 'r', encoding='utf-8') as f:
    text = f.read()

text = text.replace('run("docker compose -f docker-compose.yml -f docker-compose.test.yml up -d")', 'run("docker compose -f docker-compose.yml -f docker-compose.test.yml up -d")\nimport time\ntime.sleep(2)')

with open('run_reg3.py', 'w', encoding='utf-8') as f:
    f.write(text)
print("Added sleep to run_reg3.py")
