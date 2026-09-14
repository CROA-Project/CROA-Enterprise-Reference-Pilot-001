import subprocess
import os

try:
    proc = subprocess.Popen(
        ['git', 'credential', 'fill'],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    stdout, stderr = proc.communicate(input="protocol=https\nhost=github.com\n\n", timeout=5)
    print("STDOUT:", stdout)
except Exception as e:
    print("ERROR:", e)
