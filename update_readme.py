import os

with open("README.md", "r", encoding="utf-8") as f:
    text = f.read()

old = "This pilot proves that legitimate actions are permitted, prohibited actions are denied, cumulative trajectories are enforced *before* execution, and that operations cannot execute without a cryptographically valid Execution Change Contract (ECC)."
new = "This pilot demonstrates, within its modeled scenarios and documented trust assumptions, that legitimate actions are permitted, prohibited actions are denied, cumulative trajectories are enforced *before* execution, and that operations cannot execute without a cryptographically valid Execution Change Contract (ECC)."

text = text.replace(old, new)

with open("README.md", "w", encoding="utf-8") as f:
    f.write(text)

print("Updated README.md")
