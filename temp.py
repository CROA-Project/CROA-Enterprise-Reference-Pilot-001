import os

with open("README.md", "r", encoding="utf-8") as f:
    text = f.read()

old = "The objective is to demonstrate that an AI agent may propose actions, but execution authority remains completely outside the agent. This pilot proves that legitimate actions are permitted, prohibited actions are denied, cumulative trajectories are enforced *before* execution, and that operations cannot execute without a cryptographically valid Execution Change Contract (ECC)."
# Wait, let me check the exact string in README.md first!
