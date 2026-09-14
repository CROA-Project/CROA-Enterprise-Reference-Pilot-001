import os
with open('tests/test_ttl_enforcement.py', 'r', encoding='utf-8') as f:
    text = f.read()

bad = """    for _ in range(20):
        try:
            httpx.get(f"http://127.0.0.1:{8008}/health")
            break
        except httpx.ConnectError:
            time.sleep(0.5)
    
    try:"""

good = """    for _ in range(20):
        try:
            httpx.get(f"http://127.0.0.1:{8008}/health")
            break
        except httpx.ConnectError:
            time.sleep(0.5)
            
    try:"""

# Wait, the error is: `IndentationError: expected an indented block after 'for' statement on line 41`
# Because I probably messed up the indentation of the for loop block.
