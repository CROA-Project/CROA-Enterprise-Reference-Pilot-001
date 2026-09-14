import re

with open('croa_plane/main.py', 'r', encoding='utf-8') as f:
    text = f.read()

bad = """@app.post("/demo-control/c5-fail", dependencies=[Depends(verify_demo_control)])
def toggle_c5(req: C5ControlRequest):
    global _test_c5_unavailable
    _test_c5_unavailable = req.unavailable
    return {"status": "ok"}"""

good = """if os.environ.get("ENABLE_TEST_MODE", "0") == "1":
    @app.post("/demo-control/c5-fail", dependencies=[Depends(verify_demo_control)])
    def toggle_c5(req: C5ControlRequest):
        global _test_c5_unavailable
        _test_c5_unavailable = req.unavailable
        return {"status": "ok"}"""

if bad in text:
    text = text.replace(bad, good)
    with open('croa_plane/main.py', 'w', encoding='utf-8') as f:
        f.write(text)
    print("Replaced successfully.")
else:
    print("Not found.")
