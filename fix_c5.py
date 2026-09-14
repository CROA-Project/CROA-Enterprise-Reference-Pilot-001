import re

with open('croa_plane/main.py', 'r', encoding='utf-8') as f:
    text = f.read()

# Add a global variable for test-only C5 failure
global_var = """trajectory_state = {}
_test_c5_unavailable = False"""
text = text.replace("trajectory_state = {}", global_var)

# Add demo endpoint to toggle it
demo_endpoint = """@app.post("/reset", dependencies=[Depends(verify_demo_control)])"""
new_endpoint = """class C5ControlRequest(BaseModel):
    unavailable: bool

@app.post("/demo-control/c5-fail", dependencies=[Depends(verify_demo_control)])
def toggle_c5(req: C5ControlRequest):
    global _test_c5_unavailable
    _test_c5_unavailable = req.unavailable
    return {"status": "ok"}

@app.post("/reset", dependencies=[Depends(verify_demo_control)])"""
text = text.replace(demo_endpoint, new_endpoint)

# Modify /evidence
evidence_endpoint = """@app.post("/evidence", dependencies=[Depends(verify_internal_service)])
def log_evidence(data: dict):"""
evidence_modified = """@app.post("/evidence", dependencies=[Depends(verify_internal_service)])
def log_evidence(data: dict):
    if _test_c5_unavailable:
        raise HTTPException(status_code=503, detail="Simulated C5 Unavailable")"""
text = text.replace(evidence_endpoint, evidence_modified)

with open('croa_plane/main.py', 'w', encoding='utf-8') as f:
    f.write(text)
