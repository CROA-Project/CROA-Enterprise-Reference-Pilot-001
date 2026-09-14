import re

with open('croa_plane/main.py', 'r', encoding='utf-8') as f:
    text = f.read()

evidence_endpoint = """@app.post("/evidence", dependencies=[Depends(verify_internal_service)])
def post_evidence(ev: EvidenceRequest):"""

evidence_modified = """@app.post("/evidence", dependencies=[Depends(verify_internal_service)])
def post_evidence(ev: EvidenceRequest):
    if _test_c5_unavailable:
        raise HTTPException(status_code=503, detail="Simulated C5 Unavailable")"""

if evidence_endpoint in text:
    text = text.replace(evidence_endpoint, evidence_modified)
    with open('croa_plane/main.py', 'w', encoding='utf-8') as f:
        f.write(text)
    print("Replaced!")
else:
    print("Not found!")
