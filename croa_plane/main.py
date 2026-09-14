from fastapi import FastAPI, HTTPException, Header, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Dict, Any, Optional
import json
import hashlib
from datetime import datetime
import os
import httpx

from c3_resolver import resolve_target
from c2_governor import evaluate_request
from c5_evidence import record_event
from c7_compiler import generate_ecc
from c4_trajectory import trajectory_state

app = FastAPI()
_test_c5_unavailable = False

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8080", "http://127.0.0.1:8080"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DEMO_CONTROL_SECRET = os.environ.get("DEMO_CONTROL_SECRET")
if not DEMO_CONTROL_SECRET:
    raise RuntimeError("DEMO_CONTROL_SECRET is not set. See .env.example")
INTERNAL_SERVICE_SECRET = os.environ.get("INTERNAL_SERVICE_SECRET")
if not INTERNAL_SERVICE_SECRET:
    raise RuntimeError("INTERNAL_SERVICE_SECRET is not set. See .env.example")
C6_URL = "http://c6_firewall:8000"

def verify_demo_control(x_demo_control_secret: str = Header(None)):
    if x_demo_control_secret != DEMO_CONTROL_SECRET:
        raise HTTPException(status_code=403, detail="Forbidden: Invalid demo control secret")

def verify_internal_service(x_internal_service_secret: str = Header(None)):
    if x_internal_service_secret != INTERNAL_SERVICE_SECRET:
        raise HTTPException(status_code=403, detail="Forbidden: Invalid internal service secret")

class ProposeRequest(BaseModel):
    request_id: str
    session_id: str
    subject: str
    action: str
    target: str
    parameters: Optional[Dict[str, Any]] = {}
    expiry_seconds: Optional[int] = None

class EvidenceRequest(BaseModel):
    request_id: str
    session_id: Optional[str] = None
    subject: str
    action: str
    target: str
    event_type: str
    decision: str
    reason: str
    decision_stage: str
    ecc_id: Optional[str] = None
    execution_id: Optional[str] = None
    target_status: Optional[str] = None
    invariant_set_version: Optional[str] = None

class ResetRequest(BaseModel):
    demo_run_id: str

@app.get("/health")
def health_check():
    return {"status": "ONLINE"}

class C5ControlRequest(BaseModel):
    unavailable: bool

print("IS_TEST:", os.environ.get("ENABLE_TEST_MODE", "0") == "1")
if os.environ.get("ENABLE_TEST_MODE", "0") == "1":
    @app.post("/demo-control/c5-fail", dependencies=[Depends(verify_demo_control)])
    def toggle_c5(req: C5ControlRequest):
        global _test_c5_unavailable
        _test_c5_unavailable = req.unavailable
        return {"status": "ok"}

@app.post("/reset", dependencies=[Depends(verify_demo_control)])
def reset_demo(req: ResetRequest):
    trajectory_state.clear()
    record_event(
        request_id=req.demo_run_id,
        session_id=req.demo_run_id,
        subject="system",
        action="reset",
        target="none",
        event_type="DEMO_RESET",
        decision="ALLOW",
        reason="DEMO_RESET",
        decision_stage="C5"
    )
    return {"status": "reset", "demo_run_id": req.demo_run_id}

@app.get("/evidence", dependencies=[Depends(verify_demo_control)])
def get_evidence():
    events = []
    try:
        with open("/app/evidence_data/evidence.jsonl", "r") as f:
            for line in f:
                events.append(json.loads(line.strip()))
    except FileNotFoundError:
        pass
    return events

@app.get("/evidence/verify", dependencies=[Depends(verify_demo_control)])
def verify_evidence():
    prev = "0000000000000000000000000000000000000000000000000000000000000000"
    try:
        with open("/app/evidence_data/evidence.jsonl", "r") as f:
            for line in f:
                data = json.loads(line.strip())
                h = data.pop("event_hash")
                if data["previous_hash"] != prev:
                    return {"valid": False, "reason": f"broken chain at {data['event_id']}"}
                expected = hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()
                if expected != h:
                    return {"valid": False, "reason": f"hash mismatch at {data['event_id']}"}
                prev = h
    except FileNotFoundError:
        pass
    return {"valid": True}

@app.post("/evidence", dependencies=[Depends(verify_internal_service)])
def post_evidence(ev: EvidenceRequest):
    if _test_c5_unavailable:
        raise HTTPException(status_code=503, detail="Simulated C5 Unavailable")
    record_event(
        request_id=ev.request_id,
        session_id=ev.session_id,
        subject=ev.subject,
        action=ev.action,
        target=ev.target,
        event_type=ev.event_type,
        decision=ev.decision,
        reason=ev.reason,
        decision_stage=ev.decision_stage,
        ecc_id=ev.ecc_id,
        execution_id=ev.execution_id,
        target_status=ev.target_status,
        invariant_set_version=ev.invariant_set_version
    )
    return {"status": "ok"}

def forward_to_c6_refusal_gateway(deny_payload: dict) -> dict:
    try:
        with httpx.Client() as client:
            resp = client.post(
                f"{C6_URL}/refuse",
                json=deny_payload,
                headers={"X-Internal-Service-Secret": INTERNAL_SERVICE_SECRET}
            )
            if resp.status_code == 200:
                return resp.json()
    except Exception:
        pass
    return deny_payload

@app.post("/propose")
def propose_action(req: ProposeRequest):
    timestamp = datetime.utcnow().isoformat() + "Z"
    is_grounded, grounding_reason = resolve_target(req.action, req.target)
    
    if not is_grounded:
        record_event(req.request_id, req.session_id, req.subject, req.action, req.target, 
                     "GROUNDING_FAILED", "DENY", grounding_reason, "C3", None, "pilot-policy-set-v1")
        deny_payload = {
            "request_id": req.request_id, "session_id": req.session_id, "subject": req.subject, "action": req.action, "target": req.target,
            "decision": "DENY", "reason": grounding_reason, "decision_stage": "C3", "policy_id": None, "invariant_set_version": "pilot-policy-set-v1", "timestamp": timestamp
        }
        return forward_to_c6_refusal_gateway(deny_payload)
        
    record_event(req.request_id, req.session_id, req.subject, req.action, req.target, 
                 "GROUNDING_PASSED", "PERMIT", "TARGET_GROUNDED", "C3", None, "pilot-policy-set-v1")
        
    c2_result = evaluate_request(req.dict())
    
    if c2_result["decision"] == "DENY":
        c2_result["session_id"] = req.session_id
        return forward_to_c6_refusal_gateway(c2_result)
        
    if c2_result["decision"] == "PERMIT":
        ttl = req.expiry_seconds if (req.expiry_seconds is not None and int(os.environ.get('ENABLE_TEST_MODE', '0')) == 1) else int(os.environ.get('ECC_TTL_SECONDS', 300))
        
        ecc_data = generate_ecc(
            request_id=req.request_id, session_id=req.session_id, subject=req.subject,
            action=req.action, target=req.target, parameters=req.parameters,
            invariant_set_version=c2_result["invariant_set_version"], expiry_seconds=ttl
        )
        record_event(
            req.request_id, req.session_id, req.subject, req.action, req.target,
            "ECC_ISSUED", "PERMIT", "ECC_GENERATED", "C7", c2_result["policy_id"], c2_result["invariant_set_version"],
            ecc_data={"ecc_id": ecc_data["ecc_id"], "parameters_hash": ecc_data["parameters_hash"], "expires_at": ecc_data["expires_at"]}
        )
        c2_result["ecc_id"] = ecc_data["ecc_id"]
        c2_result["ecc"] = ecc_data["ecc"]
        c2_result["expires_at"] = ecc_data["expires_at"]
        
    return c2_result
