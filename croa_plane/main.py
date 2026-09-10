from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Dict, Any, Optional
import json
import hashlib
from datetime import datetime

from c3_resolver import resolve_target
from c2_governor import evaluate_request
from c5_evidence import record_event
from c7_compiler import generate_ecc
from c4_trajectory import trajectory_state

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class ProposeRequest(BaseModel):
    request_id: str
    session_id: str
    subject: str
    action: str
    target: str
    parameters: Optional[Dict[str, Any]] = {}
    expiry_seconds: Optional[int] = 300 # for testing

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

@app.post("/reset")
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

@app.get("/evidence")
def get_evidence():
    events = []
    try:
        with open("/app/evidence_data/evidence.jsonl", "r") as f:
            for line in f:
                events.append(json.loads(line.strip()))
    except FileNotFoundError:
        pass
    return events

@app.get("/evidence/verify")
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

@app.post("/evidence")
def post_evidence(ev: EvidenceRequest):
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

@app.post("/propose")
def propose_action(req: ProposeRequest):
    timestamp = datetime.utcnow().isoformat() + "Z"
    is_grounded, grounding_reason = resolve_target(req.action, req.target)
    
    if not is_grounded:
        record_event(req.request_id, req.session_id, req.subject, req.action, req.target, 
                     "GROUNDING_FAILED", "DENY", grounding_reason, "C3", None, "pilot-policy-set-v1")
        return {
            "request_id": req.request_id, "subject": req.subject, "action": req.action, "target": req.target,
            "decision": "DENY", "reason": grounding_reason, "decision_stage": "C3", "policy_id": None, "invariant_set_version": "pilot-policy-set-v1", "timestamp": timestamp
        }
        
    record_event(req.request_id, req.session_id, req.subject, req.action, req.target, 
                 "GROUNDING_PASSED", "PERMIT", "TARGET_GROUNDED", "C3", None, "pilot-policy-set-v1")
        
    c2_result = evaluate_request(req.dict())
    
    if c2_result["decision"] == "PERMIT":
        ecc_data = generate_ecc(
            request_id=req.request_id, session_id=req.session_id, subject=req.subject,
            action=req.action, target=req.target, parameters=req.parameters,
            invariant_set_version=c2_result["invariant_set_version"], expiry_seconds=req.expiry_seconds
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
