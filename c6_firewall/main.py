from fastapi import FastAPI, HTTPException, Header, Depends
from pydantic import BaseModel
import httpx
import jwt
import json
import hashlib
import time
import os

from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8080", "http://127.0.0.1:8080"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

PUBLIC_KEY_PATH = "/app/public.pem"
CROA_EVIDENCE_URL = "http://croa_plane:8000/evidence"
ACMEOPS_URL = "http://acmeops_api:8000"

DEMO_CONTROL_SECRET = os.environ.get("DEMO_CONTROL_SECRET", "local-pilot-secret")
INTERNAL_SERVICE_SECRET = os.environ.get("INTERNAL_SERVICE_SECRET", "local-internal-secret")

REDEEMED_NONCES = set()

with open(PUBLIC_KEY_PATH, "r") as f:
    PUBLIC_KEY = f.read()

def verify_demo_control(x_demo_control_secret: str = Header(None)):
    if x_demo_control_secret != DEMO_CONTROL_SECRET:
        raise HTTPException(status_code=403, detail="Forbidden: Invalid demo control secret")

def verify_internal_service(x_internal_service_secret: str = Header(None)):
    if x_internal_service_secret != INTERNAL_SERVICE_SECRET:
        raise HTTPException(status_code=403, detail="Forbidden: Invalid internal service secret")

class ExecuteRequest(BaseModel):
    ecc: str
    subject: str
    action: str
    target: str
    parameters: dict

class RefusalRequest(BaseModel):
    request_id: str
    session_id: str
    subject: str
    action: str
    target: str
    decision: str
    reason: str
    decision_stage: str

def hash_parameters(params: dict) -> str:
    canonical_json = json.dumps(params, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(canonical_json.encode('utf-8')).hexdigest()

def log_evidence(req_id: str, session_id: str, ecc_id: str, subject: str, action: str, target: str, event_type: str, decision: str, reason: str, invariant_set_version: str = None, execution_id: str = None, target_status: str = None, raise_on_fail: bool = False):
    data = {
        "request_id": req_id or "unknown",
        "session_id": session_id,
        "ecc_id": ecc_id,
        "subject": subject,
        "action": action,
        "target": target,
        "event_type": event_type,
        "decision": decision,
        "reason": reason,
        "decision_stage": "C6",
        "invariant_set_version": invariant_set_version
    }
    if execution_id:
        data["execution_id"] = execution_id
    if target_status:
        data["target_status"] = target_status
        
    try:
        r = httpx.post(CROA_EVIDENCE_URL, json=data, headers={"X-Internal-Service-Secret": INTERNAL_SERVICE_SECRET})
        r.raise_for_status()
    except Exception as e:
        if raise_on_fail:
            raise e

@app.post("/refuse", dependencies=[Depends(verify_internal_service)])
async def refuse_gateway(req: RefusalRequest):
    log_evidence(req.request_id, req.session_id, None, req.subject, req.action, req.target, "EXECUTION_BLOCKED", "DENY", req.reason, None)
    return {
        "request_id": req.request_id,
        "decision": "DENY",
        "reason": req.reason,
        "decision_stage": "C6_REFUSAL_GATEWAY",
        "source_stage": req.decision_stage
    }

@app.post("/execute")
async def execute(req: ExecuteRequest):
    if not req.ecc:
        log_evidence("unknown", None, None, req.subject, req.action, req.target, "EXECUTION_BLOCKED", "BLOCK", "MISSING_ECC")
        return {"decision": "BLOCK", "reason": "MISSING_ECC"}
        
    try:
        payload = jwt.decode(req.ecc, PUBLIC_KEY, algorithms=["RS256"])
    except jwt.ExpiredSignatureError:
        try:
            unverified = jwt.decode(req.ecc, options={"verify_signature": False})
            log_evidence(unverified.get("request_id"), unverified.get("session_id"), unverified.get("ecc_id"), req.subject, req.action, req.target, "EXECUTION_BLOCKED", "BLOCK", "ECC_EXPIRED", unverified.get("invariant_set_version"))
        except:
            log_evidence("unknown", None, None, req.subject, req.action, req.target, "EXECUTION_BLOCKED", "BLOCK", "ECC_EXPIRED")
        return {"decision": "BLOCK", "reason": "ECC_EXPIRED"}
    except jwt.InvalidTokenError:
        try:
            unverified = jwt.decode(req.ecc, options={"verify_signature": False})
            log_evidence(unverified.get("request_id"), unverified.get("session_id"), unverified.get("ecc_id"), req.subject, req.action, req.target, "EXECUTION_BLOCKED", "BLOCK", "INVALID_SIGNATURE", unverified.get("invariant_set_version"))
        except:
            log_evidence("unknown", None, None, req.subject, req.action, req.target, "EXECUTION_BLOCKED", "BLOCK", "INVALID_SIGNATURE")
        return {"decision": "BLOCK", "reason": "INVALID_SIGNATURE"}

    req_id = payload.get("request_id")
    ecc_id = payload.get("ecc_id")
    nonce = payload.get("nonce")
    session_id = payload.get("session_id")
    inv_version = payload.get("invariant_set_version")
    
    # Mandatory claim validation
    mandatory_claims = ["request_id", "ecc_id", "nonce", "session_id", "subject", "action", "target", "parameters_hash", "invariant_set_version", "iat", "exp"]
    if not all(claim in payload for claim in mandatory_claims):
        log_evidence(req_id, session_id, ecc_id, req.subject, req.action, req.target, "EXECUTION_BLOCKED", "BLOCK", "MALFORMED_ECC", inv_version)
        return {"decision": "BLOCK", "reason": "MALFORMED_ECC"}
        
    if not ecc_id or not nonce:
        log_evidence(req_id, session_id, ecc_id, req.subject, req.action, req.target, "EXECUTION_BLOCKED", "BLOCK", "MALFORMED_ECC", inv_version)
        return {"decision": "BLOCK", "reason": "MALFORMED_ECC"}
    
    log_evidence(req_id, session_id, ecc_id, req.subject, req.action, req.target, "EXECUTION_ATTEMPT", "EVALUATE", "VALIDATING", inv_version)
    
    if nonce in REDEEMED_NONCES:
        log_evidence(req_id, session_id, ecc_id, req.subject, req.action, req.target, "EXECUTION_BLOCKED", "BLOCK", "ECC_ALREADY_REDEEMED", inv_version)
        return {"decision": "BLOCK", "reason": "ECC_ALREADY_REDEEMED"}
        
    if payload.get("subject") != req.subject:
        log_evidence(req_id, session_id, ecc_id, req.subject, req.action, req.target, "EXECUTION_BLOCKED", "BLOCK", "SUBJECT_MISMATCH", inv_version)
        return {"decision": "BLOCK", "reason": "SUBJECT_MISMATCH"}
        
    if payload.get("action") != req.action:
        log_evidence(req_id, session_id, ecc_id, req.subject, req.action, req.target, "EXECUTION_BLOCKED", "BLOCK", "ACTION_MISMATCH", inv_version)
        return {"decision": "BLOCK", "reason": "ACTION_MISMATCH"}
        
    if payload.get("target") != req.target:
        log_evidence(req_id, session_id, ecc_id, req.subject, req.action, req.target, "EXECUTION_BLOCKED", "BLOCK", "TARGET_MISMATCH", inv_version)
        return {"decision": "BLOCK", "reason": "TARGET_MISMATCH"}
        
    if payload.get("parameters_hash") != hash_parameters(req.parameters):
        log_evidence(req_id, session_id, ecc_id, req.subject, req.action, req.target, "EXECUTION_BLOCKED", "BLOCK", "OPERATION_MISMATCH", inv_version)
        return {"decision": "BLOCK", "reason": "OPERATION_MISMATCH"}
        
    if inv_version != "pilot-policy-set-v1":
        log_evidence(req_id, session_id, ecc_id, req.subject, req.action, req.target, "EXECUTION_BLOCKED", "BLOCK", "INVARIANT_VERSION_MISMATCH", inv_version)
        return {"decision": "BLOCK", "reason": "INVARIANT_VERSION_MISMATCH"}
        
    try:
        log_evidence(req_id, session_id, ecc_id, req.subject, req.action, req.target, "EXECUTION_AUTHORIZED", "ALLOW", "ECC_VALIDATED", inv_version, raise_on_fail=True)
    except Exception:
        return {"decision": "BLOCK", "reason": "EVIDENCE_UNAVAILABLE"}

    REDEEMED_NONCES.add(nonce)
    
    try:
        async with httpx.AsyncClient() as client:
            acmeops_resp = await client.post(f"{ACMEOPS_URL}/internal/execute", json={
                "action": req.action,
                "target": req.target,
                "parameters": req.parameters
            })
            acmeops_resp.raise_for_status()
            acmeops_data = acmeops_resp.json()
            
            log_evidence(req_id, session_id, ecc_id, req.subject, req.action, req.target, "EXECUTION_SUCCEEDED", "ALLOW", "EXECUTION_COMPLETED", inv_version, execution_id=acmeops_data.get("execution_id"), target_status="SUCCESS")
            return {"decision": "ALLOW", "acmeops_result": acmeops_data}
    except Exception as e:
        log_evidence(req_id, session_id, ecc_id, req.subject, req.action, req.target, "EXECUTION_FAILED", "ALLOW", "TARGET_SYSTEM_FAILURE", inv_version, target_status="FAILURE")
        return {"decision": "ALLOW", "reason": "TARGET_SYSTEM_FAILURE"}

@app.get("/health")
async def health():
    reach = False
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            r = await client.get(f"{ACMEOPS_URL}/health")
            reach = (r.status_code == 200)
    except:
        pass
    return {"status": "ONLINE", "acmeops_reachable": reach}

@app.post("/reset", dependencies=[Depends(verify_demo_control)])
async def reset():
    REDEEMED_NONCES.clear()
    try:
        async with httpx.AsyncClient() as client:
            await client.post(f"{ACMEOPS_URL}/internal/reset")
    except:
        pass
    return {"status": "reset"}

@app.get("/acmeops/history", dependencies=[Depends(verify_demo_control)])
async def acmeops_history():
    try:
        async with httpx.AsyncClient() as client:
            r = await client.get(f"{ACMEOPS_URL}/internal/history")
            return r.json()
    except:
        return []
