from fastapi import FastAPI, HTTPException, Header, Depends
from pydantic import BaseModel
from typing import Optional, Set, Tuple
import httpx
import jwt
import json
import hashlib
import time
import os
import threading

from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8080", "http://127.0.0.1:8080"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

PUBLIC_KEY_PATH = os.environ.get("PUBLIC_KEY_PATH", "/app/public.pem")
if not os.path.exists(PUBLIC_KEY_PATH):
    _local_key = os.path.join(os.path.dirname(__file__), "public.pem")
    if os.path.exists(_local_key):
        PUBLIC_KEY_PATH = _local_key
CROA_EVIDENCE_URL = os.environ.get("CROA_EVIDENCE_URL", "http://croa_plane:8000/evidence")
UPSTREAM_TARGET_URL = os.environ.get("UPSTREAM_TARGET_URL", os.environ.get("ACMEOPS_URL", "http://acmeops_api:8000"))
ACMEOPS_URL = UPSTREAM_TARGET_URL

DEMO_CONTROL_SECRET = os.environ.get("DEMO_CONTROL_SECRET")
if not DEMO_CONTROL_SECRET:
    raise RuntimeError("DEMO_CONTROL_SECRET is not set. See .env.example")
INTERNAL_SERVICE_SECRET = os.environ.get("INTERNAL_SERVICE_SECRET")
if not INTERNAL_SERVICE_SECRET:
    raise RuntimeError("INTERNAL_SERVICE_SECRET is not set. See .env.example")

class InMemoryRedemptionStore:
    """
    SINGLE-PROCESS REFERENCE HARNESS REDEMPTION STORE ONLY.
    Maintains in-memory nonce and authorization artifact redemption tracking
    protected by a threading lock.
    Designed exclusively for reference harness demonstration and local testing.
    Not suitable for distributed production enterprise deployment.
    """
    def __init__(self):
        self._redeemed_nonces: Set[str] = set()
        self._redeemed_auth_ids: Set[str] = set()
        self._lock = threading.Lock()

    @property
    def lock(self) -> threading.Lock:
        return self._lock

    @property
    def redeemed_nonces(self) -> Set[str]:
        return self._redeemed_nonces

    @property
    def redeemed_auth_ids(self) -> Set[str]:
        return self._redeemed_auth_ids

    def clear(self) -> None:
        with self._lock:
            self._redeemed_nonces.clear()
            self._redeemed_auth_ids.clear()

default_redemption_store = InMemoryRedemptionStore()
REDEEMED_NONCES = default_redemption_store.redeemed_nonces
REDEEMED_AUTH_IDS = default_redemption_store.redeemed_auth_ids
_redemption_lock = default_redemption_store.lock

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
    request_id: Optional[str] = None

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
        log_evidence(req.request_id or "unknown", None, None, req.subject, req.action, req.target, "EXECUTION_BLOCKED", "BLOCK", "MISSING_ECC")
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

    # Atomic redemption of capability nonce and authorization artifact (NT-007 / CROA §4.8)
    auth_ref = payload.get("auth_ref") or payload.get("ecc.auth_ref")
    exception_scope = payload.get("exception_scope") or payload.get("ecc.exception_scope")

    with _redemption_lock:
        if nonce in REDEEMED_NONCES:
            log_evidence(req_id, session_id, ecc_id, req.subject, req.action, req.target, "EXECUTION_BLOCKED", "BLOCK", "ECC_ALREADY_REDEEMED", inv_version)
            return {"decision": "BLOCK", "reason": "ECC_ALREADY_REDEEMED"}

        if auth_ref:
            if auth_ref in REDEEMED_AUTH_IDS:
                log_evidence(req_id, session_id, ecc_id, req.subject, req.action, req.target, "EXECUTION_BLOCKED", "BLOCK", "AUTH_TOKEN_ALREADY_REDEEMED", inv_version)
                return {"decision": "BLOCK", "reason": "AUTH_TOKEN_ALREADY_REDEEMED"}

            if exception_scope:
                allowed_act = exception_scope.get("action_class")
                if allowed_act and allowed_act != req.action:
                    log_evidence(req_id, session_id, ecc_id, req.subject, req.action, req.target, "EXECUTION_BLOCKED", "BLOCK", "OPERATION_OUTSIDE_AUTH_SCOPE", inv_version)
                    return {"decision": "BLOCK", "reason": "OPERATION_OUTSIDE_AUTH_SCOPE"}

                allowed_tgt = exception_scope.get("target_constraints", {}).get("target")
                if allowed_tgt and allowed_tgt != req.target:
                    log_evidence(req_id, session_id, ecc_id, req.subject, req.action, req.target, "EXECUTION_BLOCKED", "BLOCK", "OPERATION_OUTSIDE_AUTH_SCOPE", inv_version)
                    return {"decision": "BLOCK", "reason": "OPERATION_OUTSIDE_AUTH_SCOPE"}

            REDEEMED_AUTH_IDS.add(auth_ref)

        REDEEMED_NONCES.add(nonce)

    try:
        log_evidence(req_id, session_id, ecc_id, req.subject, req.action, req.target, "EXECUTION_AUTHORIZED", "ALLOW", "ECC_VALIDATED", inv_version, raise_on_fail=True)
    except Exception:
        return {"decision": "BLOCK", "reason": "EVIDENCE_UNAVAILABLE"}
    
    try:
        async with httpx.AsyncClient() as client:
            acmeops_resp = await client.post(f"{UPSTREAM_TARGET_URL}/internal/execute", json={
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
            r = await client.get(f"{UPSTREAM_TARGET_URL}/health")
            reach = (r.status_code == 200)
    except:
        pass
    return {"status": "ONLINE", "acmeops_reachable": reach}

@app.post("/reset", dependencies=[Depends(verify_demo_control)])
async def reset():
    default_redemption_store.clear()
    try:
        async with httpx.AsyncClient() as client:
            await client.post(f"{UPSTREAM_TARGET_URL}/internal/reset")
    except:
        pass
    return {"status": "reset"}

@app.get("/acmeops/history", dependencies=[Depends(verify_demo_control)])
async def acmeops_history():
    try:
        async with httpx.AsyncClient() as client:
            r = await client.get(f"{UPSTREAM_TARGET_URL}/internal/history")
            return r.json()
    except:
        return []
