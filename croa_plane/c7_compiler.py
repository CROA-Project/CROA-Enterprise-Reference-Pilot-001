import jwt
from datetime import datetime, timedelta, timezone
import uuid
import json
import hashlib

import os

PRIVATE_KEY_PATH = os.environ.get("PRIVATE_KEY_PATH", "/app/private.pem")
if not os.path.exists(PRIVATE_KEY_PATH):
    _local_key = os.path.join(os.path.dirname(__file__), "private.pem")
    if os.path.exists(_local_key):
        PRIVATE_KEY_PATH = _local_key

def hash_parameters(params: dict) -> str:
    canonical_json = json.dumps(params, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(canonical_json.encode('utf-8')).hexdigest()

def generate_ecc(
    request_id: str,
    session_id: str,
    subject: str,
    action: str,
    target: str,
    parameters: dict,
    invariant_set_version: str,
    expiry_seconds: int = 300,
    decision_basis: str = "PERMIT",
    auth_id: str = None,
    exception_scope: dict = None
) -> dict:
    with open(PRIVATE_KEY_PATH, "r") as f:
        private_key = f.read()
        
    ecc_id = str(uuid.uuid4())
    nonce = str(uuid.uuid4())
    issued_at = datetime.now(timezone.utc)
    expires_at = issued_at + timedelta(seconds=expiry_seconds)
    
    payload = {
        "ecc_id": ecc_id,
        "request_id": request_id,
        "session_id": session_id,
        "subject": subject,
        "action": action,
        "target": target,
        "parameters_hash": hash_parameters(parameters),
        "invariant_set_version": invariant_set_version,
        "iat": int(issued_at.timestamp()),
        "exp": int(expires_at.timestamp()),
        "nonce": nonce,
        "decision_basis": decision_basis,
        "ecc.decision_basis": decision_basis
    }

    if decision_basis == "PERMIT_WITH_AUTHORIZATION" and auth_id:
        payload["auth_ref"] = auth_id
        payload["ecc.auth_ref"] = auth_id
        payload["exception_scope"] = exception_scope or {}
        payload["ecc.exception_scope"] = exception_scope or {}
    
    token = jwt.encode(payload, private_key, algorithm="RS256")
    
    res = {
        "ecc_id": ecc_id,
        "ecc": token,
        "issued_at": issued_at.isoformat() + "Z",
        "expires_at": expires_at.isoformat() + "Z",
        "parameters_hash": payload["parameters_hash"],
        "decision_basis": decision_basis
    }
    if decision_basis == "PERMIT_WITH_AUTHORIZATION" and auth_id:
        res["auth_ref"] = auth_id
        res["exception_scope"] = exception_scope or {}
    return res
