"""C6 — Execution Firewall.

Sits on the boundary of the governed network. Admits an operation to the
protected target only if it carries a valid, unexpired, unredeemed ECC whose
signed commitment matches the requested operation. Makes NO call to the
control plane to *decide*; it does depend on C5 to *record* the authorization
before execution, and fails closed if that record cannot be written.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from typing import Any

import httpx
import jwt
from cryptography.hazmat.primitives import serialization
from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, ConfigDict

# --------------------------------------------------------------------------- config
PLACEHOLDER_SECRETS = {"", "replace-me", "changeme", "change-me", "secret", "password"}
MIN_SECRET_LENGTH = 12


def _require_secret(name: str) -> str:
    value = os.environ.get(name, "")
    if value.strip().lower() in PLACEHOLDER_SECRETS or len(value) < MIN_SECRET_LENGTH:
        raise RuntimeError(f"{name} is unset, a placeholder, or shorter than {MIN_SECRET_LENGTH} characters. See .env.example.")
    return value


DEMO_CONTROL_SECRET = _require_secret("DEMO_CONTROL_SECRET")
INTERNAL_SERVICE_SECRET = _require_secret("INTERNAL_SERVICE_SECRET")

PUBLIC_KEY_PATH = os.environ.get("CROA_PUBLIC_KEY_PATH", "/app/keys/public.pem")
CROA_EVIDENCE_URL = os.environ.get("CROA_EVIDENCE_URL", "http://croa_plane:8000/evidence")
ACMEOPS_URL = os.environ.get("ACMEOPS_URL", "http://acmeops_api:8000")
ECC_ISSUER = os.environ.get("ECC_ISSUER", "croa-plane-pilot")
ECC_AUDIENCE = os.environ.get("ECC_AUDIENCE", "c6-firewall-pilot")
ECC_SCHEMA_VERSION = "1"
EXPECTED_INVARIANT_SET_VERSION = os.environ.get("EXPECTED_INVARIANT_SET_VERSION", "pilot-policy-set-v1")
EVIDENCE_TIMEOUT = httpx.Timeout(float(os.environ.get("C6_EVIDENCE_TIMEOUT_SECONDS", "5")))
TARGET_TIMEOUT = httpx.Timeout(float(os.environ.get("C6_TARGET_TIMEOUT_SECONDS", "5")))
REJECT_PRE_BOOT_ECCS = os.environ.get("C6_REJECT_PRE_BOOT_ECCS", "1") == "1"

# Restart epoch: the in-memory replay registry is lost on restart, so any ECC issued
# before this process started is refused. Trades liveness of pre-restart contracts
# for at-most-once execution. Documented in docs/ADR/0004-restart-epoch.md.
BOOT_TIME = int(time.time())

with open(PUBLIC_KEY_PATH, "rb") as f:
    PUBLIC_KEY_PEM = f.read()
_pub = serialization.load_pem_public_key(PUBLIC_KEY_PEM)
PUBLIC_KID = hashlib.sha256(
    _pub.public_bytes(encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo)
).hexdigest()[:16]

MANDATORY_CLAIMS = [
    "iss",
    "aud",
    "jti",
    "iat",
    "exp",
    "ecc_schema_version",
    "ecc_id",
    "nonce",
    "request_id",
    "session_id",
    "subject",
    "action",
    "target",
    "parameters_hash",
    "invariant_set_version",
]

# --------------------------------------------------------------------------- replay registry
# nonce -> {"state": "RESERVED"|"REDEEMED", "exp": int}
# INVARIANT: every read-check-then-write on this dict happens with no `await` in
# between (single event loop). _try_reserve is the only writer for new entries.
# This registry is per-process: run C6 with ONE worker. (Pilot limitation.)
REDEEMED_NONCES: dict[str, dict[str, Any]] = {}
_PURGE_THRESHOLD = 10_000


def _purge_expired(now: int) -> None:
    if len(REDEEMED_NONCES) < _PURGE_THRESHOLD:
        return
    for n in [n for n, v in REDEEMED_NONCES.items() if v["exp"] < now - 60]:
        del REDEEMED_NONCES[n]


def _try_reserve(nonce: str, exp: int) -> bool:
    """Atomic check-and-set (no await inside). True if this call took the reservation."""
    if nonce in REDEEMED_NONCES:
        return False
    REDEEMED_NONCES[nonce] = {"state": "RESERVED", "exp": exp}
    return True


def _release(nonce: str) -> None:
    entry = REDEEMED_NONCES.get(nonce)
    if entry and entry["state"] == "RESERVED":
        del REDEEMED_NONCES[nonce]


def _mark_redeemed(nonce: str) -> None:
    REDEEMED_NONCES[nonce]["state"] = "REDEEMED"


# --------------------------------------------------------------------------- app
app = FastAPI(title="CROA C6 Execution Firewall (Pilot #001)")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8080", "http://127.0.0.1:8080"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _matches(provided: str | None, expected: str) -> bool:
    return provided is not None and hmac.compare_digest(provided.encode(), expected.encode())


def verify_demo_control(x_demo_control_secret: str | None = Header(None)):
    if not _matches(x_demo_control_secret, DEMO_CONTROL_SECRET):
        raise HTTPException(status_code=403, detail="Forbidden: Invalid demo control secret")


def verify_internal_service(x_internal_service_secret: str | None = Header(None)):
    if not _matches(x_internal_service_secret, INTERNAL_SERVICE_SECRET):
        raise HTTPException(status_code=403, detail="Forbidden: Invalid internal service secret")


class ExecuteRequest(BaseModel):
    ecc: str
    subject: str
    action: str
    target: str
    parameters: dict[str, Any]


class RefusalRequest(BaseModel):
    """A control-plane denial. Extra fields (trajectory numbers, policy_id, timestamp) are
    preserved and echoed back: the gateway records the denial, it does not strip its context."""

    model_config = ConfigDict(extra="allow")

    request_id: str
    session_id: str
    subject: str
    action: str
    target: str
    decision: str
    reason: str
    decision_stage: str


def hash_parameters(params: dict[str, Any]) -> str:
    """Must be byte-identical to c7_compiler.hash_parameters (docs/ECC-SPEC.md)."""
    canonical_json = json.dumps(params, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()


async def log_evidence(
    req_id: str | None,
    session_id: str | None,
    ecc_id: str | None,
    subject: str,
    action: str,
    target: str,
    event_type: str,
    decision: str,
    reason: str,
    invariant_set_version: str | None = None,
    execution_id: str | None = None,
    target_status: str | None = None,
    execution_status: str | None = None,
    claims_verified: bool | None = None,
    raise_on_fail: bool = False,
) -> None:
    data: dict[str, Any] = {
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
        "invariant_set_version": invariant_set_version,
    }
    for k, v in (
        ("execution_id", execution_id),
        ("target_status", target_status),
        ("execution_status", execution_status),
        ("claims_verified", claims_verified),
    ):
        if v is not None:
            data[k] = v
    try:
        async with httpx.AsyncClient(timeout=EVIDENCE_TIMEOUT) as client:
            r = await client.post(CROA_EVIDENCE_URL, json=data, headers={"X-Internal-Service-Secret": INTERNAL_SERVICE_SECRET})
            r.raise_for_status()
    except httpx.HTTPError:
        if raise_on_fail:
            raise


def _block(reason: str, ecc_id: str | None = None) -> dict[str, Any]:
    return {
        "authorization": {"decision": "BLOCK", "reason": reason, "ecc_id": ecc_id},
        "execution": {"status": "NOT_ATTEMPTED"},
        # legacy top-level fields (v0.1 clients)
        "decision": "BLOCK",
        "reason": reason,
    }


def _allow(ecc_id: str, execution: dict[str, Any]) -> dict[str, Any]:
    resp = {
        "authorization": {"decision": "ALLOW", "reason": "ECC_VALIDATED", "ecc_id": ecc_id},
        "execution": execution,
        "decision": "ALLOW",
        "execution_status": execution["status"],
    }
    if execution["status"] != "SUCCEEDED":
        resp["reason"] = execution.get("reason", "TARGET_SYSTEM_FAILURE")
    if "acmeops_result" in execution:
        resp["acmeops_result"] = execution["acmeops_result"]
    return resp


@app.post("/refuse", dependencies=[Depends(verify_internal_service)])
async def refuse_gateway(req: RefusalRequest):
    await log_evidence(req.request_id, req.session_id, None, req.subject, req.action, req.target, "EXECUTION_BLOCKED", "DENY", req.reason)
    resp = req.model_dump()  # includes the source stage's context (e.g. C4 current/projected values)
    resp.update(
        {
            "decision": "DENY",
            "reason": req.reason,
            "decision_stage": "C6_REFUSAL_GATEWAY",
            "source_stage": req.decision_stage,
        }
    )
    return resp


async def _log_unverified_block(req: ExecuteRequest, reason: str) -> None:
    """Evidence for tokens that failed verification: claims are recorded but flagged unverified."""
    try:
        unverified = jwt.decode(req.ecc, options={"verify_signature": False})
        await log_evidence(
            unverified.get("request_id"),
            unverified.get("session_id"),
            unverified.get("ecc_id"),
            req.subject,
            req.action,
            req.target,
            "EXECUTION_BLOCKED",
            "BLOCK",
            reason,
            unverified.get("invariant_set_version"),
            claims_verified=False,
        )
    except Exception:
        await log_evidence(
            "unknown", None, None, req.subject, req.action, req.target, "EXECUTION_BLOCKED", "BLOCK", reason, claims_verified=False
        )


async def _reconcile(ecc_id: str) -> dict[str, Any]:
    """After an ambiguous target response, ask the target whether ecc_id executed."""
    try:
        async with httpx.AsyncClient(timeout=TARGET_TIMEOUT) as client:
            r = await client.get(
                f"{ACMEOPS_URL}/internal/executions/{ecc_id}", headers={"X-Internal-Service-Secret": INTERNAL_SERVICE_SECRET}
            )
        if r.status_code == 200:
            data = r.json()
            return {
                "status": "SUCCEEDED",
                "target_status": "RECONCILED_SUCCESS",
                "execution_id": data.get("execution_id"),
                "acmeops_result": data,
            }
        if r.status_code == 404:
            return {"status": "FAILED", "target_status": "RECONCILED_NOT_EXECUTED", "reason": "TARGET_SYSTEM_FAILURE"}
    except httpx.HTTPError:
        pass
    return {"status": "UNKNOWN", "target_status": "UNKNOWN", "reason": "TARGET_OUTCOME_UNKNOWN"}


async def _execute_on_target(req: ExecuteRequest, ecc_id: str, request_id: str | None) -> dict[str, Any]:
    body = {"ecc_id": ecc_id, "request_id": request_id, "action": req.action, "target": req.target, "parameters": req.parameters}
    try:
        async with httpx.AsyncClient(timeout=TARGET_TIMEOUT) as client:
            resp = await client.post(
                f"{ACMEOPS_URL}/internal/execute", json=body, headers={"X-Internal-Service-Secret": INTERNAL_SERVICE_SECRET}
            )
    except (httpx.ConnectError, httpx.ConnectTimeout):
        # The request never reached the target: a genuine, knowable failure.
        return {"status": "FAILED", "target_status": "NOT_REACHED", "reason": "TARGET_SYSTEM_FAILURE"}
    except httpx.HTTPError:
        # Sent, but no usable response (read timeout, connection dropped): the outcome is UNKNOWN.
        return await _reconcile(ecc_id)

    if 200 <= resp.status_code < 300:
        data = resp.json()
        return {"status": "SUCCEEDED", "target_status": "SUCCESS", "execution_id": data.get("execution_id"), "acmeops_result": data}
    if 400 <= resp.status_code < 500:
        return {"status": "FAILED", "target_status": f"HTTP_{resp.status_code}", "reason": "TARGET_SYSTEM_FAILURE"}
    # 5xx: the target received the request; whether it committed is not knowable from the status alone.
    return await _reconcile(ecc_id)


@app.post("/execute")
async def execute(req: ExecuteRequest):
    if not req.ecc:
        await log_evidence("unknown", None, None, req.subject, req.action, req.target, "EXECUTION_BLOCKED", "BLOCK", "MISSING_ECC")
        return _block("MISSING_ECC")

    # 1. Signature, algorithm pin, iss/aud, exp/iat, required claims — all in the library call.
    try:
        header = jwt.get_unverified_header(req.ecc)
        payload = jwt.decode(
            req.ecc,
            PUBLIC_KEY_PEM,
            algorithms=["RS256"],
            issuer=ECC_ISSUER,
            audience=ECC_AUDIENCE,
            options={"require": MANDATORY_CLAIMS},
        )
    except jwt.ExpiredSignatureError:
        await _log_unverified_block(req, "ECC_EXPIRED")
        return _block("ECC_EXPIRED")
    except jwt.MissingRequiredClaimError:
        await _log_unverified_block(req, "MALFORMED_ECC")
        return _block("MALFORMED_ECC")
    except (jwt.InvalidIssuerError, jwt.InvalidAudienceError):
        await _log_unverified_block(req, "ISSUER_OR_AUDIENCE_MISMATCH")
        return _block("ISSUER_OR_AUDIENCE_MISMATCH")
    except jwt.InvalidTokenError:
        await _log_unverified_block(req, "INVALID_SIGNATURE")
        return _block("INVALID_SIGNATURE")

    req_id = payload["request_id"]
    ecc_id = payload["ecc_id"]
    nonce = payload["nonce"]
    session_id = payload["session_id"]
    inv_version = payload["invariant_set_version"]
    now = int(time.time())

    async def blocked(reason: str) -> dict[str, Any]:
        await log_evidence(
            req_id,
            session_id,
            ecc_id,
            req.subject,
            req.action,
            req.target,
            "EXECUTION_BLOCKED",
            "BLOCK",
            reason,
            inv_version,
            claims_verified=True,
        )
        return _block(reason, ecc_id)

    # 2. Envelope checks the library does not do.
    if header.get("kid") != PUBLIC_KID:
        return await blocked("UNKNOWN_KEY_ID")
    if "crit" in header:
        return await blocked("MALFORMED_ECC")
    if payload.get("ecc_schema_version") != ECC_SCHEMA_VERSION:
        return await blocked("UNSUPPORTED_ECC_SCHEMA")
    if payload["jti"] != ecc_id or nonce != ecc_id:
        return await blocked("MALFORMED_ECC")
    if not isinstance(payload["iat"], int) or not isinstance(payload["exp"], int):
        return await blocked("MALFORMED_ECC")
    if REJECT_PRE_BOOT_ECCS and payload["iat"] < BOOT_TIME:
        return await blocked("ECC_PREDATES_FIREWALL_EPOCH")

    await log_evidence(
        req_id,
        session_id,
        ecc_id,
        req.subject,
        req.action,
        req.target,
        "EXECUTION_ATTEMPT",
        "EVALUATE",
        "VALIDATING",
        inv_version,
        claims_verified=True,
    )

    # 3. Early replay check (cheap rejection; the authoritative check is the reservation below).
    if nonce in REDEEMED_NONCES:
        return await blocked("ECC_ALREADY_REDEEMED")

    # 4. Binding: the operation presented must be the operation signed.
    if payload["subject"] != req.subject:
        return await blocked("SUBJECT_MISMATCH")
    if payload["action"] != req.action:
        return await blocked("ACTION_MISMATCH")
    if payload["target"] != req.target:
        return await blocked("TARGET_MISMATCH")
    if payload["parameters_hash"] != hash_parameters(req.parameters):
        return await blocked("OPERATION_MISMATCH")
    if inv_version != EXPECTED_INVARIANT_SET_VERSION:
        return await blocked("INVARIANT_VERSION_MISMATCH")

    # 5. Reservation: atomic check-and-set, no await between the check and the write.
    _purge_expired(now)
    if not _try_reserve(nonce, payload["exp"]):
        return await blocked("ECC_ALREADY_REDEEMED")

    # 6. Pre-execution evidence is mandatory. If it cannot be written, release and fail closed.
    try:
        await log_evidence(
            req_id,
            session_id,
            ecc_id,
            req.subject,
            req.action,
            req.target,
            "EXECUTION_AUTHORIZED",
            "ALLOW",
            "ECC_VALIDATED",
            inv_version,
            claims_verified=True,
            raise_on_fail=True,
        )
    except httpx.HTTPError:
        _release(nonce)
        return _block("EVIDENCE_UNAVAILABLE", ecc_id)

    _mark_redeemed(nonce)  # from here the ECC is spent regardless of outcome

    # 7. Execute. Outcome is SUCCEEDED / FAILED / UNKNOWN — never asserted beyond what is known.
    execution = await _execute_on_target(req, ecc_id, req_id)
    event = {"SUCCEEDED": "EXECUTION_SUCCEEDED", "FAILED": "EXECUTION_FAILED", "UNKNOWN": "EXECUTION_UNKNOWN"}[execution["status"]]
    await log_evidence(
        req_id,
        session_id,
        ecc_id,
        req.subject,
        req.action,
        req.target,
        event,
        "ALLOW",
        "EXECUTION_COMPLETED" if execution["status"] == "SUCCEEDED" else execution.get("reason", "TARGET_SYSTEM_FAILURE"),
        inv_version,
        execution_id=execution.get("execution_id"),
        target_status=execution.get("target_status"),
        execution_status=execution["status"],
        claims_verified=True,
    )
    return _allow(ecc_id, execution)


@app.get("/health")
async def health():
    reach = False
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            r = await client.get(f"{ACMEOPS_URL}/health")
            reach = r.status_code == 200
    except httpx.HTTPError:
        pass
    return {"status": "ONLINE", "acmeops_reachable": reach, "kid": PUBLIC_KID, "boot_time": BOOT_TIME}


@app.post("/reset", dependencies=[Depends(verify_demo_control)])
async def reset():
    REDEEMED_NONCES.clear()
    try:
        async with httpx.AsyncClient(timeout=TARGET_TIMEOUT) as client:
            await client.post(f"{ACMEOPS_URL}/internal/reset", headers={"X-Internal-Service-Secret": INTERNAL_SERVICE_SECRET})
    except httpx.HTTPError:
        pass
    return {"status": "reset"}


@app.get("/acmeops/history", dependencies=[Depends(verify_demo_control)])
async def acmeops_history():
    try:
        async with httpx.AsyncClient(timeout=TARGET_TIMEOUT) as client:
            r = await client.get(f"{ACMEOPS_URL}/internal/history", headers={"X-Internal-Service-Secret": INTERNAL_SERVICE_SECRET})
            return r.json()
    except httpx.HTTPError:
        return []
