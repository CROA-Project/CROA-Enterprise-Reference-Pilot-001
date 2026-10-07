"""
CROA Reference Harness — C6 Execution Firewall
Normative Reference: CROA Framework v1.0.1 §4.7 / §4.8 / §4.9; NT-007

Sits on the boundary of the governed network:
- Admits operations only with valid, unexpired, unredeemed ECCs.
- Verifies RS256 signature, JOSE kid, envelope claims, and operation binding.
- Validates exception scope and enforces single-use redemption of auth_ref (CROA §4.8).
- Atomically burns nonce and auth_ref before upstream target execution.
- Truthful execution reporting: separates authorization decision from target execution outcome.
- Records all stages to tamper-evident evidence log (C5).
"""

from __future__ import annotations

import hashlib
import hmac
import inspect
import json
import os
import threading
import time
from typing import Any, Optional

import httpx
import jwt
from cryptography.hazmat.primitives import serialization
from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, ConfigDict

# --------------------------------------------------------------------------- Config & Secrets
PLACEHOLDER_SECRETS = {"", "replace-me", "changeme", "change-me", "secret", "password"}
MIN_SECRET_LENGTH = 12


def _load_env_if_present() -> None:
    for candidate in [
        os.path.join(os.path.dirname(__file__), "..", ".env"),
        os.path.join(os.getcwd(), ".env"),
    ]:
        if os.path.exists(candidate):
            try:
                with open(candidate, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip().lstrip("\ufeff")
                        if line and not line.startswith("#") and "=" in line:
                            k, v = line.split("=", 1)
                            k = k.strip()
                            v = v.strip().strip("'\"")
                            if k not in os.environ:
                                os.environ[k] = v
            except Exception:
                pass
            break


_load_env_if_present()


def _require_secret(name: str) -> str:
    value = os.environ.get(name, "")
    if value.strip().lower() in PLACEHOLDER_SECRETS or len(value) < MIN_SECRET_LENGTH:
        raise RuntimeError(f"{name} is unset, a placeholder, or shorter than {MIN_SECRET_LENGTH} characters. See .env.example.")
    return value


DEMO_CONTROL_SECRET = _require_secret("DEMO_CONTROL_SECRET")
INTERNAL_SERVICE_SECRET = _require_secret("INTERNAL_SERVICE_SECRET")

CROA_EVIDENCE_URL = os.environ.get("CROA_EVIDENCE_URL", "http://croa_plane:8000/evidence")
UPSTREAM_TARGET_URL = os.environ.get("UPSTREAM_TARGET_URL", os.environ.get("ACMEOPS_URL", "http://acmeops_api:8000"))
ACMEOPS_URL = UPSTREAM_TARGET_URL
ECC_ISSUER = os.environ.get("ECC_ISSUER", "croa-plane-pilot")
ECC_AUDIENCE = os.environ.get("ECC_AUDIENCE", "c6-firewall-pilot")
ECC_SCHEMA_VERSION = "1"
EXPECTED_INVARIANT_SET_VERSION = os.environ.get("EXPECTED_INVARIANT_SET_VERSION", "pilot-policy-set-v1")
EVIDENCE_TIMEOUT = httpx.Timeout(float(os.environ.get("C6_EVIDENCE_TIMEOUT_SECONDS", "5")))
TARGET_TIMEOUT = httpx.Timeout(float(os.environ.get("C6_TARGET_TIMEOUT_SECONDS", "5")))
REJECT_PRE_BOOT_ECCS = os.environ.get("C6_REJECT_PRE_BOOT_ECCS", "1") == "1"

BOOT_TIME = int(time.time())

_loaded_public_key_path: str | None = None
PUBLIC_KEY_PEM: bytes = b""
PUBLIC_KEY: str = ""
PUBLIC_KID: str = ""


def _resolve_public_key_path() -> str:
    env_path = os.environ.get("CROA_PUBLIC_KEY_PATH", os.environ.get("PUBLIC_KEY_PATH", ""))
    if env_path and os.path.exists(env_path):
        return env_path
    for candidate in [
        os.path.join(os.path.dirname(__file__), "..", "keys", "public.pem"),
        os.path.join(os.path.dirname(__file__), "public.pem"),
        os.path.join(os.getcwd(), "keys", "public.pem"),
        os.path.join(os.getcwd(), "public.pem"),
    ]:
        if os.path.exists(candidate):
            return candidate
    return env_path or "/app/keys/public.pem"


def reload_public_key() -> tuple[bytes, str, str]:
    """Reload public key if path changed or explicitly requested."""
    global PUBLIC_KEY_PEM, PUBLIC_KEY, PUBLIC_KID, _loaded_public_key_path
    key_path = _resolve_public_key_path()
    if not PUBLIC_KEY_PEM or _loaded_public_key_path != key_path:
        with open(key_path, "rb") as f:
            PUBLIC_KEY_PEM = f.read()
        _pub = serialization.load_pem_public_key(PUBLIC_KEY_PEM)
        PUBLIC_KID = hashlib.sha256(
            _pub.public_bytes(encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo)
        ).hexdigest()[:16]
        PUBLIC_KEY = PUBLIC_KEY_PEM.decode("utf-8")
        _loaded_public_key_path = key_path
    return PUBLIC_KEY_PEM, PUBLIC_KEY, PUBLIC_KID


reload_public_key()

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

# --------------------------------------------------------------------------- Redemption Store
class InMemoryRedemptionStore:
    """
    SINGLE-PROCESS REFERENCE HARNESS REDEMPTION STORE.
    Maintains in-memory nonce and authorization artifact redemption tracking
    protected by a threading lock.
    """

    def __init__(self):
        self._redeemed_nonces: dict[str, dict[str, Any]] = {}
        self._redeemed_auth_ids: set[str] = set()
        self._lock = threading.Lock()

    @property
    def lock(self) -> threading.Lock:
        return self._lock

    @property
    def redeemed_nonces(self) -> dict[str, dict[str, Any]]:
        return self._redeemed_nonces

    @property
    def redeemed_auth_ids(self) -> set[str]:
        return self._redeemed_auth_ids

    def clear(self) -> None:
        with self._lock:
            self._redeemed_nonces.clear()
            self._redeemed_auth_ids.clear()

    def try_reserve(self, nonce: str, exp: int, auth_ref: str | None = None) -> tuple[bool, str | None]:
        with self._lock:
            if nonce in self._redeemed_nonces:
                return False, "ECC_ALREADY_REDEEMED"
            if auth_ref and auth_ref in self._redeemed_auth_ids:
                return False, "AUTH_TOKEN_ALREADY_REDEEMED"
            self._redeemed_nonces[nonce] = {"state": "RESERVED", "exp": exp}
            if auth_ref:
                self._redeemed_auth_ids.add(auth_ref)
            return True, None

    def release_reservation(self, nonce: str, auth_ref: str | None = None) -> None:
        with self._lock:
            entry = self._redeemed_nonces.get(nonce)
            if entry and entry["state"] == "RESERVED":
                del self._redeemed_nonces[nonce]
            if auth_ref and auth_ref in self._redeemed_auth_ids:
                self._redeemed_auth_ids.remove(auth_ref)

    def mark_redeemed(self, nonce: str) -> None:
        with self._lock:
            if nonce in self._redeemed_nonces:
                self._redeemed_nonces[nonce]["state"] = "REDEEMED"

    def purge_expired(self, now: int, threshold: int = 10_000) -> None:
        with self._lock:
            if len(self._redeemed_nonces) < threshold:
                return
            for n in [n for n, v in self._redeemed_nonces.items() if v.get("exp", 0) < now - 60]:
                del self._redeemed_nonces[n]


default_redemption_store = InMemoryRedemptionStore()
REDEEMED_NONCES = default_redemption_store.redeemed_nonces
REDEEMED_AUTH_IDS = default_redemption_store.redeemed_auth_ids
_redemption_lock = default_redemption_store.lock

# --------------------------------------------------------------------------- App & Endpoints
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
    request_id: Optional[str] = None


class RefusalRequest(BaseModel):
    model_config = ConfigDict(extra="allow")

    request_id: str
    session_id: str | None = None
    subject: str
    action: str
    target: str
    decision: str
    reason: str
    decision_stage: str


def hash_parameters(params: dict[str, Any]) -> str:
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
    except Exception:
        if raise_on_fail:
            raise


async def _record_evidence(*args, **kwargs):
    fn = globals().get("log_evidence")
    if fn is None:
        return None
    res = fn(*args, **kwargs)
    if inspect.isawaitable(res):
        return await res
    return res


def _block(reason: str, ecc_id: str | None = None) -> dict[str, Any]:
    return {
        "authorization": {"decision": "BLOCK", "reason": reason, "ecc_id": ecc_id},
        "execution": {"status": "NOT_ATTEMPTED"},
        "decision": "BLOCK",
        "reason": reason,
    }


def _allow(ecc_id: str, execution: dict[str, Any]) -> dict[str, Any]:
    resp: dict[str, Any] = {
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
    await _record_evidence(req.request_id, req.session_id, None, req.subject, req.action, req.target, "EXECUTION_BLOCKED", "DENY", req.reason)
    resp = req.model_dump()
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
    try:
        unverified = jwt.decode(req.ecc, options={"verify_signature": False})
        await _record_evidence(
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
        await _record_evidence(
            "unknown", None, None, req.subject, req.action, req.target, "EXECUTION_BLOCKED", "BLOCK", reason, claims_verified=False
        )


async def _reconcile(ecc_id: str) -> dict[str, Any]:
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
        return {"status": "FAILED", "target_status": "NOT_REACHED", "reason": "TARGET_SYSTEM_FAILURE"}
    except httpx.HTTPError:
        return await _reconcile(ecc_id)

    if 200 <= resp.status_code < 300:
        data = resp.json()
        return {"status": "SUCCEEDED", "target_status": "SUCCESS", "execution_id": data.get("execution_id"), "acmeops_result": data}
    if 400 <= resp.status_code < 500:
        return {"status": "FAILED", "target_status": f"HTTP_{resp.status_code}", "reason": "TARGET_SYSTEM_FAILURE"}
    return await _reconcile(ecc_id)


@app.post("/execute")
async def execute(req: ExecuteRequest):
    if not req.ecc:
        await _record_evidence("unknown", None, None, req.subject, req.action, req.target, "EXECUTION_BLOCKED", "BLOCK", "MISSING_ECC")
        return _block("MISSING_ECC")

    # 1. Cryptographic validation & mandatory claim enforcement
    try:
        reload_public_key()
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

    req_id = payload.get("request_id")
    ecc_id = payload.get("ecc_id")
    nonce = payload.get("nonce")
    session_id = payload.get("session_id")
    inv_version = payload.get("invariant_set_version")
    now = int(time.time())

    async def blocked(reason: str) -> dict[str, Any]:
        await _record_evidence(
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

    # 2. Envelope & JOSE header checks
    if header.get("kid") != PUBLIC_KID:
        return await blocked("UNKNOWN_KEY_ID")
    if "crit" in header:
        return await blocked("MALFORMED_ECC")
    if payload.get("ecc_schema_version") != ECC_SCHEMA_VERSION:
        return await blocked("UNSUPPORTED_ECC_SCHEMA")
    if payload.get("jti") != ecc_id or nonce != ecc_id:
        return await blocked("MALFORMED_ECC")
    if not isinstance(payload.get("iat"), int) or not isinstance(payload.get("exp"), int):
        return await blocked("MALFORMED_ECC")
    if REJECT_PRE_BOOT_ECCS and payload["iat"] < BOOT_TIME:
        return await blocked("ECC_PREDATES_FIREWALL_EPOCH")

    await _record_evidence(
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

    # 3. Early replay check
    if nonce in default_redemption_store.redeemed_nonces:
        return await blocked("ECC_ALREADY_REDEEMED")

    # 4. Binding validation
    if payload.get("subject") != req.subject:
        return await blocked("SUBJECT_MISMATCH")
    if payload.get("action") != req.action:
        return await blocked("ACTION_MISMATCH")
    if payload.get("target") != req.target:
        return await blocked("TARGET_MISMATCH")
    if payload.get("parameters_hash") != hash_parameters(req.parameters):
        return await blocked("OPERATION_MISMATCH")
    if inv_version != EXPECTED_INVARIANT_SET_VERSION:
        return await blocked("INVARIANT_VERSION_MISMATCH")

    # 5. Governed Exception Scope & Single-Use Authorization Artifact validation (CROA §4.8, NT-007)
    auth_ref = payload.get("auth_ref") or payload.get("ecc.auth_ref")
    exception_scope = payload.get("exception_scope") or payload.get("ecc.exception_scope")

    if auth_ref and exception_scope:
        allowed_act = exception_scope.get("action_class")
        if allowed_act and allowed_act != req.action:
            return await blocked("OPERATION_OUTSIDE_AUTH_SCOPE")

        allowed_tgt = exception_scope.get("target_constraints", {}).get("target")
        if allowed_tgt and allowed_tgt != req.target:
            return await blocked("OPERATION_OUTSIDE_AUTH_SCOPE")

    # 6. Atomic check-and-reserve of nonce and auth_ref
    default_redemption_store.purge_expired(now)
    reserved, reserve_err = default_redemption_store.try_reserve(nonce, payload["exp"], auth_ref)
    if not reserved:
        return await blocked(reserve_err or "ECC_ALREADY_REDEEMED")

    # 7. Pre-execution evidence logging (mandatory fail-closed)
    try:
        await _record_evidence(
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
    except Exception:
        default_redemption_store.release_reservation(nonce, auth_ref)
        return _block("EVIDENCE_UNAVAILABLE", ecc_id)

    default_redemption_store.mark_redeemed(nonce)

    # 8. Target Execution & Truthful Outcome Recording
    execution = await _execute_on_target(req, ecc_id, req_id)
    event = {
        "SUCCEEDED": "EXECUTION_SUCCEEDED",
        "FAILED": "EXECUTION_FAILED",
        "UNKNOWN": "EXECUTION_UNKNOWN",
    }[execution["status"]]

    await _record_evidence(
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
    default_redemption_store.clear()
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
