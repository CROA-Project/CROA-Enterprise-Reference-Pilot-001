"""
CROA Reference Harness — Control Plane Intake and Orchestrator
Normative Reference: CROA Framework v1.0.1 §4.2 / §4.5 / §4.9

Co-located control plane:
- Agent Surface admission & Subject authentication (§4.9)
- Action schema validation & parameter admission (§4.5 / §4.9.1)
- Context Resolver & Target grounding (C3)
- Execution Governor & Governed Exceptions (C2)
- Trajectory Invariant enforcement (C4)
- Tamper-evident evidence logging (C5)
- Execution Change Contract compilation (C7)
"""

from __future__ import annotations

import hmac
import json
import os
from contextlib import asynccontextmanager
from typing import Any

import httpx
from auth import SubjectAuthenticator, get_authenticator
from c2_governor import evaluate_request
from c3_resolver import resolve_target
from c4_trajectory import reset_trajectory_state
from c5_evidence import (
    EVIDENCE_FILE,
    EvidenceIntegrityError,
    load_head_hash,
    record_event,
    utc_now_iso,
    verify_chain,
)
from c7_compiler import _load_key, generate_ecc
from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

PLACEHOLDER_SECRETS = {"", "replace-me", "changeme", "change-me", "secret", "password"}
MIN_SECRET_LENGTH = 12


def _load_env_if_present() -> None:
    for candidate in [
        os.path.join(os.path.dirname(__file__), "..", ".env"),
        os.path.join(os.getcwd(), ".env"),
    ]:
        if os.path.exists(candidate):
            try:
                with open(candidate, encoding="utf-8") as f:
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
        raise RuntimeError(
            f"{name} is unset, a placeholder, or shorter than {MIN_SECRET_LENGTH} characters. Set a real value in .env (see .env.example)."
        )
    return value


DEMO_CONTROL_SECRET = _require_secret("DEMO_CONTROL_SECRET")
INTERNAL_SERVICE_SECRET = _require_secret("INTERNAL_SERVICE_SECRET")
TEST_MODE = os.environ.get("ENABLE_TEST_MODE", "0") == "1"
ECC_TTL_SECONDS = int(os.environ.get("ECC_TTL_SECONDS", "300"))
C6_URL = os.environ.get("C6_URL", "http://c6_firewall:8000")
HTTP_TIMEOUT = httpx.Timeout(5.0)
INVARIANT_SET_VERSION = "pilot-policy-set-v1"

_test_c5_unavailable = False


@asynccontextmanager
async def lifespan(_: FastAPI):
    # Fail closed at startup if signing key is missing or evidence log is not intact.
    _load_key()
    load_head_hash()
    yield


app = FastAPI(title="CROA Control Plane (Pilot #001)", lifespan=lifespan)

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


# ==============================================================================
# AGENT SURFACE INTAKE AUTHENTICATION (CROA Framework v1.0.1 §4.9)
# Pluggable SubjectAuthenticator dependency injection with strict fail-closed logic
# ==============================================================================


def authenticate_subject_intake(
    authorization: str | None = Header(None),
    x_subject_token: str | None = Header(None),
    authenticator: SubjectAuthenticator = Depends(get_authenticator),  # noqa: B008
) -> str:
    """
    Intake authentication hook verifying caller credentials against pluggable authenticator.
    Fails closed with 401 on missing or invalid tokens.
    """
    return authenticator.authenticate(authorization, x_subject_token)


class ProposeRequest(BaseModel):
    request_id: str
    session_id: str
    subject: str
    action: str
    target: str
    parameters: dict[str, Any] = Field(default_factory=dict)
    expiry_seconds: int | None = None
    authorization_artifact: dict[str, Any] | None = None


class EvidenceRequest(BaseModel):
    request_id: str
    session_id: str | None = None
    subject: str
    action: str
    target: str
    event_type: str
    decision: str
    reason: str
    decision_stage: str
    ecc_id: str | None = None
    execution_id: str | None = None
    target_status: str | None = None
    execution_status: str | None = None
    invariant_set_version: str | None = None
    claims_verified: bool | None = None


class ResetRequest(BaseModel):
    demo_run_id: str


class C5ControlRequest(BaseModel):
    unavailable: bool


@app.exception_handler(EvidenceIntegrityError)
async def _evidence_integrity(_, exc: EvidenceIntegrityError):
    from fastapi.responses import JSONResponse

    return JSONResponse(status_code=503, content={"decision": "DENY", "reason": "EVIDENCE_INTEGRITY_FAILURE", "detail": str(exc)})


@app.get("/health")
def health_check():
    return {"status": "ONLINE", "test_mode": TEST_MODE}


if TEST_MODE:

    @app.post("/demo-control/c5-fail", dependencies=[Depends(verify_demo_control)])
    def toggle_c5(req: C5ControlRequest):
        global _test_c5_unavailable
        _test_c5_unavailable = req.unavailable
        return {"status": "ok"}


@app.post("/reset", dependencies=[Depends(verify_demo_control)])
def reset_demo(req: ResetRequest):
    reset_trajectory_state()
    record_event(
        request_id=req.demo_run_id,
        session_id=req.demo_run_id,
        subject="system",
        action="reset",
        target="none",
        event_type="DEMO_RESET",
        decision="ALLOW",
        reason="DEMO_RESET",
        decision_stage="C5",
    )
    return {"status": "reset", "demo_run_id": req.demo_run_id}


@app.get("/evidence", dependencies=[Depends(verify_demo_control)])
def get_evidence():
    events: list[dict[str, Any]] = []
    if not os.path.exists(EVIDENCE_FILE):
        return events
    with open(EVIDENCE_FILE, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                break
    return events


@app.get("/evidence/verify", dependencies=[Depends(verify_demo_control)])
def verify_evidence():
    return verify_chain(EVIDENCE_FILE)


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
        execution_status=ev.execution_status,
        invariant_set_version=ev.invariant_set_version,
        claims_verified=ev.claims_verified,
    )
    return {"status": "ok"}


def forward_to_c6_refusal_gateway(deny_payload: dict[str, Any]) -> dict[str, Any]:
    """Denials are routed through C6 so the execution boundary records them too.
    C6 unavailability never changes the outcome: the denial stands."""
    try:
        with httpx.Client(timeout=HTTP_TIMEOUT) as client:
            resp = client.post(
                f"{C6_URL}/refuse",
                json=deny_payload,
                headers={"X-Internal-Service-Secret": INTERNAL_SERVICE_SECRET},
            )
            if resp.status_code == 200:
                return resp.json()
    except Exception:
        pass
    return deny_payload


@app.post("/propose")
def propose_action(
    req: ProposeRequest,
    auth_subject: str = Depends(authenticate_subject_intake),
):
    # Enforce that caller body cannot redefine or spoof authenticated Subject identity
    if req.subject and req.subject != auth_subject:
        raise HTTPException(
            status_code=403,
            detail=f"SUBJECT_AUTHENTICATION_MISMATCH: Caller claim '{req.subject}' does not match authenticated Subject '{auth_subject}'",
        )

    # Overwrite/bind authenticated Subject as authoritative identity for downstream governance
    governed_subject = auth_subject

    is_grounded, grounding_reason = resolve_target(req.action, req.target)

    if not is_grounded:
        record_event(
            request_id=req.request_id,
            session_id=req.session_id,
            subject=governed_subject,
            action=req.action,
            target=req.target,
            event_type="GROUNDING_FAILED",
            decision="DENY",
            reason=grounding_reason,
            decision_stage="C3",
            policy_id=None,
            invariant_set_version=INVARIANT_SET_VERSION,
        )
        deny_payload = {
            "request_id": req.request_id,
            "session_id": req.session_id,
            "subject": governed_subject,
            "action": req.action,
            "target": req.target,
            "decision": "DENY",
            "reason": grounding_reason,
            "decision_stage": "C3",
            "policy_id": None,
            "invariant_set_version": INVARIANT_SET_VERSION,
            "timestamp": utc_now_iso(),
        }
        return forward_to_c6_refusal_gateway(deny_payload)

    record_event(
        request_id=req.request_id,
        session_id=req.session_id,
        subject=governed_subject,
        action=req.action,
        target=req.target,
        event_type="GROUNDING_PASSED",
        decision="PERMIT",
        reason="TARGET_GROUNDED",
        decision_stage="C3",
        policy_id=None,
        invariant_set_version=INVARIANT_SET_VERSION,
    )

    proposal_data = req.model_dump()
    proposal_data["subject"] = governed_subject
    c2_result = evaluate_request(proposal_data)

    if c2_result["decision"] == "DENY":
        c2_result["session_id"] = req.session_id
        return forward_to_c6_refusal_gateway(c2_result)

    # Caller-supplied TTL is honoured ONLY in test mode (TTL-manipulation tests).
    ttl = req.expiry_seconds if (req.expiry_seconds is not None and TEST_MODE) else ECC_TTL_SECONDS

    ecc_data = generate_ecc(
        request_id=req.request_id,
        session_id=req.session_id,
        subject=governed_subject,
        action=req.action,
        target=req.target,
        parameters=req.parameters,
        invariant_set_version=c2_result["invariant_set_version"],
        expiry_seconds=ttl,
        decision_basis=c2_result["decision"],
        auth_id=c2_result.get("auth_id"),
        exception_scope=c2_result.get("exception_scope"),
        policy_id=c2_result.get("policy_id"),
    )
    ecc_ev_data = {
        "ecc_id": ecc_data["ecc_id"],
        "parameters_hash": ecc_data["parameters_hash"],
        "expires_at": ecc_data["expires_at"],
        "kid": ecc_data["kid"],
    }
    if "auth_ref" in ecc_data:
        ecc_ev_data["auth_ref"] = ecc_data["auth_ref"]

    record_event(
        request_id=req.request_id,
        session_id=req.session_id,
        subject=governed_subject,
        action=req.action,
        target=req.target,
        event_type="ECC_ISSUED",
        decision="PERMIT",
        reason="ECC_GENERATED",
        decision_stage="C7",
        policy_id=c2_result.get("policy_id"),
        invariant_set_version=c2_result["invariant_set_version"],
        ecc_data=ecc_ev_data,
    )
    c2_result.update(
        {
            "ecc_id": ecc_data["ecc_id"],
            "ecc": ecc_data["ecc"],
            "expires_at": ecc_data["expires_at"],
            "kid": ecc_data["kid"],
        }
    )
    if "auth_ref" in ecc_data:
        c2_result["auth_ref"] = ecc_data["auth_ref"]
    if "exception_scope" in ecc_data:
        c2_result["exception_scope"] = ecc_data["exception_scope"]

    return c2_result
