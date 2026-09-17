"""CROA control plane: C1 (policy), C2 (governor), C3 (grounding), C4 (trajectory),
C5 (evidence), C7 (contract compiler). Co-located in one process for the pilot."""

from __future__ import annotations

import hmac
import json
import os
from contextlib import asynccontextmanager
from typing import Any

import httpx
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
    # Fail closed at startup if the signing key is missing or the existing evidence log is not intact.
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


class ProposeRequest(BaseModel):
    request_id: str
    session_id: str
    subject: str
    action: str
    target: str
    parameters: dict[str, Any] = Field(default_factory=dict)
    expiry_seconds: int | None = None


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
    # Fail closed: no decision is returned when evidence cannot be recorded.
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
    record_event(req.demo_run_id, req.demo_run_id, "system", "reset", "none", "DEMO_RESET", "ALLOW", "DEMO_RESET", "C5")
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
                break  # stop at the first malformed record; /evidence/verify reports it
    return events


@app.get("/evidence/verify", dependencies=[Depends(verify_demo_control)])
def verify_evidence():
    return verify_chain(EVIDENCE_FILE)


@app.post("/evidence", dependencies=[Depends(verify_internal_service)])
def post_evidence(ev: EvidenceRequest):
    if _test_c5_unavailable:
        raise HTTPException(status_code=503, detail="Simulated C5 Unavailable")
    record_event(
        ev.request_id,
        ev.session_id,
        ev.subject,
        ev.action,
        ev.target,
        ev.event_type,
        ev.decision,
        ev.reason,
        ev.decision_stage,
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
            resp = client.post(f"{C6_URL}/refuse", json=deny_payload, headers={"X-Internal-Service-Secret": INTERNAL_SERVICE_SECRET})
            if resp.status_code == 200:
                return resp.json()
    except httpx.HTTPError:
        pass
    return deny_payload


@app.post("/propose")
def propose_action(req: ProposeRequest):
    is_grounded, grounding_reason = resolve_target(req.action, req.target)

    if not is_grounded:
        record_event(
            req.request_id,
            req.session_id,
            req.subject,
            req.action,
            req.target,
            "GROUNDING_FAILED",
            "DENY",
            grounding_reason,
            "C3",
            None,
            INVARIANT_SET_VERSION,
        )
        return forward_to_c6_refusal_gateway(
            {
                "request_id": req.request_id,
                "session_id": req.session_id,
                "subject": req.subject,
                "action": req.action,
                "target": req.target,
                "decision": "DENY",
                "reason": grounding_reason,
                "decision_stage": "C3",
                "policy_id": None,
                "invariant_set_version": INVARIANT_SET_VERSION,
                "timestamp": utc_now_iso(),
            }
        )

    record_event(
        req.request_id,
        req.session_id,
        req.subject,
        req.action,
        req.target,
        "GROUNDING_PASSED",
        "PERMIT",
        "TARGET_GROUNDED",
        "C3",
        None,
        INVARIANT_SET_VERSION,
    )

    c2_result = evaluate_request(req.model_dump())

    if c2_result["decision"] == "DENY":
        return forward_to_c6_refusal_gateway(c2_result)

    # Caller-supplied TTL is honoured ONLY in test mode (TTL-manipulation tests).
    ttl = req.expiry_seconds if (req.expiry_seconds is not None and TEST_MODE) else ECC_TTL_SECONDS

    ecc_data = generate_ecc(
        request_id=req.request_id,
        session_id=req.session_id,
        subject=req.subject,
        action=req.action,
        target=req.target,
        parameters=req.parameters,
        invariant_set_version=c2_result["invariant_set_version"],
        expiry_seconds=ttl,
        policy_id=c2_result["policy_id"],
    )
    record_event(
        req.request_id,
        req.session_id,
        req.subject,
        req.action,
        req.target,
        "ECC_ISSUED",
        "PERMIT",
        "ECC_GENERATED",
        "C7",
        c2_result["policy_id"],
        c2_result["invariant_set_version"],
        ecc_data={
            "ecc_id": ecc_data["ecc_id"],
            "parameters_hash": ecc_data["parameters_hash"],
            "expires_at": ecc_data["expires_at"],
            "kid": ecc_data["kid"],
        },
    )
    c2_result.update({"ecc_id": ecc_data["ecc_id"], "ecc": ecc_data["ecc"], "expires_at": ecc_data["expires_at"]})
    return c2_result
