"""AcmeOps — simulated protected enterprise target.

Pilot trust model: reachable only from C6 over the internal network AND every
/internal/* call must carry the internal service secret (the target authenticates
its firewall; reachability alone is not authority). Executions are idempotent on
`ecc_id`, so an ambiguous response to C6 can be reconciled rather than guessed.
"""

from __future__ import annotations

import asyncio
import hmac
import os
import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel

INTERNAL_SERVICE_SECRET = os.environ.get("INTERNAL_SERVICE_SECRET", "")
if len(INTERNAL_SERVICE_SECRET) < 12 or INTERNAL_SERVICE_SECRET.strip().lower() in {"replace-me", "changeme"}:
    raise RuntimeError("INTERNAL_SERVICE_SECRET is unset or a placeholder. See .env.example.")
TEST_MODE = os.environ.get("ENABLE_TEST_MODE", "0") == "1"

app = FastAPI(title="AcmeOps (simulated protected target)")

HISTORY: list[dict[str, Any]] = []
EXECUTIONS: dict[str, dict[str, Any]] = {}  # ecc_id -> record (idempotency registry)


def verify_internal_service(x_internal_service_secret: str | None = Header(None)):
    if x_internal_service_secret is None or not hmac.compare_digest(x_internal_service_secret.encode(), INTERNAL_SERVICE_SECRET.encode()):
        raise HTTPException(status_code=403, detail="Forbidden: caller is not an authenticated CROA execution firewall")


class ExecutionRequest(BaseModel):
    ecc_id: str
    request_id: str | None = None
    action: str
    target: str
    parameters: dict[str, Any]


@app.get("/health")
def health():
    return {"status": "ONLINE"}


@app.post("/internal/execute", dependencies=[Depends(verify_internal_service)])
async def execute(req: ExecutionRequest):
    existing = EXECUTIONS.get(req.ecc_id)
    if existing:
        return {"status": "duplicate", "execution_id": existing["execution_id"], "data": existing}

    record = {
        "execution_id": str(uuid.uuid4()),
        "ecc_id": req.ecc_id,
        "request_id": req.request_id,
        "timestamp": datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z"),
        "action": req.action,
        "target": req.target,
        "parameters": req.parameters,
    }
    HISTORY.append(record)
    EXECUTIONS[req.ecc_id] = record

    # Test-mode fault injection: execute, then withhold the response so the caller times out.
    if TEST_MODE and req.parameters.get("__test_fault") == "delay_response":
        await asyncio.sleep(float(req.parameters.get("__test_delay", 8)))

    return {"status": "executed", "execution_id": record["execution_id"], "data": record}


@app.get("/internal/executions/{ecc_id}", dependencies=[Depends(verify_internal_service)])
def get_execution(ecc_id: str):
    record = EXECUTIONS.get(ecc_id)
    if not record:
        raise HTTPException(status_code=404, detail="no execution for this ecc_id")
    return record


@app.get("/internal/history", dependencies=[Depends(verify_internal_service)])
def history():
    return HISTORY


@app.post("/internal/reset", dependencies=[Depends(verify_internal_service)])
def reset():
    HISTORY.clear()
    EXECUTIONS.clear()
    return {"status": "reset"}
