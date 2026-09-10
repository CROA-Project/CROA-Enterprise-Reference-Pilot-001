from fastapi import FastAPI
from pydantic import BaseModel
from typing import Dict, Any
import datetime
import uuid

app = FastAPI()

HISTORY = []

class ExecutionRequest(BaseModel):
    action: str
    target: str
    parameters: Dict[str, Any]

@app.get("/health")
def health():
    return {"status": "ONLINE"}

@app.post("/internal/execute")
def execute(req: ExecutionRequest):
    exec_id = str(uuid.uuid4())
    record = {
        "execution_id": exec_id,
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "action": req.action,
        "target": req.target,
        "parameters": req.parameters
    }
    HISTORY.append(record)
    return {
        "status": "executed",
        "execution_id": exec_id,
        "data": record
    }

@app.get("/internal/history")
def history():
    return HISTORY

@app.post("/internal/reset")
def reset():
    HISTORY.clear()
    return {"status": "reset"}
