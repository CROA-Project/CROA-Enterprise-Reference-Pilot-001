import json
import hashlib
import os
from datetime import datetime
import uuid
import threading

EVIDENCE_FILE = "/app/evidence_data/evidence.jsonl"
c5_lock = threading.Lock()

def get_last_hash() -> str:
    if not os.path.exists(EVIDENCE_FILE):
        return "0000000000000000000000000000000000000000000000000000000000000000"
    try:
        with open(EVIDENCE_FILE, "r") as f:
            lines = f.readlines()
            if lines:
                last_event = json.loads(lines[-1])
                return last_event.get("event_hash", "0000000000000000000000000000000000000000000000000000000000000000")
    except Exception:
        pass
    return "0000000000000000000000000000000000000000000000000000000000000000"

def record_event(request_id: str, session_id: str, subject: str, action: str, target: str, 
                 event_type: str, decision: str, reason: str, decision_stage: str,
                 policy_id: str = None, invariant_set_version: str = None,
                 trajectory_data: dict = None, ecc_data: dict = None, ecc_id: str = None, execution_id: str = None, target_status: str = None) -> dict:
                 
    with c5_lock:
        previous_hash = get_last_hash()
        event_id = str(uuid.uuid4())
        timestamp = datetime.utcnow().isoformat() + "Z"
        
        event_data = {
            "event_id": event_id,
            "timestamp": timestamp,
            "request_id": request_id,
            "session_id": session_id,
            "subject": subject,
            "action": action,
            "target": target,
            "event_type": event_type,
            "decision": decision,
            "reason": reason,
            "decision_stage": decision_stage,
            "policy_id": policy_id,
            "invariant_set_version": invariant_set_version,
            "previous_hash": previous_hash
        }
        
        if ecc_id:
            event_data["ecc_id"] = ecc_id
        if execution_id:
            event_data["execution_id"] = execution_id
        if target_status:
            event_data["target_status"] = target_status
            
        if trajectory_data:
            for k, v in trajectory_data.items():
                event_data[k] = v
                
        if ecc_data:
            for k, v in ecc_data.items():
                event_data[k] = v
        
        event_string = json.dumps(event_data, sort_keys=True)
        event_hash = hashlib.sha256(event_string.encode('utf-8')).hexdigest()
        
        event_data["event_hash"] = event_hash
        
        with open(EVIDENCE_FILE, "a") as f:
            f.write(json.dumps(event_data) + "\n")
            
        return event_data
