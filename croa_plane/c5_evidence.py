"""C5 — Evidence Logger.

Append-only, SHA-256 hash-chained JSONL log. Tamper-EVIDENT, not immutable:
modification of any retained record is detectable; deletion of the whole file
or truncation of the tail is only detectable relative to an anchor. This module
keeps an in-process anchor (the last hash it wrote) and refuses to append if the
file on disk no longer ends with that record. Any unreadable or malformed
history is a hard error: C5 never silently starts a new chain.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import uuid
from datetime import UTC, datetime
from typing import Any

EVIDENCE_FILE = os.environ.get("CROA_EVIDENCE_FILE", "/app/evidence_data/evidence.jsonl")
GENESIS_HASH = "0" * 64

c5_lock = threading.Lock()
_head_hash: str | None = None  # last hash this process wrote or verified; None = not yet loaded


class EvidenceIntegrityError(RuntimeError):
    """Raised when the evidence log cannot be trusted or extended safely."""


def utc_now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _canonical(event: dict[str, Any]) -> str:
    return json.dumps(event, sort_keys=True)


def compute_event_hash(event_without_hash: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical(event_without_hash).encode("utf-8")).hexdigest()


def verify_chain(path: str | None = None) -> dict[str, Any]:
    """Walk the whole file. Never raises on content problems; reports them."""
    path = path or EVIDENCE_FILE
    if not os.path.exists(path):
        return {"valid": True, "records": 0, "head_hash": GENESIS_HASH, "reason": "NO_EVIDENCE_FILE"}
    prev = GENESIS_HASH
    count = 0
    try:
        with open(path, encoding="utf-8") as f:
            for line_no, raw in enumerate(f, start=1):
                line = raw.strip()
                if not line:
                    return {"valid": False, "records": count, "reason": f"blank line at {line_no}"}
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    return {"valid": False, "records": count, "reason": f"malformed record at line {line_no}"}
                if not isinstance(record, dict) or "event_hash" not in record or "previous_hash" not in record:
                    return {"valid": False, "records": count, "reason": f"incomplete record at line {line_no}"}
                stored_hash = record.pop("event_hash")
                if record["previous_hash"] != prev:
                    return {"valid": False, "records": count, "reason": f"broken chain at {record.get('event_id', line_no)}"}
                if compute_event_hash(record) != stored_hash:
                    return {"valid": False, "records": count, "reason": f"hash mismatch at {record.get('event_id', line_no)}"}
                prev = stored_hash
                count += 1
    except OSError as e:
        return {"valid": False, "records": count, "reason": f"unreadable: {e.__class__.__name__}"}
    return {"valid": True, "records": count, "head_hash": prev}


def _read_tail_hash(path: str) -> str:
    """Hash of the last record on disk. Raises EvidenceIntegrityError on anything odd."""
    if not os.path.exists(path):
        return GENESIS_HASH
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            if size == 0:
                return GENESIS_HASH
            # read a bounded tail; records are small
            f.seek(max(0, size - 65536))
            tail = f.read().decode("utf-8", errors="strict")
    except (OSError, UnicodeDecodeError) as e:
        raise EvidenceIntegrityError(f"evidence log unreadable: {e.__class__.__name__}") from e
    if not tail.endswith("\n"):
        raise EvidenceIntegrityError("evidence log tail is truncated (no terminating newline)")
    last_line = tail.rstrip("\n").split("\n")[-1]
    try:
        record = json.loads(last_line)
    except json.JSONDecodeError as e:
        raise EvidenceIntegrityError("evidence log tail is malformed") from e
    h = record.get("event_hash") if isinstance(record, dict) else None
    if not isinstance(h, str) or len(h) != 64:
        raise EvidenceIntegrityError("evidence log tail lacks a valid event_hash")
    return h


def load_head_hash(path: str | None = None) -> str:
    """Full verification on first use. Fail closed if history is not intact."""
    global _head_hash
    path = path or EVIDENCE_FILE
    with c5_lock:
        if _head_hash is not None:
            return _head_hash
        result = verify_chain(path)
        if not result["valid"]:
            raise EvidenceIntegrityError(f"existing evidence log failed verification: {result['reason']}")
        _head_hash = result["head_hash"]
        return _head_hash


def record_event(
    request_id: str,
    session_id: str | None,
    subject: str,
    action: str,
    target: str,
    event_type: str,
    decision: str,
    reason: str,
    decision_stage: str,
    policy_id: str | None = None,
    invariant_set_version: str | None = None,
    trajectory_data: dict | None = None,
    ecc_data: dict | None = None,
    ecc_id: str | None = None,
    execution_id: str | None = None,
    target_status: str | None = None,
    execution_status: str | None = None,
    claims_verified: bool | None = None,
) -> dict[str, Any]:
    global _head_hash
    if _head_hash is None:
        load_head_hash()

    with c5_lock:
        # Continuity check: the file must still end with the record we last saw.
        on_disk = _read_tail_hash(EVIDENCE_FILE)
        if on_disk != _head_hash:
            raise EvidenceIntegrityError(
                "evidence log head does not match this process's anchor "
                f"(disk={on_disk[:12]}…, anchor={_head_hash[:12]}…); refusing to extend a replaced or truncated log"
            )

        event: dict[str, Any] = {
            "event_id": str(uuid.uuid4()),
            "timestamp": utc_now_iso(),
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
            "previous_hash": _head_hash,
        }
        for k, v in (
            ("ecc_id", ecc_id),
            ("execution_id", execution_id),
            ("target_status", target_status),
            ("execution_status", execution_status),
            ("claims_verified", claims_verified),
        ):
            if v is not None:
                event[k] = v
        if trajectory_data:
            event.update(trajectory_data)
        if ecc_data:
            event.update(ecc_data)

        event["event_hash"] = compute_event_hash({k: v for k, v in event.items() if k != "event_hash"})

        os.makedirs(os.path.dirname(EVIDENCE_FILE), exist_ok=True)
        with open(EVIDENCE_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(event) + "\n")
            f.flush()
            os.fsync(f.fileno())
        _head_hash = event["event_hash"]
        return event


def reset_anchor_for_tests() -> None:
    global _head_hash
    with c5_lock:
        _head_hash = None
