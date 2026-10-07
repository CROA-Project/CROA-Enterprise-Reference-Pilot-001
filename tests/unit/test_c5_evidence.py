"""C5: fail closed on corrupt/replaced history; verification never crashes."""

import json

import pytest


def _write(c5, n=3):
    for i in range(n):
        c5.record_event(f"r{i}", "s", "agent", "get_customer", "customer:342", "TEST", "PERMIT", "OK", "C2")


def test_chain_verifies_and_tamper_is_detected(services):
    c5 = services["c5"]
    _write(c5)
    assert c5.verify_chain()["valid"] and c5.verify_chain()["records"] == 3
    lines = services["evidence"].read_text().splitlines()
    rec = json.loads(lines[1])
    rec["decision"] = "DENY"
    lines[1] = json.dumps(rec)
    services["evidence"].write_text("\n".join(lines) + "\n")
    v = c5.verify_chain()
    assert not v["valid"] and "hash mismatch" in v["reason"]


def test_truncated_tail_fails_closed_on_write_and_reports_on_verify(services):
    c5 = services["c5"]
    _write(c5)
    data = services["evidence"].read_bytes()
    services["evidence"].write_bytes(data[:-20])  # chop the last record
    with pytest.raises(c5.EvidenceIntegrityError):
        c5.record_event("r9", "s", "agent", "get_customer", "customer:342", "TEST", "PERMIT", "OK", "C2")
    v = c5.verify_chain()
    assert v["valid"] is False and "malformed" in v["reason"]
    # and nothing was appended
    assert services["evidence"].read_bytes() == data[:-20]


def test_deleted_log_is_not_silently_restarted(services):
    c5 = services["c5"]
    _write(c5)
    services["evidence"].unlink()
    with pytest.raises(c5.EvidenceIntegrityError):
        c5.record_event("r9", "s", "agent", "get_customer", "customer:342", "TEST", "PERMIT", "OK", "C2")


def test_startup_refuses_corrupt_history(services):
    c5 = services["c5"]
    _write(c5)
    services["evidence"].write_text(services["evidence"].read_text() + "{not json\n")
    c5.reset_anchor_for_tests()
    with pytest.raises(c5.EvidenceIntegrityError):
        c5.load_head_hash()


def test_verify_endpoint_returns_structured_result_not_500(croa_client, services):
    _write(services["c5"])
    services["evidence"].write_text(services["evidence"].read_text() + "garbage\n")
    r = croa_client.get("/evidence/verify", headers={"X-Demo-Control-Secret": "unit-test-demo-control-secret"})
    assert r.status_code == 200 and r.json()["valid"] is False


def test_evidence_timestamps_are_valid_iso_z(services):
    c5 = services["c5"]
    ev = c5.record_event("r", "s", "agent", "get_customer", "customer:342", "TEST", "PERMIT", "OK", "C2")
    assert ev["timestamp"].endswith("Z") and "+00:00" not in ev["timestamp"]


def test_concurrent_writes_preserve_chain(services):
    from concurrent.futures import ThreadPoolExecutor

    c5 = services["c5"]
    with ThreadPoolExecutor(max_workers=8) as ex:
        list(ex.map(lambda i: c5.record_event(f"r{i}", "s", "agent", "a", "t", "TEST", "PERMIT", "OK", "C2"), range(40)))
    v = c5.verify_chain()
    assert v["valid"] and v["records"] == 40
