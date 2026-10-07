"""C4: atomic reservation under concurrency; all applicable invariants evaluated together."""

import threading
from concurrent.futures import ThreadPoolExecutor

from conftest import propose


def test_concurrent_reservations_never_exceed_limit(services):
    c4 = services["c4"]
    permits = []
    barrier = threading.Barrier(10)

    def worker(i):
        barrier.wait()
        decision, _ = c4.reserve_trajectory("sess-c", "agent:1", "export_customers", {"count": 30})
        permits.append(decision)

    with ThreadPoolExecutor(max_workers=10) as ex:
        list(ex.map(worker, range(10)))

    committed = c4.get_trajectory_state("sess-c:agent:1", "INVARIANT-TRAJ-001")
    assert committed <= 100
    assert permits.count("PERMIT") == 3  # 3 x 30 = 90; a 4th would be 120
    assert committed == 90


def test_concurrent_proposals_over_http_never_exceed_limit(croa_client):
    barrier = threading.Barrier(8)

    def worker(i):
        barrier.wait()
        return propose(
            croa_client,
            request_id=f"r{i}",
            session_id="sess-http",
            action="export_customers",
            target="endpoint:analytics.internal",
            parameters={"count": 40},
        )

    with ThreadPoolExecutor(max_workers=8) as ex:
        results = list(ex.map(worker, range(8)))

    permitted = [r for r in results if r["decision"] == "PERMIT"]
    assert len(permitted) == 2  # 2 x 40 = 80; a third would be 120 > 100
    assert all(r["reason"] == "TRAJECTORY_LIMIT_EXCEEDED" for r in results if r["decision"] == "DENY")


def test_sequential_scenario_d(croa_client):
    r = [
        propose(
            croa_client,
            request_id=f"d{i}",
            session_id="sess-d",
            action="export_customers",
            target="endpoint:analytics.internal",
            parameters={"count": 40},
        )
        for i in range(3)
    ]
    assert [x["decision"] for x in r] == ["PERMIT", "PERMIT", "DENY"]
    assert r[2]["current_value"] == 80 and r[2]["projected_value"] == 120


def test_multiple_invariants_all_evaluated_and_committed(services, monkeypatch):
    c4 = services["c4"]
    two = [
        {
            "invariant_id": "INV-A",
            "name": "a",
            "description": "",
            "profile": "TP-C",
            "action": "export_customers",
            "accumulation_parameter": "count",
            "limit": 100,
            "scope": "session_subject",
            "version": "1",
        },
        {
            "invariant_id": "INV-B",
            "name": "b",
            "description": "",
            "profile": "TP-C",
            "action": "export_customers",
            "accumulation_parameter": "count",
            "limit": 50,
            "scope": "session_subject",
            "version": "1",
        },
    ]
    monkeypatch.setattr(c4, "INVARIANTS", two)
    d1, data1 = c4.reserve_trajectory("s", "a", "export_customers", {"count": 40})
    assert d1 == "PERMIT" and len(data1["invariants"]) == 2
    assert c4.get_trajectory_state("s:a", "INV-A") == 40 and c4.get_trajectory_state("s:a", "INV-B") == 40
    d2, data2 = c4.reserve_trajectory("s", "a", "export_customers", {"count": 20})
    assert d2 == "DENY" and data2["invariant_id"] == "INV-B"  # the tighter invariant denies
    # all-or-nothing: INV-A must not have been committed when INV-B denied
    assert c4.get_trajectory_state("s:a", "INV-A") == 40


def test_invalid_accumulation_parameter_rejects_bool_float_negative(services):
    c4 = services["c4"]
    for bad in ({"count": True}, {"count": 40.0}, {"count": -1}, {"count": 0}, {"count": "40"}, {}):
        d, data = c4.reserve_trajectory("s", "a", "export_customers", bad)
        assert d == "DENY" and data["reason"] == "INVALID_ACCUMULATION_PARAMETER", bad
