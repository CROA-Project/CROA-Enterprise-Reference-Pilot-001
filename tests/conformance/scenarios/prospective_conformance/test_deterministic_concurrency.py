import os
import sys
import threading
import copy
import pytest
from fastapi.testclient import TestClient

# Ensure croa_plane path
repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
croa_plane_path = os.path.join(repo_root, "croa_plane")
if croa_plane_path not in sys.path:
    sys.path.insert(0, croa_plane_path)

os.environ["DEMO_CONTROL_SECRET"] = "test-secret"
os.environ["INTERNAL_SERVICE_SECRET"] = "test-internal-secret"

import c1_policy
import c4_trajectory
import c5_evidence
import c7_compiler
from main import app
from auth import get_authenticator, TokenRegistryAuthenticator

def test_deterministic_concurrency_serialization():
    # Setup paths
    scratch_dir = os.path.join(repo_root, "tests", "conformance", "evidence", "prospective_green", "scratch")
    os.makedirs(scratch_dir, exist_ok=True)
    c5_evidence.EVIDENCE_FILE = os.path.join(scratch_dir, "concurrency_test_evidence.jsonl")
    if os.path.exists(c5_evidence.EVIDENCE_FILE):
        os.remove(c5_evidence.EVIDENCE_FILE)

    c7_compiler.PRIVATE_KEY_PATH = os.path.join(croa_plane_path, "private.pem")

    auth = get_authenticator()
    if isinstance(auth, TokenRegistryAuthenticator):
        auth.register_token("valid_token_finance_ai", "finance_ai")

    test_inv = {
        "invariant_id": "INVARIANT-TRAJ-CONCURRENCY-001",
        "description": "Deterministic Concurrency TP-X Invariant",
        "action": "export_customers",
        "accumulation_parameter": "count",
        "limit": 100,
        "window": "cross_session",
        "trajectory_profile": "TP-X",
        "accumulation_key_dimensions": ["subject"]
    }

    orig_invariants = copy.deepcopy(c1_policy.INVARIANTS)
    c1_policy.INVARIANTS = [test_inv]
    c4_trajectory.trajectory_state.clear()

    # Precondition: State = 80, Limit = 100
    target_key = "inv:INVARIANT-TRAJ-CONCURRENCY-001:subject:finance_ai"
    c4_trajectory.trajectory_state[target_key] = 80

    client = TestClient(app)
    barrier = threading.Barrier(2)

    results = {}

    def worker(worker_id: str):
        payload = {
            "request_id": f"concur-{worker_id}",
            "session_id": f"sess-concur-{worker_id}",
            "subject": "finance_ai",
            "action": "export_customers",
            "target": "endpoint:analytics.internal",
            "parameters": {"count": 15}
        }
        headers = {
            "Authorization": "Bearer valid_token_finance_ai"
        }
        # Synchronize release
        barrier.wait()
        resp = client.post("/propose", json=payload, headers=headers)
        results[worker_id] = resp.json()

    t_a = threading.Thread(target=worker, args=("A",))
    t_b = threading.Thread(target=worker, args=("B",))

    t_a.start()
    t_b.start()
    t_a.join()
    t_b.join()

    # Restore policy
    c1_policy.INVARIANTS = orig_invariants

    dec_a = results["A"].get("decision")
    dec_b = results["B"].get("decision")
    final_state = c4_trajectory.trajectory_state.get(target_key, 0)

    # Assertions
    permits = [d for d in [dec_a, dec_b] if d == "PERMIT"]
    denies = [d for d in [dec_a, dec_b] if d == "DENY"]

    assert len(permits) == 1, f"Expected exactly 1 PERMIT, got {len(permits)} (A: {dec_a}, B: {dec_b})"
    assert len(denies) == 1, f"Expected exactly 1 DENY, got {len(denies)} (A: {dec_a}, B: {dec_b})"
    assert final_state == 95, f"Expected final state 95, got {final_state}"

    # Print summary for forensic logging
    print("\n--- CONCURRENCY TEST SUMMARY ---")
    print(f"REQUEST_A_DECISION = {dec_a}")
    print(f"REQUEST_B_DECISION = {dec_b}")
    print(f"FINAL_TRAJECTORY_STATE = {final_state}")
    print(f"PERMIT_COUNT = {len(permits)}")
    print(f"DENY_COUNT = {len(denies)}")
