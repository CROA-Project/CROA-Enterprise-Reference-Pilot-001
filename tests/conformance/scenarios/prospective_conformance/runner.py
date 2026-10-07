"""
Prospective Conformance Test Runner
Evaluates the CURRENT un-remediated MRH SUT against normative CROA v1.0.1 requirements.
Strict separation: SUT source code remains unmodified.
"""

import sys
import os
import json
import copy
from typing import Dict, Any, List

# Ensure croa_plane is importable
repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
croa_plane_path = os.path.join(repo_root, "croa_plane")
if croa_plane_path not in sys.path:
    sys.path.insert(0, croa_plane_path)

os.environ["DEMO_CONTROL_SECRET"] = "test-secret-unit-test"
os.environ["INTERNAL_SERVICE_SECRET"] = "test-internal-secret"

import c1_policy
import c4_trajectory
import c2_governor
import c5_evidence
import c7_compiler
from main import app
from fastapi.testclient import TestClient
from .definitions import get_prospective_tests, ProspectiveTestCase
from .fixtures import TEST_SUBJECT_TOKENS
from auth import get_authenticator, TokenRegistryAuthenticator

def run_prospective_tests(evidence_output_path: str = None) -> Dict[str, Any]:
    # Route evidence and keys to host test paths to ensure zero modification to SUT source files
    orig_evidence_file = c5_evidence.EVIDENCE_FILE
    orig_key = c7_compiler.PRIVATE_KEY_PATH
    scratch_evidence_dir = os.path.join(repo_root, "tests", "conformance", "evidence", "prospective_red", "scratch")
    os.makedirs(scratch_evidence_dir, exist_ok=True)
    c5_evidence.EVIDENCE_FILE = os.path.join(scratch_evidence_dir, "red_run_evidence.jsonl")
    if os.path.exists(c5_evidence.EVIDENCE_FILE):
        os.remove(c5_evidence.EVIDENCE_FILE)
    c5_evidence.reset_anchor_for_tests()

    # Point compiler to local private key path
    c7_compiler.PRIVATE_KEY_PATH = os.path.join(croa_plane_path, "private.pem")
    if hasattr(c7_compiler, "reset_key_cache"):
        c7_compiler.reset_key_cache()

    # Register prospective conformance test identity tokens in authenticator
    auth = get_authenticator()
    if isinstance(auth, TokenRegistryAuthenticator):
        for tok, subj in TEST_SUBJECT_TOKENS.items():
            auth.register_token(tok, subj)

    client = TestClient(app)
    original_invariants = copy.deepcopy(c1_policy.INVARIANTS)

    test_cases = get_prospective_tests()
    test_results = {}

    try:
        for tc in test_cases:
            c4_trajectory.trajectory_state.clear()
            # Configure invariant under test without modifying SUT source files
            c1_policy.INVARIANTS = [tc.applicable_invariant]

            step_records = []
            test_passed_normative = True
            mrh_non_conformance = False

            for step in tc.steps:
                payload = {
                    "request_id": f"{tc.test_id}-{step.step_id}",
                    "session_id": step.session_id,
                    "subject": step.subject_body,
                    "action": step.action,
                    "target": step.target,
                    "parameters": step.parameters
                }

                # Attach test identity header where specified
                headers = {}
                if step.auth_token:
                    headers["Authorization"] = f"Bearer {step.auth_token}"

                # Invoke MRH proposal intake
                response = client.post("/propose", json=payload, headers=headers)
                resp_json = response.json()

                status_code = response.status_code
                if status_code in (401, 403):
                    observed_decision = "REJECT_INTAKE"
                    observed_stage = "AGENT_SURFACE"
                else:
                    observed_decision = resp_json.get("decision", "NONE")
                    observed_stage = resp_json.get("decision_stage", "NONE")

                # Evaluate observation against normative oracle
                is_step_conformant = True
                if step.expected_decision == "REJECT_INTAKE":
                    # Normative requirement: Agent Surface must reject unauthenticated/spoofed intake (401/403)
                    # If current MRH allows unauthenticated proposal intake (status 200 with PERMIT/ECC issued),
                    # it demonstrates non-conformance to §4.9.
                    if status_code == 200 and observed_decision != "DENY":
                        is_step_conformant = False
                        mrh_non_conformance = True
                        test_passed_normative = False
                else:
                    if observed_decision != step.expected_decision:
                        is_step_conformant = False
                        mrh_non_conformance = True
                        test_passed_normative = False

                step_records.append({
                    "step_id": step.step_id,
                    "session_id": step.session_id,
                    "subject_body": step.subject_body,
                    "auth_token": step.auth_token,
                    "parameters": step.parameters,
                    "expected_decision": step.expected_decision,
                    "expected_stage": step.expected_stage,
                    "observed_status_code": status_code,
                    "observed_decision": observed_decision,
                    "observed_stage": observed_stage,
                    "step_conformant": is_step_conformant,
                    "response_payload": resp_json
                })

            if test_passed_normative:
                classification = "PASS_CURRENT_BEHAVIOR_CONFORMANT"
            elif mrh_non_conformance:
                classification = "RED_MRH_NON_CONFORMANCE"
            else:
                classification = "INCONCLUSIVE"

            test_results[tc.test_id] = {
                "test_id": tc.test_id,
                "name": tc.name,
                "trajectory_profile": tc.trajectory_profile,
                "conformance_result": classification,
                "normative_rationale": tc.normative_rationale,
                "steps": step_records
            }

    finally:
        # Restore c1_policy.INVARIANTS
        c1_policy.INVARIANTS = original_invariants

    report = {
        "title": "Prospective Conformance Red Baseline Report",
        "authoritative_baseline": "CROA Framework v1.0.1",
        "sut_state": "CURRENT_UN_REMEDIATED_MRH",
        "results": test_results
    }

    if evidence_output_path:
        with open(evidence_output_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)

    return report

if __name__ == "__main__":
    report = run_prospective_tests()
    print(json.dumps(report, indent=2))
