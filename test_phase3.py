import httpx
import json
import sys

CROA_URL = "http://localhost:8000/propose"

PHASE2_TESTS = [
    {"name": "TEST-01", "payload": {"request_id": "req-01", "session_id": "s1", "subject": "agent:1", "action": "get_customer", "target": "customer:342", "parameters": {}}, "expected_decision": "PERMIT", "expected_reason": "POLICY_ALLOWED"},
    {"name": "TEST-02", "payload": {"request_id": "req-02", "session_id": "s1", "subject": "agent:1", "action": "get_customer", "target": "customer:999", "parameters": {}}, "expected_decision": "DENY", "expected_reason": "TARGET_NOT_REGISTERED"},
    {"name": "TEST-03", "payload": {"request_id": "req-03", "session_id": "s1", "subject": "agent:1", "action": "deploy_service", "target": "customer:342", "parameters": {}}, "expected_decision": "DENY", "expected_reason": "TARGET_TYPE_MISMATCH"},
    {"name": "TEST-04", "payload": {"request_id": "req-04", "session_id": "s1", "subject": "agent:1", "action": "change_config", "target": "environment:dev", "parameters": {}}, "expected_decision": "PERMIT", "expected_reason": "POLICY_ALLOWED"},
    {"name": "TEST-05", "payload": {"request_id": "req-05", "session_id": "s1", "subject": "agent:1", "action": "change_config", "target": "environment:prod", "parameters": {}}, "expected_decision": "DENY", "expected_reason": "POLICY_DENIED"},
    {"name": "TEST-06", "payload": {"request_id": "req-06", "session_id": "s1", "subject": "agent:1", "action": "delete_environment", "target": "environment:dev", "parameters": {}}, "expected_decision": "DENY", "expected_reason": "POLICY_DENIED"},
    {"name": "TEST-07", "payload": {"request_id": "req-07", "session_id": "s1", "subject": "agent:1", "action": "deploy_service", "target": "service:billing", "parameters": {}}, "expected_decision": "PERMIT", "expected_reason": "POLICY_ALLOWED"},
    {"name": "TEST-08", "payload": {"request_id": "req-08", "session_id": "s1", "subject": "agent:1", "action": "export_customers", "target": "endpoint:analytics.internal", "parameters": {"count": 1}}, "expected_decision": "PERMIT", "expected_reason": "POLICY_ALLOWED"}
]

PHASE3_TESTS = [
    {"name": "TEST-C4-01", "payload": {"request_id": "p3-01", "session_id": "s-test-1", "subject": "agent:1", "action": "export_customers", "target": "endpoint:analytics.internal", "parameters": {"count": 40}}, "expected_decision": "PERMIT", "expected_current": 0, "expected_projected": 40},
    {"name": "TEST-C4-02", "payload": {"request_id": "p3-02", "session_id": "s-test-1", "subject": "agent:1", "action": "export_customers", "target": "endpoint:analytics.internal", "parameters": {"count": 40}}, "expected_decision": "PERMIT", "expected_current": 40, "expected_projected": 80},
    {"name": "TEST-C4-03", "payload": {"request_id": "p3-03", "session_id": "s-test-1", "subject": "agent:1", "action": "export_customers", "target": "endpoint:analytics.internal", "parameters": {"count": 40}}, "expected_decision": "DENY", "expected_reason": "TRAJECTORY_LIMIT_EXCEEDED", "expected_current": 80, "expected_projected": 120},
    {"name": "TEST-C4-04", "payload": {"request_id": "p3-04", "session_id": "s-test-1", "subject": "agent:1", "action": "export_customers", "target": "endpoint:analytics.internal", "parameters": {"count": 20}}, "expected_decision": "PERMIT", "expected_current": 80, "expected_projected": 100},
    {"name": "TEST-C4-05", "payload": {"request_id": "p3-05", "session_id": "s-test-1", "subject": "agent:1", "action": "export_customers", "target": "endpoint:analytics.internal", "parameters": {"count": 1}}, "expected_decision": "DENY", "expected_reason": "TRAJECTORY_LIMIT_EXCEEDED", "expected_current": 100, "expected_projected": 101},
    {"name": "TEST-C4-06", "payload": {"request_id": "p3-06", "session_id": "s-test-2", "subject": "agent:1", "action": "export_customers", "target": "endpoint:analytics.internal", "parameters": {"count": 40}}, "expected_decision": "PERMIT", "expected_current": 0, "expected_projected": 40},
    {"name": "TEST-C4-07", "payload": {"request_id": "p3-07", "session_id": "s-test-2", "subject": "agent:1", "action": "export_customers", "target": "endpoint:analytics.internal", "parameters": {}}, "expected_decision": "DENY", "expected_reason": "INVALID_ACCUMULATION_PARAMETER"},
    {"name": "TEST-C4-08", "payload": {"request_id": "p3-08", "session_id": "s-test-2", "subject": "agent:1", "action": "export_customers", "target": "endpoint:analytics.internal", "parameters": {"count": -1}}, "expected_decision": "DENY", "expected_reason": "INVALID_ACCUMULATION_PARAMETER"},
    {"name": "TEST-C4-09", "payload": {"request_id": "p3-09", "session_id": "s-test-2", "subject": "agent:1", "action": "export_customers", "target": "endpoint:analytics.internal", "parameters": {"count": "forty"}}, "expected_decision": "DENY", "expected_reason": "INVALID_ACCUMULATION_PARAMETER"},
    {"name": "TEST-C4-10", "payload": {"request_id": "p3-10", "session_id": "s-test-3", "subject": "agent:1", "action": "change_config", "target": "environment:dev", "parameters": {}}, "expected_decision": "PERMIT", "expected_reason": "POLICY_ALLOWED"}
]

def run_tests():
    results = {}
    passed_all = True
    with httpx.Client() as client:
        # Phase 2 tests
        for t in PHASE2_TESTS:
            try:
                resp = client.post(CROA_URL, json=t["payload"])
                resp.raise_for_status()
                data = resp.json()
                
                passed = data.get("decision") == t["expected_decision"] and (
                    t["expected_reason"] is None or data.get("reason") == t["expected_reason"])
                    
                if passed:
                    results[t["name"]] = "PASS"
                else:
                    results[t["name"]] = f"FAIL (Got: {data.get('decision')} / {data.get('reason')})"
                    passed_all = False
            except Exception as e:
                results[t["name"]] = f"FAIL (Error: {str(e)})"
                passed_all = False
                
        # Phase 3 tests
        for t in PHASE3_TESTS:
            try:
                resp = client.post(CROA_URL, json=t["payload"])
                resp.raise_for_status()
                data = resp.json()
                
                passed = data.get("decision") == t["expected_decision"]
                if "expected_reason" in t:
                    passed = passed and data.get("reason") == t["expected_reason"]
                if "expected_current" in t:
                    passed = passed and data.get("current_value") == t["expected_current"]
                if "expected_projected" in t:
                    passed = passed and data.get("projected_value") == t["expected_projected"]
                    
                if passed:
                    results[t["name"]] = "PASS"
                else:
                    results[t["name"]] = f"FAIL (Got: {json.dumps(data)})"
                    passed_all = False
            except Exception as e:
                results[t["name"]] = f"FAIL (Error: {str(e)})"
                passed_all = False
    return results, passed_all

if __name__ == "__main__":
    results, passed_all = run_tests()
    print(json.dumps(results, indent=2))
    if not passed_all:
        sys.exit(1)
