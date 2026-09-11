import httpx
import json
import sys

CROA_URL = "http://localhost:8000/propose"

TESTS = [
    {
        "name": "TEST-01",
        "payload": {"request_id": "req-01", "session_id": "s1", "subject": "agent:1", "action": "get_customer", "target": "customer:342", "parameters": {}},
        "expected_decision": "PERMIT",
        "expected_reason": "POLICY_ALLOWED"
    },
    {
        "name": "TEST-02",
        "payload": {"request_id": "req-02", "session_id": "s1", "subject": "agent:1", "action": "get_customer", "target": "customer:999", "parameters": {}},
        "expected_decision": "DENY",
        "expected_reason": "TARGET_NOT_REGISTERED"
    },
    {
        "name": "TEST-03",
        "payload": {"request_id": "req-03", "session_id": "s1", "subject": "agent:1", "action": "deploy_service", "target": "customer:342", "parameters": {}},
        "expected_decision": "DENY",
        "expected_reason": "TARGET_TYPE_MISMATCH"
    },
    {
        "name": "TEST-04",
        "payload": {"request_id": "req-04", "session_id": "s1", "subject": "agent:1", "action": "change_config", "target": "environment:dev", "parameters": {}},
        "expected_decision": "PERMIT",
        "expected_reason": "POLICY_ALLOWED"
    },
    {
        "name": "TEST-05",
        "payload": {"request_id": "req-05", "session_id": "s1", "subject": "agent:1", "action": "change_config", "target": "environment:prod", "parameters": {}},
        "expected_decision": "DENY",
        "expected_reason": "POLICY_DENIED"
    },
    {
        "name": "TEST-06",
        "payload": {"request_id": "req-06", "session_id": "s1", "subject": "agent:1", "action": "delete_environment", "target": "environment:dev", "parameters": {}},
        "expected_decision": "DENY",
        "expected_reason": "POLICY_DENIED"
    },
    {
        "name": "TEST-07",
        "payload": {"request_id": "req-07", "session_id": "s1", "subject": "agent:1", "action": "deploy_service", "target": "service:billing", "parameters": {}},
        "expected_decision": "PERMIT",
        "expected_reason": "POLICY_ALLOWED"
    },
    {
        "name": "TEST-08",
        "payload": {"request_id": "req-08", "session_id": "s1", "subject": "agent:1", "action": "export_customers", "target": "endpoint:analytics.internal", "parameters": {}},
        "expected_decision": "PERMIT",
        "expected_reason": "POLICY_ALLOWED"
    }
]

def run_tests():
    results = {}
    passed_all = True
    with httpx.Client() as client:
        for t in TESTS:
            try:
                # We will run this inside the c6_firewall container which has httpx installed.
                # So we hit croa_plane:8000 directly
                resp = client.post("http://croa_plane:8000/propose", json=t["payload"])
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
    return results, passed_all

if __name__ == "__main__":
    results, passed_all = run_tests()
    print(json.dumps(results, indent=2))
    if not passed_all:
        sys.exit(1)
