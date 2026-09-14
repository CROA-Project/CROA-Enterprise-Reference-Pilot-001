import httpx
import json
import os
import time

CROA_URL = "http://croa_plane:8000"
C6_URL = "http://localhost:8000"

def get_history(client):
    try:
        r = client.get(f"{C6_URL}/acmeops/history", headers={"X-Demo-Control-Secret": os.environ["DEMO_CONTROL_SECRET"]})
        return r.json()
    except Exception:
        return []

def run_tests():
    passed_all = True
    results = {}
    
    with httpx.Client() as client:
        # Reset
        run_id = f"test-run-{int(time.time())}"
        client.post(f"{CROA_URL}/reset", json={"demo_run_id": run_id}, headers={"X-Demo-Control-Secret": os.environ["DEMO_CONTROL_SECRET"]})
        client.post(f"{C6_URL}/reset", headers={"X-Demo-Control-Secret": os.environ["DEMO_CONTROL_SECRET"]})
        
        # Scenario A
        try:
            h_before = len(get_history(client))
            r = client.post(f"{CROA_URL}/propose", json={
                "request_id": f"{run_id}-A", "session_id": f"sess-{run_id}", "subject": "agent:1", "action": "get_customer", "target": "customer:342", "parameters": {}
            }).json()
            x = client.post(f"{C6_URL}/execute", json={
                "ecc": r["ecc"], "subject": "agent:1", "action": "get_customer", "target": "customer:342", "parameters": {}
            }).json()
            h_after = len(get_history(client))
            if x["decision"] == "ALLOW" and h_after == h_before + 1:
                results["Scenario A"] = "PASS"
            else:
                results["Scenario A"] = "FAIL"
                passed_all = False
        except Exception as e:
            results["Scenario A"] = f"FAIL ({e})"
            passed_all = False
            
        # Scenario B
        try:
            h_before = len(get_history(client))
            r = client.post(f"{CROA_URL}/propose", json={
                "request_id": f"{run_id}-B", "session_id": f"sess-{run_id}", "subject": "agent:1", "action": "get_customer", "target": "customer:999", "parameters": {}
            }).json()
            h_after = len(get_history(client))
            if r["decision_stage"] in ["C3", "C6_REFUSAL_GATEWAY"] and r["decision"] == "DENY" and h_before == h_after:
                results["Scenario B"] = "PASS"
            else:
                results["Scenario B"] = "FAIL"
                passed_all = False
        except Exception as e:
            results["Scenario B"] = f"FAIL ({e})"
            passed_all = False
            
        # Scenario C
        try:
            h_before = len(get_history(client))
            r = client.post(f"{CROA_URL}/propose", json={
                "request_id": f"{run_id}-C", "session_id": f"sess-{run_id}", "subject": "agent:1", "action": "delete_environment", "target": "environment:dev", "parameters": {}
            }).json()
            h_after = len(get_history(client))
            if r["decision_stage"] in ["C2", "C6_REFUSAL_GATEWAY"] and r["decision"] == "DENY" and h_before == h_after:
                results["Scenario C"] = "PASS"
            else:
                results["Scenario C"] = "FAIL"
                passed_all = False
        except Exception as e:
            results["Scenario C"] = f"FAIL ({e})"
            passed_all = False

        # Scenario D
        try:
            h_before = len(get_history(client))
            sess = f"sess-{run_id}-D"
            reqs = [
                {"request_id": f"{run_id}-D1", "session_id": sess, "subject": "agent:1", "action": "export_customers", "target": "endpoint:analytics.internal", "parameters": {"count": 40}},
                {"request_id": f"{run_id}-D2", "session_id": sess, "subject": "agent:1", "action": "export_customers", "target": "endpoint:analytics.internal", "parameters": {"count": 40}},
                {"request_id": f"{run_id}-D3", "session_id": sess, "subject": "agent:1", "action": "export_customers", "target": "endpoint:analytics.internal", "parameters": {"count": 40}}
            ]
            
            p1 = client.post(f"{CROA_URL}/propose", json=reqs[0]).json()
            client.post(f"{C6_URL}/execute", json={"ecc": p1["ecc"], **reqs[0]})
            p2 = client.post(f"{CROA_URL}/propose", json=reqs[1]).json()
            client.post(f"{C6_URL}/execute", json={"ecc": p2["ecc"], **reqs[1]})
            p3 = client.post(f"{CROA_URL}/propose", json=reqs[2]).json()
            
            h_after = len(get_history(client))
            if p3["decision_stage"] in ["C4", "C6_REFUSAL_GATEWAY"] and p3["decision"] == "DENY" and (h_after - h_before) == 2:
                results["Scenario D"] = "PASS"
            else:
                results["Scenario D"] = f"FAIL (decision: {p3['decision']}, stage: {p3.get('decision_stage')}, count diff: {h_after - h_before})"
                passed_all = False
        except Exception as e:
            results["Scenario D"] = f"FAIL ({e})"
            passed_all = False
            
        # Scenario E
        try:
            h_before = len(get_history(client))
            x = client.post(f"{C6_URL}/execute", json={
                "ecc": "", "subject": "agent:1", "action": "get_customer", "target": "customer:342", "parameters": {}
            }).json()
            h_after = len(get_history(client))
            if x["decision"] == "BLOCK" and x["reason"] == "MISSING_ECC" and h_before == h_after:
                results["Scenario E"] = "PASS"
            else:
                results["Scenario E"] = "FAIL"
                passed_all = False
        except Exception as e:
            results["Scenario E"] = f"FAIL ({e})"
            passed_all = False

        # Scenario F
        try:
            h_before = len(get_history(client))
            r = client.post(f"{CROA_URL}/propose", json={
                "request_id": f"{run_id}-F", "session_id": f"sess-{run_id}", "subject": "agent:1", "action": "get_customer", "target": "customer:342", "parameters": {}
            }).json()
            x = client.post(f"{C6_URL}/execute", json={
                "ecc": r["ecc"] + ".forged", "subject": "agent:1", "action": "get_customer", "target": "customer:342", "parameters": {}
            }).json()
            h_after = len(get_history(client))
            if x["decision"] == "BLOCK" and x["reason"] == "INVALID_SIGNATURE" and h_before == h_after:
                results["Scenario F"] = "PASS"
            else:
                results["Scenario F"] = "FAIL"
                passed_all = False
        except Exception as e:
            results["Scenario F"] = f"FAIL ({e})"
            passed_all = False

        # Scenario G
        try:
            h_before = len(get_history(client))
            r = client.post(f"{CROA_URL}/propose", json={
                "request_id": f"{run_id}-G", "session_id": f"sess-{run_id}", "subject": "agent:1", "action": "export_customers", "target": "endpoint:analytics.internal", "parameters": {"count": 40}
            }).json()
            x = client.post(f"{C6_URL}/execute", json={
                "ecc": r["ecc"], "subject": "agent:1", "action": "export_customers", "target": "endpoint:analytics.internal", "parameters": {"count": 400}
            }).json()
            h_after = len(get_history(client))
            if x["decision"] == "BLOCK" and x["reason"] == "OPERATION_MISMATCH" and h_before == h_after:
                results["Scenario G"] = "PASS"
            else:
                results["Scenario G"] = "FAIL"
                passed_all = False
        except Exception as e:
            results["Scenario G"] = f"FAIL ({e})"
            passed_all = False

        # Scenario H
        try:
            h_before = len(get_history(client))
            r = client.post(f"{CROA_URL}/propose", json={
                "request_id": f"{run_id}-H", "session_id": f"sess-{run_id}", "subject": "agent:1", "action": "export_customers", "target": "endpoint:analytics.internal", "parameters": {"count": 40}
            }).json()
            x1 = client.post(f"{C6_URL}/execute", json={
                "ecc": r["ecc"], "subject": "agent:1", "action": "export_customers", "target": "endpoint:analytics.internal", "parameters": {"count": 40}
            }).json()
            x2 = client.post(f"{C6_URL}/execute", json={
                "ecc": r["ecc"], "subject": "agent:1", "action": "export_customers", "target": "endpoint:analytics.internal", "parameters": {"count": 40}
            }).json()
            h_after = len(get_history(client))
            if x1["decision"] == "ALLOW" and x2["decision"] == "BLOCK" and x2["reason"] == "ECC_ALREADY_REDEEMED" and h_after == h_before + 1:
                results["Scenario H"] = "PASS"
            else:
                results["Scenario H"] = "FAIL"
                passed_all = False
        except Exception as e:
            results["Scenario H"] = f"FAIL ({e})"
            passed_all = False

    print(json.dumps(results, indent=2))
    return passed_all

if __name__ == "__main__":
    if not run_tests():
        exit(1)
