import httpx
import json
import os
import time

CROA_URL = "http://localhost:8000/propose"
C6_URL = "http://localhost:8000/execute" # When run in c6 container, it will hit its own execute endpoint
ACMEOPS_HISTORY_URL = "http://acmeops_api:8000/internal/history"

def get_acmeops_history(client):
    resp = client.get(ACMEOPS_HISTORY_URL, headers={"X-Demo-Control-Secret": os.environ["DEMO_CONTROL_SECRET"]})
    return resp.json()

def run_tests():
    results = {}
    passed_all = True
    with httpx.Client() as client:
        # TEST-ECC-01
        try:
            h_before = len(get_acmeops_history(client))
            resp = client.post("http://croa_plane:8000/propose", json={
                "request_id": "req-ecc-01", "session_id": "s-ecc-$((Get-Date).Ticks)", "subject": "agent:1", "action": "get_customer", "target": "customer:342", "parameters": {}
            })
            ecc_data = resp.json()
            ecc_token = ecc_data.get("ecc")
            
            resp2 = client.post("http://localhost:8000/execute", json={
                "ecc": ecc_token, "subject": "agent:1", "action": "get_customer", "target": "customer:342", "parameters": {}
            })
            c6_data = resp2.json()
            
            h_after = len(get_acmeops_history(client))
            
            if c6_data.get("decision") == "ALLOW" and h_after == h_before + 1:
                results["TEST-ECC-01"] = "PASS"
            else:
                results["TEST-ECC-01"] = f"FAIL (C6: {c6_data.get('decision')}, History diff: {h_after - h_before})"
                passed_all = False
        except Exception as e:
            results["TEST-ECC-01"] = f"FAIL ({e})"
            passed_all = False

        # TEST-ECC-02 Missing ECC
        try:
            h_before = len(get_acmeops_history(client))
            resp2 = client.post("http://localhost:8000/execute", json={
                "ecc": "", "subject": "agent:1", "action": "get_customer", "target": "customer:342", "parameters": {}
            })
            c6_data = resp2.json()
            h_after = len(get_acmeops_history(client))
            if c6_data.get("reason") == "MISSING_ECC" and h_after == h_before:
                results["TEST-ECC-02"] = "PASS"
            else:
                results["TEST-ECC-02"] = f"FAIL"
                passed_all = False
        except Exception as e:
            results["TEST-ECC-02"] = f"FAIL ({e})"
            passed_all = False

        # TEST-ECC-03 Forged ECC
        try:
            h_before = len(get_acmeops_history(client))
            resp2 = client.post("http://localhost:8000/execute", json={
                "ecc": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIifQ.invalid_signature", "subject": "agent:1", "action": "get_customer", "target": "customer:342", "parameters": {}
            })
            c6_data = resp2.json()
            h_after = len(get_acmeops_history(client))
            if c6_data.get("reason") == "INVALID_SIGNATURE" and h_after == h_before:
                results["TEST-ECC-03"] = "PASS"
            else:
                results["TEST-ECC-03"] = f"FAIL"
                passed_all = False
        except Exception as e:
            results["TEST-ECC-03"] = f"FAIL ({e})"
            passed_all = False

        # Generate a base ECC for mutations
        resp = client.post("http://croa_plane:8000/propose", json={
            "request_id": "req-ecc-mut", "session_id": "s-ecc-$((Get-Date).Ticks)", "subject": "agent:1", "action": "export_customers", "target": "endpoint:analytics.internal", "parameters": {"count": 40}
        })
        base_ecc = resp.json().get("ecc")

        # TEST-ECC-04 Parameter Mutation
        try:
            h_before = len(get_acmeops_history(client))
            resp2 = client.post("http://localhost:8000/execute", json={
                "ecc": base_ecc, "subject": "agent:1", "action": "export_customers", "target": "endpoint:analytics.internal", "parameters": {"count": 400}
            })
            c6_data = resp2.json()
            h_after = len(get_acmeops_history(client))
            if c6_data.get("reason") == "OPERATION_MISMATCH" and h_after == h_before:
                results["TEST-ECC-04"] = "PASS"
            else:
                results["TEST-ECC-04"] = f"FAIL"
                passed_all = False
        except Exception as e:
            results["TEST-ECC-04"] = f"FAIL ({e})"
            passed_all = False

        # TEST-ECC-05 Action Mutation
        try:
            h_before = len(get_acmeops_history(client))
            resp2 = client.post("http://localhost:8000/execute", json={
                "ecc": base_ecc, "subject": "agent:1", "action": "delete_environment", "target": "endpoint:analytics.internal", "parameters": {"count": 40}
            })
            c6_data = resp2.json()
            h_after = len(get_acmeops_history(client))
            if c6_data.get("reason") == "ACTION_MISMATCH" and h_after == h_before:
                results["TEST-ECC-05"] = "PASS"
            else:
                results["TEST-ECC-05"] = f"FAIL"
                passed_all = False
        except Exception as e:
            results["TEST-ECC-05"] = f"FAIL ({e})"
            passed_all = False

        # TEST-ECC-06 Target Mutation
        try:
            h_before = len(get_acmeops_history(client))
            resp2 = client.post("http://localhost:8000/execute", json={
                "ecc": base_ecc, "subject": "agent:1", "action": "export_customers", "target": "customer:871", "parameters": {"count": 40}
            })
            c6_data = resp2.json()
            h_after = len(get_acmeops_history(client))
            if c6_data.get("reason") == "TARGET_MISMATCH" and h_after == h_before:
                results["TEST-ECC-06"] = "PASS"
            else:
                results["TEST-ECC-06"] = f"FAIL"
                passed_all = False
        except Exception as e:
            results["TEST-ECC-06"] = f"FAIL ({e})"
            passed_all = False

        # TEST-ECC-07 Subject Substitution
        try:
            h_before = len(get_acmeops_history(client))
            resp2 = client.post("http://localhost:8000/execute", json={
                "ecc": base_ecc, "subject": "agent:2", "action": "export_customers", "target": "endpoint:analytics.internal", "parameters": {"count": 40}
            })
            c6_data = resp2.json()
            h_after = len(get_acmeops_history(client))
            if c6_data.get("reason") == "SUBJECT_MISMATCH" and h_after == h_before:
                results["TEST-ECC-07"] = "PASS"
            else:
                results["TEST-ECC-07"] = f"FAIL"
                passed_all = False
        except Exception as e:
            results["TEST-ECC-07"] = f"FAIL ({e})"
            passed_all = False

        # TEST-ECC-08 Replay
        try:
            h_before = len(get_acmeops_history(client))
            # First execution
            client.post("http://localhost:8000/execute", json={
                "ecc": base_ecc, "subject": "agent:1", "action": "export_customers", "target": "endpoint:analytics.internal", "parameters": {"count": 40}
            })
            # Second execution
            resp2 = client.post("http://localhost:8000/execute", json={
                "ecc": base_ecc, "subject": "agent:1", "action": "export_customers", "target": "endpoint:analytics.internal", "parameters": {"count": 40}
            })
            c6_data = resp2.json()
            h_after = len(get_acmeops_history(client))
            if c6_data.get("reason") == "ECC_ALREADY_REDEEMED" and h_after == h_before + 1:
                results["TEST-ECC-08"] = "PASS"
            else:
                results["TEST-ECC-08"] = f"FAIL"
                passed_all = False
        except Exception as e:
            results["TEST-ECC-08"] = f"FAIL ({e})"
            passed_all = False

        # TEST-ECC-09 Expired ECC
        try:
            resp = client.post("http://croa_plane:8000/propose", headers={"X-Test-Expiry-Seconds": "1"}, json={
                "request_id": "req-ecc-exp", "session_id": "s-ecc-$((Get-Date).Ticks)", "subject": "agent:1", "action": "get_customer", "target": "customer:342", "parameters": {}, "expiry_seconds": 1
            })
            exp_ecc = resp.json().get("ecc")
            time.sleep(2) # wait for expiry
            h_before = len(get_acmeops_history(client))
            resp2 = client.post("http://localhost:8000/execute", json={
                "ecc": exp_ecc, "subject": "agent:1", "action": "get_customer", "target": "customer:342", "parameters": {}
            })
            c6_data = resp2.json()
            h_after = len(get_acmeops_history(client))
            if c6_data.get("reason") == "ECC_EXPIRED" and h_after == h_before:
                results["TEST-ECC-09"] = "PASS"
            else:
                results["TEST-ECC-09"] = f"FAIL (Got {c6_data})"
                passed_all = False
        except Exception as e:
            results["TEST-ECC-09"] = f"FAIL ({e})"
            passed_all = False

        # TEST-ECC-10 DENY produces no ECC
        try:
            resp = client.post("http://croa_plane:8000/propose", json={
                "request_id": "req-ecc-10", "session_id": "s-ecc-$((Get-Date).Ticks)", "subject": "agent:1", "action": "delete_environment", "target": "environment:dev", "parameters": {}
            })
            if resp.json().get("ecc") is None:
                results["TEST-ECC-10"] = "PASS"
            else:
                results["TEST-ECC-10"] = "FAIL"
                passed_all = False
        except Exception as e:
            results["TEST-ECC-10"] = f"FAIL ({e})"
            passed_all = False

        # Trajectory + Execution Test
        try:
            h_before = get_acmeops_history(client)
            exp_before = sum([x["parameters"]["count"] for x in h_before if x["action"] == "export_customers" and "count" in x["parameters"]])
            sid = "s-traj-" + str(time.time())
            # 1
            r1 = client.post("http://croa_plane:8000/propose", json={"request_id": "r1", "session_id": sid, "subject": "agent:1", "action": "export_customers", "target": "endpoint:analytics.internal", "parameters": {"count": 40}}).json()
            client.post("http://localhost:8000/execute", json={"ecc": r1["ecc"], "subject": "agent:1", "action": "export_customers", "target": "endpoint:analytics.internal", "parameters": {"count": 40}})
            # 2
            r2 = client.post("http://croa_plane:8000/propose", json={"request_id": "r2", "session_id": sid, "subject": "agent:1", "action": "export_customers", "target": "endpoint:analytics.internal", "parameters": {"count": 40}}).json()
            client.post("http://localhost:8000/execute", json={"ecc": r2["ecc"], "subject": "agent:1", "action": "export_customers", "target": "endpoint:analytics.internal", "parameters": {"count": 40}})
            # 3
            r3 = client.post("http://croa_plane:8000/propose", json={"request_id": "r3", "session_id": sid, "subject": "agent:1", "action": "export_customers", "target": "endpoint:analytics.internal", "parameters": {"count": 40}}).json()
            
            h = get_acmeops_history(client)
            # count exports in history
            export_count = sum([x["parameters"]["count"] for x in h if x["action"] == "export_customers" and "count" in x["parameters"]])
            if r3.get("decision") == "DENY" and (export_count - exp_before) == 80:
                results["TEST-TRAJ-EXEC"] = "PASS"
            else:
                results["TEST-TRAJ-EXEC"] = f"FAIL (decision: {r3.get('decision')}, observed exports: {export_count - exp_before})"
                passed_all = False
        except Exception as e:
            results["TEST-TRAJ-EXEC"] = f"FAIL ({e})"
            passed_all = False
            
    print(json.dumps(results, indent=2))
    return passed_all

if __name__ == "__main__":
    if not run_tests():
        exit(1)

