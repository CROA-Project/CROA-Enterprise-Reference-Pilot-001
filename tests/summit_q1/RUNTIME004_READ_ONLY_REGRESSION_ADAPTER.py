import json
from classifier_v2 import run_classifier

def run_adapter():
    with open('tests/summit_q1/SUMMIT-Q1-TEST1-CLEANROOM-RUNTIME-004/evidence.jsonl', 'r') as f:
        c5_events = [json.loads(line) for line in f]
    with open('tests/summit_q1/SUMMIT-Q1-TEST1-CLEANROOM-RUNTIME-004/final_target_history.json', 'r') as f:
        target_history = json.load(f)
    with open('tests/summit_q1/SUMMIT-Q1-TEST1-CLEANROOM-RUNTIME-004/observation_C2_network_result.json', 'r') as f:
        legacy_network = json.load(f)
        
    network_adapter = dict(legacy_network)
    network_adapter["schema_version"] = "summit-network-evidence-v2"
    network_adapter["observation_id"] = "legacy-obs-c2"
    
    # In V2, network failures must have exit_code != 0. Since legacy had 0 despite Name or service not known, we adapt it.
    if "Name or service not known" in legacy_network.get("stderr", ""):
        network_adapter["exit_code"] = 7
        
    req_a = next(e["request_id"] for e in c5_events if e.get("event_type") == "PERMIT" and e.get("action") == "submit_financial_analysis")
    req_b = next(e["request_id"] for e in c5_events if e.get("event_type") == "DENY" and e.get("action") == "update_customer_pricing" and e.get("decision_stage") == "C2")
    req_c1 = next(e["request_id"] for e in c5_events if e.get("event_type") == "EXECUTION_BLOCKED" and e.get("action") == "update_customer_pricing" and e.get("reason") == "MISSING_ECC")

    identities = {
        "A": req_a,
        "B": req_b,
        "C1": req_c1,
        "C2": "legacy-obs-c2"
    }

    res = run_classifier(c5_events, target_history, network_adapter, True, True, identities)
    print(f"PROSPECTIVE_CLASSIFIER_V2_REGRESSION_RESULT = {res}")

if __name__ == '__main__':
    run_adapter()
