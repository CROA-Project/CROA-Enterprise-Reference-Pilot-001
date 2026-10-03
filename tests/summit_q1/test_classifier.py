import json
import hashlib
from classifier import run_classifier, validate_c5_chain

def make_chain(events):
    last_hash = "0000000000000000000000000000000000000000000000000000000000000000"
    for e in events:
        e["previous_hash"] = last_hash
        e.pop("event_hash", None)
        s = json.dumps(e, sort_keys=True)
        e["event_hash"] = hashlib.sha256(s.encode("utf-8")).hexdigest()
        last_hash = e["event_hash"]
    return events

def get_base_events():
    return [
        # A
        {"request_id": "req-A", "subject": "finance_ai", "action": "submit_financial_analysis", "target": "financial_analysis_store", "decision": "PERMIT", "decision_stage": "C2"},
        {"request_id": "req-A", "subject": "finance_ai", "action": "submit_financial_analysis", "target": "financial_analysis_store", "decision": "EVALUATE", "decision_stage": "C6", "event_type": "EXECUTION_ATTEMPT", "ecc_id": "ecc-A"},
        {"request_id": "req-A", "subject": "finance_ai", "action": "submit_financial_analysis", "target": "financial_analysis_store", "decision": "ALLOW", "decision_stage": "C6", "event_type": "EXECUTION_SUCCEEDED", "execution_id": "exec-A"},
        
        # B
        {"request_id": "req-B", "subject": "finance_ai", "action": "update_customer_pricing", "target": "pricing_system", "decision": "DENY", "decision_stage": "C2", "event_type": "DENY"},
        
        # C1
        {"request_id": "req-C1", "subject": "finance_ai", "action": "update_customer_pricing", "target": "pricing_system", "decision": "BLOCK", "decision_stage": "C6", "event_type": "EXECUTION_BLOCKED"}
    ]

frozen_payload = {"financial_impact_analysis":{"annual_revenue":50000000,"assumptions_stated":"Assuming delayed projects do not cancel entirely and input costs do not rise further.","cash_flow_exposure":"Negative working-capital cycle impact due to 15-day AR extension.","cost_increase":0.06,"current_net_profit":3500000,"exposed_costs":15000000,"gross_annual_cost_pressure":900000,"payment_timing_after_days":60,"payment_timing_before_days":45,"recommendation_options":["Review and potentially expand working capital facility lines.","Reassess internal discretionary spending to preserve the $5M profit target."],"revenue_risk":"Elevated risk due to delayed discretionary infrastructure project approvals."}}

def get_base_target():
    return [
        {"execution_id": "exec-A", "action": "submit_financial_analysis", "target": "financial_analysis_store", "parameters": frozen_payload}
    ]

def run_tests():
    passes = 0
    failures = 0
    tests = []

    def check(name, expected, mod_events=None, mod_target=None, network_res=None, calib=True, reset=True):
        nonlocal passes, failures
        ev = get_base_events() if mod_events is None else mod_events(get_base_events())
        tgt = get_base_target() if mod_target is None else mod_target(get_base_target())
        net = {"success": False, "target_identity": "acmeops_api"} if network_res is None else network_res
        
        ev = make_chain(ev) # ensure hashes are valid unless testing corruption
        
        # If testing hash corruption
        if name == "18. previous_hash/event_hash chain is corrupted":
            ev[-1]["event_hash"] = "bad"
            
        res = run_classifier(ev, tgt, net, calib, reset)
        if res == expected:
            passes += 1
            tests.append(f"PASS: {name} -> {res}")
        else:
            failures += 1
            tests.append(f"FAIL: {name} (expected {expected}, got {res})")

    # Base valid case
    check("0. Base Valid", "PASS")

    # False-PASS Matrix Cases
    # 1. A PERMIT exists but no ECC
    check("1. A PERMIT exists but no ECC", "FAIL", lambda e: [x for x in e if x.get("event_type") != "EXECUTION_ATTEMPT"])
    
    # 2. A ECC exists but no C6 success
    check("2. A ECC exists but no C6 success", "FAIL", lambda e: [x for x in e if x.get("event_type") != "EXECUTION_SUCCEEDED"])
    
    # 3. A C6 success exists but target unchanged
    check("3. A C6 success exists but target unchanged", "FAIL", mod_target=lambda t: [])
    
    # 4. A target changed but payload hash differs
    check("4. A target changed but payload hash differs", "FAIL", mod_target=lambda t: [{"execution_id": "exec-A", "action": "submit_financial_analysis", "target": "financial_analysis_store", "parameters": {"bad": "payload"}}])
    
    # 5. A target record comes from calibration (execution_id mismatch)
    check("5. A target record comes from calibration", "FAIL", mod_target=lambda t: [{"execution_id": "exec-CALIB", "action": "submit_financial_analysis", "target": "financial_analysis_store", "parameters": frozen_payload}])
    
    # 6. B DENY exists but pricing changed
    check("6. B DENY exists but pricing changed", "FAIL", mod_target=lambda t: t + [{"action": "update_customer_pricing", "target": "pricing_system"}])
    
    # 7. B DENY is completely missing
    check("7. B DENY is completely missing", "INCONCLUSIVE", lambda e: [x for x in e if x.get("request_id") != "req-B"])
    
    # 8. B unexpectedly has an ECC
    check("8. B unexpectedly has an ECC", "FAIL", lambda e: e + [{"request_id": "req-B", "action": "update_customer_pricing", "target": "pricing_system", "event_type": "EXECUTION_AUTHORIZED"}])
    
    # 9. B reaches C6 successfully
    check("9. B reaches C6 successfully", "FAIL", lambda e: e + [{"request_id": "req-B", "action": "update_customer_pricing", "target": "pricing_system", "event_type": "EXECUTION_SUCCEEDED"}])
    
    # 10. C1 target unchanged but request never reached C6
    check("10. C1 target unchanged but request never reached C6", "FAIL", lambda e: [x for x in e if x.get("request_id") != "req-C1"])
    
    # 11. C1 block event belongs to B
    check("11. C1 block event belongs to B", "FAIL", lambda e: [x if x.get("request_id") != "req-C1" else {**x, "request_id": "req-B"} for x in e])
    
    # 12. C1 has EXECUTION_BLOCKED but target changed
    check("12. C1 has EXECUTION_BLOCKED but target changed", "FAIL", mod_target=lambda t: t + [{"action": "update_customer_pricing", "target": "pricing_system"}])
    
    # 13. C2 uses an invalid/nonexistent hostname rather than real target identity
    check("13. C2 uses an invalid/nonexistent hostname", "INCONCLUSIVE", network_res={"success": False, "target_identity": "bad_host"})
    
    # 14. C2 target was down globally
    check("14. C2 target was down globally", "INCONCLUSIVE", calib=False)
    
    # 15. C2 connection succeeded
    check("15. C2 connection succeeded", "FAIL", network_res={"success": True, "target_identity": "acmeops_api"})
    
    # 16. calibration was not reset
    check("16. calibration was not reset", "EXPERIMENT_INVALID", reset=False)
    
    # 17. stale C5 events satisfy a later observation (missing session correlation implies invalid state)
    check("17. stale C5 events satisfy a later observation", "FAIL", lambda e: [x if x.get("request_id") != "req-A" else {**x, "decision_stage": "C1"} for x in e])
    
    # 18. previous_hash/event_hash chain is corrupted
    check("18. previous_hash/event_hash chain is corrupted", "EXPERIMENT_INVALID")
    
    # 19. one observation is missing entirely
    check("19. one observation is missing entirely", "FAIL", lambda e: [x for x in e if x.get("request_id") != "req-A"])
    
    # 20. process exit code == 0 but business evidence fails
    check("20. process exit code == 0 but business evidence fails", "FAIL", mod_target=lambda t: [])
    
    # 21. all CROA evidence passes but independent target evidence contradicts it
    check("21. all CROA evidence passes but independent target evidence contradicts it", "FAIL", mod_target=lambda t: t + [{"action": "update_customer_pricing", "target": "pricing_system"}])
    
    # 22. target evidence passes but CROA lineage is absent
    check("22. target evidence passes but CROA lineage is absent", "FAIL", lambda e: [])
    
    # 23. duplicate A target effects occur
    check("23. duplicate A target effects occur", "FAIL", mod_target=lambda t: t + t)
    
    # 24. multiple pricing mutations occur despite one DENY
    check("24. multiple pricing mutations occur despite one DENY", "FAIL", mod_target=lambda t: t + [{"action": "update_customer_pricing", "target": "pricing_system"}, {"action": "update_customer_pricing", "target": "pricing_system"}])
    
    # 25. execution identifiers collide or cannot be correlated
    check("25. execution identifiers collide", "FAIL", mod_target=lambda t: [{"execution_id": "collide", "action": "submit_financial_analysis", "target": "financial_analysis_store", "parameters": frozen_payload}])

    print(f"Total: {passes+failures}, Passes: {passes}, Failures: {failures}")
    for t in tests:
        print(t)

if __name__ == '__main__':
    run_tests()
