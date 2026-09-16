"""ECC verification at C6: cryptographic forgery, envelope, binding, replay, restart epoch."""

import asyncio
import time
import uuid

import jwt
import pytest
from conftest import exec_body, propose


def _issue(croa_client, **kw):
    r = propose(croa_client, **kw)
    assert r["decision"] == "PERMIT", r
    return r


def _sign(key, payload, **headers):
    return jwt.encode(payload, key, algorithm="RS256", headers=headers or None)


def _valid_payload(services, **over):
    now = int(time.time())
    eid = str(uuid.uuid4())
    p = {
        "iss": "croa-plane-pilot",
        "aud": "c6-firewall-pilot",
        "jti": eid,
        "iat": now,
        "exp": now + 300,
        "ecc_schema_version": "1",
        "ecc_id": eid,
        "nonce": eid,
        "request_id": "r",
        "session_id": "s",
        "subject": "agent:1",
        "action": "get_customer",
        "target": "customer:342",
        "parameters_hash": services["c7"].hash_parameters({}),
        "invariant_set_version": "pilot-policy-set-v1",
    }
    p.update(over)
    return p


async def _exec(c6_client, body):
    r = await c6_client.post("/execute", json=body)
    assert r.status_code == 200, r.text
    return r.json()


async def test_happy_path_executes_once_with_separated_outcome(croa_client, c6_client, services):
    r = _issue(croa_client)
    x = await _exec(c6_client, exec_body(r["ecc"]))
    assert x["authorization"]["decision"] == "ALLOW" and x["execution"]["status"] == "SUCCEEDED"
    assert x["decision"] == "ALLOW"  # legacy field
    hist = services["acme"].HISTORY
    assert len(hist) == 1 and hist[0]["ecc_id"] == r["ecc_id"]


async def test_forged_with_wrong_key_is_invalid_signature(c6_client, services):
    token = _sign(services["wrong_key"], _valid_payload(services), kid=services["c6"].PUBLIC_KID)
    x = await _exec(c6_client, exec_body(token))
    assert x["decision"] == "BLOCK" and x["reason"] == "INVALID_SIGNATURE"
    assert services["acme"].HISTORY == []


async def test_alg_none_rejected(c6_client, services):
    token = jwt.encode(_valid_payload(services), key=None, algorithm="none", headers={"kid": services["c6"].PUBLIC_KID})
    x = await _exec(c6_client, exec_body(token))
    assert x["decision"] == "BLOCK" and x["reason"] == "INVALID_SIGNATURE"


async def test_hs256_with_public_key_as_secret_rejected(c6_client, services):
    pub_str = services["public_pem"].decode()
    # PyJWT refuses to use a public key as an HMAC secret; build the token by hand to be sure.
    import base64
    import hashlib
    import hmac
    import json

    def b64(b):
        return base64.urlsafe_b64encode(b).rstrip(b"=")

    header = b64(json.dumps({"alg": "HS256", "typ": "JWT", "kid": services["c6"].PUBLIC_KID}).encode())
    payload = b64(json.dumps(_valid_payload(services)).encode())
    sig = b64(hmac.new(pub_str.encode(), header + b"." + payload, hashlib.sha256).digest())
    token = (header + b"." + payload + b"." + sig).decode()
    x = await _exec(c6_client, exec_body(token))
    assert x["decision"] == "BLOCK" and x["reason"] == "INVALID_SIGNATURE"


async def test_wrong_kid_rejected(c6_client, services):
    token = _sign(services["private_key"], _valid_payload(services), kid="deadbeefdeadbeef")
    x = await _exec(c6_client, exec_body(token))
    assert x["reason"] == "UNKNOWN_KEY_ID"


async def test_wrong_issuer_and_audience_rejected(c6_client, services):
    for over in ({"iss": "evil"}, {"aud": "someone-else"}):
        token = _sign(services["private_key"], _valid_payload(services, **over), kid=services["c6"].PUBLIC_KID)
        x = await _exec(c6_client, exec_body(token))
        assert x["reason"] == "ISSUER_OR_AUDIENCE_MISMATCH", over


async def test_missing_claims_are_malformed(c6_client, services):
    for missing in ("nonce", "ecc_id", "parameters_hash", "jti", "ecc_schema_version", "iat"):
        p = _valid_payload(services)
        del p[missing]
        token = _sign(services["private_key"], p, kid=services["c6"].PUBLIC_KID)
        x = await _exec(c6_client, exec_body(token))
        assert x["reason"] == "MALFORMED_ECC", missing


async def test_unknown_crit_header_rejected(c6_client, services):
    token = _sign(services["private_key"], _valid_payload(services), kid=services["c6"].PUBLIC_KID, crit=["exp"])
    x = await _exec(c6_client, exec_body(token))
    assert x["decision"] == "BLOCK"


async def test_expired_ecc_rejected(c6_client, services):
    now = int(time.time())
    token = _sign(services["private_key"], _valid_payload(services, iat=now - 400, exp=now - 100), kid=services["c6"].PUBLIC_KID)
    x = await _exec(c6_client, exec_body(token))
    assert x["reason"] == "ECC_EXPIRED"


async def test_ecc_issued_before_firewall_boot_rejected(c6_client, services):
    boot = services["c6"].BOOT_TIME
    token = _sign(services["private_key"], _valid_payload(services, iat=boot - 10, exp=boot + 290), kid=services["c6"].PUBLIC_KID)
    x = await _exec(c6_client, exec_body(token))
    assert x["reason"] == "ECC_PREDATES_FIREWALL_EPOCH"


async def test_binding_mismatches(croa_client, c6_client, services):
    r = _issue(croa_client, action="export_customers", target="endpoint:analytics.internal", parameters={"count": 40})
    base = dict(action="export_customers", target="endpoint:analytics.internal", parameters={"count": 40})
    cases = {
        "SUBJECT_MISMATCH": {**base, "subject": "agent:2"},
        "ACTION_MISMATCH": {**base, "action": "delete_environment"},
        "TARGET_MISMATCH": {**base, "target": "customer:871"},
        "OPERATION_MISMATCH": {**base, "parameters": {"count": 400}},
    }
    for reason, over in cases.items():
        x = await _exec(c6_client, exec_body(r["ecc"], **over))
        assert x["reason"] == reason, reason
    assert services["acme"].HISTORY == []


async def test_replay_blocked(croa_client, c6_client, services):
    r = _issue(croa_client)
    first = await _exec(c6_client, exec_body(r["ecc"]))
    second = await _exec(c6_client, exec_body(r["ecc"]))
    assert first["decision"] == "ALLOW" and second["reason"] == "ECC_ALREADY_REDEEMED"
    assert len(services["acme"].HISTORY) == 1


async def test_simultaneous_redemption_executes_exactly_once(croa_client, c6_client, services):
    r = _issue(croa_client)
    results = await asyncio.gather(*[_exec(c6_client, exec_body(r["ecc"])) for _ in range(20)])
    allowed = [x for x in results if x["decision"] == "ALLOW"]
    assert len(allowed) == 1
    assert len(services["acme"].HISTORY) == 1


async def test_evidence_unavailable_fails_closed_and_releases_reservation(croa_client, c6_client, services):
    r = _issue(croa_client)
    services["faults"].evidence_down = True
    x = await _exec(c6_client, exec_body(r["ecc"]))
    assert x["reason"] == "EVIDENCE_UNAVAILABLE" and services["acme"].HISTORY == []
    services["faults"].evidence_down = False
    y = await _exec(c6_client, exec_body(r["ecc"]))
    assert y["decision"] == "ALLOW"  # the ECC was not spent by the failed attempt


async def test_target_unreachable_is_a_knowable_failure(croa_client, c6_client, services):
    r = _issue(croa_client)
    services["faults"].acme_connect_error = True
    x = await _exec(c6_client, exec_body(r["ecc"]))
    assert x["authorization"]["decision"] == "ALLOW"
    assert x["execution"]["status"] == "FAILED" and x["execution"]["target_status"] == "NOT_REACHED"


async def test_lost_response_reconciles_to_succeeded(croa_client, c6_client, services):
    r = _issue(croa_client)
    services["faults"].acme_drop_response = True
    x = await _exec(c6_client, exec_body(r["ecc"]))
    assert x["execution"]["status"] == "SUCCEEDED" and x["execution"]["target_status"] == "RECONCILED_SUCCESS"
    assert len(services["acme"].HISTORY) == 1
    # and the ECC is spent
    y = await _exec(c6_client, exec_body(r["ecc"]))
    assert y["reason"] == "ECC_ALREADY_REDEEMED"


async def test_lost_response_and_no_reconciliation_is_unknown_not_failure(croa_client, c6_client, services):
    r = _issue(croa_client)
    services["faults"].acme_drop_response = True
    services["faults"].acme_unreachable_after = True
    x = await _exec(c6_client, exec_body(r["ecc"]))
    assert x["execution"]["status"] == "UNKNOWN" and x["reason"] == "TARGET_OUTCOME_UNKNOWN"
    # evidence must say UNKNOWN, never FAILURE
    evs = services["c5"].verify_chain()
    assert evs["valid"]
    lines = services["evidence"].read_text().splitlines()
    last = __import__("json").loads(lines[-1])
    assert last["event_type"] == "EXECUTION_UNKNOWN" and last["execution_status"] == "UNKNOWN"


async def test_missing_ecc_blocked(c6_client, services):
    x = await _exec(c6_client, exec_body(""))
    assert x["reason"] == "MISSING_ECC"


async def test_unverified_claims_are_flagged_in_evidence(c6_client, services):
    token = _sign(services["wrong_key"], _valid_payload(services), kid=services["c6"].PUBLIC_KID)
    await _exec(c6_client, exec_body(token))
    import json

    last = json.loads(services["evidence"].read_text().splitlines()[-1])
    assert last["claims_verified"] is False and last["reason"] == "INVALID_SIGNATURE"


@pytest.mark.parametrize(
    "a,b,same",
    [
        ({"count": 40}, {"count": 40.0}, False),
        ({"b": 1, "a": 2}, {"a": 2, "b": 1}, True),
        ({"x": {"b": 1, "a": [1, 2]}}, {"x": {"a": [1, 2], "b": 1}}, True),
        ({"x": [1, 2]}, {"x": [2, 1]}, False),
        ({"s": "é"}, {"s": "e\u0301"}, False),
        ({"n": 10**30}, {"n": 10**30}, True),
    ],
)
def test_parameter_canonicalization(services, a, b, same):
    h = services["c7"].hash_parameters
    assert (h(a) == h(b)) is same
    assert h(a) == services["c6"].hash_parameters(a)  # C7 and C6 agree byte-for-byte
