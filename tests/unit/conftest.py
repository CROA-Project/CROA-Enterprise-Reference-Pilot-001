"""In-process test harness: loads the three services with generated keys, a temp
evidence file, and an httpx transport that routes C6's outbound calls to the
control-plane and AcmeOps ASGI apps (with fault injection). No Docker required."""

from __future__ import annotations

import functools
import importlib.util
import os
import sys
from pathlib import Path

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

ROOT = Path(__file__).resolve().parents[2]
DEMO_SECRET = "unit-test-demo-control-secret"
INTERNAL_SECRET = "unit-test-internal-service-secret"


def _gen_key(path: Path) -> tuple[Path, Path, rsa.RSAPrivateKey]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv = path / "private.pem"
    pub = path / "public.pem"
    priv.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    pub.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    return priv, pub, key


def _load(name: str, file: Path, extra_path: Path | None = None):
    if extra_path and str(extra_path) not in sys.path:
        sys.path.insert(0, str(extra_path))
    spec = importlib.util.spec_from_file_location(name, file)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


class Faults:
    """Per-test fault switches for the routed transport."""

    def __init__(self):
        self.acme_drop_response = False  # execute reaches target, response is lost (ReadTimeout)
        self.acme_connect_error = False  # target unreachable
        self.acme_unreachable_after = False  # reconciliation call also fails
        self.evidence_down = False  # C5 unavailable


class RoutingTransport(httpx.AsyncBaseTransport):
    def __init__(self, croa_app, acme_app, faults: Faults):
        self.croa = httpx.ASGITransport(app=croa_app)
        self.acme = httpx.ASGITransport(app=acme_app)
        self.faults = faults

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        host = request.url.host
        if host == "croa_plane":
            if self.faults.evidence_down:
                return httpx.Response(503, json={"detail": "C5 down"})
            return await self.croa.handle_async_request(request)
        if host == "acmeops_api":
            path = request.url.path
            if path == "/internal/execute":
                if self.faults.acme_connect_error:
                    raise httpx.ConnectError("connection refused", request=request)
                resp = await self.acme.handle_async_request(request)
                if self.faults.acme_drop_response:
                    await resp.aread()
                    raise httpx.ReadTimeout("response lost", request=request)
                return resp
            if path.startswith("/internal/executions/") and self.faults.acme_unreachable_after:
                raise httpx.ConnectError("connection refused", request=request)
            return await self.acme.handle_async_request(request)
        raise httpx.ConnectError(f"unrouted host {host}", request=request)


@pytest.fixture(scope="session")
def services(tmp_path_factory):
    base = tmp_path_factory.mktemp("croa")
    keys = base / "keys"
    keys.mkdir()
    priv, pub, key = _gen_key(keys)
    (base / "wrong").mkdir()
    _, wrong_pub, wrong_key = _gen_key(base / "wrong")
    evidence = base / "evidence" / "evidence.jsonl"

    os.environ.update(
        {
            "DEMO_CONTROL_SECRET": DEMO_SECRET,
            "INTERNAL_SERVICE_SECRET": INTERNAL_SECRET,
            "CROA_PRIVATE_KEY_PATH": str(priv),
            "CROA_PUBLIC_KEY_PATH": str(pub),
            "CROA_EVIDENCE_FILE": str(evidence),
            "ENABLE_TEST_MODE": "1",
            "ECC_TTL_SECONDS": "300",
        }
    )

    croa = _load("croa_main", ROOT / "croa_plane" / "main.py", ROOT / "croa_plane")
    c6 = _load("c6_main", ROOT / "c6_firewall" / "main.py")
    acme = _load("acme_main", ROOT / "acmeops_api" / "main.py")
    c5 = sys.modules["c5_evidence"]
    c4 = sys.modules["c4_trajectory"]
    c7 = sys.modules["c7_compiler"]

    faults = Faults()
    router = RoutingTransport(croa.app, acme.app, faults)
    c6.httpx.AsyncClient = functools.partial(httpx.AsyncClient, transport=router)  # type: ignore[attr-defined]
    # Denials are still routed through C6 in production; in-process we short-circuit the gateway.
    croa.forward_to_c6_refusal_gateway = lambda payload: payload

    return {
        "croa": croa,
        "c6": c6,
        "acme": acme,
        "c5": c5,
        "c4": c4,
        "c7": c7,
        "faults": faults,
        "evidence": evidence,
        "private_key": key,
        "wrong_key": wrong_key,
        "public_pem": pub.read_bytes(),
    }


@pytest.fixture(autouse=True)
def clean_state(services):
    """Fresh evidence log, trajectory state, replay registry and target history for every test."""
    s = services
    f = s["faults"]
    f.acme_drop_response = f.acme_connect_error = f.acme_unreachable_after = f.evidence_down = False
    if s["evidence"].exists():
        s["evidence"].unlink()
    s["c5"].reset_anchor_for_tests()
    s["c4"].reset_trajectory_state()
    s["c6"].REDEEMED_NONCES.clear()
    s["acme"].HISTORY.clear()
    s["acme"].EXECUTIONS.clear()
    s["croa"]._test_c5_unavailable = False
    yield


@pytest.fixture
def croa_client(services):
    from fastapi.testclient import TestClient

    with TestClient(services["croa"].app) as c:
        yield c


@pytest.fixture
def c6_client(services):
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=services["c6"].app), base_url="http://c6")


def propose(client, **overrides):
    body = {
        "request_id": overrides.pop("request_id", "req-1"),
        "session_id": "sess-1",
        "subject": "agent:1",
        "action": "get_customer",
        "target": "customer:342",
        "parameters": {},
    }
    body.update(overrides)
    return client.post("/propose", json=body).json()


def exec_body(ecc: str, **overrides):
    body = {"ecc": ecc, "subject": "agent:1", "action": "get_customer", "target": "customer:342", "parameters": {}}
    body.update(overrides)
    return body
