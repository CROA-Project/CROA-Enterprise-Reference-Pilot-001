"""
CROA Reference Harness — C7 Contract Compiler
Normative Reference: CROA Framework v1.0.1 §4.4 / §4.9

Issues cryptographically signed Execution Change Contracts (ECCs) as RS256 JWTs.
Reconciled ECC Contract:
- Standard JWT claims: iss, aud, jti, iat, exp.
- Reconciled identity roles:
    jti: RFC 7519 unique token identifier.
    ecc_id: CROA contract identifier (bound to jti).
    nonce: Single-use replay prevention token consumed by C6 PEP (bound to ecc_id).
- Schema: ecc_schema_version ("1").
- Governance claims: request_id, session_id, subject, action, target,
  parameters_hash, invariant_set_version, decision_basis.
- Governed Exception claims (CROA §4.3 / §4.9): auth_ref, exception_scope.
- JOSE header: kid derived from public key DER digest.
"""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
from cryptography.hazmat.primitives import serialization

PRIVATE_KEY_PATH = os.environ.get("CROA_PRIVATE_KEY_PATH", os.environ.get("PRIVATE_KEY_PATH", "/app/keys/private.pem"))
ECC_ISSUER = os.environ.get("ECC_ISSUER", "croa-plane-pilot")
ECC_AUDIENCE = os.environ.get("ECC_AUDIENCE", "c6-firewall-pilot")
ECC_SCHEMA_VERSION = "1"

_private_key_pem: bytes | None = None
_kid: str | None = None


_loaded_key_path: str | None = None


def reset_key_cache() -> None:
    """Explicitly reset cached key so new key path or rotated keys are loaded."""
    global _private_key_pem, _kid, _loaded_key_path
    _private_key_pem = None
    _kid = None
    _loaded_key_path = None


def _resolve_private_key_path() -> str:
    global PRIVATE_KEY_PATH
    if PRIVATE_KEY_PATH and os.path.exists(PRIVATE_KEY_PATH):
        return PRIVATE_KEY_PATH
    env_path = os.environ.get("CROA_PRIVATE_KEY_PATH", os.environ.get("PRIVATE_KEY_PATH", ""))
    if env_path and os.path.exists(env_path):
        return env_path
    for candidate in [
        os.path.join(os.path.dirname(__file__), "..", "keys", "private.pem"),
        os.path.join(os.path.dirname(__file__), "private.pem"),
        os.path.join(os.getcwd(), "keys", "private.pem"),
        os.path.join(os.getcwd(), "private.pem"),
    ]:
        if os.path.exists(candidate):
            return candidate
    return env_path or "/app/keys/private.pem"


def _load_key() -> tuple[bytes, str]:
    """Load the signing key; derive `kid` from public key so C6 matches it."""
    global _private_key_pem, _kid, _loaded_key_path
    key_path = _resolve_private_key_path()
    if _private_key_pem is None or _loaded_key_path != key_path:
        with open(key_path, "rb") as f:
            _private_key_pem = f.read()
        private_key = serialization.load_pem_private_key(_private_key_pem, password=None)
        pub_der = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        _kid = key_id_for_public_der(pub_der)
        _loaded_key_path = key_path
    return _private_key_pem, _kid


def key_id_for_public_der(pub_der: bytes) -> str:
    return hashlib.sha256(pub_der).hexdigest()[:16]


def reset_key_for_tests() -> None:
    global _private_key_pem, _kid
    _private_key_pem = None
    _kid = None


def hash_parameters(params: dict[str, Any]) -> str:
    """Canonical form: sorted keys (recursive), compact separators, ASCII-escaped.
    Both C7 and C6 must use this exact function."""
    canonical_json = json.dumps(params, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()


def _iso_z(dt: datetime) -> str:
    return dt.isoformat(timespec="seconds").replace("+00:00", "Z")


def generate_ecc(
    request_id: str,
    session_id: str,
    subject: str,
    action: str,
    target: str,
    parameters: dict[str, Any],
    invariant_set_version: str,
    expiry_seconds: int = 300,
    decision_basis: str = "PERMIT",
    auth_id: str | None = None,
    exception_scope: dict[str, Any] | None = None,
    policy_id: str | None = None,
) -> dict[str, Any]:
    private_key, kid = _load_key()

    ecc_id = str(uuid.uuid4())
    nonce = ecc_id  # Unify jti, ecc_id, and replay nonce to prevent ambiguity
    issued_at = datetime.now(UTC)
    expires_at = issued_at + timedelta(seconds=expiry_seconds)

    payload: dict[str, Any] = {
        # Standard JWT claims (RFC 7519)
        "iss": ECC_ISSUER,
        "aud": ECC_AUDIENCE,
        "jti": ecc_id,
        "iat": int(issued_at.timestamp()),
        "exp": int(expires_at.timestamp()),
        # ECC schema and identity
        "ecc_schema_version": ECC_SCHEMA_VERSION,
        "ecc_id": ecc_id,
        "nonce": nonce,
        # Governance authorization context
        "request_id": request_id,
        "session_id": session_id,
        "subject": subject,
        "action": action,
        "target": target,
        "parameters_hash": hash_parameters(parameters),
        "invariant_set_version": invariant_set_version,
        "decision_basis": decision_basis,
        "ecc.decision_basis": decision_basis,
    }

    if policy_id:
        payload["policy_id"] = policy_id

    if decision_basis == "PERMIT_WITH_AUTHORIZATION" and auth_id:
        payload["auth_ref"] = auth_id
        payload["ecc.auth_ref"] = auth_id
        payload["exception_scope"] = exception_scope or {}
        payload["ecc.exception_scope"] = exception_scope or {}

    token = jwt.encode(payload, private_key, algorithm="RS256", headers={"kid": kid})

    res: dict[str, Any] = {
        "ecc_id": ecc_id,
        "ecc": token,
        "kid": kid,
        "issued_at": _iso_z(issued_at),
        "expires_at": _iso_z(expires_at),
        "parameters_hash": payload["parameters_hash"],
        "decision_basis": decision_basis,
    }
    if policy_id:
        res["policy_id"] = policy_id
    if decision_basis == "PERMIT_WITH_AUTHORIZATION" and auth_id:
        res["auth_ref"] = auth_id
        res["exception_scope"] = exception_scope or {}
    return res
