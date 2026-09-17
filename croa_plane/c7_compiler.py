"""C7 — Contract Compiler: issues signed Execution Change Contracts (ECCs).

ECC envelope (schema version 1) is documented in docs/ECC-SPEC.md.
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

PRIVATE_KEY_PATH = os.environ.get("CROA_PRIVATE_KEY_PATH", "/app/keys/private.pem")
ECC_ISSUER = os.environ.get("ECC_ISSUER", "croa-plane-pilot")
ECC_AUDIENCE = os.environ.get("ECC_AUDIENCE", "c6-firewall-pilot")
ECC_SCHEMA_VERSION = "1"

_private_key_pem: bytes | None = None
_kid: str | None = None


def _load_key() -> tuple[bytes, str]:
    """Load the signing key once; derive `kid` from the public key so C6 can match it."""
    global _private_key_pem, _kid
    if _private_key_pem is None:
        with open(PRIVATE_KEY_PATH, "rb") as f:
            _private_key_pem = f.read()
        private_key = serialization.load_pem_private_key(_private_key_pem, password=None)
        pub_der = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        _kid = key_id_for_public_der(pub_der)
    return _private_key_pem, _kid


def key_id_for_public_der(pub_der: bytes) -> str:
    return hashlib.sha256(pub_der).hexdigest()[:16]


def hash_parameters(params: dict[str, Any]) -> str:
    """Canonical form: sorted keys (recursive), compact separators, ASCII-escaped.
    See docs/ECC-SPEC.md §Canonicalization. Both C7 and C6 must use this exact function."""
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
    policy_id: str | None = None,
) -> dict[str, Any]:
    private_key, kid = _load_key()

    ecc_id = str(uuid.uuid4())
    issued_at = datetime.now(UTC)
    expires_at = issued_at + timedelta(seconds=expiry_seconds)

    payload = {
        # Standard JWT claims
        "iss": ECC_ISSUER,
        "aud": ECC_AUDIENCE,
        "jti": ecc_id,
        "iat": int(issued_at.timestamp()),
        "exp": int(expires_at.timestamp()),
        # ECC claims
        "ecc_schema_version": ECC_SCHEMA_VERSION,
        "ecc_id": ecc_id,
        "nonce": ecc_id,  # retained for v0.1 compatibility; identical to jti
        "request_id": request_id,
        "session_id": session_id,
        "subject": subject,
        "action": action,
        "target": target,
        "parameters_hash": hash_parameters(parameters),
        "invariant_set_version": invariant_set_version,
    }
    if policy_id:
        payload["policy_id"] = policy_id

    token = jwt.encode(payload, private_key, algorithm="RS256", headers={"kid": kid})

    return {
        "ecc_id": ecc_id,
        "ecc": token,
        "kid": kid,
        "issued_at": _iso_z(issued_at),
        "expires_at": _iso_z(expires_at),
        "parameters_hash": payload["parameters_hash"],
    }
