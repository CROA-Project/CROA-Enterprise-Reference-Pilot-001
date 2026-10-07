"""
CROA Reference Harness — Agent Surface Authentication Abstraction
Normative Reference: CROA Framework v1.0.1 §4.9 Agent Surface Authentication

Defines the pluggable SubjectAuthenticator interface and reference in-memory token registry.
Zero test identities or implicit test-mode prefix bypasses embedded in core logic.
Strict fail-closed behavior on missing or unverified credentials.
"""

from __future__ import annotations

import json
import os
from abc import ABC, abstractmethod

from fastapi import HTTPException


def _load_env_if_present() -> None:
    for candidate in [
        os.path.join(os.path.dirname(__file__), "..", ".env"),
        os.path.join(os.getcwd(), ".env"),
    ]:
        if os.path.exists(candidate):
            try:
                with open(candidate, encoding="utf-8") as f:
                    for line in f:
                        line = line.strip().lstrip("\ufeff")
                        if line and not line.startswith("#") and "=" in line:
                            k, v = line.split("=", 1)
                            k = k.strip()
                            v = v.strip().strip("'\"")
                            if k not in os.environ:
                                os.environ[k] = v
            except Exception:
                pass
            break


_load_env_if_present()


def load_subject_tokens_from_env(authenticator: TokenRegistryAuthenticator | None = None) -> TokenRegistryAuthenticator:
    """
    Loads subject tokens from CROA_SUBJECT_TOKENS environment variable if set.
    Fails closed with ValueError on malformed JSON, non-dict structure, or invalid keys/values.
    """
    auth = authenticator if authenticator is not None else TokenRegistryAuthenticator()
    raw = os.environ.get("CROA_SUBJECT_TOKENS")
    if raw is None:
        return auth
    raw_str = raw.strip()
    if not raw_str:
        return auth

    try:
        data = json.loads(raw_str)
    except Exception as exc:
        raise ValueError(f"MALFORMED_SUBJECT_TOKENS_CONFIG: Invalid JSON: {exc}") from exc

    if not isinstance(data, dict):
        raise ValueError("MALFORMED_SUBJECT_TOKENS_CONFIG: CROA_SUBJECT_TOKENS must be a JSON object")

    for k, v in data.items():
        if not isinstance(k, str) or not k.strip():
            raise ValueError("MALFORMED_SUBJECT_TOKENS_CONFIG: Token key must be a non-empty string")
        if not isinstance(v, str) or not v.strip():
            raise ValueError("MALFORMED_SUBJECT_TOKENS_CONFIG: Subject value must be a non-empty string")
        auth.register_token(k.strip(), v.strip())

    return auth


class SubjectAuthenticator(ABC):
    """Abstract interface for Agent Surface intake authentication."""

    @abstractmethod
    def authenticate(self, authorization: str | None, x_subject_token: str | None) -> str:
        """
        Extracts credential and returns authenticated Subject identity string.
        Raises HTTPException(status_code=401) on missing or invalid credential.
        """
        pass


class TokenRegistryAuthenticator(SubjectAuthenticator):
    """
    Reference/Demo implementation backed by an explicit token-to-subject registry.
    Requires explicit registration of valid tokens; unknown tokens fail closed.
    """

    def __init__(self, token_to_subject: dict[str, str] | None = None):
        self._registry: dict[str, str] = dict(token_to_subject or {})
        load_subject_tokens_from_env(self)

    def register_token(self, token: str, subject: str) -> None:
        """Registers a valid token and its bound subject identity."""
        self._registry[token.strip()] = subject.strip()

    def unregister_token(self, token: str) -> None:
        """Removes a token from the registry."""
        self._registry.pop(token.strip(), None)

    def clear(self) -> None:
        """Clears all registered tokens."""
        self._registry.clear()

    def authenticate(self, authorization: str | None, x_subject_token: str | None) -> str:
        token: str | None = None
        if authorization:
            if authorization.startswith("Bearer "):
                token = authorization[len("Bearer ") :].strip()
            else:
                token = authorization.strip()
        elif x_subject_token:
            token = x_subject_token.strip()

        if not token:
            raise HTTPException(
                status_code=401, detail="MISSING_AUTHENTICATION_CREDENTIAL: §4.9 Subject authentication required at Agent Surface intake"
            )

        subject = self._registry.get(token)
        if subject:
            return subject

        raise HTTPException(status_code=401, detail="INVALID_AUTHENTICATION_CREDENTIAL: §4.9 Invalid or unverified subject token")


# Global default authenticator instance for reference harness
default_authenticator: SubjectAuthenticator = TokenRegistryAuthenticator()


def get_authenticator() -> SubjectAuthenticator:
    """FastAPI dependency provider for subject authenticator."""
    return default_authenticator


def set_authenticator(authenticator: SubjectAuthenticator) -> None:
    """Sets the active subject authenticator."""
    global default_authenticator
    default_authenticator = authenticator
