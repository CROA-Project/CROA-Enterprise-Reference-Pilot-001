"""
CROA Reference Harness — Agent Surface Authentication Abstraction
Normative Reference: CROA Framework v1.0.1 §4.9 Agent Surface Authentication

Defines the pluggable SubjectAuthenticator interface and reference in-memory token registry.
Zero test identities or implicit test-mode prefix bypasses embedded in core logic.
Strict fail-closed behavior on missing or unverified credentials.
"""

from abc import ABC, abstractmethod
from typing import Optional, Dict
from fastapi import HTTPException

class SubjectAuthenticator(ABC):
    """Abstract interface for Agent Surface intake authentication."""

    @abstractmethod
    def authenticate(self, authorization: Optional[str], x_subject_token: Optional[str]) -> str:
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

    def __init__(self, token_to_subject: Optional[Dict[str, str]] = None):
        self._registry: Dict[str, str] = dict(token_to_subject or {})

    def register_token(self, token: str, subject: str) -> None:
        """Registers a valid token and its bound subject identity."""
        self._registry[token.strip()] = subject.strip()

    def unregister_token(self, token: str) -> None:
        """Removes a token from the registry."""
        self._registry.pop(token.strip(), None)

    def clear(self) -> None:
        """Clears all registered tokens."""
        self._registry.clear()

    def authenticate(self, authorization: Optional[str], x_subject_token: Optional[str]) -> str:
        token: Optional[str] = None
        if authorization:
            if authorization.startswith("Bearer "):
                token = authorization[len("Bearer "):].strip()
            else:
                token = authorization.strip()
        elif x_subject_token:
            token = x_subject_token.strip()

        if not token:
            raise HTTPException(
                status_code=401,
                detail="MISSING_AUTHENTICATION_CREDENTIAL: §4.9 Subject authentication required at Agent Surface intake"
            )

        subject = self._registry.get(token)
        if subject:
            return subject

        raise HTTPException(
            status_code=401,
            detail="INVALID_AUTHENTICATION_CREDENTIAL: §4.9 Invalid or unverified subject token"
        )

# Global default authenticator instance for reference harness
default_authenticator: SubjectAuthenticator = TokenRegistryAuthenticator()

def get_authenticator() -> SubjectAuthenticator:
    """FastAPI dependency provider for subject authenticator."""
    return default_authenticator

def set_authenticator(authenticator: SubjectAuthenticator) -> None:
    """Sets the active subject authenticator."""
    global default_authenticator
    default_authenticator = authenticator
