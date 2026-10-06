"""
CROA Reference Harness — Authorization Verifier Abstraction
Normative Reference: CROA Framework v1.0.1 §4.3.1 Authorization Artifacts / Appendix Q NT-007

Separates structural and semantic validation from signature verification mechanisms.
Reference/Test verifier provided for deterministic in-process testing.
Zero hardcoded test keys embedded in generic core logic.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Tuple, Optional, Set

class AuthorizationVerifier(ABC):
    """Abstract interface for validating cryptographic authorization artifact signatures."""

    @abstractmethod
    def verify_signature(self, artifact: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Validates issuer key and cryptographic signature of the authorization artifact.
        Returns (True, "VALID") or (False, "<REASON_CODE>").
        """
        pass

class MockAuthorizationVerifier(AuthorizationVerifier):
    """
    REFERENCE / TEST IMPLEMENTATION ONLY.
    Validates against explicitly registered trusted issuer key IDs and proof strings.
    NOT production PKI or asymmetric cryptographic signature verification.
    """

    def __init__(
        self,
        trusted_issuer_keys: Optional[Set[str]] = None,
        expected_signature_proof: Optional[str] = None
    ):
        self._trusted_issuer_keys: Set[str] = set(trusted_issuer_keys or set())
        self._expected_signature_proof: Optional[str] = expected_signature_proof

    def register_trusted_key(self, key_id: str) -> None:
        """Registers a trusted issuer key ID."""
        self._trusted_issuer_keys.add(key_id.strip())

    def set_expected_signature_proof(self, proof: str) -> None:
        """Sets the expected mock signature proof."""
        self._expected_signature_proof = proof.strip()

    def clear(self) -> None:
        """Clears registered keys and proof strings."""
        self._trusted_issuer_keys.clear()
        self._expected_signature_proof = None

    def verify_signature(self, artifact: Dict[str, Any]) -> Tuple[bool, str]:
        issuer_key = artifact.get("issuer_key_id")
        signature = artifact.get("signature")

        if not issuer_key or not signature:
            return False, "INVALID_AUTHORIZATION_SIGNATURE: Missing key or signature field"

        if issuer_key not in self._trusted_issuer_keys:
            return False, "INVALID_AUTHORIZATION_SIGNATURE: Untrusted or unregistered issuer key"

        if self._expected_signature_proof and signature != self._expected_signature_proof:
            return False, "INVALID_AUTHORIZATION_SIGNATURE: Cryptographic proof does not match expected attestation"

        return True, "VALID"

# Global default verifier instance for reference harness
default_verifier: AuthorizationVerifier = MockAuthorizationVerifier()

def get_verifier() -> AuthorizationVerifier:
    """Returns the active authorization verifier instance."""
    return default_verifier

def set_verifier(verifier: AuthorizationVerifier) -> None:
    """Sets the active authorization verifier instance."""
    global default_verifier
    default_verifier = verifier
