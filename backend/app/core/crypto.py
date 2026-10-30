"""Encryption helpers for evidence at rest and sensitive fields.

Uses Fernet (symmetric) from the `cryptography` package. If no key is configured in
the environment, a deterministic development key is generated so the app is runnable
out-of-the-box. Production deployments MUST set `EVIDENCE_ENCRYPTION_KEY`.
"""
import base64
import hashlib
import os

from cryptography.fernet import Fernet, InvalidToken

from app.core.config import settings


def _dev_key() -> bytes:
    """Build a stable Fernet key from the app secret for development only."""
    digest = hashlib.sha256(settings.secret_key.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest)


def get_fernet() -> Fernet:
    key: bytes
    if settings.evidence_encryption_key:
        key = settings.evidence_encryption_key.encode("utf-8")
        # Ensure it is valid urlsafe base64; raise early if misconfigured.
        try:
            Fernet(key)
        except (ValueError, TypeError) as exc:  # pragma: no cover - config guard
            raise RuntimeError("EVIDENCE_ENCRYPTION_KEY is not a valid Fernet key.") from exc
    else:
        key = _dev_key()
    return Fernet(key)


_fernet: Fernet | None = None


def _fernet_instance() -> Fernet:
    global _fernet
    if _fernet is None:
        _fernet = get_fernet()
    return _fernet


def encrypt_bytes(data: bytes) -> bytes:
    """Encrypt raw bytes into a Fernet token (suffix ``.enc`` by convention at call site)."""
    return _fernet_instance().encrypt(data)


def decrypt_bytes(token: bytes) -> bytes:
    """Decrypt a Fernet token back to raw bytes. Raises InvalidToken on tampering."""
    return _fernet_instance().decrypt(token)


def verify_token_integrity(token: bytes) -> bool:
    """Return True if the token decrypts cleanly (integrity check)."""
    try:
        _fernet_instance().decrypt(token)
        return True
    except InvalidToken:
        return False


def encrypt_text(plaintext: str) -> str:
    return encrypt_bytes(plaintext.encode("utf-8")).decode("utf-8")


def decrypt_text(token_text: str) -> str:
    return decrypt_bytes(token_text.encode("utf-8")).decode("utf-8")


def new_encryption_key() -> str:
    """Generate a fresh Fernet key string for configuration."""
    return Fernet.generate_key().decode("utf-8")