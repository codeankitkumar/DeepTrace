"""Cryptographic hashing and integrity verification (SHA-256)."""
from __future__ import annotations

import hashlib
from pathlib import Path


def sha256_file(path: str, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verify_integrity(path: str, expected_sha256: str) -> tuple[bool, str]:
    """Return (valid, actual_sha256) for the file at `path`."""
    actual = sha256_file(path)
    return actual.lower() == expected_sha256.lower(), actual


def sha256_file_optional(path: str) -> str:
    """Return hash for a path that may not exist (empty string when missing)."""
    if not Path(path).exists():
        return ""
    return sha256_file(path)