"""API key generation, hashing, and formatting utilities."""

from __future__ import annotations

import hashlib
import secrets


def generate_key(prefix: str = "ak") -> str:
    """Generate a random token with the given prefix (ak, rt, or at)."""
    return f"{prefix}_{secrets.token_hex(16)}"


def hash_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def key_prefix(raw_key: str) -> str:
    return raw_key[:7] + "..."
