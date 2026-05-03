"""Tests for API key utilities."""
import pytest


def test_generate_key_has_prefix():
    from app.auth.key_utils import generate_key

    raw_key = generate_key()
    assert raw_key.startswith("ak_")
    assert len(raw_key) == 35  # "ak_" + 32 hex chars


def test_generate_key_is_unique():
    from app.auth.key_utils import generate_key

    keys = {generate_key() for _ in range(100)}
    assert len(keys) == 100


def test_hash_key_is_deterministic():
    from app.auth.key_utils import hash_key

    h1 = hash_key("ak_abc123")
    h2 = hash_key("ak_abc123")
    assert h1 == h2
    assert isinstance(h1, str)
    assert len(h1) == 64  # SHA-256 hex


def test_hash_key_different_inputs():
    from app.auth.key_utils import hash_key

    h1 = hash_key("ak_abc123")
    h2 = hash_key("ak_def456")
    assert h1 != h2


def test_key_prefix():
    from app.auth.key_utils import key_prefix

    prefix = key_prefix("ak_3f8b2a91e7d4c6f0ab12de3456789012")
    assert prefix == "ak_3f8b..."


def test_key_prefix_short_key():
    from app.auth.key_utils import key_prefix

    prefix = key_prefix("ak_ab")
    assert prefix == "ak_ab..."
