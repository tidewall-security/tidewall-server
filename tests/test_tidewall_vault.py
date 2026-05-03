"""Tests for TidewallVault — the in-memory placeholder→original mapping."""

import pytest

from app.vault import TidewallVault


def test_empty_vault_unredacts_to_input_unchanged():
    vault = TidewallVault()
    assert vault.unredact("hello world") == "hello world"


def test_store_and_unredact_single_entity():
    vault = TidewallVault()
    placeholder = vault.store("PERSON", "Alice")
    assert placeholder == "[REDACTED_PERSON_1]"
    assert vault.unredact(f"hi {placeholder}") == "hi Alice"


def test_store_increments_counter_per_type():
    vault = TidewallVault()
    p1 = vault.store("PERSON", "Alice")
    p2 = vault.store("PERSON", "Bob")
    p3 = vault.store("EMAIL_ADDRESS", "a@b.com")
    assert p1 == "[REDACTED_PERSON_1]"
    assert p2 == "[REDACTED_PERSON_2]"
    assert p3 == "[REDACTED_EMAIL_ADDRESS_1]"


def test_store_returns_existing_placeholder_for_duplicate_value():
    vault = TidewallVault()
    p1 = vault.store("PERSON", "Alice")
    p2 = vault.store("PERSON", "Alice")
    assert p1 == p2  # same original → same placeholder, no double-numbering


def test_unredact_replaces_all_occurrences():
    vault = TidewallVault()
    p = vault.store("PERSON", "Alice")
    assert vault.unredact(f"{p} and {p} again") == "Alice and Alice again"


def test_serialize_round_trip():
    vault = TidewallVault()
    vault.store("PERSON", "Alice")
    vault.store("EMAIL_ADDRESS", "a@b.com")
    blob = vault.to_bytes()
    restored = TidewallVault.from_bytes(blob)
    assert restored.unredact("[REDACTED_PERSON_1] [REDACTED_EMAIL_ADDRESS_1]") == "Alice a@b.com"


def test_from_bytes_rejects_non_object_payload():
    with pytest.raises(ValueError, match="JSON object"):
        TidewallVault.from_bytes(b"null")
    with pytest.raises(ValueError, match="JSON object"):
        TidewallVault.from_bytes(b"[]")


def test_from_bytes_rejects_malformed_placeholder():
    import json

    blob = json.dumps({"placeholders": {"random_key": "Alice"}, "counters": {"PERSON": 1}}).encode()
    with pytest.raises(ValueError, match="Malformed placeholder"):
        TidewallVault.from_bytes(blob)


def test_from_bytes_empty_round_trip():
    blob = TidewallVault().to_bytes()
    restored = TidewallVault.from_bytes(blob)
    assert restored.unredact("nothing here") == "nothing here"


def test_counters_continue_after_deserialization():
    v = TidewallVault()
    v.store("PERSON", "Alice")
    v.store("PERSON", "Bob")
    restored = TidewallVault.from_bytes(v.to_bytes())
    assert restored.store("PERSON", "Carol") == "[REDACTED_PERSON_3]"
