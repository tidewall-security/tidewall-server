"""Tests for PIIDetector with per-entity-type redaction rules."""

import pytest

from app.detectors.pii import PIIDetector
from app.vault import TidewallVault


@pytest.fixture
def pii_detector_with_rules():
    config = {
        "enabled": True,
        "action": "redact",
        "rules": [
            {"type": "US_SSN", "action": "replacement", "replacement_value": "<US_SSN>"},
            {
                "type": "PHONE_NUMBER",
                "action": "partial_mask",
                "mask_char": "*",
                "unmasked_right": 4,
                "chars_to_ignore": "-",
            },
            {"type": "EMAIL_ADDRESS", "action": "mask"},
        ],
    }
    return PIIDetector(config)


def test_pii_entity_action_label_is_aidr_compat_format(pii_detector_with_rules):
    result = pii_detector_with_rules.scan("My SSN is 234-56-7890")
    if result.detected and result.data:
        for entity in result.data.get("entities", []):
            assert entity["action"] in (
                "redacted:replaced",
                "redacted:masked",
                "redacted:hashed",
                "defanged",
                "reported",
            )


def test_pii_default_rules_still_work():
    config = {"enabled": True, "action": "redact"}
    detector = PIIDetector(config)
    result = detector.scan("My SSN is 234-56-7890")
    if result.detected and result.data:
        for entity in result.data.get("entities", []):
            assert entity["action"] == "redacted:replaced"


def test_duplicate_value_appears_as_two_entities():
    """Same name twice in the prompt should produce two entity entries
    even when the vault dedupes the placeholder. This regression only
    surfaces with a vault — the fallback (no-vault) path generates a
    fresh counter per occurrence and never hit the bug."""
    config = {"enabled": True, "action": "redact"}
    detector = PIIDetector(config)
    vault = TidewallVault()
    result = detector.scan("Alice Johnson met Alice Johnson at the office", vault=vault)
    assert result.detected is True
    assert result.data is not None
    person_entities = [e for e in result.data["entities"] if e["type"] == "PERSON"]
    # Two occurrences of "Alice Johnson" should produce two PERSON entities
    # even though the vault returns the same placeholder for both.
    assert len(person_entities) == 2
    # start_pos must differ — they are different occurrences in the text.
    assert person_entities[0]["start_pos"] != person_entities[1]["start_pos"]


def test_placeholder_numbering_is_left_to_right():
    """Left-to-right document order: first email gets _1, second gets _2.
    Regression test for the right-to-left walk that the overlap-filter
    refactor introduced."""
    config = {"enabled": True, "action": "redact"}
    detector = PIIDetector(config)
    result = detector.scan("Email bob@example.com or carol@example.com please")
    assert result.detected is True
    assert "[REDACTED_EMAIL_ADDRESS_1]" in result.sanitized_text
    assert "[REDACTED_EMAIL_ADDRESS_2]" in result.sanitized_text
    # _1 must appear before _2 in the sanitized text.
    pos_1 = result.sanitized_text.find("[REDACTED_EMAIL_ADDRESS_1]")
    pos_2 = result.sanitized_text.find("[REDACTED_EMAIL_ADDRESS_2]")
    assert pos_1 != -1 and pos_2 != -1
    assert pos_1 < pos_2
