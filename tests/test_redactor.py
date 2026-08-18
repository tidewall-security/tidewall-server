"""Tests for the Redactor service — 5 redaction methods."""


def test_replacement():
    from app.services.redactor import Redactor

    r = Redactor()
    result = r.redact("234-56-7890", "US_SSN", {"action": "replacement", "replacement_value": "<US_SSN>"})
    assert result["redacted"] == "<US_SSN>"
    assert result["action_label"] == "redacted:replaced"


def test_replacement_default_value():
    from app.services.redactor import Redactor

    r = Redactor()
    result = r.redact("234-56-7890", "US_SSN", {"action": "replacement"})
    assert result["redacted"] == "<US_SSN>"  # default is <TYPE>


def test_mask():
    from app.services.redactor import Redactor

    r = Redactor()
    result = r.redact("234-56-7890", "US_SSN", {"action": "mask"})
    assert result["redacted"] == "***********"
    assert result["action_label"] == "redacted:masked"


def test_partial_mask_default():
    from app.services.redactor import Redactor

    r = Redactor()
    result = r.redact("234-56-7890", "US_SSN", {"action": "partial_mask", "unmasked_right": 4})
    assert result["redacted"] == "*******7890"
    assert result["action_label"] == "redacted:masked"


def test_partial_mask_with_ignore():
    from app.services.redactor import Redactor

    r = Redactor()
    result = r.redact(
        "234-56-7890",
        "US_SSN",
        {
            "action": "partial_mask",
            "mask_char": "#",
            "unmasked_right": 4,
            "chars_to_ignore": "-",
        },
    )
    assert result["redacted"] == "###-##-7890"


def test_partial_mask_unmasked_left():
    from app.services.redactor import Redactor

    r = Redactor()
    result = r.redact(
        "234-56-7890",
        "PHONE_NUMBER",
        {
            "action": "partial_mask",
            "unmasked_left": 3,
            "unmasked_right": 4,
        },
    )
    assert result["redacted"] == "234****7890"


def test_hash():
    from app.services.redactor import Redactor

    r = Redactor()
    result = r.redact("234-56-7890", "US_SSN", {"action": "hash", "salt": "mysalt"})
    assert len(result["redacted"]) == 12  # truncated hash
    assert result["action_label"] == "redacted:hashed"


def test_hash_deterministic():
    from app.services.redactor import Redactor

    r = Redactor()
    r1 = r.redact("234-56-7890", "US_SSN", {"action": "hash", "salt": "mysalt"})
    r2 = r.redact("234-56-7890", "US_SSN", {"action": "hash", "salt": "mysalt"})
    assert r1["redacted"] == r2["redacted"]


def test_hash_different_salt():
    from app.services.redactor import Redactor

    r = Redactor()
    r1 = r.redact("234-56-7890", "US_SSN", {"action": "hash", "salt": "salt1"})
    r2 = r.redact("234-56-7890", "US_SSN", {"action": "hash", "salt": "salt2"})
    assert r1["redacted"] != r2["redacted"]


def test_defang_ip():
    from app.services.redactor import Redactor

    r = Redactor()
    result = r.redact("47.84.32.175", "IP", {"action": "defang"})
    assert result["redacted"] == "47[.]84[.]32[.]175"
    assert result["action_label"] == "defanged"


def test_defang_url():
    from app.services.redactor import Redactor

    r = Redactor()
    result = r.redact("http://evil.com/path", "URL", {"action": "defang"})
    assert result["redacted"] == "http://evil[.]com/path"
    assert result["action_label"] == "defanged"


def test_defang_domain():
    from app.services.redactor import Redactor

    r = Redactor()
    result = r.redact("evil.example.com", "DOMAIN", {"action": "defang"})
    assert result["redacted"] == "evil[.]example[.]com"
    assert result["action_label"] == "defanged"


def test_unknown_action_falls_back_to_replacement():
    from app.services.redactor import Redactor

    r = Redactor()
    result = r.redact("secret", "CUSTOM", {"action": "unknown_action"})
    assert result["redacted"] == "<CUSTOM>"
    assert result["action_label"] == "redacted:replaced"


def test_report_action():
    from app.services.redactor import Redactor

    r = Redactor()
    result = r.redact("234-56-7890", "US_SSN", {"action": "report"})
    assert result["redacted"] == "234-56-7890"  # unchanged
    assert result["action_label"] == "reported"


def test_fpe_action_is_rejected_at_policy_write_time():
    """FPE was removed; a policy asking for it must not silently do something else.

    The action previously fell through to replacement whenever no FPE service
    was injected — which was always, since no production caller ever supplied
    one. An operator selecting encryption received replacement and was told
    nothing. Now the policy is rejected with an explanation.
    """
    import pytest as _pytest

    from app.services.policy_validation import PolicyValidationError, validate_action

    with _pytest.raises(PolicyValidationError, match="format-preserving encryption was removed"):
        validate_action("fpe", where="detectors.confidential_and_pii_entity.action")


def test_redactor_has_no_fpe_action():
    from app.services.redactor import Redactor

    result = Redactor().redact("2345678901", "US_SSN", {"action": "fpe"})
    # Unknown actions fall through to the default; the point is that nothing
    # claims to have encrypted anything.
    assert result["action_label"] != "redacted:encrypted"
    assert "fpe_context" not in result
