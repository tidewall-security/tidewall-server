"""Tests for SecretsDetector — direct detect-secrets integration."""

from app.detectors.secrets import SecretsDetector


def _make(action="redact"):
    return SecretsDetector({"enabled": True, "action": action})


def test_no_secrets_returns_undetected():
    d = _make()
    r = d.scan("This is a normal sentence with no secrets at all.")
    assert r.detected is False


def test_aws_key_is_redacted():
    d = _make()
    r = d.scan("My AWS key is AKIAIOSFODNN7EXAMPLE for testing")
    assert r.detected is True
    assert r.sanitized_text == "My AWS key is [REDACTED] for testing"
    assert "AKIAIOSFODNN7EXAMPLE" not in r.sanitized_text
    assert len(r.data["entities"]) == 1


def test_jwt_token_is_redacted():
    jwt = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
        "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    )
    d = _make()
    r = d.scan(f"Here is the token: {jwt}")
    assert r.detected is True
    assert jwt not in r.sanitized_text
    assert "[REDACTED]" in r.sanitized_text


def test_literal_redacted_token_in_input_is_not_a_false_positive():
    """Regression test: user input containing the literal '[REDACTED]' string
    must not be counted as a secret we sanitized. Only secrets the detector
    actually replaced should appear in entities."""
    d = _make()
    r = d.scan("Earlier I wrote [REDACTED] but no real secrets are here today.")
    assert r.detected is False
    assert r.data is None
    assert r.sanitized_text is None


def test_literal_redacted_alongside_real_secret_only_reports_one():
    """If input has both a literal [REDACTED] AND a real secret, only the
    real secret should appear in entities."""
    d = _make()
    r = d.scan("[REDACTED] and AKIAIOSFODNN7EXAMPLE are different things")
    assert r.detected is True
    assert len(r.data["entities"]) == 1
    # The original [REDACTED] is preserved; only the AWS key was replaced.
    assert r.sanitized_text == "[REDACTED] and [REDACTED] are different things"


def test_no_false_positive_on_password_keyword():
    """Regression test: KeywordDetector was excluded from the plugin list
    so words like 'password' alone should not trigger the detector."""
    d = _make()
    r = d.scan("Please use a strong password for your account")
    assert r.detected is False


def test_no_false_positive_on_natural_language_with_short_words():
    """Regression test: high-entropy detectors were excluded so normal
    short words should not trigger the detector."""
    d = _make()
    r = d.scan("My is for AWS key the testing for")
    assert r.detected is False


def test_start_pos_points_to_redacted_token_in_sanitized_text():
    """start_pos in each entity should align with the [REDACTED] token's
    position in the SANITIZED text (not the original)."""
    d = _make()
    r = d.scan("a AKIAIOSFODNN7EXAMPLE b")
    assert r.detected is True
    assert len(r.data["entities"]) == 1
    pos = r.data["entities"][0]["start_pos"]
    assert r.sanitized_text[pos : pos + len("[REDACTED]")] == "[REDACTED]"


def test_duplicate_secret_on_same_line_is_fully_redacted():
    """Regression: detect-secrets dedupes by value, but every occurrence in
    the line must still be replaced or copies of the same secret leak."""
    d = _make()
    r = d.scan("AKIAIOSFODNN7EXAMPLE then AKIAIOSFODNN7EXAMPLE again")
    assert r.detected is True
    assert "AKIAIOSFODNN7EXAMPLE" not in r.sanitized_text
    assert r.sanitized_text == "[REDACTED] then [REDACTED] again"
    assert len(r.data["entities"]) == 2


def test_three_duplicates_on_same_line_all_redacted():
    """Triple-occurrence sanity check that the loop terminates correctly."""
    d = _make()
    secret = "AKIAIOSFODNN7EXAMPLE"
    r = d.scan(f"{secret} A {secret} B {secret} C")
    assert "AKIAIOSFODNN7EXAMPLE" not in r.sanitized_text
    assert r.sanitized_text == "[REDACTED] A [REDACTED] B [REDACTED] C"
    assert len(r.data["entities"]) == 3


def test_duplicate_across_separate_lines_is_fully_redacted():
    """Duplicate secrets on different lines must both be redacted (covers
    the line-by-line outer loop boundary)."""
    d = _make()
    r = d.scan("AKIAIOSFODNN7EXAMPLE\nsome text\nAKIAIOSFODNN7EXAMPLE")
    assert "AKIAIOSFODNN7EXAMPLE" not in r.sanitized_text
    assert r.sanitized_text == "[REDACTED]\nsome text\n[REDACTED]"
    assert len(r.data["entities"]) == 2
