"""Tests for CustomEntityDetector — pattern matching with placeholder redaction."""

from app.detectors.custom_entity import CustomEntityDetector


def _make(patterns, action="redact"):
    return CustomEntityDetector({"enabled": True, "action": action, "patterns": patterns})


def test_no_patterns_returns_inactive():
    d = CustomEntityDetector({"enabled": True, "action": "redact"})
    r = d.scan("anything goes")
    assert r.detected is False


def test_single_pattern_matches_and_redacts():
    d = _make([r"PROJ-\d+"])
    r = d.scan("See PROJ-123 and PROJ-456 for details")
    assert r.detected is True
    assert r.sanitized_text == "See [REDACTED_CUSTOM_1] and [REDACTED_CUSTOM_2] for details"
    assert [e["value"] for e in r.data["entities"]] == ["PROJ-123", "PROJ-456"]
    assert all(e["action"] == "redacted:replaced" for e in r.data["entities"])


def test_no_matches_returns_undetected():
    d = _make([r"PROJ-\d+"])
    r = d.scan("nothing matching here")
    assert r.detected is False


def test_invalid_pattern_makes_the_detector_fail_rather_than_skip():
    """A malformed pattern used to be skipped so the others still worked.

    That silently removed whatever rule the broken pattern expressed: the
    policy says an entity is detected and it never would be, and the response
    was indistinguishable from having checked and found nothing. Invalid
    patterns are now rejected at policy-write time, and a detector that somehow
    receives one reports a failure rather than a clean verdict.
    """
    from app.detectors.base import DetectorStatus, FailureCode

    d = _make([r"(invalid", r"PROJ-\d+"])
    r = d.scan("PROJ-1 here")

    assert r.status is DetectorStatus.FAILED
    assert r.failure_code is FailureCode.CONFIG_INVALID
    assert r.detected is False


def test_overlapping_patterns_dedupe_to_longest_at_same_start():
    # Pattern 1 matches "foo"; pattern 2 matches "foobar" at the same start.
    # The longer span wins; the shorter is dropped to avoid destructive overlap.
    d = _make([r"foo", r"foo[a-z]+"])
    r = d.scan("foobar")
    assert r.detected is True
    assert r.sanitized_text == "[REDACTED_CUSTOM_1]"
    assert len(r.data["entities"]) == 1
    assert r.data["entities"][0]["value"] == "foobar"


def test_non_overlapping_repeats_get_sequential_indices():
    d = _make([r"\d+"])
    r = d.scan("a 1 b 22 c 333")
    assert r.sanitized_text == "a [REDACTED_CUSTOM_1] b [REDACTED_CUSTOM_2] c [REDACTED_CUSTOM_3]"


def test_start_pos_is_position_in_original_text():
    d = _make([r"X"])
    r = d.scan("--X--X--")
    assert [e["start_pos"] for e in r.data["entities"]] == [2, 5]
