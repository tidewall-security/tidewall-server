"""Failure-injection matrix for P0-2.

Every test here injects a specific failure and asserts it is *visible* as a
failure rather than silently becoming a clean verdict.

These replace the AST-based structural test originally proposed, which could
only find a literal ``DetectorResult(detected=False)`` lexically inside an
``except``. It could not see state set in a constructor, an exception swallowed
in a helper, a ``return None``, or a catch in a service — which is where most of
the real fail-open paths were.
"""

from __future__ import annotations

import pytest

from app.detectors.base import (
    BaseDetector,
    DetectorResult,
    DetectorStatus,
    FailureCode,
    SkipReason,
)
from app.scanner_engine import FailedDetector, ScanResult

# ---------------------------------------------------------------------------
# The value type
# ---------------------------------------------------------------------------


def test_failed_result_cannot_claim_a_detection():
    """A failed detector has no verdict, so FAILED + detected is incoherent."""
    with pytest.raises(ValueError, match="FAILED and detected"):
        DetectorResult(
            detected=True,
            status=DetectorStatus.FAILED,
            failure_code=FailureCode.SCAN_FAILED,
        )


def test_failed_result_requires_a_code():
    with pytest.raises(ValueError, match="requires a failure_code"):
        DetectorResult(status=DetectorStatus.FAILED)


def test_skipped_result_requires_a_reason():
    with pytest.raises(ValueError, match="requires a skip_reason"):
        DetectorResult(status=DetectorStatus.SKIPPED)


def test_skip_is_not_a_failure():
    """A skip is a policy outcome and must never degrade the verdict."""
    assert DetectorResult.skipped(SkipReason.NOT_ENABLED).trustworthy is True
    assert DetectorResult.failed(FailureCode.SCAN_FAILED).trustworthy is False


# ---------------------------------------------------------------------------
# ScanResult aggregation
# ---------------------------------------------------------------------------


def test_clean_scan_is_not_degraded():
    assert ScanResult().degraded is False
    assert ScanResult().enforcement_degraded is False


def test_failed_reporter_degrades_observability_not_enforcement():
    """A failed reporter is worth surfacing but does not make a request unsafe."""
    result = ScanResult()
    result.record_failure("topic", FailureCode.MODEL_LOAD_FAILED, action="report")

    assert result.degraded is True
    assert result.enforcement_degraded is False


@pytest.mark.parametrize("action", ["block", "redact"])
def test_failed_enforcing_detector_degrades_enforcement(action):
    """A failed blocker or redactor means the request was not protected."""
    result = ScanResult()
    result.record_failure("malicious_prompt", FailureCode.MODEL_LOAD_FAILED, action=action)

    assert result.enforcement_degraded is True


def test_failure_is_visible_in_the_detector_payload():
    """The per-detector payload must not read as 'scanned, found nothing'."""
    result = ScanResult()
    result.record_failure("pii", FailureCode.DEPENDENCY_MISSING, action="redact")

    payload = result.detectors["pii"]
    assert payload["detected"] is False
    assert payload["status"] == "failed"
    assert payload["failure_code"] == "dependency_missing"


def test_failed_detector_action_defaults_to_report():
    assert FailedDetector("x", FailureCode.SCAN_FAILED).enforcing is False


# ---------------------------------------------------------------------------
# Construction failures
# ---------------------------------------------------------------------------


def _engine(detectors: dict):
    from app.scanner_engine import ScannerEngine

    return ScannerEngine.from_detectors(detectors)


def test_unknown_detector_is_a_failure_not_a_skip():
    """An unknown name used to be silently dropped at DEBUG level."""
    engine = _engine({"no_such_detector": {"enabled": True, "action": "block"}})

    failures = engine.construction_failures
    assert [f.code for f in failures] == [FailureCode.DETECTOR_UNKNOWN]
    assert engine.is_enforcement_complete is False


def test_construction_failure_is_reported_on_every_scan():
    """Not just at startup — every request it should have covered is degraded."""
    engine = _engine({"no_such_detector": {"enabled": True, "action": "block"}})

    for _ in range(3):
        result = engine.scan("hello", event_type="input", vault_id="v", vault=None)
        assert result.enforcement_degraded is True
        assert result.detectors["no_such_detector"]["status"] == "failed"


def test_disabled_detector_is_not_a_failure():
    engine = _engine({"no_such_detector": {"enabled": False, "action": "block"}})
    assert engine.construction_failures == []
    assert engine.is_enforcement_complete is True


def test_failed_reporter_leaves_enforcement_complete():
    engine = _engine({"no_such_detector": {"enabled": True, "action": "report"}})
    assert engine.construction_failures != []
    assert engine.is_enforcement_complete is True


# ---------------------------------------------------------------------------
# Runtime failures
# ---------------------------------------------------------------------------


class _RaisingDetector(BaseDetector):
    @property
    def name(self) -> str:
        return "exploding"

    def scan(self, text: str, **kwargs) -> DetectorResult:
        raise RuntimeError("canary_exception_text_must_not_leak")


class _SelfReportingDetector(BaseDetector):
    """Reports failure by value rather than raising."""

    @property
    def name(self) -> str:
        return "self_reporting"

    def scan(self, text: str, **kwargs) -> DetectorResult:
        return DetectorResult.failed(FailureCode.OUTPUT_INVALID)


def _engine_with(detector: BaseDetector, action: str = "block"):
    engine = _engine({})
    detector.action = action
    engine._detectors.append((detector.name, detector))
    return engine


def test_raising_detector_produces_a_failure_not_a_clean_verdict():
    engine = _engine_with(_RaisingDetector({"action": "block"}))

    result = engine.scan("hello", event_type="input", vault_id="v", vault=None)

    assert result.enforcement_degraded is True
    assert result.detectors["exploding"]["failure_code"] == "scan_failed"


def test_exception_text_does_not_reach_the_result():
    """Exception detail is logged at the boundary and nowhere else."""
    engine = _engine_with(_RaisingDetector({"action": "block"}))

    result = engine.scan("hello", event_type="input", vault_id="v", vault=None)

    assert "canary_exception_text_must_not_leak" not in str(result.detectors)
    assert "canary_exception_text_must_not_leak" not in str(result.failures)


def test_detector_may_report_failure_by_value():
    engine = _engine_with(_SelfReportingDetector({"action": "block"}))

    result = engine.scan("hello", event_type="input", vault_id="v", vault=None)

    assert result.enforcement_degraded is True
    assert result.detectors["self_reporting"]["failure_code"] == "output_invalid"


# ---------------------------------------------------------------------------
# Redaction — the disclosure path
# ---------------------------------------------------------------------------


class _WorkingRedactor(BaseDetector):
    @property
    def name(self) -> str:
        return "confidential_and_pii_entity"

    def scan(self, text: str, **kwargs) -> DetectorResult:
        return DetectorResult(detected=True, sanitized_text=text.replace("Alice", "[NAME]"))


class _FailingRedactor(BaseDetector):
    @property
    def name(self) -> str:
        return "secret_and_key_entity"

    def scan(self, text: str, **kwargs) -> DetectorResult:
        raise RuntimeError("redactor exploded")


def test_redactor_failure_returns_no_text_at_all():
    """Partially redacted output must never be returned.

    The first redactor succeeds and removes the name; the second raises before
    it can remove the secret. Returning the partially cleaned text would leak
    exactly what the second redactor existed to remove.
    """
    engine = _engine({})
    for det in (_WorkingRedactor({"action": "redact"}), _FailingRedactor({"action": "redact"})):
        det.action = "redact"
        engine._detectors.append((det.name, det))

    result = engine.scan_single("Alice's key is AKIAIOSFODNN7EXAMPLE", vault_id="v", vault=None)

    assert result.enforcement_degraded is True
    assert result.transformed is False
    assert result.guard_output_text is None


def test_successful_redaction_still_returns_text():
    """The failure path must not break the ordinary case."""
    engine = _engine({})
    det = _WorkingRedactor({"action": "redact"})
    det.action = "redact"
    engine._detectors.append((det.name, det))

    result = engine.scan_single("Alice is here", vault_id="v", vault=None)

    assert result.transformed is True
    assert result.guard_output_text == "[NAME] is here"
    assert result.degraded is False
