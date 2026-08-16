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


# ---------------------------------------------------------------------------
# Composite truth table (malicious_prompt)
# ---------------------------------------------------------------------------


def _composite(**config):
    from app.detectors.malicious_prompt import MaliciousPromptDetector

    cfg = {"generic_injection_detection": False, "action": "block"}
    cfg.update(config)
    return MaliciousPromptDetector(cfg)


class _FakeListSvc:
    def __init__(self, malicious=False, benign=False, raises=False, raises_on=None):
        self._malicious, self._benign, self._raises = malicious, benign, raises
        self._raises_on = raises_on

    def check_match(self, text, kind):
        if self._raises or self._raises_on == kind:
            raise RuntimeError("list service exploded")
        return self._malicious if kind == "malicious" else self._benign


def test_composite_enabled_but_unconfigured_model_is_a_failure():
    """Asking for protection you have not configured is a misconfiguration.

    This previously logged at INFO and carried on, so a policy that switched on
    injection detection without a model silently had none.
    """
    d = _composite(generic_injection_detection=True)  # no model/tokenizer
    r = d.scan("anything")

    assert r.status is DetectorStatus.FAILED
    assert r.failure_code is FailureCode.CONFIG_INVALID


def test_composite_lists_enabled_without_session_factory_is_a_failure():
    d = _composite(custom_malicious_detection=True)
    r = d.scan("anything")

    assert r.status is DetectorStatus.FAILED
    assert r.failure_code is FailureCode.CONSTRUCT_FAILED


def test_composite_failure_with_no_detection_is_failed():
    d = _composite(custom_malicious_detection=True)
    d._prompt_list_svc = _FakeListSvc(raises=True)
    d._load_failures.clear()
    r = d.scan("anything")

    assert r.status is DetectorStatus.FAILED
    assert r.components["custom_malicious"].status is DetectorStatus.FAILED


def test_composite_failure_is_absorbed_when_a_detection_already_fired():
    """Block invariance: detected cannot become more true."""
    d = _composite(custom_malicious_detection=True, custom_benign_detection=True)
    d._prompt_list_svc = _FakeListSvc(malicious=True)
    d._load_failures.clear()
    # Force a later component to have failed at construction.
    d._load_failures["intent_conformance"] = FailureCode.CONSTRUCT_FAILED

    r = d.scan("bad prompt")

    assert r.detected is True
    assert r.status is DetectorStatus.OK
    assert r.data["action"] == "blocked"


def test_benign_match_short_circuits_as_ok_not_degraded():
    """A benign override is a policy decision, not a degradation."""
    d = _composite(custom_benign_detection=True)
    d._prompt_list_svc = _FakeListSvc(benign=True)
    d._load_failures.clear()

    r = d.scan("known good")

    assert r.detected is False
    assert r.status is DetectorStatus.OK
    assert r.components["generic_injection"].skip_reason is SkipReason.SHORT_CIRCUITED
    assert r.components["intent_conformance"].skip_reason is SkipReason.SHORT_CIRCUITED


def test_malformed_model_output_is_attributed_to_the_sub_detector():
    """r["label"] indexing on an unexpected shape must not bubble anonymously."""
    d = _composite(generic_injection_detection=True, model="m", tokenizer="t")
    d._pipeline = lambda text: [{"unexpected": "shape"}]
    d._load_failures.clear()

    r = d.scan("anything")

    assert r.status is DetectorStatus.FAILED
    assert r.failure_code is FailureCode.OUTPUT_INVALID
    assert r.components["generic_injection"].failure_code is FailureCode.OUTPUT_INVALID


def test_composite_all_ok_is_clean():
    d = _composite(custom_malicious_detection=True, custom_benign_detection=True)
    d._prompt_list_svc = _FakeListSvc()
    d._load_failures.clear()

    r = d.scan("ordinary text")

    assert r.detected is False
    assert r.status is DetectorStatus.OK


def test_benign_match_does_not_excuse_an_earlier_failure():
    """A benign override only excuses stages that run after it.

    The malicious list runs first and short-circuits to a block. If it failed,
    a benign match cannot stand in for the answer we never got.
    """
    d = _composite(custom_malicious_detection=True, custom_benign_detection=True)
    # The malicious check explodes; the benign check then matches.
    d._prompt_list_svc = _FakeListSvc(benign=True, raises_on="malicious")
    d._load_failures.clear()

    r = d.scan("known good")

    assert r.status is DetectorStatus.FAILED
    assert r.failure_code is FailureCode.SCAN_FAILED


# ---------------------------------------------------------------------------
# Invariant hardening (review findings)
# ---------------------------------------------------------------------------


def test_raw_string_status_does_not_bypass_invariants():
    """`status="failed"` used to slip past every identity check."""
    with pytest.raises(ValueError, match="FAILED and detected"):
        DetectorResult(detected=True, status="failed", failure_code=FailureCode.SCAN_FAILED)


def test_invalid_status_is_rejected_not_treated_as_ok():
    from app.detectors.base import ComponentStatus

    with pytest.raises(ValueError, match="not a valid DetectorStatus"):
        DetectorResult(status="nonsense")
    with pytest.raises(ValueError, match="not a valid DetectorStatus"):
        ComponentStatus(status="nonsense")


def test_component_status_enforces_the_same_invariants():
    from app.detectors.base import ComponentStatus

    with pytest.raises(ValueError, match="requires a failure_code"):
        ComponentStatus(status=DetectorStatus.FAILED)
    with pytest.raises(ValueError, match="requires a skip_reason"):
        ComponentStatus(status=DetectorStatus.SKIPPED)


def test_valid_string_status_is_coerced_to_the_enum():
    r = DetectorResult(status="ok")
    assert r.status is DetectorStatus.OK


# ---------------------------------------------------------------------------
# Construction-failure filtering (review findings)
# ---------------------------------------------------------------------------


def test_inapplicable_detector_failure_does_not_degrade_the_scan():
    """A failed output-only detector must not degrade an input scan."""
    engine = _engine({"malicious_entity": {"enabled": True, "action": "block"}})
    engine._construction_failures = [
        FailedDetector("malicious_entity", FailureCode.MODEL_LOAD_FAILED, action="block")
    ]

    on_input = engine.scan("hi", event_type="input", vault_id="v", vault=None)
    on_output = engine.scan("hi", event_type="output", vault_id="v", vault=None)

    assert on_input.enforcement_degraded is False
    assert on_output.enforcement_degraded is True


def test_scan_single_only_reports_redactor_failures():
    """scan_single is a redactor-only pass.

    A failed reporter must not mark every message reconstruction degraded and
    discard perfectly good redacted output.
    """
    engine = _engine({})
    engine._construction_failures = [
        FailedDetector("topic", FailureCode.MODEL_LOAD_FAILED, action="report"),
        FailedDetector("secret_and_key_entity", FailureCode.DEPENDENCY_MISSING, action="redact"),
    ]

    result = engine.scan_single("text", vault_id="v", vault=None)

    assert [f.name for f in result.failures] == ["secret_and_key_entity"]


def test_unavailable_intent_service_is_a_failure_not_a_pass():
    """_load_intents used to raise into the constructor and vanish.

    The composite caught it, left the service absent, and intent conformance
    silently never ran while the detector reported a confident clean verdict.
    """

    class _BrokenIntentSvc:
        available = False
        failure_code = "construct_failed"

    d = _composite()
    d._intent_enabled = True
    d._intent_svc = _BrokenIntentSvc()
    d._load_failures.clear()

    r = d.scan("anything")

    assert r.status is DetectorStatus.FAILED
    assert r.components["intent_conformance"].status is DetectorStatus.FAILED


def test_self_disabled_detector_counts_as_unable_to_run():
    """The second source of truth for "cannot run".

    A detector that catches its own load error calls mark_unavailable() and
    constructs *successfully*, so it sits in _detectors looking healthy. PII
    without Presidio is exactly this. Counting only construction exceptions
    would let the startup preflight declare an engine servable while one of its
    redactors is dead.
    """
    engine = _engine({})
    det = _RaisingDetector({"action": "redact"})
    det.action = "redact"
    det.mark_unavailable(FailureCode.DEPENDENCY_MISSING)
    engine._detectors.append((det.name, det))

    names = [f.name for f in engine.construction_failures]
    assert "exploding" in names
    assert engine.is_enforcement_complete is False


def test_healthy_detector_does_not_count_as_unavailable():
    engine = _engine({})
    det = _RaisingDetector({"action": "redact"})
    det.action = "redact"
    engine._detectors.append((det.name, det))

    assert engine.construction_failures == []
    assert engine.is_enforcement_complete is True


def test_benign_override_does_not_leave_a_contradictory_failed_component():
    """A response must not say "complete" while its own payload says otherwise.

    A component that failed to construct, for a stage the benign override then
    prevented from running, is not a degradation — that stage was never going
    to contribute. setdefault left it FAILED, so the composite returned
    status=OK/degraded=False alongside components.generic_injection=failed.
    """
    d = _composite(custom_benign_detection=True, generic_injection_detection=True)
    d._prompt_list_svc = _FakeListSvc(benign=True)
    d._load_failures.clear()
    d._load_failures["generic_injection"] = FailureCode.MODEL_LOAD_FAILED
    d._intent_enabled = False

    r = d.scan("known good")

    assert r.status is DetectorStatus.OK
    assert r.degraded is False
    assert r.components["generic_injection"].status is DetectorStatus.SKIPPED
    assert r.components["generic_injection"].skip_reason is SkipReason.SHORT_CIRCUITED


def test_malicious_override_does_not_report_a_prevented_stage_as_degraded():
    d = _composite(custom_malicious_detection=True, generic_injection_detection=True)
    d._prompt_list_svc = _FakeListSvc(malicious=True)
    d._load_failures.clear()
    d._load_failures["generic_injection"] = FailureCode.MODEL_LOAD_FAILED
    d._intent_enabled = False

    r = d.scan("bad prompt")

    assert r.detected is True
    assert r.degraded is False
    assert r.components["generic_injection"].status is DetectorStatus.SKIPPED


def test_composite_component_failure_reaches_the_preflight():
    """A composite that constructed fine with a dead sub-component.

    The detector reports available, so only the component view surfaces this.
    The activation preflight reads construction_failures, and would otherwise
    certify an engine whose injection model never loaded.
    """
    engine = _engine({})
    d = _composite(generic_injection_detection=True)  # no model configured
    d.action = "block"
    engine._detectors.append((d.name, d))

    names = [f.name for f in engine.construction_failures]
    assert "malicious_prompt.generic_injection" in names
    assert engine.is_enforcement_complete is False
