"""Degradation must reach every sink, not just the HTTP response.

The recurring defect in this workstream was values produced and never
consumed. Degradation is carried as a reserved `_degraded` entry in the
detectors payload precisely so the interaction row and every export format
transport it verbatim — but "carried by construction" is the same claim that
turned out to be false three times, so it is pinned here instead.
"""

from __future__ import annotations

import pytest

from app.detectors.base import DetectorResult, DetectorStatus, FailureCode
from app.services.export_service import ExportService

# ---------------------------------------------------------------------------
# The invariant
# ---------------------------------------------------------------------------


def test_degraded_requires_a_verdict():
    """A FAILED result has no verdict, so it cannot be an incomplete one."""
    with pytest.raises(ValueError, match="degraded requires status OK"):
        DetectorResult(
            status=DetectorStatus.FAILED,
            failure_code=FailureCode.SCAN_FAILED,
            degraded=True,
        )


def test_degraded_requires_a_detection():
    """An incomplete negative is not a negative — that case is FAILED."""
    with pytest.raises(ValueError, match="degraded requires a detection"):
        DetectorResult(detected=False, degraded=True)


def test_degraded_positive_is_valid():
    r = DetectorResult(detected=True, degraded=True)
    assert r.degraded is True
    assert r.status is DetectorStatus.OK


def test_ordinary_results_are_not_degraded():
    assert DetectorResult(detected=True).degraded is False
    assert DetectorResult(detected=False).degraded is False
    assert DetectorResult.failed(FailureCode.SCAN_FAILED).degraded is False


# ---------------------------------------------------------------------------
# Propagation to every export format
# ---------------------------------------------------------------------------


_DEGRADED_DETECTORS = {
    "malicious_prompt": {"detected": False, "status": "failed", "failure_code": "model_load_failed"},
    "_degraded": {"degraded": True, "failed_detectors": ["malicious_prompt"]},
}


def _event(fmt: str) -> dict:
    svc = ExportService.__new__(ExportService)
    return svc._build_event(
        fmt,
        status="allowed",
        request_id="tw_test",
        timestamp="2026-08-16T00:00:00Z",
        summary="Scan incomplete: one or more detectors could not run.",
        policy_name="default",
        event_type="input",
        detectors=_DEGRADED_DETECTORS,
        user_id="u",
        app_id="a",
        model="m",
        llm_provider="p",
    )


@pytest.mark.parametrize("fmt", ["raw", "ocsf", "aidr_compat"])
def test_every_export_format_carries_the_degraded_marker(fmt):
    """A consumer must not have to parse the summary string to learn this."""
    event = _event(fmt)
    serialized = str(event)

    assert "_degraded" in serialized, f"{fmt} dropped the degraded marker"
    assert "malicious_prompt" in serialized


@pytest.mark.parametrize("fmt", ["raw", "ocsf", "aidr_compat"])
def test_every_export_format_carries_the_honest_summary(fmt):
    event = _event(fmt)
    assert "No threats detected" not in str(event)


def test_clean_events_carry_no_degraded_marker():
    svc = ExportService.__new__(ExportService)
    event = svc._build_event(
        "raw",
        status="allowed",
        request_id="tw_test",
        timestamp="2026-08-16T00:00:00Z",
        summary="No threats detected.",
        policy_name="default",
        event_type="input",
        detectors={"topic": {"detected": False, "status": "ok"}},
        user_id="u",
        app_id="a",
        model="m",
        llm_provider="p",
    )
    assert "_degraded" not in str(event)


def test_interaction_row_carries_the_degraded_marker():
    """The audit trail is the record that outlives the response."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

    from app.db.models import Base, Interaction
    from app.interaction_log import InteractionLog

    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine)

    InteractionLog(SessionLocal).log_event(
        request_id="tw_test",
        timestamp="2026-08-16T00:00:00Z",
        event_type="input",
        policy="default",
        blocked=False,
        transformed=False,
        status="allowed",
        latency_ms=1.0,
        policy_id="policy-default",
        evidence=_DEGRADED_DETECTORS,
    )

    session = SessionLocal()
    try:
        row = session.query(Interaction).one()
        assert row.evidence_json["_degraded"]["degraded"] is True
        assert row.evidence_json["_degraded"]["failed_detectors"] == ["malicious_prompt"]
        # summary is gone: it carried the access-rule name and detector-derived
        # strings, and was displayed and searched in the UI.
        assert not hasattr(row, "summary")
    finally:
        session.close()


def test_reserved_keys_are_distinguishable_from_detectors():
    """The `_degraded` marker shares a namespace with detector names.

    Two shipped UI consumers iterated `detectors_json` assuming every key named
    a detector, and rendered the marker as a detector with a "Clear" badge —
    exactly backwards for a degraded scan. The convention is that keys
    beginning with "_" are reserved scan metadata; this pins it so a future
    reserved key does not have to rediscover the rule.
    """
    from app.scanner_engine import _DETECTOR_REGISTRY

    detector_names = [k for k in _DEGRADED_DETECTORS if not k.startswith("_")]
    reserved = [k for k in _DEGRADED_DETECTORS if k.startswith("_")]

    assert reserved == ["_degraded"]
    assert all(name in _DETECTOR_REGISTRY for name in detector_names)


def test_ui_consumers_exclude_reserved_keys():
    """Guards the consumer that renders `_degraded` as a detector.

    There were two. The stale duplicate at app/static/dashboard.html was
    removed in step 4: it was publicly reachable, sent no bearer token so every
    API call it made returned 401, and still read the removed content columns.
    A forgotten consumer of a content DTO is worth deleting rather than
    maintaining.
    """
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent
    assert not (root / "app/static/dashboard.html").exists(), "the stale duplicate dashboard is back"

    findings = (root / "app/static/js/findings.js").read_text()
    assert findings.count("charAt(0)") >= 2
