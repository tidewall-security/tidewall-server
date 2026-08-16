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

    engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
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
        summary="Scan incomplete: one or more detectors could not run.",
        input_messages=[],
        output_messages=None,
        detectors_json=_DEGRADED_DETECTORS,
    )

    session = SessionLocal()
    try:
        row = session.query(Interaction).one()
        assert row.detectors_json["_degraded"]["degraded"] is True
        assert row.detectors_json["_degraded"]["failed_detectors"] == ["malicious_prompt"]
        assert "No threats detected" not in row.summary
    finally:
        session.close()
