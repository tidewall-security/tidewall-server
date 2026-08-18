"""Tests for ExportService — event dispatch to webhooks and syslog."""

import json
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from app.db.engine import get_engine, get_session_factory
from app.db.models import Base, ExportTarget


@pytest.fixture
def db_session():
    engine = get_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = get_session_factory(engine)
    session = Session()
    yield session
    session.close()


@pytest.fixture
def session_with_webhook(db_session):
    db_session.add(
        ExportTarget(
            name="test-webhook",
            type="webhook",
            config={"url": "https://example.com/hook", "headers": {"X-Token": "abc"}},
            format="ocsf",
            events=["blocked", "alerted"],
            enabled=True,
        )
    )
    db_session.commit()
    return db_session


@pytest.fixture
def session_with_disabled_target(db_session):
    db_session.add(
        ExportTarget(
            name="disabled",
            type="webhook",
            config={"url": "https://example.com/hook"},
            format="ocsf",
            events=["blocked"],
            enabled=False,
        )
    )
    db_session.commit()
    return db_session


def test_no_targets_no_dispatch(db_session):
    from app.services.export_service import ExportService

    svc = ExportService(db_session)
    # Should not raise
    import asyncio

    asyncio.run(
        svc.emit(
            status="blocked",
            request_id="test",
            timestamp="now",
            summary="test",
            policy_name="p",
            event_type="input",
            detectors={},
        )
    )


def test_event_filter_matches(session_with_webhook):
    from app.services.export_service import ExportService

    svc = ExportService(session_with_webhook)
    targets = svc._get_matching_targets("blocked")
    assert len(targets) == 1
    assert targets[0].name == "test-webhook"


def test_event_filter_no_match(session_with_webhook):
    from app.services.export_service import ExportService

    svc = ExportService(session_with_webhook)
    targets = svc._get_matching_targets("allowed")
    assert len(targets) == 0


def test_disabled_target_skipped(session_with_disabled_target):
    from app.services.export_service import ExportService

    svc = ExportService(session_with_disabled_target)
    targets = svc._get_matching_targets("blocked")
    assert len(targets) == 0


def test_build_event_ocsf_format(db_session):
    from app.services.export_service import ExportService

    svc = ExportService(db_session)
    event = svc._build_event(
        format="ocsf",
        status="blocked",
        request_id="test",
        timestamp="now",
        summary="test",
        policy_name="p",
        event_type="input",
        detectors={},
    )
    assert event["class_uid"] == 2006


def test_build_event_aidr_compat_format(db_session):
    from app.services.export_service import ExportService

    svc = ExportService(db_session)
    event = svc._build_event(
        format="aidr_compat",
        status="blocked",
        request_id="test",
        timestamp="now",
        summary="test",
        policy_name="p",
        event_type="input",
        detectors={},
    )
    assert event["event_simpleName"] == "TidewallPromptDataEvent"


def test_build_event_raw_format(db_session):
    from app.services.export_service import ExportService

    svc = ExportService(db_session)
    event = svc._build_event(
        format="raw",
        status="blocked",
        request_id="test",
        timestamp="now",
        summary="test",
        policy_name="p",
        event_type="input",
        detectors={"malicious_prompt": {"detected": True}},
    )
    assert event["status"] == "blocked"
    assert "detectors" in event
