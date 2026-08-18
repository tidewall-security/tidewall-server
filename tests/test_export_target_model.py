"""Tests for ExportTarget ORM model."""

import pytest
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


def test_create_webhook_target(db_session):
    target = ExportTarget(
        name="slack-alerts",
        type="webhook",
        config={"url": "https://hooks.slack.com/xxx", "headers": {"Content-Type": "application/json"}},
        format="ocsf",
        events=["blocked", "alerted"],
        enabled=True,
    )
    db_session.add(target)
    db_session.commit()
    assert target.id is not None
    assert target.type == "webhook"
    assert target.events == ["blocked", "alerted"]


def test_create_syslog_target(db_session):
    target = ExportTarget(
        name="siem-ingest",
        type="syslog",
        config={"host": "syslog.company.com", "port": 514, "protocol": "udp"},
        format="ocsf",
        events=["blocked", "alerted", "transformed"],
        enabled=True,
    )
    db_session.add(target)
    db_session.commit()
    assert target.config["port"] == 514


def test_create_aidr_compat_format_target(db_session):
    target = ExportTarget(
        name="cs-compat",
        type="webhook",
        config={"url": "https://siem.company.com/ingest"},
        format="aidr_compat",
        events=["blocked"],
        enabled=False,
    )
    db_session.add(target)
    db_session.commit()
    assert target.format == "aidr_compat"
    assert target.enabled is False
