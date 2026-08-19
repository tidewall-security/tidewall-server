"""Tests for ActivityService."""

import pytest
from app.db.engine import get_engine, get_session_factory
from app.db.models import Base, ActivityLog


@pytest.fixture
def db_session():
    engine = get_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = get_session_factory(engine)
    session = Session()
    yield session
    session.close()


def test_log_activity(db_session):
    from app.services.activity_service import ActivityService

    svc = ActivityService(db_session)
    svc.log(
        actor="admin-key",
        action="update",
        target_type="policy",
        target_id="p123",
        old_value={"action": "report"},
        new_value={"action": "block"},
    )
    entries = db_session.query(ActivityLog).all()
    assert len(entries) == 1
    assert entries[0].actor == "admin-key"
    assert entries[0].old_value == {"action": "report"}


def test_list_activity(db_session):
    from app.services.activity_service import ActivityService

    svc = ActivityService(db_session)
    svc.log(actor="a", action="create", target_type="policy", target_id="1")
    svc.log(actor="b", action="update", target_type="key", target_id="2")
    entries = svc.list_recent(limit=10)
    assert len(entries) == 2


def test_list_activity_ordered_by_timestamp(db_session):
    from app.services.activity_service import ActivityService

    svc = ActivityService(db_session)
    svc.log(actor="first", action="create", target_type="policy", target_id="1")
    svc.log(actor="second", action="update", target_type="policy", target_id="1")
    entries = svc.list_recent(limit=10)
    # Most recent first
    assert entries[0].actor == "second"
