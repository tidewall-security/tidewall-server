"""Optional raw content capture and retention (P0-6, step 5).

Capture and retention land together deliberately. A configuration flag that can
say "capture is on" before anything honours it is a lie the operator cannot
detect: they would believe prompts were retained for an investigation that will
find nothing, or believe they were not retained when they were.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.models import Base, Interaction, InteractionContent, Policy
from app.interaction_log import InteractionLog

CANARY = "CANARY-capture-5c1a-secret"


@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)


def _policy(factory, *, enabled=False, retention_days=None, pid="policy-a"):
    session = factory()
    policy = Policy(
        id=pid,
        name=f"p-{pid}",
        type="application",
        raw_content_enabled=enabled,
        raw_content_retention_days=retention_days,
    )
    session.add(policy)
    session.commit()
    session.close()
    return pid


def _write(factory, policy_id, *, rid="tw_0000000000000001"):
    InteractionLog(factory).log_event(
        request_id=rid,
        timestamp="2026-08-19T00:00:00Z",
        event_type="input",
        policy="p",
        policy_id=policy_id,
        blocked=False,
        transformed=False,
        latency_ms=1.0,
        evidence={},
        content={"input": [{"role": "user", "content": f"my secret is {CANARY}"}], "output": None, "matches": None},
    )


def test_capture_off_by_default_stores_nothing(db):
    """A fresh policy retains nothing: the insecure state is never the one you
    get by not reading the documentation."""
    policy_id = _policy(db)

    _write(db, policy_id)

    session = db()
    try:
        assert session.query(InteractionContent).count() == 0
        assert session.query(Interaction).one().content_available is False
    finally:
        session.close()


def test_capture_on_stores_the_content_and_marks_the_event(db):
    policy_id = _policy(db, enabled=True)

    _write(db, policy_id)

    session = db()
    try:
        content = session.query(InteractionContent).one()
        event = session.query(Interaction).one()
        assert CANARY in str(content.input_json)
        assert content.interaction_id == event.id
        assert event.content_available is True
        assert content.byte_size > 0
    finally:
        session.close()


def test_the_event_never_claims_content_it_does_not_have(db):
    """content_available is what the UI uses to decide between 'not retained'
    and 'withheld from you'. A wrong value sends an operator hunting for
    something that was never stored."""
    policy_id = _policy(db)

    _write(db, policy_id)

    session = db()
    try:
        event = session.query(Interaction).one()
        assert event.content_available is False
        assert session.query(InteractionContent).filter_by(interaction_id=event.id).count() == 0
    finally:
        session.close()


def test_no_expiry_is_the_default(db):
    """Configurable retention with no default expiry, chosen deliberately."""
    policy_id = _policy(db, enabled=True)

    _write(db, policy_id)

    session = db()
    try:
        assert session.query(InteractionContent).one().expires_at is None
    finally:
        session.close()


def test_a_retention_window_sets_an_expiry(db):
    policy_id = _policy(db, enabled=True, retention_days=7)

    _write(db, policy_id)

    session = db()
    try:
        expires = session.query(InteractionContent).one().expires_at
        assert expires is not None
        delta = expires.replace(tzinfo=UTC) - datetime.now(UTC)
        assert timedelta(days=6) < delta <= timedelta(days=7)
    finally:
        session.close()


def test_expired_content_is_purged_and_the_event_survives(db):
    """The event is the audit record; only its content expires."""
    from app.services.content_capture import purge_expired

    policy_id = _policy(db, enabled=True, retention_days=1)
    _write(db, policy_id)

    session = db()
    try:
        content = session.query(InteractionContent).one()
        content.expires_at = datetime.now(UTC) - timedelta(hours=1)
        session.commit()

        purge_expired(session)

        assert session.query(InteractionContent).count() == 0
        event = session.query(Interaction).one()
        assert event.content_available is False, "the event still advertises content that is gone"
    finally:
        session.close()


def test_expiry_is_enforced_on_read_even_before_the_purge_runs(db):
    """There is no scheduler, so a read must not serve content that should
    already be gone just because nothing has deleted it yet. Expiry is a
    promise about disclosure, not about when a row disappears."""
    from app.services.content_capture import is_expired

    policy_id = _policy(db, enabled=True, retention_days=1)
    _write(db, policy_id)

    session = db()
    try:
        content = session.query(InteractionContent).one()
        content.expires_at = datetime.now(UTC) - timedelta(seconds=1)
        session.commit()

        assert is_expired(content) is True
    finally:
        session.close()


def test_purge_is_idempotent_and_safe_to_repeat(db):
    from app.services.content_capture import purge_expired

    policy_id = _policy(db, enabled=True, retention_days=1)
    _write(db, policy_id)

    session = db()
    try:
        session.query(InteractionContent).one().expires_at = datetime.now(UTC) - timedelta(hours=1)
        session.commit()

        assert purge_expired(session) == 1
        assert purge_expired(session) == 0
    finally:
        session.close()


def test_usage_is_a_gauge_for_a_choice_with_no_size_cap(db):
    """No size cap was chosen deliberately, so the least this can do is let an
    operator see what unbounded retention is costing."""
    from app.services.content_capture import usage

    policy_id = _policy(db, enabled=True)
    _write(db, policy_id)

    session = db()
    try:
        stats = usage(session)
    finally:
        session.close()

    assert stats["rows"] == 1
    assert stats["bytes"] > 0
    assert stats["oldest_captured_at"] is not None


def test_turning_capture_on_takes_effect_on_the_next_request(db):
    """Policy changes must not need a restart."""
    policy_id = _policy(db)
    _write(db, policy_id, rid="tw_0000000000000001")

    session = db()
    try:
        session.get(Policy, policy_id).raw_content_enabled = True
        session.commit()
    finally:
        session.close()

    _write(db, policy_id, rid="tw_0000000000000002")

    session = db()
    try:
        assert session.query(InteractionContent).count() == 1
        stored = {e.request_id: e.content_available for e in session.query(Interaction).all()}
        assert stored == {"tw_0000000000000001": False, "tw_0000000000000002": True}
    finally:
        session.close()
