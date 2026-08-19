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
    """Read the policy the way the guard does — at admission — and pass the
    decision in, rather than letting the writer re-read it later."""
    session = factory()
    try:
        policy = session.get(Policy, policy_id)
        enabled = bool(policy.raw_content_enabled)
        retention = policy.raw_content_retention_days
    finally:
        session.close()

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
        capture_enabled=enabled,
        retention_days=retention,
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


# ---------------------------------------------------------------------------
# Round 1 review
# ---------------------------------------------------------------------------


def test_creating_an_enabled_policy_actually_enables_it(db):
    """create_policy accepted both settings and assigned neither, so a request
    to create an enabled policy returned 201 with capture silently off —
    precisely the state this step exists to make impossible."""
    from app.services.policy_service import PolicyService

    session = db()
    try:
        policy = PolicyService(session).create_policy(
            name="enabled", type="application", raw_content_enabled=True, raw_content_retention_days=7
        )
        stored = session.get(Policy, policy.id)
        assert stored.raw_content_enabled is True
        assert stored.raw_content_retention_days == 7
    finally:
        session.close()


def test_creating_a_policy_validates_retention(db):
    from app.services.policy_service import PolicyService

    session = db()
    try:
        with pytest.raises(ValueError, match="positive number of days"):
            PolicyService(session).create_policy(name="bad", type="application", raw_content_retention_days=0)
    finally:
        session.close()


def test_tools_are_captured_with_the_messages(db):
    """Tools are scanned, so a captured tool-listing event without them records
    less than was actually evaluated."""
    policy_id = _policy(db, enabled=True)

    InteractionLog(db).log_event(
        request_id="tw_000000000000000a",
        timestamp="2026-08-19T00:00:00Z",
        event_type="tool_listing",
        policy="p",
        policy_id=policy_id,
        blocked=False,
        transformed=False,
        latency_ms=1.0,
        evidence={},
        content={
            "input": [{"role": "user", "content": "list tools"}],
            "output": None,
            "matches": None,
            "tools": [{"name": "exfiltrate", "description": f"send {CANARY}"}],
        },
        capture_enabled=True,
    )

    session = db()
    try:
        stored = session.query(InteractionContent).one().input_json
    finally:
        session.close()

    assert "tools" in stored
    assert CANARY in str(stored["tools"])


def test_is_expired_handles_a_naive_clock():
    """Comparing one aware and one naive datetime raises, so a caller passing a
    naive `now` turned an expiry check into a TypeError — failing the read
    rather than the disclosure decision."""
    from app.db.models import InteractionContent as IC
    from app.services.content_capture import is_expired

    content = IC(interaction_id=1, expires_at=datetime.now(UTC) - timedelta(hours=1))

    assert is_expired(content, now=datetime.now()) is True  # naive
    assert is_expired(content, now=datetime.now(UTC)) is True  # aware


def test_a_null_expiry_never_expires():
    from app.db.models import InteractionContent as IC
    from app.services.content_capture import is_expired

    assert is_expired(IC(interaction_id=1, expires_at=None)) is False


def test_a_content_failure_keeps_the_audit_event(db):
    """The logging concern must not take down the thing it is logging.

    An unserialisable payload previously rolled both rows back, erasing the
    audit record and turning a completed guard decision into an HTTP error.
    """
    policy_id = _policy(db, enabled=True)

    InteractionLog(db).log_event(
        request_id="tw_000000000000000b",
        timestamp="2026-08-19T00:00:00Z",
        event_type="input",
        policy="p",
        policy_id=policy_id,
        blocked=False,
        transformed=False,
        latency_ms=1.0,
        evidence={},
        # A set is not JSON serialisable.
        content={"input": {"impossible"}, "output": None, "matches": None},
        capture_enabled=True,
    )

    session = db()
    try:
        event = session.query(Interaction).one()
        assert event.content_available is False
        assert session.query(InteractionContent).count() == 0
    finally:
        session.close()


def test_a_content_failure_does_not_log_the_content(db, caplog):
    """This path reaches an operator's log, and the value is the thing being
    protected."""
    policy_id = _policy(db, enabled=True)

    with caplog.at_level("ERROR"):
        InteractionLog(db).log_event(
            request_id="tw_000000000000000c",
            timestamp="2026-08-19T00:00:00Z",
            event_type="input",
            policy="p",
            policy_id=policy_id,
            blocked=False,
            transformed=False,
            latency_ms=1.0,
            evidence={},
            content={"input": {CANARY}, "output": None, "matches": None},
            capture_enabled=True,
        )

    assert CANARY not in caplog.text


def test_capture_is_decided_at_admission_not_at_log_time(db):
    """Re-reading the policy in the writer meant enabling capture mid-request
    could retain content that entered while capture was off."""
    policy_id = _policy(db, enabled=False)

    session = db()
    try:
        session.get(Policy, policy_id).raw_content_enabled = True
        session.commit()
    finally:
        session.close()

    # Admitted while capture was off, so the decision passed in is False even
    # though the policy now says otherwise.
    InteractionLog(db).log_event(
        request_id="tw_000000000000000d",
        timestamp="2026-08-19T00:00:00Z",
        event_type="input",
        policy="p",
        policy_id=policy_id,
        blocked=False,
        transformed=False,
        latency_ms=1.0,
        evidence={},
        content={"input": [{"content": CANARY}], "output": None, "matches": None},
        capture_enabled=False,
    )

    session = db()
    try:
        assert session.query(InteractionContent).count() == 0
        assert session.query(Interaction).one().content_available is False
    finally:
        session.close()


def test_the_seed_round_trips_the_capture_settings(tmp_path):
    """An exported enabled policy used as first-boot configuration silently
    seeded capture off."""
    import yaml
    from sqlalchemy import create_engine as _ce
    from sqlalchemy.orm import sessionmaker as _sm

    from app.db.seed import seed_from_yaml

    path = tmp_path / "policy.yaml"
    path.write_text(
        yaml.dump(
            {
                "name": "seeded",
                "report_only": False,
                "raw_content_enabled": True,
                "raw_content_retention_days": 14,
                "detectors": {},
            }
        )
    )

    engine = _ce(f"sqlite:///{tmp_path / 'seed.db'}")
    Base.metadata.create_all(engine)
    factory = _sm(bind=engine)
    session = factory()
    try:
        seed_from_yaml(session, str(path))
        policy = session.query(Policy).one()
        assert policy.raw_content_enabled is True
        assert policy.raw_content_retention_days == 14
    finally:
        session.close()
        engine.dispose()


def test_the_seed_rejects_an_unenforceable_retention(tmp_path):
    """A seed file that says something unenforceable should fail loudly at
    first boot rather than quietly become a different policy."""
    import yaml
    from sqlalchemy import create_engine as _ce
    from sqlalchemy.orm import sessionmaker as _sm

    from app.db.seed import seed_from_yaml

    path = tmp_path / "policy.yaml"
    path.write_text(yaml.dump({"name": "bad", "raw_content_retention_days": True, "detectors": {}}))

    engine = _ce(f"sqlite:///{tmp_path / 'bad.db'}")
    Base.metadata.create_all(engine)
    session = _sm(bind=engine)()
    try:
        with pytest.raises(ValueError, match="positive integer"):
            seed_from_yaml(session, str(path))
    finally:
        session.close()
        engine.dispose()


def test_a_persistence_failure_also_keeps_the_audit_event(db, monkeypatch):
    """Pre-serialising caught unsupported Python values and did nothing for a
    failure at persistence, which still destroyed the audit event."""

    policy_id = _policy(db, enabled=True)

    def _explode(*_args, **_kwargs):
        raise RuntimeError("constraint violation at insert")

    monkeypatch.setattr("app.services.content_capture.capture_content", _explode)

    InteractionLog(db).log_event(
        request_id="tw_000000000000000e",
        timestamp="2026-08-19T00:00:00Z",
        event_type="input",
        policy="p",
        policy_id=policy_id,
        blocked=False,
        transformed=False,
        latency_ms=1.0,
        evidence={},
        content={"input": [{"content": CANARY}], "output": None, "matches": None},
        capture_enabled=True,
    )

    session = db()
    try:
        event = session.query(Interaction).one()
        assert event.content_available is False
        assert session.query(InteractionContent).count() == 0
    finally:
        session.close()


@pytest.mark.parametrize("value", ["false", "true", 0, 1, "no"])
def test_the_seed_rejects_a_non_boolean_capture_flag(tmp_path, value):
    """YAML raw_content_enabled: "false" is a non-empty string, so bool() made
    it True — turning prompt capture ON from configuration that reads as off."""
    import yaml
    from sqlalchemy import create_engine as _ce
    from sqlalchemy.orm import sessionmaker as _sm

    from app.db.seed import seed_from_yaml

    path = tmp_path / "policy.yaml"
    path.write_text(yaml.dump({"name": "p", "raw_content_enabled": value, "detectors": {}}))

    engine = _ce(f"sqlite:///{tmp_path / f'flag{hash(str(value))}.db'}")
    Base.metadata.create_all(engine)
    session = _sm(bind=engine)()
    try:
        with pytest.raises(ValueError, match="must be true or false"):
            seed_from_yaml(session, str(path))
    finally:
        session.close()
        engine.dispose()


def test_byte_size_is_the_bytes_actually_stored():
    """The previous version measured one synthetic wrapper with compact
    separators, which is not what goes into three separate JSON columns."""
    import json as _json

    from app.services.content_capture import build_content

    prepared = build_content(
        input_messages=[{"content": "café"}],
        output_messages=[{"content": "reply"}],
        matches={"pii": 1},
        tools=[],
        retention_days=None,
    )

    expected = sum(
        len(_json.dumps(v).encode("utf-8"))
        for v in (prepared.input_json, prepared.output_json, prepared.matches_json)
        if v is not None
    )
    assert prepared.byte_size == expected


def test_an_empty_tools_list_is_still_recorded_as_a_wrapper():
    """The truthiness branch dropped an explicitly empty tools list, so the
    stored shape depended on whether any happened to be present."""
    from app.services.content_capture import build_content

    prepared = build_content(
        input_messages=[{"content": "x"}], output_messages=None, matches=None, tools=[], retention_days=None
    )

    assert isinstance(prepared.input_json, dict)
    assert prepared.input_json["tools"] == []
