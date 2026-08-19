"""The durable record of one content export attempt.

`pending` is committed BEFORE any I/O, so a crash is visible as pending rather
than misrecorded as a success. Nothing here retries: retrying an export whose
delivery is unknown is how one disclosure becomes two.
"""

from __future__ import annotations

import threading

import pytest
import sqlalchemy as sa
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.models import Base, ContentExportAttempt, ContentExportNote
from app.services import content_export as svc


def _factory_for(path):
    """File-backed WAL with separate connections.

    The in-memory StaticPool fixture used elsewhere shares ONE connection and
    cannot exhibit the reservation race at all, so a test built on it would pass
    without proving anything.
    """
    engine = create_engine(f"sqlite:///{path}")
    with engine.begin() as conn:
        conn.execute(sa.text("PRAGMA journal_mode=WAL"))
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)


@pytest.fixture
def factory(tmp_path):
    return _factory_for(tmp_path / "x.db")


def _attempt(**over):
    base = dict(
        interaction_id=1,
        policy_id="p",
        target_id="t",
        api_key_id="k",
        actor_role="admin",
        view="full",
        grant_used="interaction:content:export",
        payload_bytes=10,
        idempotency_key_digest=None,
        fingerprint="f",
        destination_host="h",
        destination_port=443,
        destination_addrs=["1.2.3.4"],
        target_config_digest="d",
        boot_id="boot-1",
    )
    base.update(over)
    return base


def test_reserve_writes_pending_before_any_io(factory):
    attempt_id, replay = svc.reserve(factory, attempt=_attempt())
    assert replay is False
    with factory() as s:
        row = s.get(ContentExportAttempt, attempt_id)
        assert row.state == "pending"
        assert row.settled_at is None
        assert row.transport_status is None
        assert row.destination_addr is None, "a peer was recorded before any connection"


def test_a_repeated_key_replays_rather_than_reserving_again(factory):
    digest = svc.digest_key("k1")
    first, replay1 = svc.reserve(factory, attempt=_attempt(idempotency_key_digest=digest))
    second, replay2 = svc.reserve(factory, attempt=_attempt(idempotency_key_digest=digest))
    assert replay1 is False and replay2 is True
    assert first == second
    with factory() as s:
        assert s.query(ContentExportAttempt).count() == 1


def test_a_different_credential_may_reuse_the_same_key(factory):
    """Scoped to the credential, because global uniqueness would let one admin's
    key collide with or probe another's."""
    digest = svc.digest_key("shared")
    a, _ = svc.reserve(factory, attempt=_attempt(api_key_id="k1", idempotency_key_digest=digest))
    b, replay = svc.reserve(factory, attempt=_attempt(api_key_id="k2", idempotency_key_digest=digest))
    assert a != b
    assert replay is False


def test_the_key_itself_is_never_stored(factory):
    svc.reserve(factory, attempt=_attempt(idempotency_key_digest=svc.digest_key("super-secret")))
    with factory() as s:
        row = s.query(ContentExportAttempt).one()
        assert row.idempotency_key_digest != "super-secret"
        assert "super-secret" not in str(
            {c.name: getattr(row, c.name) for c in row.__table__.columns}
        )


def test_settlement_is_a_compare_and_set(factory):
    attempt_id, _ = svc.reserve(factory, attempt=_attempt())
    assert svc.settle(
        factory, attempt_id=attempt_id, state="succeeded", transport_status=204, peer="1.2.3.4"
    ) is True
    # A row already settled is not overwritten: the caller answers 502 with the
    # stored state rather than 202.
    assert svc.settle(
        factory, attempt_id=attempt_id, state="failed", transport_status=500, peer=None
    ) is False
    with factory() as s:
        row = s.get(ContentExportAttempt, attempt_id)
        assert row.state == "succeeded"
        assert row.transport_status == 204
        assert row.destination_addr == "1.2.3.4"
        assert row.settled_at is not None


def test_only_foreign_boot_ids_are_abandoned(factory):
    """A row from the CURRENT boot is owned by a live coroutine and is never
    touched, however old: age has no role in this protocol."""
    mine, _ = svc.reserve(factory, attempt=_attempt(boot_id="boot-current"))
    theirs, _ = svc.reserve(
        factory, attempt=_attempt(boot_id="boot-old", idempotency_key_digest="d2")
    )
    with factory() as s:
        assert svc.abandon_foreign_pending(s, boot_id="boot-current") == 1
        s.commit()
        assert s.get(ContentExportAttempt, mine).state == "pending"
        row = s.get(ContentExportAttempt, theirs)
        assert row.state == "abandoned_indeterminate"
        assert row.settled_at is not None


def test_an_aged_row_from_the_current_boot_is_still_left_alone(factory):
    """Asserted by ageing one artificially, because that is exactly the case a
    time threshold got wrong."""
    from datetime import UTC, datetime, timedelta

    attempt_id, _ = svc.reserve(factory, attempt=_attempt(boot_id="boot-current"))
    with factory() as s:
        s.execute(
            sa.update(ContentExportAttempt)
            .where(ContentExportAttempt.attempt_id == attempt_id)
            .values(created_at=datetime.now(UTC).replace(tzinfo=None) - timedelta(days=30))
        )
        s.commit()
        assert svc.abandon_foreign_pending(s, boot_id="boot-current") == 0


def test_a_settled_row_is_not_abandoned(factory):
    attempt_id, _ = svc.reserve(factory, attempt=_attempt(boot_id="boot-old"))
    svc.settle(factory, attempt_id=attempt_id, state="failed", transport_status=500, peer=None)
    with factory() as s:
        assert svc.abandon_foreign_pending(s, boot_id="boot-current") == 0


def test_notes_are_best_effort_and_bounded(factory):
    attempt_id, _ = svc.reserve(factory, attempt=_attempt())
    svc.write_note(factory, attempt_id=attempt_id, kind="settlement_lost", detail="x" * 5000)
    with factory() as s:
        note = s.query(ContentExportNote).one()
        assert len(note.detail) <= svc.MAX_EVIDENCE


def test_a_note_that_cannot_be_written_does_not_raise(factory):
    """A note is evidence ABOUT an export, not a precondition of one."""

    def _broken():
        raise RuntimeError("no session")

    svc.write_note(_broken, attempt_id="whatever", kind="settlement_lost", detail="d")


def test_pending_health_is_derived_from_the_rows(factory):
    """Not an in-memory counter: that is lost on exactly the crash most likely
    to have created the row."""
    assert svc.pending_health(factory()) == (0, None)
    svc.reserve(factory, attempt=_attempt())
    count, age = svc.pending_health(factory())
    assert count == 1
    assert age is not None and age >= 0


def test_two_concurrent_reservations_with_one_key_produce_one_attempt(tmp_path):
    """The race a sequential test cannot show.

    A check-then-insert passes the sequential test and fails this one, which is
    the whole reason the reservation is a unique-constrained insert.
    """
    factory = _factory_for(tmp_path / "race.db")
    digest = svc.digest_key("same")
    results: list[tuple[str, bool]] = []
    errors: list[BaseException] = []
    barrier = threading.Barrier(2)

    def _go():
        try:
            barrier.wait(10)
            results.append(svc.reserve(factory, attempt=_attempt(idempotency_key_digest=digest)))
        except BaseException as exc:  # noqa: BLE001 - recorded and re-raised by the assertions
            errors.append(exc)

    threads = [threading.Thread(target=_go) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(20)

    assert not errors, f"a reservation raised: {errors}"
    assert len(results) == 2
    assert sorted(r[1] for r in results) == [False, True], "both reserved, or neither did"
    assert results[0][0] == results[1][0], "the two calls disagree about the attempt"
    with factory() as s:
        assert s.query(ContentExportAttempt).count() == 1
