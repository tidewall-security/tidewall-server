"""Correcting what an export attempt actually did.

The attempt's own state is the original observation and is never edited. A
correction is appended, and the effective state is the latest one.
"""

from __future__ import annotations

from datetime import datetime

import pytest
import sqlalchemy as sa
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.models import Base, ContentExportAttempt, ContentExportReconciliation
from app.routes.content_export_admin import append_reconciliation, effective_state
from app.services import content_export as svc


@pytest.fixture
def factory(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'r.db'}")
    with engine.begin() as conn:
        conn.execute(sa.text("PRAGMA journal_mode=WAL"))
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)


def _settled(factory, state="indeterminate"):
    attempt_id, _ = svc.reserve(
        factory,
        attempt_id=svc.new_attempt_id(),
        attempt=dict(
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
            boot_id="b",
        ),
    )
    svc.settle(factory, attempt_id=attempt_id, state=state, transport_status=None, peer=None)
    return attempt_id


def test_the_effective_state_starts_as_the_observation(factory):
    attempt_id = _settled(factory)
    with factory() as s:
        assert effective_state(s, attempt_id) == "indeterminate"


def test_the_attempt_row_is_never_edited(factory):
    attempt_id = _settled(factory)
    with factory() as s:
        append_reconciliation(
            s,
            attempt_id=attempt_id,
            from_state="indeterminate",
            to_state="succeeded",
            evidence="receiver log line 42",
            actor="k",
        )
        s.commit()
        assert s.get(ContentExportAttempt, attempt_id).state == "indeterminate"
        assert effective_state(s, attempt_id) == "succeeded"


def test_the_latest_is_by_id_not_by_timestamp(factory):
    """Two records written in the same clock tick would otherwise be unordered,
    and the answer would depend on which one a query returned first."""
    attempt_id = _settled(factory)
    same_instant = datetime(2026, 8, 19, 0, 0, 0)
    with factory() as s:
        s.add(
            ContentExportReconciliation(
                attempt_id=attempt_id,
                from_state="indeterminate",
                to_state="failed",
                evidence="e1",
                reconciled_by="k",
                reconciled_at=same_instant,
            )
        )
        s.flush()
        s.add(
            ContentExportReconciliation(
                attempt_id=attempt_id,
                from_state="failed",
                to_state="succeeded",
                evidence="e2",
                reconciled_by="k",
                reconciled_at=same_instant,
            )
        )
        s.commit()
        assert effective_state(s, attempt_id) == "succeeded"


def test_a_stale_from_state_is_rejected(factory):
    attempt_id = _settled(factory)
    with factory() as s:
        append_reconciliation(
            s,
            attempt_id=attempt_id,
            from_state="indeterminate",
            to_state="failed",
            evidence="e",
            actor="k",
        )
        s.commit()
    with factory() as s:
        with pytest.raises(ValueError, match="not the current effective state"):
            # The effective state is now "failed"; this claims something untrue.
            append_reconciliation(
                s,
                attempt_id=attempt_id,
                from_state="indeterminate",
                to_state="succeeded",
                evidence="e",
                actor="k",
            )


@pytest.mark.parametrize(
    "kwargs,match",
    [
        ({"to_state": "pending"}, "cannot reconcile"),
        ({"to_state": "abandoned_indeterminate"}, "cannot reconcile"),
        ({"evidence": ""}, "evidence must be"),
        ({"evidence": "x" * (svc.MAX_EVIDENCE + 1)}, "evidence must be"),
        ({"evidence": 5}, "evidence must be"),
    ],
)
def test_a_defective_correction_is_refused(factory, kwargs, match):
    attempt_id = _settled(factory)
    base = dict(
        attempt_id=attempt_id,
        from_state="indeterminate",
        to_state="succeeded",
        evidence="receiver log",
        actor="k",
    )
    base.update(kwargs)
    with factory() as s:
        with pytest.raises(ValueError, match=match):
            append_reconciliation(s, **base)


def test_an_unknown_attempt_is_refused(factory):
    with factory() as s:
        with pytest.raises(ValueError, match="no such export attempt"):
            append_reconciliation(
                s,
                attempt_id="nope",
                from_state="indeterminate",
                to_state="failed",
                evidence="e",
                actor="k",
            )


def test_a_succeeded_attempt_can_still_be_corrected(factory):
    """`succeeded` is an upper bound on delivery, not proof of receipt: the
    interval between the commit and the network is unavoidable."""
    attempt_id = _settled(factory, state="succeeded")
    with factory() as s:
        append_reconciliation(
            s,
            attempt_id=attempt_id,
            from_state="succeeded",
            to_state="failed",
            evidence="receiver has no record of it",
            actor="k",
        )
        s.commit()
        assert effective_state(s, attempt_id) == "failed"
        assert s.get(ContentExportAttempt, attempt_id).state == "succeeded"
