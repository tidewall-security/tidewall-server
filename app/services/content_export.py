"""The durable record of one content export attempt.

``pending`` is committed BEFORE any I/O, so a crash is visible as pending rather
than misrecorded. An ``exported``-then-``export_failed`` pair would leave a
misleading success row and a correlation that only works if the process survives
to write the second one -- which is exactly the case that matters.

Nothing here retries. Retrying an export whose delivery is unknown is how one
disclosure becomes two.
"""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from datetime import UTC, datetime
from typing import Any

import sqlalchemy as sa
from sqlalchemy.exc import IntegrityError

from app.db.models import ContentExportAttempt, ContentExportNote
from app.services.safe_logging import report

logger = logging.getLogger(__name__)

TERMINAL = ("succeeded", "failed", "indeterminate", "abandoned_indeterminate")
NOTE_KINDS = ("settlement_lost", "body_read_failed", "settlement_commit_failed", "cleanup_failed")

#: Bounds the evidence an operator may attach and the detail a note may carry.
MAX_EVIDENCE = 500

#: Contention on the reservation and the settlement waits briefly rather than
#: failing immediately or hanging. It bounds a LOCK WAIT and nothing else --
#: connection acquisition, fsync and a stalled disk are all outside it -- which
#: is why the abandonment protocol does not depend on any wall-clock bound.
BUSY_TIMEOUT_MS = 5000


def digest_key(raw: str) -> str:
    """Store a digest, never the key.

    A caller-supplied correlator can be credential-like, and this row is
    readable by anyone who can read the database.
    """
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def fingerprint_for(*, policy_id: str, interaction_id: int, view: str, target_id: str) -> str:
    """Everything that fixes the bytes or the authority.

    Target *configuration* is deliberately absent: replay means the original
    attempt, and rebuilding a result under current configuration would report
    something that never happened.
    """
    payload = json.dumps(
        {
            "policy_id": policy_id,
            "interaction_id": interaction_id,
            "view": view,
            "target_id": target_id,
            "schema": "tidewall.content_export.v1",
        },
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def reserve(session_factory: Any, *, attempt: dict[str, Any]) -> tuple[str, bool]:
    """Write the pending row, or discover that this key already reserved one.

    Returns ``(attempt_id, is_replay)``.

    A check-then-insert lets two concurrent requests with the same key both pass
    the check and disclose twice, so this is a unique-constrained insert in its
    own ``BEGIN IMMEDIATE`` transaction. The write lock is taken up front: a
    deferred read transaction upgrading to a write can raise ``SQLITE_BUSY``
    instead of the ``IntegrityError`` this protocol expects.
    """
    attempt_id = uuid.uuid4().hex
    session = session_factory()
    try:
        session.execute(sa.text(f"PRAGMA busy_timeout = {BUSY_TIMEOUT_MS}"))
        session.execute(sa.text("BEGIN IMMEDIATE"))
        session.add(
            ContentExportAttempt(
                attempt_id=attempt_id,
                state="pending",
                created_at=datetime.now(UTC).replace(tzinfo=None),
                **attempt,
            )
        )
        session.commit()
        return attempt_id, False
    except IntegrityError:
        # Roll back FIRST. After an integrity error the session is failed and
        # cannot read anything, and the winner may not be visible until a new
        # transaction begins.
        session.rollback()
        digest = attempt.get("idempotency_key_digest")
        existing = (
            session.query(ContentExportAttempt)
            .filter_by(api_key_id=attempt.get("api_key_id"), idempotency_key_digest=digest)
            .one_or_none()
        )
        if existing is None:
            # Neither reserved nor found its predecessor. Sending now would be a
            # guess about whether another request is already doing it.
            raise
        return existing.attempt_id, True
    finally:
        session.close()


def settle(
    session_factory: Any,
    *,
    attempt_id: str,
    state: str,
    transport_status: int | None,
    peer: str | None,
) -> bool:
    """Move pending to a terminal state. Returns whether *this* call did it.

    A compare-and-set, so a row already settled by something else is not
    overwritten; the caller then answers 502 with the stored state rather than
    202, because the terminal outcome it observed was never committed.

    No timeout is wrapped around this. ``busy_timeout`` bounds a lock wait, and
    cancelling an awaited thread detaches it rather than stopping it -- so an
    outer deadline would let the caller report "expired, row still pending"
    while the thread went on to commit the terminal state.
    """
    session = session_factory()
    try:
        session.execute(sa.text(f"PRAGMA busy_timeout = {BUSY_TIMEOUT_MS}"))
        result = session.execute(
            sa.update(ContentExportAttempt)
            .where(
                ContentExportAttempt.attempt_id == attempt_id,
                ContentExportAttempt.state == "pending",
            )
            .values(
                state=state,
                transport_status=transport_status,
                destination_addr=peer,
                settled_at=datetime.now(UTC).replace(tzinfo=None),
            )
        )
        session.commit()
        return bool(result.rowcount == 1)
    finally:
        session.close()


def write_note(session_factory: Any, *, attempt_id: str, kind: str, detail: str) -> None:
    """Record what happened on a path that does not own the attempt row.

    Its own session in its own short transaction. That alone is not enough: the
    caller must have rolled back and closed the failed transaction first, or on
    SQLite it can still hold the writer lock and this fails for the same reason
    the settlement did.

    Best effort. A note is evidence ABOUT an export, not a precondition of one,
    so a failure degrades to a log and never changes the response -- deliberately
    the opposite direction from the attempt row.
    """
    session = None
    try:
        session = session_factory()
        session.add(
            ContentExportNote(
                attempt_id=attempt_id,
                kind=kind,
                detail=detail[:MAX_EVIDENCE],
                created_at=datetime.now(UTC).replace(tzinfo=None),
            )
        )
        session.commit()
    except Exception as exc:
        report(logger, "error", f"content export note could not be written: attempt={attempt_id} kind={kind}", exc)
    finally:
        if session is not None:
            try:
                session.close()
            except Exception:
                pass


def abandon_foreign_pending(session: Any, *, boot_id: str) -> int:
    """Terminate pending rows this process cannot own. Returns how many.

    A row whose ``boot_id`` is not ours belongs to a process that no longer
    exists -- which the database lock makes true -- so nothing can be in flight
    for it. A row from the CURRENT boot is never touched, however old: age has
    no role in this protocol, and every version of this design that used a time
    threshold rested on a wall-clock bound that does not exist.

    Never sends anything.
    """
    result = session.execute(
        sa.update(ContentExportAttempt)
        .where(
            ContentExportAttempt.state == "pending",
            ContentExportAttempt.boot_id != boot_id,
        )
        .values(
            state="abandoned_indeterminate",
            settled_at=datetime.now(UTC).replace(tzinfo=None),
        )
    )
    return int(result.rowcount or 0)


def pending_health(session: Any) -> tuple[int, float | None]:
    """How many attempts are pending, and the age of the oldest, in seconds.

    Derived from the rows rather than from a counter incremented after a commit:
    that counter is lost on exactly the crash most likely to have created the
    row, and the scheduler that would clear these is best-effort by design.
    """
    try:
        rows = session.query(ContentExportAttempt.created_at).filter_by(state="pending").all()
        if not rows:
            return 0, None
        now = datetime.now(UTC).replace(tzinfo=None)
        return len(rows), max((now - row[0]).total_seconds() for row in rows)
    finally:
        session.close()
