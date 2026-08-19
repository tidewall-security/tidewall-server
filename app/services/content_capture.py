"""Optional raw content capture and its retention (P0-6, step 5).

Capture and retention land together deliberately. A configuration flag that
can say "capture is on" before anything honours it is a lie the operator has
no way to detect — they would believe prompts were being retained for an
investigation that will find nothing, or believe they were not being retained
when they were.

Three properties this module is responsible for:

**Off by default.** A fresh policy retains nothing. The insecure state is never
the one you get by not reading the documentation.

**Atomic with the event.** Content is written in the same transaction as the
interaction, so there is never a content row without its event, and never an
event claiming `content_available` when the write failed.

**Bounded by time only.** Retention is configurable with no default expiry and
**no size cap** — the product owner chose that explicitly, twice, against the
recommendation and against every comparable product researched. So an operator
who enables capture gets unbounded growth of the most sensitive table. That is
deliberate; the byte accounting below exists so it is at least visible.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy.orm import Session

from app.db.models import Interaction, InteractionContent
from app.services.audit_evidence import MAX_MATCHES_JSON_BYTES
from app.services.safe_logging import report

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class PreparedContent:
    """Content that has already been serialised successfully.

    Built before the event commits, so a payload that cannot be stored is
    discovered while the audit record can still be written without it.
    """

    input_json: Any
    output_json: Any
    matches_json: Any
    byte_size: int
    expires_at: datetime | None


def build_content(
    *,
    input_messages: Any,
    output_messages: Any,
    matches: dict[str, Any] | None,
    tools: Any = None,
    retention_days: int | None,
) -> PreparedContent:
    """Assemble and serialise the payload, raising if it cannot be stored.

    Serialising here rather than at commit is the point: the canonical bytes
    are produced once, used for the size accounting, and prove the value will
    survive persistence — so a bad payload fails before it can take the event
    down with it.
    """
    # Tools travel with the input: they are scanned, so a captured tool-listing
    # event without them records less than was evaluated. The wrapper is used
    # whenever tools were supplied at all, including an empty list, so the
    # stored shape does not depend on whether any happened to be present.
    payload_in: Any = {"messages": input_messages, "tools": tools} if tools is not None else input_messages

    # Measured per column, exactly as each is stored. The previous version
    # measured one synthetic wrapper with compact separators, which is not what
    # SQLAlchemy writes into three separate JSON columns — so the gauge counted
    # keys and punctuation that do not exist and missed the ones that do.
    #
    # json.dumps with default arguments is SQLAlchemy's default JSON
    # serializer, and it is strict: an unsupported value raises here, before
    # the event commits, rather than at persistence.
    encoded = b"".join(
        json.dumps(value).encode("utf-8") for value in (payload_in, output_messages, matches) if value is not None
    )

    # The match bound, enforced on what is actually persisted. The collector
    # checks its own compact canonical form, but that is not what goes into the
    # JSON column — so a payload under the limit there could exceed it here.
    if matches is not None:
        stored_matches = len(json.dumps(matches).encode("utf-8"))
        if stored_matches > MAX_MATCHES_JSON_BYTES:
            raise ValueError(f"stored matches would be {stored_matches} bytes, over the {MAX_MATCHES_JSON_BYTES} limit")

    expires_at = datetime.now(UTC) + timedelta(days=retention_days) if retention_days else None
    return PreparedContent(
        input_json=payload_in,
        output_json=output_messages,
        matches_json=matches,
        byte_size=len(encoded),
        expires_at=expires_at,
    )


def capture_content(session: Session, *, interaction: Interaction, prepared: PreparedContent) -> None:
    """Add the already-serialised content to the caller's transaction.

    Uses the caller's session because the content and the event have to commit
    together or not at all.
    """
    # Duplicated from the parent rather than joined. The check the read path
    # makes is that the credential's policy, the interaction's policy and the
    # content row's *own* policy all agree; a join proves the first two and
    # assumes the third. The parent has already been flushed, so this is a
    # validated non-null value, not a hopeful one.
    session.add(
        InteractionContent(
            interaction_id=interaction.id,
            policy_id=interaction.policy_id,
            input_json=prepared.input_json,
            output_json=prepared.output_json,
            matches_json=prepared.matches_json,
            byte_size=prepared.byte_size,
            captured_at=datetime.now(UTC),
            expires_at=prepared.expires_at,
        )
    )


def purge_expired(session: Session, *, now: datetime | None = None) -> int:
    """Delete content past its expiry. Returns how many rows went.

    Idempotent and safe to run concurrently: it deletes by predicate rather
    than by a list read earlier, so two callers racing simply both find less to
    do.
    """
    moment = now or datetime.now(UTC)
    deleted = (
        session.query(InteractionContent)
        .filter(InteractionContent.expires_at.isnot(None), InteractionContent.expires_at <= moment)
        .delete(synchronize_session=False)
    )
    if deleted:
        # The event survives; only its content goes. content_available is
        # corrected so the UI stops offering something that is no longer there.
        session.query(Interaction).filter(
            Interaction.content_available.is_(True),
            ~Interaction.id.in_(session.query(InteractionContent.interaction_id)),
        ).update({"content_available": False}, synchronize_session=False)
        session.commit()
        report(logger, "info", f"Purged {deleted} expired content row(s)")
    return deleted


def is_expired(content: InteractionContent, *, now: datetime | None = None) -> bool:
    """Whether this content is past its expiry regardless of whether the purge
    has run.

    The purge is scheduled, but it is best effort: it runs on an interval, and
    startup continues if the scheduler cannot start at all. So a read must not
    serve content that should already be gone merely because nothing has
    deleted it yet. Expiry is a promise about what will be disclosed, not about
    when a row is removed.

    (This said "There is no scheduler" until step 5 added one, and stayed wrong
    afterwards. The conclusion was right for the wrong reason: the guarantee
    does not come from the purge's promptness either way.)
    """
    if content.expires_at is None:
        return False
    expiry = content.expires_at
    if expiry.tzinfo is None:
        # SQLite returns naive datetimes; they were written as UTC.
        expiry = expiry.replace(tzinfo=UTC)
    moment = now or datetime.now(UTC)
    if moment.tzinfo is None:
        # Normalise the caller's clock too. Comparing one aware and one naive
        # datetime raises, so a caller passing a naive `now` turned an expiry
        # check into a TypeError — which fails the read rather than the
        # disclosure decision.
        moment = moment.replace(tzinfo=UTC)
    return expiry <= moment


def usage(session: Session) -> dict[str, Any]:
    """Byte usage and age range, for an operator who chose unbounded retention.

    Not a limit — a gauge. With no size cap, the least this can do is let
    someone see what the choice is costing.
    """
    from sqlalchemy import func

    row = session.query(
        func.count(InteractionContent.id),
        func.coalesce(func.sum(InteractionContent.byte_size), 0),
        func.min(InteractionContent.captured_at),
        func.max(InteractionContent.captured_at),
    ).one()
    return {
        "rows": row[0],
        "bytes": int(row[1] or 0),
        "oldest_captured_at": str(row[2]) if row[2] else None,
        "newest_captured_at": str(row[3]) if row[3] else None,
    }
