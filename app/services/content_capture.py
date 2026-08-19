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
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy.orm import Session

from app.db.models import Interaction, InteractionContent, Policy

logger = logging.getLogger(__name__)


def _byte_size(*payloads: Any) -> int:
    """What this row costs, so unbounded growth is at least measurable."""
    total = 0
    for payload in payloads:
        if payload is None:
            continue
        total += len(json.dumps(payload, default=str, ensure_ascii=False).encode("utf-8"))
    return total


def capture_content(
    session: Session,
    *,
    interaction: Interaction,
    policy: Policy,
    input_messages: Any,
    output_messages: Any,
    matches: dict[str, Any] | None,
) -> bool:
    """Write raw content for this event, if the policy asks for it.

    Returns whether content was stored, which the caller records on the event
    so a reader can tell "not retained" from "retained but withheld from you".

    Uses the caller's session rather than opening its own: the content and the
    event have to commit together or not at all.
    """
    if not policy.raw_content_enabled:
        return False

    expires_at = None
    if policy.raw_content_retention_days:
        expires_at = datetime.now(UTC) + timedelta(days=policy.raw_content_retention_days)

    session.add(
        InteractionContent(
            interaction_id=interaction.id,
            input_json=input_messages,
            output_json=output_messages,
            matches_json=matches,
            byte_size=_byte_size(input_messages, output_messages, matches),
            captured_at=datetime.now(UTC),
            expires_at=expires_at,
        )
    )
    return True


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
        logger.info("Purged %d expired content row(s)", deleted)
    return deleted


def is_expired(content: InteractionContent, *, now: datetime | None = None) -> bool:
    """Whether this content is past its expiry regardless of whether the purge
    has run.

    There is no scheduler, so a read must not serve content that should already
    be gone just because nothing has deleted it yet. Expiry is a promise about
    what will be disclosed, not about when a row is removed.
    """
    if content.expires_at is None:
        return False
    expiry = content.expires_at
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=UTC)
    return expiry <= (now or datetime.now(UTC))


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
