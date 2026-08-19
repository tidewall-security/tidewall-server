"""Correcting what an export attempt actually did.

`indeterminate` and `abandoned_indeterminate` are honest states -- a timeout may
mean the receiver accepted it, and a process that died mid-flight cannot know --
but without a way to record external evidence they are permanently unresolvable,
and a table nothing writes is worse than no table.

The attempt's own state is the original OBSERVATION and is never edited. A
correction is appended, and the effective state is the reconciliation with the
highest id.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import sqlalchemy as sa
from fastapi import APIRouter, Depends, HTTPException, Request

from app.auth.dependencies import require_role
from app.db.models import ContentExportAttempt, ContentExportReconciliation
from app.services.content_export import MAX_EVIDENCE

router = APIRouter()

#: An operator may assert what happened. They may not assert that nothing has
#: happened yet, which is what `pending` means.
ALLOWED_TO = frozenset({"succeeded", "failed", "indeterminate"})


def effective_state(session: Any, attempt_id: str) -> str:
    """The current understanding: the latest correction, or the observation.

    Latest by monotonic integer id, not by timestamp: two records written in the
    same clock tick would otherwise be unordered, and the answer would depend on
    which one a query happened to return first.
    """
    latest = (
        session.query(ContentExportReconciliation)
        .filter_by(attempt_id=attempt_id)
        .order_by(ContentExportReconciliation.id.desc())
        .first()
    )
    if latest is not None:
        return str(latest.to_state)
    attempt = session.get(ContentExportAttempt, attempt_id)
    if attempt is None:
        raise ValueError("no such export attempt")
    return str(attempt.state)


def append_reconciliation(
    session: Any, *, attempt_id: str, from_state: str, to_state: str, evidence: str, actor: str | None
) -> None:
    """Append a correction, as a compare-and-set against the effective state.

    "Inside one transaction" is not enough to make it one: under SQLite two
    connections can both read the current effective state in deferred read
    transactions and both proceed, and one records a `from_state` that was never
    true. ``BEGIN IMMEDIATE`` takes the write lock before the read.
    """
    if to_state not in ALLOWED_TO:
        raise ValueError(f"cannot reconcile to {to_state!r}")
    if not isinstance(evidence, str) or not evidence or len(evidence) > MAX_EVIDENCE:
        raise ValueError(f"evidence must be 1 to {MAX_EVIDENCE} characters")

    session.execute(sa.text("PRAGMA busy_timeout = 5000"))
    session.execute(sa.text("BEGIN IMMEDIATE"))
    current = effective_state(session, attempt_id)
    if current != from_state:
        raise ValueError(f"from_state {from_state!r} is not the current effective state {current!r}")
    session.add(
        ContentExportReconciliation(
            attempt_id=attempt_id,
            from_state=from_state,
            to_state=to_state,
            evidence=evidence,
            reconciled_by=actor,
            reconciled_at=datetime.now(UTC).replace(tzinfo=None),
        )
    )


@router.post("/v1/content-exports/{attempt_id}/reconcile", dependencies=[Depends(require_role("admin"))])
async def reconcile(attempt_id: str, request: Request) -> dict:
    """Record what an export attempt actually did, on external evidence."""
    try:
        body = await request.json()
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Body must be JSON") from exc
    if not isinstance(body, dict) or set(body) != {"from_state", "to_state", "evidence"}:
        raise HTTPException(status_code=400, detail="Expected exactly from_state, to_state and evidence")

    session = request.app.state.session_factory()
    try:
        append_reconciliation(
            session,
            attempt_id=attempt_id,
            from_state=body["from_state"],
            to_state=body["to_state"],
            evidence=body["evidence"],
            actor=getattr(request.state, "api_key_id", None),
        )
        session.commit()
        return {"attempt_id": attempt_id, "effective_state": body["to_state"]}
    except ValueError as exc:
        session.rollback()
        # A stale from_state or an unknown attempt is the caller disagreeing
        # with the record, not a fault.
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    finally:
        session.close()
