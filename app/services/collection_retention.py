"""Reclaim expired collector evidence, leaving enrollment replay protection intact."""

from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import AgentObservation, AgentSession, CollectorOutcome, CollectorProgress, NativePromptObservation


def purge_collection(session: Session, now: datetime) -> int:
    """Delete details and empty sessions atomically, returning rows deleted or cleared."""
    removed = (
        session.query(CollectorOutcome).filter(CollectorOutcome.expires_at <= now).delete(synchronize_session=False)
    )
    removed += (
        session.query(AgentObservation).filter(AgentObservation.expires_at <= now).delete(synchronize_session=False)
    )
    has_events = (
        select(AgentObservation.event_id).where(AgentObservation.session_id == AgentSession.session_id).exists()
    )
    has_native = (
        select(NativePromptObservation.event_id)
        .where(NativePromptObservation.session_id == AgentSession.session_id)
        .exists()
    )
    removed += session.query(AgentSession).filter(~has_events, ~has_native).delete(synchronize_session=False)
    removed += (
        session.query(CollectorProgress)
        .filter(CollectorProgress.heartbeat_expires_at <= now)
        .update(
            {
                CollectorProgress.heartbeat_json: None,
                CollectorProgress.heartbeat_received_at: None,
                CollectorProgress.heartbeat_expires_at: None,
            },
            synchronize_session=False,
        )
    )
    session.commit()
    return removed
