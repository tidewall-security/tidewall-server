"""Commit metadata-only collector reports under live device authority."""

import hashlib
import json
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta

from fastapi import HTTPException
from sqlalchemy import delete, select, text, update
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.agent_events import (
    Batch,
    Heartbeat,
    HeartbeatAck,
    Observation,
    Receipt,
    Rejected,
    Row,
    Stored,
    canonical_observation_bytes,
)
from app.db.models import AgentObservation, AgentSession, CollectorOutcome, CollectorProgress, Device
from app.services.collector_identity import CollectorPrincipal, authorize_collector
from app.utils import as_utc

DETAIL_LIFETIME = timedelta(days=30)


@contextmanager
def _authorized_write(
    session: Session,
    principal: CollectorPrincipal,
    enrollment_id: str,
    now: Callable[[], datetime],
) -> Iterator[tuple[CollectorProgress, datetime]]:
    def check_binding(at: datetime) -> None:
        if authorize_collector(session, principal.token_hash, enrollment_id, at) != principal:
            raise HTTPException(status_code=403, detail="Collector binding changed")

    try:
        with session.begin():
            session.execute(text("BEGIN IMMEDIATE"))
            received = as_utc(now()).astimezone(UTC)
            check_binding(received)
            progress = session.get(CollectorProgress, principal.device_id)
            if progress is None:
                progress = CollectorProgress(
                    device_id=principal.device_id,
                    policy_id=principal.policy_id,
                    high_water=0,
                    heartbeat_revision=0,
                    totals={},
                )
                session.add(progress)
            elif progress.policy_id != principal.policy_id:
                # A rebound enrollment cannot inherit the old scope's receipts or health.
                raise HTTPException(status_code=403, detail="Collector binding changed")
            yield progress, received
            session.flush()
            check_binding(now())
    except SQLAlchemyError:
        pass
    else:
        return
    # Never disclose a statement, its parameters, or an uncommitted receipt.
    raise HTTPException(status_code=503, detail="Collector storage unavailable", headers={"Retry-After": "1"})


def _retire_session(session: Session, session_id: str, received: datetime) -> bool:
    """Forget a fully expired correlation while the writer holds BEGIN IMMEDIATE."""
    events = AgentObservation.session_id == session_id
    live = select(AgentObservation.event_id).where(events, AgentObservation.expires_at > received).exists()
    if session.scalar(select(live)):
        return False
    session.execute(delete(AgentObservation).where(events))
    session.execute(delete(AgentSession).where(AgentSession.session_id == session_id))
    return True


def _session_id(session: Session, progress: CollectorProgress, obs: Observation, received: datetime) -> str | None:
    if obs.native_session_token is None:
        return None
    scope = dict(
        device_id=progress.device_id,
        policy_id=progress.policy_id,
        agent=obs.agent,
        native_session_token=obs.native_session_token,
    )
    stored = session.scalar(select(AgentSession).filter_by(**scope))
    if stored is not None and as_utc(stored.received_at) + DETAIL_LIFETIME <= received:
        if _retire_session(session, stored.session_id, received):
            stored = None
    if stored is None:
        stored = AgentSession(**scope, received_at=received)
        session.add(stored)
        session.flush()
    return stored.session_id


def _apply_source(
    session: Session,
    progress: CollectorProgress,
    row: Row,
    canonical: bytes,
    digest: str,
    received: datetime,
) -> tuple[Stored | Rejected, datetime]:
    obs = row.observation
    expires = received + DETAIL_LIFETIME
    source = dict(
        device_id=progress.device_id,
        policy_id=progress.policy_id,
        agent=obs.agent,
        channel=obs.source.channel,
        source_key=obs.source_key,
    )
    event = session.scalar(select(AgentObservation).filter_by(**source))
    if event is not None and as_utc(event.expires_at) <= received:
        # The deduplication key becomes reusable at the retention boundary,
        # including when the periodic deletion has not run yet.
        old_session_id = event.session_id
        session.delete(event)
        session.flush()
        if old_session_id is not None:
            _retire_session(session, old_session_id, received)
        event = None
    if event is None:
        event = AgentObservation(
            **source,
            session_id=_session_id(session, progress, obs, received),
            observation_json=canonical.decode("ascii"),
            digest=digest,
            received_at=received,
            expires_at=expires,
        )
        session.add(event)
        session.flush()
        return Stored(ordinal=row.ordinal, digest=digest, outcome="accepted", event_id=event.event_id), expires
    if event.digest == digest:
        return Stored(
            ordinal=row.ordinal, digest=digest, outcome="duplicate", event_id=event.event_id
        ), event.expires_at
    return Rejected(ordinal=row.ordinal, digest=digest, outcome="rejected", reason="identity_conflict"), expires


def _record_row(
    session: Session,
    progress: CollectorProgress,
    row: Row,
    received: datetime,
) -> Stored | Rejected:
    canonical = canonical_observation_bytes(row.observation)
    digest = hashlib.sha256(canonical).hexdigest()
    identity = dict(device_id=progress.device_id, ordinal=row.ordinal, digest=digest)
    previous = session.get(CollectorOutcome, identity)
    if previous is not None:
        if as_utc(previous.expires_at) > received:
            if previous.event_id is not None:
                return Stored(ordinal=row.ordinal, digest=digest, outcome="duplicate", event_id=previous.event_id)
            return Rejected.model_validate(
                dict(ordinal=row.ordinal, digest=digest, outcome="rejected", reason=previous.reason)
            )
        # The expired row remains eligible for purge. Its ordinal is already
        # retired by the enrollment's durable high-water mark.
        return Rejected(ordinal=row.ordinal, digest=digest, outcome="rejected", reason="retired_ordinal")

    occupied = (
        select(CollectorOutcome)
        .filter_by(device_id=progress.device_id, ordinal=row.ordinal)
        .where(CollectorOutcome.event_id.is_not(None), CollectorOutcome.expires_at > received)
        .exists()
    )
    expires = received + DETAIL_LIFETIME
    disposition: Stored | Rejected
    if session.scalar(select(occupied)):
        disposition = Rejected(ordinal=row.ordinal, digest=digest, outcome="rejected", reason="identity_conflict")
    elif row.ordinal <= progress.high_water:
        disposition = Rejected(ordinal=row.ordinal, digest=digest, outcome="rejected", reason="retired_ordinal")
    else:
        disposition, expires = _apply_source(session, progress, row, canonical, digest, received)

    session.add(
        CollectorOutcome(
            **identity,
            outcome=disposition.outcome,
            event_id=disposition.event_id if isinstance(disposition, Stored) else None,
            reason=disposition.reason if isinstance(disposition, Rejected) else None,
            received_at=received,
            expires_at=expires,
        )
    )
    progress.high_water = max(progress.high_water, row.ordinal)
    return disposition


def ingest(session: Session, principal: CollectorPrincipal, batch: Batch, now: Callable[[], datetime]) -> Receipt:
    with _authorized_write(session, principal, batch.enrollment_id, now) as (progress, received):
        receipt = Receipt(
            version=1,
            enrollment_id=batch.enrollment_id,
            batch_id=batch.batch_id,
            results=[_record_row(session, progress, row, received) for row in batch.rows],
        )
    return receipt


def heartbeat(
    session: Session,
    principal: CollectorPrincipal,
    report: Heartbeat,
    now: Callable[[], datetime],
) -> HeartbeatAck:
    with _authorized_write(session, principal, report.enrollment_id, now) as (progress, received):
        snapshot = json.dumps(report.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(snapshot.encode("ascii")).hexdigest()
        totals = report.totals.model_dump()
        if (
            report.revision < progress.heartbeat_revision
            or (report.revision == progress.heartbeat_revision and digest != progress.heartbeat_digest)
            or any(totals[key] < old for key, old in progress.totals.items())
        ):
            raise HTTPException(status_code=409, detail="Conflicting collector heartbeat")
        if report.revision > progress.heartbeat_revision:
            progress.heartbeat_revision = report.revision
            progress.heartbeat_digest = digest
            progress.totals = totals
            progress.heartbeat_json = snapshot
            progress.heartbeat_received_at = received
            progress.heartbeat_expires_at = received + DETAIL_LIFETIME
            session.execute(update(Device).where(Device.id == principal.device_id).values(last_seen=received))
        ack = HeartbeatAck(
            version=1,
            enrollment_id=report.enrollment_id,
            revision=report.revision,
            capture="metadata_only",
            retain_content=False,
        )
    return ack
