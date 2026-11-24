"""Policy-scoped views of the collector's retained metadata."""

import base64
import binascii
import hashlib
import hmac
import json
import secrets
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import TypeAdapter, ValidationError
from sqlalchemy import and_, case, func, select, text, tuple_
from sqlalchemy.orm import Session, load_only

from app.auth.dependencies import require_role
from app.db.models import (
    AgentObservation,
    AgentSession,
    CollectorProgress,
    NativePromptAssessment,
    NativePromptDecision,
    NativePromptObservation,
)
from app.native_prompt_views import NativePromptPage, attach_report_summaries, project_native_observation
from app.routes.logs import _read_scope
from app.utils import as_utc

router = APIRouter(dependencies=[Depends(require_role("viewer"))])
Limit = Annotated[int, Query(ge=1, le=100)]
# A restart invalidates pending dashboard pages. No secret reaches the browser.
_CURSOR_KEY = secrets.token_bytes(32)
_PAGE_LIMIT = TypeAdapter(Limit)


def _scope(request: Request) -> str | None:
    allowed, policy = _read_scope(request)
    if not allowed:
        raise HTTPException(403, "A policy binding is required")
    return policy


def _scoped(query, model, policy):
    return query.where(model.policy_id == policy) if policy is not None else query


def _stamp(at: datetime) -> str:
    return as_utc(at).astimezone(UTC).isoformat().replace("+00:00", "Z")


def _signature(binding: bytes, position: bytes) -> bytes:
    return hmac.digest(_CURSOR_KEY, binding + b"\x00" + position, hashlib.sha256)


def _page(
    db: Session,
    query,
    time_column,
    id_column,
    project: Callable,
    *,
    scope: str | None,
    query_id: str,
    limit: int,
    cursor: str | None,
) -> dict:
    """Each query supplies its authorized rows, receipt sort key, opaque ID and projection."""
    binding = json.dumps([scope, query_id], separators=(",", ":")).encode()
    if cursor is not None:
        try:
            if len(cursor) > 512:
                raise ValueError
            raw = base64.b64decode(cursor, altchars=b"-_", validate=True)
            mac, position = raw[:32], raw[32:]
            if not hmac.compare_digest(mac, _signature(binding, position)):
                raise ValueError
            timestamp, row_id = json.loads(position)
            query = query.where(tuple_(time_column, id_column) < (datetime.fromisoformat(timestamp), row_id))
        except (ValueError, binascii.Error, UnicodeError):
            raise HTTPException(400, "Invalid page cursor") from None
    rows = db.execute(
        query.add_columns(time_column, id_column).order_by(time_column.desc(), id_column.desc()).limit(limit + 1)
    ).all()
    next_cursor = None
    if len(rows) > limit:
        at, row_id = rows[limit - 1][-2:]
        position = json.dumps([at.isoformat(), row_id], separators=(",", ":")).encode()
        next_cursor = base64.urlsafe_b64encode(_signature(binding, position) + position).decode()
    return {"items": [project(*row[:-2]) for row in rows[:limit]], "next_cursor": next_cursor}


def _sessions(policy: str | None, now: datetime):
    def live_count(model):
        return (
            select(func.count())
            .select_from(model)
            .where(model.session_id == AgentSession.session_id, model.expires_at > now)
            .correlate(AgentSession)
            .scalar_subquery()
        )

    count = live_count(AgentObservation) + live_count(NativePromptObservation)
    return _scoped(select(AgentSession, count).where(count > 0), AgentSession, policy)


def _require_visible_session(db: Session, session_id: str, policy: str | None, now: datetime) -> None:
    # Authorize a retained parent before interpreting cursors or reading either detail family.
    def has_live(model):
        return (
            select(model.event_id).where(model.session_id == AgentSession.session_id, model.expires_at > now).exists()
        )

    parent = _scoped(select(AgentSession.session_id), AgentSession, policy).where(
        AgentSession.session_id == session_id, has_live(AgentObservation) | has_live(NativePromptObservation)
    )
    if db.scalar(parent) is None:
        raise HTTPException(404, "Session not found")


def _session(row: AgentSession, count: int) -> dict:
    return dict(
        session_id=row.session_id,
        policy_id=row.policy_id,
        device_id=row.device_id,
        agent=row.agent,
        received_at=_stamp(row.received_at),
        observation_count=count,
    )


@router.get("/v1/agent-sessions")
def sessions(request: Request, limit: Limit = 50, cursor: str | None = None, policy=Depends(_scope)):
    with request.app.state.session_factory() as db:
        return _page(
            db,
            _sessions(policy, datetime.now(UTC)),
            AgentSession.received_at,
            AgentSession.session_id,
            _session,
            scope=policy,
            query_id="sessions",
            limit=limit,
            cursor=cursor,
        )


def _observation(row: AgentObservation) -> dict:
    obs = json.loads(row.observation_json)
    source = obs["source"]
    return dict(
        event_id=row.event_id,
        session_id=row.session_id,
        device_id=row.device_id,
        policy_id=row.policy_id,
        agent=row.agent,
        agent_version="unknown",
        fixture_profile=obs["fixture_profile"],
        adapter_version=obs["adapter_version"],
        upstream_sha=obs["upstream_sha"],
        kind=obs["kind"],
        channel=row.channel,
        received_at=_stamp(row.received_at),
        source_at=obs.get("source_at"),
        availability=obs["availability"],
        gaps=obs["gaps"],
        assessment_status="not_assessed",
        tool_name=obs.get("tool_name"),
        provenance={
            key: source[key]
            for key in ("record_origin", "parser_evidence_version", "part", "byte_position", "native_event")
            if key in source
        },
    )


def _observations(request: Request, policy: str | None, session_id: str | None, limit: int, cursor: str | None):
    now = datetime.now(UTC)
    with request.app.state.session_factory() as db:
        if session_id is not None:
            # Use one SQLite snapshot for the existence check and the page.
            db.execute(text("BEGIN"))
            _require_visible_session(db, session_id, policy, now)
        query = _scoped(select(AgentObservation), AgentObservation, policy).where(
            AgentObservation.session_id == session_id, AgentObservation.expires_at > now
        )
        return _page(
            db,
            query,
            AgentObservation.received_at,
            AgentObservation.event_id,
            _observation,
            scope=policy,
            query_id=f"observations/{session_id}",
            limit=limit,
            cursor=cursor,
        )


@router.get("/v1/agent-sessions/{session_id}/observations")
def session_observations(
    request: Request, session_id: str, limit: Limit = 50, cursor: str | None = None, policy=Depends(_scope)
):
    return _observations(request, policy, session_id, limit, cursor)


@router.get("/v1/agent-sessions/{session_id}/native-prompts", response_model=NativePromptPage)
def session_native_prompts(
    request: Request,
    session_id: str,
    limit: Annotated[str, Query(description="Page size from 1 to 100")] = "50",
    cursor: str | None = None,
    policy=Depends(_scope),
):
    observation, decision, assessment = NativePromptObservation, NativePromptDecision, NativePromptAssessment
    with request.app.state.session_factory() as db:
        db.execute(text("BEGIN"))
        now = datetime.now(UTC)
        _require_visible_session(db, session_id, policy, now)
        # Reject pagination errors only after the caller can see this session.
        try:
            page_size = _PAGE_LIMIT.validate_python(limit)
        except ValidationError:
            raise HTTPException(422, "Page size must be an integer from 1 to 100") from None
        query = (
            _scoped(select(observation, decision, assessment), observation, policy)
            .where(observation.session_id == session_id, observation.expires_at > now)
            .outerjoin(decision, and_(decision.event_id == observation.event_id, decision.expires_at > now))
            .outerjoin(assessment, assessment.decision_id == decision.decision_id)
            .options(
                load_only(
                    observation.event_id,
                    observation.occurrence_id,
                    observation.session_id,
                    observation.agent,
                    observation.agent_version,
                    observation.native_profile,
                    observation.received_at,
                ),
                load_only(
                    decision.decision_id,
                    decision.request_id,
                    decision.status,
                    decision.policy_revision,
                    decision.mode,
                    decision.input_state,
                    decision.reason,
                    decision.evaluated_action,
                    decision.response_prepared,
                    decision.returned_action,
                ),
                load_only(
                    assessment.status,
                    assessment.reason,
                    assessment.profile,
                    assessment.model_identity,
                    assessment.unsafe_score,
                    assessment.score_kind,
                    assessment.input_tokens,
                ),
            )
        )
        page = _page(
            db,
            query,
            observation.received_at,
            observation.event_id,
            project_native_observation,
            scope=policy,
            query_id=f"native-prompts/{session_id}",
            limit=page_size,
            cursor=cursor,
        )
        attach_report_summaries(db, page["items"], now)
        return page


@router.get("/v1/agent-observations")
def unassigned_observations(
    request: Request, unassigned: Literal["true"], limit: Limit = 50, cursor: str | None = None, policy=Depends(_scope)
):
    return _observations(request, policy, None, limit, cursor)


@router.get("/v1/collector-health")
def collector_health(request: Request, limit: Limit = 50, cursor: str | None = None, policy=Depends(_scope)):
    now = datetime.now(UTC)
    live = CollectorProgress.heartbeat_expires_at > now
    # Undated rows follow the retained heartbeats, ordered by device UUID.
    # Expired timestamps never enter a cursor or a response.
    order = case((live, CollectorProgress.heartbeat_received_at), else_=datetime.min)
    query = _scoped(
        select(
            CollectorProgress.device_id,
            CollectorProgress.policy_id,
            CollectorProgress.heartbeat_revision,
            CollectorProgress.totals,
            case((live, CollectorProgress.heartbeat_json)),
            case((live, CollectorProgress.heartbeat_received_at)),
        ),
        CollectorProgress,
        policy,
    )

    def project(device: str, bound: str, revision: int, totals: dict, snapshot: str | None, at: datetime | None):
        heartbeat: dict[str, Any] | None = None
        if snapshot is not None:
            data = json.loads(snapshot)
            heartbeat = {
                key: data[key] for key in ("adapter_version", "upstream_sha", "state", "pending", "queue_bytes")
            }
        return dict(
            device_id=device,
            policy_id=bound,
            heartbeat_revision=revision,
            totals=totals,
            received_at=_stamp(at) if at else None,
            heartbeat=heartbeat,
            agent_version="unknown",
        )

    with request.app.state.session_factory() as db:
        return _page(
            db,
            query,
            order,
            CollectorProgress.device_id,
            project,
            scope=policy,
            query_id="health",
            limit=limit,
            cursor=cursor,
        )
