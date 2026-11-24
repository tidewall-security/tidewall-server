"""Decide one native occurrence against a frozen policy under its original budget."""

from __future__ import annotations

import asyncio
import hmac
import json
import secrets
import sqlite3
import threading
import time
from collections.abc import AsyncIterator, Callable, Iterator
from concurrent.futures import Future
from contextlib import asynccontextmanager, contextmanager, suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, TypeVar
from uuid import UUID, uuid4

from sqlalchemy import or_, select, text, update
from sqlalchemy.engine import CursorResult
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from app.db.models import NativePromptAssessment, NativePromptDecision, NativePromptDelivery, NativePromptObservation
from app.native_prompt import (
    MODEL_IDENTITY_JSON,
    NativeDecisionReply,
    NativeDeliveryAck,
    NativeDeliveryReport,
    NativeError,
    NativePromptRequest,
)
from app.services.native_prompt_grants import (
    NativePrincipal,
    authorize_native,
    read_native_config,
    upsert_native_observation,
)
from app.services.native_prompt_policy import (
    NativeOutcome,
    NativePolicySnapshot,
    NativePolicyUnsupported,
    Precheck,
    evaluate_native_precheck,
    freeze_native_policy,
    resolve_native_result,
)
from app.services.prompt_classifier_client import (
    MODEL_IDENTITY,
    AssessmentResult,
    CompletePrompt,
    PromptClassifierClient,
)
from app.utils import as_utc

T = TypeVar("T")
Decision = NativePromptDecision
_MAX_BINDINGS = 1024


def _now() -> datetime:
    return datetime.now(UTC)


@dataclass
class _Budget:
    deadline: float
    cancelled: threading.Event = field(default_factory=threading.Event)

    def check(self) -> None:
        if self.cancelled.is_set():
            raise NativeError("request_retired", 409)
        if time.monotonic() >= self.deadline:
            raise NativeError("deadline_exceeded", 504)


@dataclass
class _Binding:
    digest: bytes = field(repr=False)
    deadline: float
    nonce: str = field(default_factory=lambda: str(uuid4()))
    decision_id: str = field(default_factory=lambda: str(uuid4()))
    published_decision_id: str | None = None
    finished: Future[None] = field(default_factory=Future)
    reserved: threading.Event = field(default_factory=threading.Event)


@dataclass(frozen=True)
class _Reservation:
    decision_id: str
    inference_id: UUID
    snapshot: NativePolicySnapshot
    precheck: Precheck


def retire_pending(session: Session, *, process_id: UUID, now: datetime) -> int:
    """The startup process lock proves previous processes can no longer serve these rows."""
    result = session.execute(
        update(Decision)
        .where(Decision.status == "pending", Decision.process_id != str(process_id))
        .values(status="abandoned", reason="request_retired")
    )
    assert isinstance(result, CursorResult)
    return result.rowcount


def _authority(session: Session, principal: NativePrincipal) -> None:
    if authorize_native(session, principal.collector_token_hash, principal.capability_hash, now=_now()) != principal:
        raise NativeError("unauthorized", 403)


def _snapshot(session: Session, principal: NativePrincipal) -> NativePolicySnapshot:
    try:
        return freeze_native_policy(session, principal.policy_id, read_native_config(session, principal.policy_id))
    except NativePolicyUnsupported:
        raise NativeError("policy_unsupported", 409) from None


def _reply(d: NativePromptDecision, assessment: NativePromptAssessment) -> NativeDecisionReply:
    detail: dict[str, Any] = dict(status=assessment.status, reason=assessment.reason, profile=assessment.profile)
    if assessment.model_identity is not None:
        detail.update(
            model_identity=json.loads(assessment.model_identity),
            unsafe_score=assessment.unsafe_score,
            score_kind=assessment.score_kind,
            input_tokens=assessment.input_tokens,
        )
    return NativeDecisionReply.model_validate(
        dict(
            version=1,
            request_id=d.request_id,
            occurrence_id=d.occurrence_id,
            decision_id=d.decision_id,
            event_id=d.event_id,
            session_id=d.session_id,
            grant_id=d.grant_id,
            grant_generation=d.grant_generation,
            policy_revision=d.policy_revision,
            mode=d.mode,
            assessment=detail,
            evaluated_action=d.evaluated_action,
            returned_action=d.returned_action,
            reason=d.reason,
        )
    )


class NativeDecisionService:
    def __init__(self, sessions: sessionmaker[Session], classifier: PromptClassifierClient | None, *, process_id: UUID):
        self.sessions = sessions
        self.classifier = classifier
        self.process_id = process_id
        self._key = secrets.token_bytes(32)
        self._bindings: dict[tuple[str, str], _Binding] = {}
        self._bindings_lock = threading.Lock()
        self._tasks: set[asyncio.Task[Any]] = set()
        self._cleanup_needed = threading.Event()

    def _track(self, task: asyncio.Task[T]) -> asyncio.Task[T]:
        self._tasks.add(task)

        def done(completed: asyncio.Task[T]) -> None:
            self._tasks.discard(completed)
            if not completed.cancelled():
                completed.exception()  # A disconnected caller may have stopped waiting.

        task.add_done_callback(done)
        return task

    async def _worker(self, func: Callable[..., T], *args: Any) -> T:
        # Cancelling the caller never detaches an untracked database worker from shutdown.
        return await asyncio.shield(self._track(asyncio.create_task(asyncio.to_thread(func, *args))))

    @contextmanager
    def _transaction(self, budget: _Budget, *, write: bool = True) -> Iterator[Session]:
        budget.check()
        try:
            # Own the checkout until the connection-local busy handler is restored.
            with self.sessions.kw["bind"].connect() as conn:
                budget.check()
                raw = conn.connection.driver_connection
                previous = raw.execute("PRAGMA busy_timeout").fetchone()[0]
                try:
                    remaining = max(0, int((budget.deadline - time.monotonic()) * 1000))
                    raw.execute(f"PRAGMA busy_timeout={remaining}")
                    with self.sessions(bind=conn) as session:
                        session.execute(text("BEGIN IMMEDIATE" if write else "BEGIN"))
                        budget.check()
                        yield session
                        session.flush()
                        budget.check()
                        session.commit()
                finally:
                    raw.execute(f"PRAGMA busy_timeout={previous}")
        except (SQLAlchemyError, sqlite3.Error):
            raise NativeError("storage_unavailable", 503) from None
        budget.check()  # A physical COMMIT can finish after the output boundary.

    def _purge_bindings(self, now: float) -> None:
        for key, entry in list(self._bindings.items()):
            if now >= entry.deadline:
                entry.digest = b""
                del self._bindings[key]

    def _binding(self, key: tuple[str, str]) -> _Binding | None:
        with self._bindings_lock:
            self._purge_bindings(time.monotonic())
            return self._bindings.get(key)

    def _register(self, key: tuple[str, str], entry: _Binding) -> None:
        with self._bindings_lock:
            self._purge_bindings(time.monotonic())
            if key in self._bindings:
                raise NativeError("request_retired", 409)
            if len(self._bindings) >= _MAX_BINDINGS:
                raise NativeError("capacity", 503)
            self._bindings[key] = entry

    def can_return(self, principal: NativePrincipal, reply: NativeDecisionReply, *, deadline: float) -> bool:
        # The transport can take time to render a replay after its DB check.
        with self._bindings_lock:
            entry = self._bindings.get((principal.device_id, reply.request_id))
            return (
                entry is not None
                and entry.published_decision_id == reply.decision_id
                and time.monotonic() < min(entry.deadline, deadline)
            )

    def _admit(
        self, request: NativePromptRequest, p: NativePrincipal, candidate: _Binding, budget: _Budget
    ) -> _Reservation | NativeDecisionReply | _Binding:
        with self._transaction(budget) as session:
            _authority(session, p)
            snapshot = _snapshot(session, p)
            key = (p.device_id, request.request_id)
            # budget_ms is transport time. Compare semantic content only after
            # both credentials and scope have been checked in this reservation.
            digest = hmac.digest(self._key, request.model_dump_json(exclude={"budget_ms"}).encode(), "sha256")
            rows = session.scalars(
                select(Decision).where(
                    Decision.device_id == p.device_id,
                    or_(
                        Decision.request_id == request.request_id,
                        Decision.event_id
                        == select(NativePromptObservation.event_id)
                        .where(
                            NativePromptObservation.device_id == p.device_id,
                            NativePromptObservation.occurrence_id == request.observation.occurrence_id,
                        )
                        .scalar_subquery(),
                    ),
                )
            ).all()
            if rows:
                d = rows[0]
                if (
                    len(rows) != 1
                    or d.request_id != request.request_id
                    or d.occurrence_id != request.observation.occurrence_id
                    or d.grant_id != p.grant_id
                    or d.grant_generation != p.grant_generation
                    or d.input_state != request.input_state
                ):
                    raise NativeError("identity_conflict", 409)
                entry = self._binding(key)
                if (
                    entry is None
                    or d.owner_nonce != entry.nonce
                    or d.process_id != str(self.process_id)
                    or d.status == "abandoned"
                    or as_utc(d.expires_at) <= _now()
                ):
                    raise NativeError("request_retired", 409)
                if not hmac.compare_digest(digest, entry.digest):
                    raise NativeError("identity_conflict", 409)
                if d.policy_revision != snapshot.revision:
                    raise NativeError("policy_changed", 409)
                budget.deadline = min(budget.deadline, entry.deadline)
                if not entry.finished.done():
                    return entry
                if entry.published_decision_id != d.decision_id or d.status != "committed" or not d.response_prepared:
                    raise NativeError("request_retired", 409)
                detail = session.get(NativePromptAssessment, d.decision_id)
                if detail is None:
                    raise NativeError("storage_unavailable", 503)
                reply = _reply(d, detail)
                _authority(session, p)
                return reply
            candidate.digest = digest
            self._register(key, candidate)
            now = _now()
            obs = upsert_native_observation(session, p, request.observation, now=now)
            d = Decision(
                decision_id=candidate.decision_id,
                event_id=obs.event_id,
                request_id=request.request_id,
                occurrence_id=obs.occurrence_id,
                session_id=obs.session_id,
                device_id=p.device_id,
                policy_id=p.policy_id,
                session_token=p.session_token,
                grant_id=p.grant_id,
                grant_generation=p.grant_generation,
                policy_generation=p.policy_generation,
                policy_revision=snapshot.revision,
                mode=snapshot.mode,
                input_state=request.input_state,
                process_id=str(self.process_id),
                owner_nonce=candidate.nonce,
                received_at=now,
                expires_at=obs.expires_at,
            )
            session.add(d)
            session.flush()
            did, iid = d.decision_id, UUID(d.inference_request_id)
            _authority(session, p)
            candidate.reserved.set()
        precheck = evaluate_native_precheck(snapshot, request.prompt)
        budget.check()
        return _Reservation(did, iid, snapshot, precheck)

    def _owned(
        self, session: Session, p: NativePrincipal, entry: _Binding, reservation: _Reservation
    ) -> NativePromptDecision:
        _authority(session, p)
        d = session.scalar(
            select(Decision).where(
                Decision.decision_id == reservation.decision_id,
                Decision.process_id == str(self.process_id),
                Decision.owner_nonce == entry.nonce,
                Decision.status == "pending",
                Decision.grant_id == p.grant_id,
                Decision.grant_generation == p.grant_generation,
                Decision.policy_generation == p.policy_generation,
                Decision.device_id == p.device_id,
                Decision.policy_id == p.policy_id,
                Decision.session_token == p.session_token,
                Decision.inference_request_id == str(reservation.inference_id),
            )
        )
        if d is None or as_utc(d.expires_at) <= _now():
            raise NativeError("request_retired", 409)
        if (
            d.policy_revision != reservation.snapshot.revision
            or _snapshot(session, p).revision != reservation.snapshot.revision
        ):
            raise NativeError("policy_changed", 409)
        return d

    def _dispatch_check(self, p: NativePrincipal, entry: _Binding, reservation: _Reservation, budget: _Budget) -> None:
        with self._transaction(budget, write=False) as session:
            _authority(session, p)
            nonce = session.scalar(
                select(Decision.owner_nonce).where(
                    Decision.decision_id == reservation.decision_id,
                    Decision.status == "pending",
                    Decision.process_id == str(self.process_id),
                )
            )
            if nonce != entry.nonce:
                raise NativeError("request_retired", 409)

    def _finalize(
        self, p: NativePrincipal, entry: _Binding, reservation: _Reservation, outcome: NativeOutcome, budget: _Budget
    ) -> NativeDecisionReply:
        with self._transaction(budget) as session:
            d = self._owned(session, p, entry, reservation)
            result = session.execute(
                update(Decision)
                .where(
                    Decision.decision_id == d.decision_id,
                    Decision.process_id == str(self.process_id),
                    Decision.owner_nonce == entry.nonce,
                    Decision.status == "pending",
                )
                .values(
                    status="committed",
                    evaluated_action=outcome.evaluated_action,
                    returned_action=outcome.returned_action,
                    reason=outcome.reason,
                    response_prepared=True,
                )
            )
            if not isinstance(result, CursorResult) or result.rowcount != 1:
                raise NativeError("request_retired", 409)
            a = outcome.assessment
            assessment = NativePromptAssessment(
                decision_id=d.decision_id,
                device_id=p.device_id,
                policy_id=p.policy_id,
                status=a.status,
                reason=a.reason,
                profile=a.profile,
                unsafe_score=a.unsafe_score,
                input_tokens=a.input_tokens,
                score_kind=a.score_kind,
                model_identity=MODEL_IDENTITY_JSON if a.model_identity is not None else None,
            )
            session.add(assessment)
            session.flush()
            reply = _reply(d, assessment)
            _authority(session, p)
        return reply

    def _abandon(self, entry: _Binding, reason: str) -> None:
        try:
            with self._transaction(_Budget(time.monotonic() + 1)) as session:
                session.execute(
                    update(Decision)
                    .where(
                        Decision.decision_id == entry.decision_id,
                        Decision.process_id == str(self.process_id),
                        Decision.owner_nonce == entry.nonce,
                        Decision.status == "pending",
                    )
                    .values(status="abandoned", reason=reason)
                )
        except NativeError:
            self._cleanup_needed.set()

    async def decide(
        self, request: NativePromptRequest, principal: NativePrincipal, *, deadline: float
    ) -> NativeDecisionReply:
        deadline = min(deadline, time.monotonic() + request.budget_ms / 1000)
        budget = _Budget(deadline)
        budget.check()
        if (
            request.observation.session_token != principal.session_token
            or request.observation.native_profile != principal.profile
            or (request.input_state != "capture_disabled" and not principal.capture_allowed)
        ):
            raise NativeError("unauthorized", 403)
        live = self._binding((principal.device_id, request.request_id))
        if live is not None:
            budget.deadline = min(budget.deadline, live.deadline)
        entry = _Binding(b"", budget.deadline)
        cause = "request_retired"
        try:
            async with asyncio.timeout(max(0, budget.deadline - time.monotonic())) as timeout:
                reservation = await self._worker(self._admit, request, principal, entry, budget)
                if isinstance(reservation, _Binding):
                    timeout.reschedule(asyncio.get_running_loop().time() + max(0, budget.deadline - time.monotonic()))
                    await asyncio.shield(asyncio.wrap_future(reservation.finished))
                    reservation = await self._worker(self._admit, request, principal, entry, budget)
                    if isinstance(reservation, _Binding):
                        raise NativeError("request_retired", 409)
                if isinstance(reservation, NativeDecisionReply):
                    budget.check()
                    return reservation
                assessment = None
                if request.input_state in ("unsupported", "input_too_large"):
                    assessment = AssessmentResult(
                        "unsupported",
                        "input_too_large" if request.input_state == "input_too_large" else "input_unsupported",
                    )
                elif reservation.precheck.needs_assessment:
                    if self.classifier is None:
                        assessment = AssessmentResult("unavailable", "classifier_unavailable")
                    else:
                        await self._worker(self._dispatch_check, principal, entry, reservation, budget)
                        budget.check()
                        assert request.prompt is not None
                        provider = self._track(
                            asyncio.create_task(
                                self.classifier.assess(
                                    CompletePrompt(request.prompt),
                                    request_id=reservation.inference_id,
                                    deadline=budget.deadline,
                                )
                            )
                        )
                        try:
                            assessment = await asyncio.shield(provider)
                        finally:
                            if not provider.done():
                                provider.cancel()
                budget.check()
                if (
                    assessment is not None
                    and assessment.status == "assessed"
                    and assessment.model_identity != MODEL_IDENTITY
                ):
                    assessment = AssessmentResult("failed", "classifier_invalid")
                outcome = resolve_native_result(reservation.snapshot, reservation.precheck, assessment)
                reply = await self._worker(self._finalize, principal, entry, reservation, outcome, budget)
                budget.check()
                entry.published_decision_id = reply.decision_id
                return reply
        except TimeoutError:
            cause = "deadline_exceeded"
            raise NativeError("deadline_exceeded", 504) from None
        except NativeError as exc:
            cause = {
                "grant_revoked": "authority_changed",
                "grant_expired": "authority_changed",
                "unauthorized": "authority_changed",
                "policy_changed": "policy_changed",
                "policy_unsupported": "policy_unsupported",
                "storage_unavailable": "storage_unavailable",
                "deadline_exceeded": "deadline_exceeded",
            }.get(exc.code, "request_retired")
            raise
        finally:
            budget.cancelled.set()
            entry.finished.set_result(None)
            # System cleanup cannot authorize a response; its independent budget
            # is never applied to model I/O, evaluation or wire preparation.
            if entry.reserved.is_set() and entry.published_decision_id is None:
                cleanup = self._track(asyncio.create_task(asyncio.to_thread(self._abandon, entry, cause)))
                remaining = budget.deadline - time.monotonic()
                if remaining > 0:
                    await asyncio.wait({cleanup}, timeout=remaining)

    def submit_delivery(self, principal: NativePrincipal, report: NativeDeliveryReport) -> NativeDeliveryAck:
        with self._transaction(_Budget(time.monotonic() + 1.8)) as session:
            _authority(session, principal)
            d = session.scalar(
                select(Decision).where(
                    Decision.decision_id == report.decision_id,
                    Decision.device_id == principal.device_id,
                    Decision.policy_id == principal.policy_id,
                    Decision.grant_id == principal.grant_id,
                    Decision.grant_generation == principal.grant_generation,
                    Decision.request_id == report.request_id,
                    Decision.occurrence_id == report.occurrence_id,
                    Decision.session_token == principal.session_token,
                )
            )
            if d is None or as_utc(d.expires_at) <= _now():
                raise NativeError("request_retired", 409)
            values = report.model_dump()
            existing = session.get(NativePromptDelivery, report.report_id)
            if existing:
                if any(getattr(existing, k) != v for k, v in values.items()):
                    raise NativeError("identity_conflict", 409)
            else:
                session.add(
                    NativePromptDelivery(
                        **values,
                        device_id=d.device_id,
                        policy_id=d.policy_id,
                        grant_id=d.grant_id,
                        grant_generation=d.grant_generation,
                        received_at=_now(),
                        expires_at=d.expires_at,
                    )
                )
                session.flush()
            _authority(session, principal)
        return NativeDeliveryAck(version=1, report_id=report.report_id, decision_id=report.decision_id)

    def _retire(self, startup: bool) -> None:
        with self._transaction(_Budget(time.monotonic() + 5)) as session:
            if startup:
                retire_pending(session, process_id=self.process_id, now=_now())
            else:
                with self._bindings_lock:
                    live = [
                        e.nonce
                        for e in self._bindings.values()
                        if not e.finished.done() and e.deadline > time.monotonic()
                    ]
                session.execute(
                    update(Decision)
                    .where(
                        Decision.status == "pending",
                        Decision.process_id == str(self.process_id),
                        Decision.owner_nonce.not_in(live),
                    )
                    .values(status="abandoned", reason="request_retired")
                )

    def _retry_cleanup(self) -> None:
        try:
            self._retire(False)
        except NativeError:
            self._cleanup_needed.set()

    async def _maintain(self) -> None:
        while True:
            await asyncio.sleep(5)
            with self._bindings_lock:
                self._purge_bindings(time.monotonic())
            if self._cleanup_needed.is_set():
                self._cleanup_needed.clear()
                # A queued or busy cleanup worker cannot postpone erasure of
                # the in-memory content bindings on the next timer tick.
                self._track(asyncio.create_task(asyncio.to_thread(self._retry_cleanup)))

    @asynccontextmanager
    async def lifecycle(self) -> AsyncIterator[None]:
        await self._worker(self._retire, True)
        maintenance = asyncio.create_task(self._maintain())
        try:
            yield
        finally:
            maintenance.cancel()
            with suppress(asyncio.CancelledError):
                await maintenance
            while self._tasks:
                await asyncio.gather(*list(self._tasks), return_exceptions=True)
            with self._bindings_lock:
                self._purge_bindings(float("inf"))
