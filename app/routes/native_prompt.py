"""Administer native session grants, decide bounded callbacks, and record delivery facts."""

import asyncio
import time
from collections.abc import Awaitable, Callable, Iterator
from contextlib import contextmanager
from dataclasses import asdict
from datetime import UTC, datetime
from typing import Annotated, TypeVar

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse, Response
from pydantic import ValidationError
from sqlalchemy import select, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session
from starlette.requests import ClientDisconnect
from starlette.types import Receive, Scope, Send

from app.auth.dependencies import require_native, require_role
from app.auth.grants import GrantError, validate_grants
from app.auth.key_utils import hash_key
from app.db.models import APIKey
from app.native_prompt import (
    NativeConfigAck,
    NativeDecisionReply,
    NativeDeliveryReport,
    NativeError,
    NativeGrantRequest,
    NativeMetadata,
    NativeObservationAck,
    NativePolicySettings,
    NativePromptRequest,
    NativeRefusal,
    WireModel,
    parse_wire,
)
from app.routes.collector_ingest import _body
from app.services.native_prompt_grants import (
    NativePrincipal,
    authorize_native,
    configure_native,
    issue_native_grant,
    revoke_native_grant,
    upsert_native_observation,
)
from app.utils import as_utc

router = APIRouter()
T = TypeVar("T", bound=WireModel)
_ADMIN = [Depends(require_role("admin"))]
_PRIVATE = {"Cache-Control": "no-store"}


async def read_native_body(request: Request, dto: type[T]) -> T:
    try:
        data = await _body(request, dto.byte_limit)
    except HTTPException as exc:
        raise NativeError("invalid_request", exc.status_code) from None
    return parse_wire(data, dto)


def _body_of(dto: type[T]) -> Callable[[Request], Awaitable[T]]:
    async def read(request: Request) -> T:
        return await read_native_body(request, dto)

    return read


async def _require_empty_body(request: Request) -> None:
    async for chunk in request.stream():
        if chunk:
            raise NativeError("invalid_request", 422)


def native_refusal(error: NativeError, request_id: str | None = None) -> JSONResponse:
    try:
        body = NativeRefusal(version=1, request_id=request_id, code=error.code)
    except ValidationError:
        body = NativeRefusal(version=1, request_id=None, code="invalid_request")
    return JSONResponse(body.model_dump(), status_code=error.status, headers=_PRIVATE)


async def native_error_handler(request: Request, error: Exception) -> JSONResponse:
    assert isinstance(error, NativeError)
    return native_refusal(error)


@contextmanager
def _write(request: Request) -> Iterator[Session]:
    try:
        with request.app.state.session_factory.begin() as session:
            session.execute(text("BEGIN IMMEDIATE"))
            yield session
    except SQLAlchemyError:
        pass
    else:
        return
    raise NativeError("storage_unavailable", 503)


def _admin_scope(request: Request, session: Session) -> str | None:
    """Recheck the API key inside the writer reservation, after the request body."""
    key = session.scalar(
        select(APIKey)
        .execution_options(populate_existing=True)
        .where(
            APIKey.id == request.state.api_key_id,
            APIKey.key_hash == hash_key(request.headers["authorization"][7:]),
        )
    )
    if (
        key is None
        or key.role != "admin"
        or key.policy_id != request.state.policy_id
        or (key.expires_at is not None and as_utc(key.expires_at) <= datetime.now(UTC))
    ):
        raise NativeError("unauthorized", 403)
    try:
        validate_grants(key.role, key.policy_id, key.grants)
    except GrantError:
        raise NativeError("unauthorized", 403) from None
    return key.policy_id


@router.put("/v1/policies/{policy_id}/native-prompt", dependencies=_ADMIN)
def configure(
    request: Request, policy_id: str, body: Annotated[NativePolicySettings, Depends(_body_of(NativePolicySettings))]
):
    with _write(request) as session:
        config = configure_native(session, policy_id, body, _admin_scope(request, session))
    return JSONResponse(NativeConfigAck(policy_id=policy_id, **asdict(config)).model_dump(), headers=_PRIVATE)


@router.post("/v1/native-prompt/grants", dependencies=_ADMIN, status_code=201)
def issue(request: Request, body: Annotated[NativeGrantRequest, Depends(_body_of(NativeGrantRequest))]):
    with _write(request) as session:
        result = issue_native_grant(session, body, _admin_scope(request, session), now=datetime.now(UTC))
    return JSONResponse(result.model_dump(), status_code=201, headers=_PRIVATE)


@router.delete(
    "/v1/native-prompt/grants/{grant_id}", dependencies=[*_ADMIN, Depends(_require_empty_body)], status_code=204
)
def revoke(request: Request, grant_id: str):
    with _write(request) as session:
        revoke_native_grant(session, grant_id, _admin_scope(request, session), now=datetime.now(UTC))
    return Response(status_code=204, headers=_PRIVATE)


@router.post("/v1/native-prompt/observations")
def observe(
    request: Request,
    principal: Annotated[NativePrincipal, Depends(require_native)],
    metadata: Annotated[NativeMetadata, Depends(_body_of(NativeMetadata))],
):
    with _write(request) as session:

        def recheck(now: datetime) -> None:
            if (
                authorize_native(session, principal.collector_token_hash, principal.capability_hash, now=now)
                != principal
            ):
                raise NativeError("unauthorized", 403)

        received = datetime.now(UTC)
        recheck(received)
        event = upsert_native_observation(session, principal, metadata, now=received)
        receipt = NativeObservationAck(
            version=1, event_id=event.event_id, session_id=event.session_id, occurrence_id=event.occurrence_id
        )
        recheck(datetime.now(UTC))
    return JSONResponse(receipt.model_dump(), headers=_PRIVATE)


async def _disconnected(request: Request) -> None:
    # The bounded body is already consumed. The only remaining useful ASGI
    # event is disconnect; no polling reads compete with the body reader.
    while (await request.receive())["type"] != "http.disconnect":
        pass


class _PreparedDecision(JSONResponse):
    """Refuse an expired reply at the last controllable ASGI response boundary."""

    def __init__(self, reply: NativeDecisionReply, timely: Callable[[], bool]):
        super().__init__(reply.model_dump(), headers=_PRIVATE)
        self._request_id = reply.request_id
        self._timely = timely

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if self._timely():
            await super().__call__(scope, receive, send)
        else:
            refusal = native_refusal(NativeError("deadline_exceeded", 504), self._request_id)
            await refusal(scope, receive, send)


@router.post("/v1/native-prompt/decisions")
async def decide(request: Request, principal: Annotated[NativePrincipal, Depends(require_native)]):
    started = request.state.native_started_at
    try:
        async with asyncio.timeout(max(0, started + 1.8 - time.monotonic())):
            body = await read_native_body(request, NativePromptRequest)
    except TimeoutError:
        return native_refusal(NativeError("deadline_exceeded", 504))
    except ClientDisconnect:
        return native_refusal(NativeError("request_retired", 409))
    deadline = started + body.budget_ms / 1000
    service = request.app.state.native_decisions
    worker = asyncio.create_task(service.decide(body, principal, deadline=deadline))
    disconnect = asyncio.create_task(_disconnected(request))
    try:
        done, _ = await asyncio.wait({worker, disconnect}, return_when=asyncio.FIRST_COMPLETED)
        if disconnect in done:
            return native_refusal(NativeError("request_retired", 409), body.request_id)
        reply = worker.result()
        return _PreparedDecision(reply, lambda: service.can_return(principal, reply, deadline=deadline))
    except NativeError as exc:
        return native_refusal(exc, body.request_id)
    finally:
        for task in (worker, disconnect):
            if not task.done():
                task.cancel()
        await asyncio.gather(worker, disconnect, return_exceptions=True)


@router.post("/v1/native-prompt/deliveries")
def deliver(
    request: Request,
    principal: Annotated[NativePrincipal, Depends(require_native)],
    body: Annotated[NativeDeliveryReport, Depends(_body_of(NativeDeliveryReport))],
):
    try:
        ack = request.app.state.native_decisions.submit_delivery(principal, body)
    except NativeError as exc:
        return native_refusal(exc, body.request_id)
    return JSONResponse(ack.model_dump(), headers=_PRIVATE)
