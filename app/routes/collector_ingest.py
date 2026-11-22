"""Bounded, metadata-only collector writes."""

from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse

from app.agent_events import (
    MAX_BATCH_BYTES,
    MAX_HEARTBEAT_BYTES,
    Batch,
    Heartbeat,
    HeartbeatAck,
    Receipt,
    WireError,
    parse_batch,
    parse_heartbeat,
)
from app.auth.dependencies import require_collector
from app.services.agent_event_service import heartbeat, ingest
from app.services.collector_identity import CollectorPrincipal

router = APIRouter()


async def _body(request: Request, limit: int) -> bytes:
    media = request.headers.getlist("content-type")
    encoding = request.headers.getlist("content-encoding")
    if len(media) != 1 or (encoding and [v.strip().lower() for v in encoding] != ["identity"]):
        raise HTTPException(status_code=415, detail="Unsupported collector representation")
    parts = [part.strip().lower() for part in media[0].split(";")]
    if parts[0] != "application/json" or parts[1:] not in ([], ["charset=utf-8"], ['charset="utf-8"']):
        raise HTTPException(status_code=415, detail="Unsupported collector representation")
    body = bytearray()
    async for chunk in request.stream():
        if len(chunk) > limit - len(body):
            raise HTTPException(status_code=413, detail="Collector message too large")
        body.extend(chunk)
    return bytes(body)


async def _batch(request: Request) -> Batch | JSONResponse:
    try:
        return parse_batch(await _body(request, MAX_BATCH_BYTES))
    except WireError as exc:
        return JSONResponse(exc.refusal.model_dump(), status_code=422)


async def _report(request: Request) -> Heartbeat | JSONResponse:
    try:
        return parse_heartbeat(await _body(request, MAX_HEARTBEAT_BYTES))
    except WireError as exc:
        return JSONResponse(exc.refusal.model_dump(), status_code=422)


def _now() -> datetime:
    return datetime.now(UTC)


@router.post("/v1/collector/observations", response_model=Receipt)
def observations(
    request: Request,
    principal: Annotated[CollectorPrincipal, Depends(require_collector)],
    batch: Annotated[Batch | JSONResponse, Depends(_batch)],
) -> Receipt | JSONResponse:
    if isinstance(batch, JSONResponse):
        return batch
    with request.app.state.session_factory() as session:
        return ingest(session, principal, batch, _now)


@router.post("/v1/collector/heartbeat", response_model=HeartbeatAck)
def collector_heartbeat(
    request: Request,
    principal: Annotated[CollectorPrincipal, Depends(require_collector)],
    report: Annotated[Heartbeat | JSONResponse, Depends(_report)],
) -> HeartbeatAck | JSONResponse:
    if isinstance(report, JSONResponse):
        return report
    with request.app.state.session_factory() as session:
        return heartbeat(session, principal, report, _now)
