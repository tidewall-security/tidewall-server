"""The one path by which retained content leaves this system.

Everything before this step kept content in. Step 4 removed it from ordinary
storage and exports, step 5 made capture optional and isolated, step 6 built one
audited read, step 7 put a deliberate handle on that read. This deliberately
opens a controlled external path, and it is last on purpose.

The order below is fixed and is the design's, not FastAPI's. The route declares
no typed parameters and no body model: the body is read with ``await
request.json()`` and validated by hand, so the framework cannot produce a 422
before the application's 400 and dependency resolution order is irrelevant.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
from datetime import UTC, datetime
from typing import Any

import sqlalchemy as sa
from fastapi import APIRouter, Request, Response

from app.auth.grants import CONTENT_EXPORT
from app.db.models import ContentExportAttempt, ExportTarget, Interaction, InteractionContent
from app.services import content_export as attempts
from app.services.cancellation import join_and_drain
from app.services.content_projection import (
    Corrupt,
    canonical_json,
    parse_stored_timestamp,
    project_content,
    render_timestamp,
)
from app.services.export_transport import (
    DestinationRefused,
    send_payload,
    state_for_phase,
    validate_destination,
    validate_headers,
)
from app.services.safe_logging import report

logger = logging.getLogger(__name__)

router = APIRouter()


PAYLOAD_SCHEMA = "tidewall.content_export.v1"

_MAX_ID = 2**63 - 1
_MAX_TARGET_ID = 200
_MAX_IDEMPOTENCY_KEY = 255
_MAX_PAYLOAD_BYTES = 8 * 1024 * 1024

#: The submission only. Admission and the reservation are outside it, so no
#: database work is ever inside a cancellable timeout -- cancelling an awaited
#: thread detaches it rather than stopping it.
TRANSPORT_DEADLINE_SECONDS = 30.0
#: The connection close, after settlement is joined.
CLEANUP_BUDGET_SECONDS = 5.0
#: How many exports may be in flight at once.
MAX_CONCURRENT_EXPORTS = 4

_admission = asyncio.Semaphore(MAX_CONCURRENT_EXPORTS)

_NO_STORE = {
    "Cache-Control": "no-store",
    "Pragma": "no-cache",
    "X-Content-Type-Options": "nosniff",
}


def _json_response(status: int, body: dict[str, Any]) -> Response:
    return Response(
        content=canonical_json(body),
        status_code=status,
        media_type="application/json",
        headers=dict(_NO_STORE),
    )


def _error(status: int, detail: str, **extra: Any) -> Response:
    return _json_response(status, {"detail": detail, **extra})


def _syntax(request: Request, body: Any) -> tuple[int, str, str, str | None] | Response:
    """Step 2. Everything that can be wrong about the request's shape.

    Before authorization and before any query, so a malformed id cannot reach
    the driver and a bad view cannot become FastAPI's 422.
    """
    if not isinstance(body, dict) or set(body) != {"view", "target_id"}:
        return _error(400, "Body must be an object with exactly 'view' and 'target_id'")

    view = body["view"]
    if view not in ("matches", "full"):
        return _error(400, "view must be 'matches' or 'full'")

    target_id = body["target_id"]
    if not isinstance(target_id, str) or not target_id or len(target_id) > _MAX_TARGET_ID:
        return _error(400, "target_id must be a non-empty string")

    raw_id = request.path_params.get("interaction_id", "")
    if not isinstance(raw_id, str) or not raw_id.isdigit():
        return _error(400, "interaction_id must be a positive integer")
    interaction_id = int(raw_id)
    if interaction_id < 1 or interaction_id > _MAX_ID:
        # Checked before the query: an integer larger than SQLite can hold would
        # otherwise reach the driver.
        return _error(400, "interaction_id is out of range")

    key = request.headers.get("idempotency-key")
    if key is not None:
        if not key or len(key) > _MAX_IDEMPOTENCY_KEY:
            return _error(400, "Idempotency-Key must be 1 to 255 characters")
        if any(ord(c) <= 0x20 or ord(c) >= 0x7F for c in key):
            return _error(400, "Idempotency-Key must be printable ASCII without whitespace")

    return interaction_id, view, target_id, key


def _replay_response(row: Any) -> Response:
    """Step 4. Answer from the stored state, whatever has happened since.

    Above every gate that consults current state, deliberately: a replay depends
    on none of them. Placed lower, it would return 404 after the content was
    purged, 409 after the target was deleted, or 500 if the projection no longer
    built -- instead of the result it actually had.
    """
    body = {"attempt_id": row.attempt_id, "state": row.state, "view": row.view}
    if row.state in ("succeeded", "pending"):
        # pending means the outcome is unknown, not that nothing was sent. This
        # replay sends nothing either way.
        return _json_response(202, body)
    return _json_response(502, body)


def _select(interaction_id: int, policy_id: str) -> sa.Select:
    """Step 5. One policy-scoped statement, as in the read endpoint.

    Payload columns are cast to TEXT so nothing is decoded while the row is
    fetched: SQLAlchemy's JSON and DateTime result processors raise there,
    before anything could classify the row.
    """
    c = sa.orm.aliased(InteractionContent)
    return (
        sa.select(
            Interaction.id.label("interaction_id"),
            c.id.label("content_id"),
            sa.cast(c.captured_at, sa.Text).label("captured_raw"),
            sa.cast(c.expires_at, sa.Text).label("expires_raw"),
            sa.cast(c.input_json, sa.Text).label("input_raw"),
            sa.cast(c.output_json, sa.Text).label("output_raw"),
            sa.cast(c.matches_json, sa.Text).label("matches_raw"),
        )
        .select_from(Interaction)
        .outerjoin(c, sa.and_(c.interaction_id == Interaction.id, c.policy_id == policy_id))
        .where(Interaction.id == interaction_id, Interaction.policy_id == policy_id)
    )


def _target_refusal(target: Any, policy_id: str, view: str) -> str | None:
    """Step 6. Why this destination may not receive this content, if it may not.

    Closed reason codes, because these are actionable configuration states of a
    target the caller can already enumerate through the admin API.
    """
    if not target.enabled:
        return "disabled"
    if not target.allow_content_export:
        return "not_approved"
    if target.type != "webhook":
        # Syslog cannot carry the semantics: UDP success means sendto accepted
        # bytes locally, and TCP success means a socket did. Neither is an
        # acknowledgement, so 202 would be a claim the transport cannot support.
        return "unsupported_transport"
    if target.content_export_policy_id != policy_id:
        return "policy_not_approved"
    if view not in (target.content_export_views or []):
        return "view_not_approved"
    return None


@router.post("/v1/logs/{interaction_id}/content-export")
async def export_content(request: Request) -> Response:
    """Send one interaction's retained content to one opted-in destination."""
    try:
        return await _authorize_and_export(request)
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        report(logger, "error", "content export failed unexpectedly", exc)
        return _error(500, "Internal error")


async def _authorize_and_export(request: Request) -> Response:
    # 1. authenticate -- middleware has already run.
    # 2. syntax.
    try:
        body = await request.json()
    except Exception:
        return _error(400, "Body must be JSON")
    parsed = _syntax(request, body)
    if isinstance(parsed, Response):
        return parsed
    interaction_id, view, target_id, idempotency_key = parsed

    # 3. authorize on properties that do not depend on the id, so the answer is
    #    identical for every id and leaks nothing.
    role = getattr(request.state, "role", None)
    grants: frozenset[str] = getattr(request.state, "grants", frozenset())
    policy_id = getattr(request.state, "policy_id", None)
    api_key_id = getattr(request.state, "api_key_id", None)

    if role is None:
        return _error(401, "Not authenticated")
    if role != "admin" or not policy_id or CONTENT_EXPORT not in grants:
        # Reading one record in the UI and shipping it to an external system are
        # different acts, and this one is admin-only.
        return _error(403, "Content export requires an admin credential with an explicit grant")

    session_factory = request.app.state.session_factory
    digest = attempts.digest_key(idempotency_key) if idempotency_key else None
    fingerprint = attempts.fingerprint_for(
        policy_id=policy_id, interaction_id=interaction_id, view=view, target_id=target_id
    )

    # 4. replay, above every gate that consults current state.
    if digest is not None:
        session = session_factory()
        try:
            existing = (
                session.query(ContentExportAttempt)
                .filter_by(api_key_id=api_key_id, idempotency_key_digest=digest)
                .one_or_none()
            )
        finally:
            session.close()
        if existing is not None:
            if existing.fingerprint != fingerprint:
                return _error(
                    409, "This idempotency key was used for a different export", reason="idempotency_key_reused"
                )
            return _replay_response(existing)

    # 5. one policy-scoped statement.
    session = session_factory()
    try:
        row = session.execute(_select(interaction_id, policy_id)).first()
        if row is None or row.content_id is None:
            # Deliberately the same answer as an unknown target below: ambiguity
            # is the security property here.
            return _error(404, "Not found")

        # 6. expiry, from the parsed canonical timestamp -- ABOVE the target,
        #    so content past its retention window is never exported and the
        #    answer is the same ambiguous 404 as everything else here.
        #
        #    Parsed rather than compared in SQL: SQL cannot both classify expiry
        #    and vouch that the stored value is a valid datetime, so a malformed
        #    value would sort one way or the other and give two different
        #    answers for the same corruption.
        try:
            expires_at = None if row.expires_raw is None else parse_stored_timestamp(row.expires_raw)
        except Corrupt as exc:
            report(logger, "error", "stored expiry is corrupt; not exporting", exc)
            return _error(500, "Stored content is unreadable")
        if expires_at is not None and expires_at <= datetime.now(UTC):
            return _error(404, "Not found")

        # 7. resolve the target.
        target = session.get(ExportTarget, target_id)
        if target is None:
            return _error(404, "Not found")
        refusal = _target_refusal(target, policy_id, view)
        if refusal is not None:
            return _error(409, "This destination may not receive this content", reason=refusal)

        config = dict(target.config or {})
        url = config.get("url")
        if not isinstance(url, str) or not url:
            return _error(409, "This destination may not receive this content", reason="unsupported_transport")
        try:
            host, port, addresses = validate_destination(url)
            headers = validate_headers(config.get("headers"))
        except DestinationRefused as exc:
            return _error(
                409,
                "This destination may not receive this content",
                reason="destination_refused",
                detail_reason=str(exc),
            )

        # 8. build the projection.
        try:
            projection = project_content(
                view=view,
                captured_raw=row.captured_raw,
                expires_raw=row.expires_raw,
                input_raw=row.input_raw,
                output_raw=row.output_raw,
                matches_raw=row.matches_raw,
            )
        except (Corrupt, ValueError) as exc:
            report(logger, "error", "stored content is corrupt; not exporting", exc)
            return _error(500, "Stored content is unreadable")

        config_digest = hashlib.sha256(json.dumps(config, sort_keys=True, default=str).encode("utf-8")).hexdigest()
    finally:
        try:
            session.close()
        except Exception as exc:
            report(logger, "error", "could not close the export read session", exc)

    return await _reserve_and_send(
        request=request,
        interaction_id=interaction_id,
        view=view,
        target_id=target_id,
        policy_id=policy_id,
        api_key_id=api_key_id,
        role=role,
        digest=digest,
        fingerprint=fingerprint,
        projection=projection,
        url=url,
        headers=headers,
        host=host,
        port=port,
        addresses=addresses,
        config_digest=config_digest,
    )


async def _reserve_and_send(*, request: Request, **ctx: Any) -> Response:
    """Steps 8-12: admission, reservation, submission, settlement.

    Split out so the ordering is legible: admission before the reservation, so a
    refusal never leaves a pending row for an export that was never attempted.
    """
    session_factory = request.app.state.session_factory
    boot_id = getattr(request.app.state, "boot_id", "unknown")

    # The id is generated before the payload because the payload contains it.
    # That ordering is what lets the bytes be built and bounded BEFORE anything
    # is reserved: an oversized projection then costs neither a transport slot
    # nor a row, and the size recorded on the attempt is the real one rather
    # than a placeholder nobody notices is always zero.
    attempt_id = attempts.new_attempt_id()
    payload_body = {
        "schema": PAYLOAD_SCHEMA,
        "attempt_id": attempt_id,
        "interaction_id": ctx["interaction_id"],
        "view": ctx["view"],
        # When this export happened, which is NOT when the content was
        # captured -- the two can be days apart, and the payload already
        # carries content.captured_at for the latter. An earlier version set
        # this from the projection, so every export told its receiver it had
        # happened at capture time.
        "exported_at": render_timestamp(datetime.now(UTC)),
        "content": ctx["projection"],
    }
    # Deliberately absent: policy_id, the API key id, and the guard's request_id.
    # No receiving system has been shown to need them, and each hands a tenant or
    # control-plane identifier to an external destination.
    encoded = canonical_json(payload_body).encode("utf-8")
    if len(encoded) > _MAX_PAYLOAD_BYTES:
        return _error(413, "The projection is too large to export")

    # 9. admission. Before the reservation, so a refusal never leaves a pending
    #    row -- and a replay never reaches here at all, because it takes no
    #    transport slot.
    try:
        await asyncio.wait_for(_admission.acquire(), timeout=1.0)
    except TimeoutError:
        return _error(503, "Too many exports in flight")

    permit_released = False

    def _release() -> None:
        nonlocal permit_released
        if not permit_released:
            permit_released = True
            _admission.release()

    try:
        # 10. reserve: pending, committed, before any I/O.
        try:
            _, is_replay = attempts.reserve(
                session_factory,
                attempt_id=attempt_id,
                attempt={
                    "interaction_id": ctx["interaction_id"],
                    "policy_id": ctx["policy_id"],
                    "target_id": ctx["target_id"],
                    "api_key_id": ctx["api_key_id"],
                    "actor_role": ctx["role"],
                    "view": ctx["view"],
                    "grant_used": CONTENT_EXPORT,
                    "payload_bytes": len(encoded),
                    "idempotency_key_digest": ctx["digest"],
                    "fingerprint": ctx["fingerprint"],
                    "destination_host": ctx["host"],
                    "destination_port": ctx["port"],
                    "destination_addrs": ctx["addresses"],
                    "target_config_digest": ctx["config_digest"],
                    "boot_id": boot_id,
                },
            )
        except Exception as exc:
            report(logger, "error", "could not reserve a content export attempt", exc)
            return _error(503, "Export could not be recorded, so nothing was sent")

        if is_replay:
            # Lost the unique race: another request reserved this key first. It
            # is now in exactly the situation step 4 handles, and it holds a slot
            # it does not need.
            _release()
            session = session_factory()
            try:
                # The WINNER's row, not the id this request generated: it lost
                # the race, so its own id was never written.
                winner = (
                    session.query(ContentExportAttempt)
                    .filter_by(api_key_id=ctx["api_key_id"], idempotency_key_digest=ctx["digest"])
                    .one_or_none()
                )
            finally:
                session.close()
            if winner is None:
                return _error(503, "Export could not be recorded, so nothing was sent")
            return _replay_response(winner)

        # 11. submit. The server-owned attempt id is the receiver's idempotency
        #     token; the caller's key never leaves.
        result = await send_payload(
            url=ctx["url"],
            headers={**ctx["headers"], "Idempotency-Key": attempt_id},
            body=encoded,
            addresses=ctx["addresses"],
            deadline_seconds=TRANSPORT_DEADLINE_SECONDS,
            max_request_bytes=_MAX_PAYLOAD_BYTES,
        )

        # 12. settle. Its own task, uncancelled by anything here, so the database
        #     work cannot be detached by a cancellation arriving mid-flight.
        state = state_for_phase(result)

        def _settle() -> bool:
            return attempts.settle(
                session_factory,
                attempt_id=attempt_id,
                state=state,
                transport_status=result.status,
                peer=result.peer,
            )

        # Through the scheduler's worker registry when there is one, so shutdown
        # waits for the THREAD rather than the coroutine: registration happens
        # before dispatch and deregistration inside the thread, and cancelling
        # an awaited thread detaches it rather than stopping it.
        scheduler = getattr(request.app.state, "scheduler", None)
        if scheduler is not None:
            settle_task = asyncio.create_task(scheduler.run_in_worker(_settle))
        else:
            settle_task = asyncio.create_task(asyncio.to_thread(_settle))
        settlements = getattr(request.app.state, "export_settlements", None)
        if settlements is not None:
            # Owned by the process: a bare create_task is owned by nothing, and
            # at shutdown the loop can close with it still in flight.
            settlements.add(settle_task)
            settle_task.add_done_callback(settlements.discard)

        settle_errors: list[Exception] = []
        cancelled = await join_and_drain(settle_task, on_error=settle_errors.append)

        # 13. cleanup, after settlement is joined and with its own budget. Its
        #     failure is a note and nothing else: it runs outside the thing that
        #     owns a state, so it cannot contradict one.
        cleanup_errors: list[Exception] = []
        if result.closer is not None:

            async def _close() -> None:
                async with asyncio.timeout(CLEANUP_BUDGET_SECONDS):
                    await result.closer()

            cleanup_task = asyncio.create_task(_close())
            cancelled = await join_and_drain(cleanup_task, on_error=cleanup_errors.append) or cancelled
        if cleanup_errors:
            attempts.write_note(
                session_factory,
                attempt_id=attempt_id,
                kind="cleanup_failed",
                detail=type(cleanup_errors[0]).__name__,
            )

        if result.error and result.phase == "headers_received":
            attempts.write_note(session_factory, attempt_id=attempt_id, kind="body_read_failed", detail=result.error)

        if settle_errors:
            attempts.write_note(
                session_factory,
                attempt_id=attempt_id,
                kind="settlement_commit_failed",
                detail=f"observed={state} status={result.status} error={type(settle_errors[0]).__name__}",
            )
            if cancelled:
                raise asyncio.CancelledError
            return _json_response(502, {"attempt_id": attempt_id, "state": "pending"})

        settled = settle_task.result() if not settle_task.cancelled() else False
        if not settled:
            # Something else settled it first. Never 202: the terminal outcome
            # this request observed was not the one committed.
            session = session_factory()
            try:
                stored = session.get(ContentExportAttempt, attempt_id)
                stored_state = stored.state if stored is not None else "unknown"
            finally:
                session.close()
            attempts.write_note(
                session_factory,
                attempt_id=attempt_id,
                kind="settlement_lost",
                detail=f"observed={state} stored={stored_state}",
            )
            if cancelled:
                raise asyncio.CancelledError
            return _json_response(502, {"attempt_id": attempt_id, "state": stored_state})

        # A handler that absorbed a cancellation does not then report success.
        #
        # Through the full stack this is invisible: asyncio still has the
        # cancellation pending and delivers it at Starlette's send(), so
        # removing this line changes nothing an HTTP client can see. That is
        # why it is bound by a test that calls this function directly, where
        # its return value is the only thing that answers:
        # test_the_handler_re_raises_a_deferred_cancellation_instead_of_returning_202.
        if cancelled:
            raise asyncio.CancelledError

        if state == "succeeded":
            return _json_response(202, {"attempt_id": attempt_id, "state": state})
        # failed and indeterminate alike: the caller could not confirm delivery
        # either way, while the row keeps the distinction an operator needs.
        return _json_response(502, {"attempt_id": attempt_id, "state": state})
    finally:
        _release()
