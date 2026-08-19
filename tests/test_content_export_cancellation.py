"""Cancelling the request must not cancel the disclosure record or the cleanup.

`join_and_drain` has its own unit tests. These are different: they prove the
ROUTE uses it, at both of its load-bearing call sites, by cancelling a real
in-flight request through the real handler.

That distinction is the whole point. A direct test of a helper says nothing
about whether production calls it -- both call sites were independently
replaceable with a plain `await` while the entire suite stayed green, which is
how the gap was found.

What cancellation must not be allowed to do:

* skip the settlement, leaving a disclosure that happened with no terminal
  record of it having happened;
* skip the cleanup, leaving the connection that carried the content open.
"""

from __future__ import annotations

import asyncio
import json
import threading
from datetime import UTC, datetime

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from starlette.requests import Request

from app.auth.grants import CONTENT_EXPORT
from app.auth.key_utils import generate_key, hash_key, key_prefix
from app.auth.middleware import AuthMiddleware
from app.db.models import (
    APIKey,
    Base,
    ContentExportAttempt,
    ExportTarget,
    Interaction,
    InteractionContent,
    Policy,
)
from app.services.export_transport import SendResult


def _build(monkeypatch):
    """A real router over a real database, with the transport stubbed."""
    import app.routes.content_export as route

    monkeypatch.setattr(route, "validate_destination", lambda url: ("127.0.0.1", 443, ["203.0.113.9"]))

    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)

    app = FastAPI()
    app.add_middleware(AuthMiddleware)
    app.state.session_factory = Session
    app.state.boot_id = "boot-test"
    app.state.export_settlements = set()
    app.include_router(route.router)

    session = Session()
    session.add(Policy(id="policy-a", name="policy-a", type="application"))
    raw = generate_key(prefix="ak")
    session.add(
        APIKey(
            name="admin",
            key_hash=hash_key(raw),
            key_prefix=key_prefix(raw),
            role="admin",
            policy_id="policy-a",
            grants=[CONTENT_EXPORT],
        )
    )
    interaction = Interaction(
        request_id="tw_00000000000000bb",
        timestamp="2026-08-19T00:00:00Z",
        event_type="input",
        policy_id="policy-a",
        policy_name="policy-a",
        blocked=False,
        transformed=False,
        latency_ms=1.0,
        content_available=True,
    )
    session.add(interaction)
    session.flush()
    session.add(
        InteractionContent(
            interaction_id=interaction.id,
            policy_id="policy-a",
            input_json=[{"role": "user", "content": "swordfish-42"}],
            byte_size=10,
            captured_at=datetime.now(UTC),
        )
    )
    target = ExportTarget(
        name="siem",
        type="webhook",
        config={"url": "https://receiver.invalid/hook"},
        format="ocsf",
        events=[],
        enabled=True,
        allow_content_export=True,
        content_export_policy_id="policy-a",
        content_export_views=["full"],
    )
    session.add(target)
    session.commit()
    body = {"view": "full", "target_id": target.id}
    path = f"/v1/logs/{interaction.id}/content-export"
    session.close()

    return app, Session, path, body, {"Authorization": f"Bearer {raw}"}


def _api_key_id(Session):
    session = Session()
    try:
        return session.query(APIKey).one().id
    finally:
        session.close()


def _attempt(Session):
    session = Session()
    try:
        return session.query(ContentExportAttempt).one_or_none()
    finally:
        session.close()


def _state(Session):
    attempt = _attempt(Session)
    return None if attempt is None else attempt.state


#: How long the handler must stay unfinished to count as still joining. The
#: thing it is waiting on is held for 10s, so a build that defers cancellation
#: blocks for the full 10 and a build that obeys it returns immediately; this
#: sits an order of magnitude away from both. Its failure direction is a
#: spurious pass on a badly overloaded machine, never a spurious failure.
_STILL_JOINING_SECONDS = 0.75


async def _stays_pending(task):
    """Whether the task is STILL RUNNING after the wait above.

    The load-bearing assertion in this module. Checking effects after
    asyncio.run() has returned cannot distinguish a drained join from a
    detached one: loop shutdown waits for the executor, so a settlement that
    the handler abandoned still lands in the database before any post-run
    assertion reads it. The question has to be asked while the loop is running,
    and it has to be asked of the HANDLER: is it still here?
    """
    done, _pending = await asyncio.wait({task}, timeout=_STILL_JOINING_SECONDS)
    return not done


def test_cancelling_during_settlement_defers_until_it_and_the_cleanup_are_done(monkeypatch):
    """Cancel the handler while the settlement is inside its database worker.

    The settlement is the record that this content left the building, so a
    cancellation arriving mid-flight must be deferred until it and the cleanup
    behind it have run -- not obeyed at the join, and not merely "eventually
    completed by something".
    """
    import app.routes.content_export as route
    import app.services.content_export as service

    app, Session, path, body, headers = _build(monkeypatch)

    entered = threading.Event()
    release = threading.Event()
    real_settle = service.settle

    def _blocking_settle(*args, **kwargs):
        entered.set()
        release.wait(10)
        return real_settle(*args, **kwargs)

    closed = asyncio.Event()

    async def _closer():
        closed.set()

    async def _send(**kwargs):
        return SendResult(phase="headers_received", status=204, peer="127.0.0.1", closer=_closer)

    monkeypatch.setattr(route.attempts, "settle", _blocking_settle)
    monkeypatch.setattr(route, "send_payload", _send)

    async def _go():
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            request = asyncio.create_task(client.post(path, json=body, headers=headers))
            await asyncio.to_thread(entered.wait, 10)

            assert not request.done()
            assert request.cancel() is True, "nothing live was cancelled, so this proves nothing"
            # Repeatedly, and through the real route: one absorbed cancellation
            # is a weaker claim than a handler that keeps absorbing them.
            for _ in range(3):
                await asyncio.sleep(0)
                request.cancel()

            assert await _stays_pending(request), "the handler returned while its settlement was still writing"
            assert not closed.is_set(), "cleanup ran before the settlement had been joined"
            assert _state(Session) == "pending", "settled while the worker was still blocked"

            release.set()

            with pytest.raises(asyncio.CancelledError):
                await request

            # In the loop, before it is torn down: the evidence has to be here
            # already, not merely arrive during shutdown.
            assert closed.is_set(), "the handler exited without draining cleanup"
            assert _state(Session) == "succeeded", "the disclosure has no terminal record"

    asyncio.run(_go())

    assert _state(Session) == "succeeded"


def test_cancelling_during_cleanup_defers_until_the_closer_finishes(monkeypatch):
    """Cancel the handler while the closer is running.

    Settlement is already done here, so only the second join is under test. An
    interrupted closer leaks the connection the content went out on.
    """
    import app.routes.content_export as route

    app, Session, path, body, headers = _build(monkeypatch)

    started = asyncio.Event()
    proceed = asyncio.Event()
    finished = asyncio.Event()

    async def _closer():
        started.set()
        await proceed.wait()
        finished.set()

    async def _send(**kwargs):
        return SendResult(phase="headers_received", status=204, peer="127.0.0.1", closer=_closer)

    monkeypatch.setattr(route, "send_payload", _send)

    async def _go():
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            request = asyncio.create_task(client.post(path, json=body, headers=headers))
            await asyncio.wait_for(started.wait(), 10)

            assert not request.done()
            assert request.cancel() is True, "nothing live was cancelled, so this proves nothing"
            for _ in range(3):
                await asyncio.sleep(0)
                request.cancel()

            assert await _stays_pending(request), "the handler returned while its cleanup was still running"
            # The gate is still shut, so nothing incidental can have finished
            # the closer -- if it is done here, the handler did not wait for it.
            assert not finished.is_set()

            proceed.set()

            with pytest.raises(asyncio.CancelledError):
                await request

            assert finished.is_set(), (
                "the closer was interrupted, so the connection that carried the content " "was left open"
            )

    asyncio.run(_go())
    assert _state(Session) == "succeeded"


def test_an_uncancelled_request_is_unaffected(monkeypatch):
    """The control. Without it the two tests above would still pass if the
    endpoint had simply stopped working."""
    import app.routes.content_export as route

    app, Session, path, body, headers = _build(monkeypatch)

    closed = asyncio.Event()

    async def _closer():
        closed.set()

    async def _send(**kwargs):
        return SendResult(phase="headers_received", status=204, peer="127.0.0.1", closer=_closer)

    monkeypatch.setattr(route, "send_payload", _send)

    async def _go():
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            return await client.post(path, json=body, headers=headers)

    resp = asyncio.run(_go())
    assert resp.status_code == 202, resp.text
    assert closed.is_set()
    attempt = _attempt(Session)
    assert attempt is not None and attempt.state == "succeeded"


def test_the_settlement_task_is_always_owned_by_the_process(monkeypatch):
    """A bare create_task is owned by nothing.

    Checked at the only moment it is observable -- while the settlement is
    still in flight -- rather than after the fact, when the done callback has
    already discarded it.
    """
    import app.routes.content_export as route
    import app.services.content_export as service

    app, Session, path, body, headers = _build(monkeypatch)

    entered = threading.Event()
    release = threading.Event()
    real_settle = service.settle

    def _blocking_settle(*args, **kwargs):
        entered.set()
        release.wait(10)
        return real_settle(*args, **kwargs)

    async def _send(**kwargs):
        return SendResult(phase="headers_received", status=204, peer="127.0.0.1")

    monkeypatch.setattr(route.attempts, "settle", _blocking_settle)
    monkeypatch.setattr(route, "send_payload", _send)

    observed: list[int] = []

    async def _go():
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            request = asyncio.create_task(client.post(path, json=body, headers=headers))
            await asyncio.to_thread(entered.wait, 10)
            observed.append(len(app.state.export_settlements))
            release.set()
            return await request

    resp = asyncio.run(_go())
    assert resp.status_code == 202, resp.text
    assert observed == [1], f"the in-flight settlement was not owned by the process: {observed}"
    assert not app.state.export_settlements, "the done callback did not discard it"


def test_a_cancelled_export_never_emits_a_success_response(monkeypatch):
    """A cancelled export is never answered with a success status.

    `pytest.raises(CancelledError)` above proves less than it looks like it
    proves: removing the route's final `if cancelled: raise` leaves those tests
    green, because asyncio delivers the pending cancellation at the next await
    inside the HTTP client anyway. The distinction only becomes visible with
    nothing awaiting after the handler -- so this drives the app as a raw ASGI
    callable and asks a different question: what did it SEND?

    Note the division of labour. This proves the externally observable
    property -- a cancelled export is never answered with a success status --
    and it holds through the whole stack. It does NOT bind the route's own
    re-raise, because the pending cancellation fires at Starlette's send()
    before any response goes out, so both builds send nothing. The line itself
    is bound by the direct-handler test below.
    """
    import app.routes.content_export as route
    import app.services.content_export as service

    app, Session, path, body, headers = _build(monkeypatch)

    entered = threading.Event()
    release = threading.Event()
    real_settle = service.settle

    def _blocking_settle(*args, **kwargs):
        entered.set()
        release.wait(10)
        return real_settle(*args, **kwargs)

    async def _closer():
        return None

    async def _send_payload(**kwargs):
        return SendResult(phase="headers_received", status=204, peer="127.0.0.1", closer=_closer)

    monkeypatch.setattr(route.attempts, "settle", _blocking_settle)
    monkeypatch.setattr(route, "send_payload", _send_payload)

    payload = json.dumps(body).encode()
    scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.1"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "root_path": "",
        "headers": [
            (b"host", b"test"),
            (b"content-type", b"application/json"),
            (b"content-length", str(len(payload)).encode()),
            (b"authorization", headers["Authorization"].encode()),
        ],
        "client": ("127.0.0.1", 51234),
        "server": ("test", 80),
    }

    sent: list[dict] = []

    async def _receive():
        return {"type": "http.request", "body": payload, "more_body": False}

    async def _send(message):
        sent.append(message)

    async def _go():
        call = asyncio.create_task(app(scope, _receive, _send))
        await asyncio.to_thread(entered.wait, 10)

        assert not call.done()
        assert call.cancel() is True, "nothing live was cancelled, so this proves nothing"
        assert await _stays_pending(call), "the handler returned while its settlement was writing"

        release.set()
        with pytest.raises(asyncio.CancelledError):
            await call

    asyncio.run(_go())

    starts = [m for m in sent if m["type"] == "http.response.start"]
    assert not starts, (
        f"the cancelled request was answered with {starts[0].get('status')}; a handler "
        "that has absorbed a cancellation must not then report success"
    )
    # The disclosure still has its terminal record: absorbing the cancellation
    # is about the RESPONSE, never about the evidence.
    assert _state(Session) == "succeeded"


def test_the_handler_re_raises_a_deferred_cancellation_instead_of_returning_202(monkeypatch):
    """The route's final re-raise, bound directly.

    Through the full stack this line is invisible: asyncio has the cancellation
    pending and delivers it at Starlette's send(), so removing the re-raise
    changes nothing anyone can observe from outside. An earlier version of this
    file concluded the line was untestable and said so in a comment. That was
    wrong, and the fix is to call the handler itself -- the function whose
    RETURN VALUE the line governs -- with nothing downstream to mask it.
    """
    import app.routes.content_export as route
    import app.services.content_export as service

    app, Session, path, body, headers = _build(monkeypatch)

    entered = threading.Event()
    release = threading.Event()
    real_settle = service.settle

    def _blocking_settle(*args, **kwargs):
        entered.set()
        release.wait(10)
        return real_settle(*args, **kwargs)

    async def _closer():
        return None

    async def _send_payload(**kwargs):
        return SendResult(phase="headers_received", status=204, peer="127.0.0.1", closer=_closer)

    monkeypatch.setattr(route.attempts, "settle", _blocking_settle)
    monkeypatch.setattr(route, "send_payload", _send_payload)

    payload = json.dumps(body).encode()

    async def _receive():
        return {"type": "http.request", "body": payload, "more_body": False}

    async def _go():
        scope = {
            "type": "http",
            "asgi": {"version": "3.0", "spec_version": "2.1"},
            "http_version": "1.1",
            "method": "POST",
            "scheme": "http",
            "path": path,
            "raw_path": path.encode(),
            "query_string": b"",
            "root_path": "",
            "headers": [(b"host", b"test"), (b"content-type", b"application/json")],
            "client": ("127.0.0.1", 51234),
            "server": ("test", 80),
            "app": app,
            # Normally the router's path match supplies this.
            "path_params": {"interaction_id": path.split("/")[3]},
        }
        request = Request(scope, _receive)
        # What the auth middleware would have established. This test is about
        # the cancellation contract, not about authentication, which has its
        # own suite; supplying it here keeps the handler reachable without a
        # stack that would mask the very line under test.
        request.state.role = "admin"
        request.state.grants = frozenset({CONTENT_EXPORT})
        request.state.policy_id = "policy-a"
        # A real one: the route requires it, because the idempotency
        # constraint it feeds is not unique over NULL.
        request.state.api_key_id = _api_key_id(Session)

        handler = asyncio.create_task(route._authorize_and_export(request))
        await asyncio.to_thread(entered.wait, 10)

        if handler.done():
            returned = handler.result()
            raise AssertionError(
                f"the handler returned {returned.status_code} before reaching settlement, so "
                f"nothing below this point was exercised: {bytes(returned.body)!r}"
            )
        assert handler.cancel() is True, "nothing live was cancelled, so this proves nothing"
        assert await _stays_pending(handler), "the handler returned while its settlement was writing"

        release.set()
        with pytest.raises(asyncio.CancelledError):
            returned = await handler
            raise AssertionError(f"the handler answered a cancelled request with {returned.status_code}")

        assert _state(Session) == "succeeded", "the disclosure lost its terminal record"

    asyncio.run(_go())
