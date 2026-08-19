"""Cancelling the request must not cancel the disclosure record or the cleanup.

`_join_and_drain` has its own unit tests. These are different: they prove the
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
import threading
from datetime import UTC, datetime

from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

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


def _attempt(Session):
    session = Session()
    try:
        return session.query(ContentExportAttempt).one_or_none()
    finally:
        session.close()


def test_cancelling_during_settlement_still_settles_and_still_cleans_up(monkeypatch):
    """Cancel the handler while the settlement is inside its database worker.

    The settlement is the record that this content left the building. A
    cancellation arriving mid-flight must be deferred until it and the cleanup
    that follows it have run, not obeyed at the join.
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

            request.cancel()
            await asyncio.sleep(0)
            release.set()

            try:
                await request
            except (asyncio.CancelledError, Exception):
                pass

    asyncio.run(_go())

    attempt = _attempt(Session)
    assert attempt is not None, "no attempt row at all"
    assert attempt.state == "succeeded", (
        f"the disclosure was not recorded as settled: state={attempt.state!r}. "
        "A cancellation obeyed at the settlement join leaves the attempt pending "
        "while the content has already been sent."
    )
    assert closed.is_set(), (
        "cleanup never ran: the cancellation was obeyed at the settlement join, "
        "so the connection that carried the content was never closed"
    )


def test_cancelling_during_cleanup_still_finishes_the_cleanup(monkeypatch):
    """Cancel the handler while the closer is running.

    The settlement is already done here, so only the second join is under test.
    An interrupted closer leaks the connection the content went out on.
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

            request.cancel()
            await asyncio.sleep(0)
            proceed.set()

            try:
                await request
            except (asyncio.CancelledError, Exception):
                pass

    asyncio.run(_go())

    assert finished.is_set(), (
        "the closer was interrupted by the handler's cancellation, so the "
        "connection that carried the content was left open"
    )
    attempt = _attempt(Session)
    assert attempt is not None and attempt.state == "succeeded"


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
