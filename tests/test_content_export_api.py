"""The one path by which retained content leaves this system."""

from __future__ import annotations

import json
import threading
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from starlette.requests import Request

from app.auth.grants import CONTENT_EXPORT, CONTENT_READ, MATCHES_READ
from app.auth.key_utils import generate_key, hash_key, key_prefix
from app.auth.middleware import AuthMiddleware
from app.config import Settings
from app.db.models import (
    APIKey,
    Base,
    ContentExportAttempt,
    ExportTarget,
    Interaction,
    InteractionContent,
    Policy,
)
from app.security_headers import SecurityHeadersMiddleware

CANARY = "swordfish-42"


class _Receiver(BaseHTTPRequestHandler):
    status = 204
    received: list[bytes] = []
    headers_seen: list[dict] = []

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        type(self).received.append(body)
        type(self).headers_seen.append(dict(self.headers))
        self.send_response(type(self).status)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args):
        pass


@pytest.fixture
def env(monkeypatch):
    _Receiver.received = []
    _Receiver.headers_seen = []
    _Receiver.status = 204

    server = HTTPServer(("127.0.0.1", 0), _Receiver)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()

    # The sender refuses plain http and non-public addresses, correctly. The
    # receiver here is a loopback HTTP server, so validation is stubbed to
    # return the loopback address -- what is under test is the endpoint's
    # ordering and lifecycle, not the SSRF controls, which have their own suite.
    import app.routes.content_export as route

    monkeypatch.setattr(route, "validate_destination", lambda url, posture: ("127.0.0.1", port, ["127.0.0.1"]))

    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)

    app = FastAPI()
    app.add_middleware(AuthMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)
    app.state.session_factory = Session
    app.state.boot_id = "boot-test"
    # The route reads the declared NAT64 posture from app.state before it
    # calls validate_destination, so a bare app needs one or it raises
    # AttributeError before the test's own double is ever reached.
    app.state.settings = Settings(PREF64="none")
    app.state.export_settlements = set()
    app.include_router(route.router)

    session = Session()
    for name in ("policy-a", "policy-b"):
        session.add(Policy(id=name, name=name, type="application"))
    session.commit()
    session.close()

    yield TestClient(app), Session, port
    server.shutdown()


def _key(Session, *, role="admin", policy_id="policy-a", grants=None):
    raw = generate_key(prefix="ak")
    session = Session()
    session.add(
        APIKey(
            name=f"k-{raw[-6:]}",
            key_hash=hash_key(raw),
            key_prefix=key_prefix(raw),
            role=role,
            policy_id=policy_id,
            grants=grants,
        )
    )
    session.commit()
    session.close()
    return {"Authorization": f"Bearer {raw}"}


_next_id = 0


def _interaction(Session, *, policy_id="policy-a", content=True, expires_at=None, captured_at=None):
    global _next_id
    _next_id += 1
    session = Session()
    row = Interaction(
        request_id=f"tw_{_next_id:016x}",
        timestamp="2026-08-19T00:00:00Z",
        event_type="input",
        policy_id=policy_id,
        policy_name=policy_id,
        blocked=False,
        transformed=False,
        latency_ms=1.0,
        content_available=content,
    )
    session.add(row)
    session.flush()
    interaction_id = row.id
    if content:
        session.add(
            InteractionContent(
                interaction_id=interaction_id,
                policy_id=policy_id,
                input_json=[{"role": "user", "content": CANARY}],
                output_json=[{"role": "assistant", "content": "reply"}],
                matches_json=None,
                byte_size=10,
                captured_at=captured_at or datetime.now(UTC),
                expires_at=expires_at,
            )
        )
    session.commit()
    session.close()
    return interaction_id


def _target(Session, port, *, allow=True, policy="policy-a", views=("full",), enabled=True, type_="webhook", url=None):
    session = Session()
    target = ExportTarget(
        name="siem",
        type=type_,
        config={"url": url or f"http://127.0.0.1:{port}/hook"},
        format="ocsf",
        events=[],
        enabled=enabled,
        allow_content_export=allow,
        content_export_policy_id=policy,
        content_export_views=list(views),
    )
    session.add(target)
    session.commit()
    target_id = target.id
    session.close()
    return target_id


def _attempts(Session):
    session = Session()
    try:
        return session.query(ContentExportAttempt).order_by(ContentExportAttempt.created_at).all()
    finally:
        session.close()


@pytest.mark.parametrize(
    "role,policy_id,grants,expected",
    [
        ("admin", "policy-a", [CONTENT_EXPORT], 202),
        ("admin", "policy-a", None, 403),
        # Reading one record in the UI and shipping it to an external system are
        # different acts; this one is admin-only.
        ("viewer", "policy-a", [CONTENT_EXPORT], 403),
        # A read grant does not confer export, and export confers neither read.
        ("admin", "policy-a", [CONTENT_READ], 403),
        ("admin", "policy-a", [MATCHES_READ], 403),
        ("api", "policy-a", None, 403),
        # A null binding never means all policies -- and a grant on an unbound
        # key makes the credential invalid, not merely weaker.
        ("admin", None, [CONTENT_EXPORT], 401),
    ],
)
def test_the_authorization_matrix(env, role, policy_id, grants, expected):
    client, Session, port = env
    headers = _key(Session, role=role, policy_id=policy_id, grants=grants)
    interaction_id = _interaction(Session)
    target_id = _target(Session, port)
    resp = client.post(
        f"/v1/logs/{interaction_id}/content-export",
        json={"view": "full", "target_id": target_id},
        headers=headers,
    )
    assert resp.status_code == expected


@pytest.mark.parametrize(
    "kwargs,reason",
    [
        ({"allow": False}, "not_approved"),
        ({"enabled": False}, "disabled"),
        ({"policy": "policy-b"}, "policy_not_approved"),
        ({"views": ("matches",)}, "view_not_approved"),
        ({"views": ()}, "view_not_approved"),
        ({"type_": "syslog"}, "unsupported_transport"),
    ],
)
def test_the_interlock_and_its_scope(env, kwargs, reason):
    client, Session, port = env
    headers = _key(Session, grants=[CONTENT_EXPORT])
    interaction_id = _interaction(Session)
    target_id = _target(Session, port, **kwargs)
    resp = client.post(
        f"/v1/logs/{interaction_id}/content-export",
        json={"view": "full", "target_id": target_id},
        headers=headers,
    )
    assert resp.status_code == 409
    assert resp.json()["reason"] == reason
    assert _attempts(Session) == [], "a refused destination reserved an attempt"


def test_flipping_only_the_interlock_is_what_changes_the_answer(env):
    client, Session, port = env
    headers = _key(Session, grants=[CONTENT_EXPORT])
    interaction_id = _interaction(Session)
    target_id = _target(Session, port, allow=False)

    assert (
        client.post(
            f"/v1/logs/{interaction_id}/content-export",
            json={"view": "full", "target_id": target_id},
            headers=headers,
        ).status_code
        == 409
    )

    session = Session()
    session.get(ExportTarget, target_id).allow_content_export = True
    session.commit()
    session.close()

    assert (
        client.post(
            f"/v1/logs/{interaction_id}/content-export",
            json={"view": "full", "target_id": target_id},
            headers=headers,
        ).status_code
        == 202
    )


def test_an_unknown_target_and_an_unknown_interaction_are_the_same_404(env):
    """Ambiguity is the security property: the pair would otherwise say which of
    the two things was missing."""
    client, Session, port = env
    headers = _key(Session, grants=[CONTENT_EXPORT])
    interaction_id = _interaction(Session)
    target_id = _target(Session, port)

    unknown_target = client.post(
        f"/v1/logs/{interaction_id}/content-export",
        json={"view": "full", "target_id": "no-such-target"},
        headers=headers,
    )
    unknown_interaction = client.post(
        f"/v1/logs/{interaction_id + 9999}/content-export",
        json={"view": "full", "target_id": target_id},
        headers=headers,
    )
    assert unknown_target.status_code == unknown_interaction.status_code == 404
    assert unknown_target.content == unknown_interaction.content


def test_a_foreign_policy_interaction_is_the_same_404(env):
    client, Session, port = env
    headers = _key(Session, grants=[CONTENT_EXPORT])
    foreign = _interaction(Session, policy_id="policy-b")
    target_id = _target(Session, port)
    resp = client.post(
        f"/v1/logs/{foreign}/content-export",
        json={"view": "full", "target_id": target_id},
        headers=headers,
    )
    assert resp.status_code == 404


def test_the_interaction_resolves_before_the_target(env):
    """A caller with no exportable record learns nothing about destinations."""
    client, Session, port = env
    headers = _key(Session, grants=[CONTENT_EXPORT])
    _interaction(Session)
    resp = client.post(
        "/v1/logs/999999/content-export",
        json={"view": "full", "target_id": "no-such-target"},
        headers=headers,
    )
    assert resp.status_code == 404, "target state was decided before the interaction"


@pytest.mark.parametrize(
    "body",
    [
        "not json",
        "[]",
        '"a string"',
        '{"view": "full"}',
        '{"target_id": "t"}',
        '{"view": "full", "target_id": "t", "extra": 1}',
        '{"view": "everything", "target_id": "t"}',
        '{"view": "full", "target_id": ""}',
        '{"view": "full", "target_id": 5}',
        '{"view": "full", "target_id": null}',
    ],
)
def test_a_malformed_body_is_400_and_reserves_nothing(env, body):
    client, Session, port = env
    headers = _key(Session, grants=[CONTENT_EXPORT])
    interaction_id = _interaction(Session)
    resp = client.post(
        f"/v1/logs/{interaction_id}/content-export",
        content=body,
        headers={**headers, "Content-Type": "application/json"},
    )
    assert resp.status_code == 400, resp.text
    assert _attempts(Session) == []


@pytest.mark.parametrize("raw_id", ["abc", "-1", "0", "1.5", "1e3", str(2**63), " 1"])
def test_a_bad_interaction_id_is_400_before_any_query(env, raw_id):
    client, Session, port = env
    headers = _key(Session, grants=[CONTENT_EXPORT])
    resp = client.post(
        f"/v1/logs/{raw_id}/content-export",
        json={"view": "full", "target_id": "t"},
        headers=headers,
    )
    assert resp.status_code == 400


def test_syntax_is_checked_before_authorization(env):
    """Fixed order, asserted rather than assumed."""
    client, Session, port = env
    headers = _key(Session, grants=None)
    interaction_id = _interaction(Session)
    resp = client.post(
        f"/v1/logs/{interaction_id}/content-export",
        json={"view": "bogus", "target_id": "t"},
        headers=headers,
    )
    assert resp.status_code == 400


def test_the_payload_carries_the_content_and_nothing_that_identifies_the_tenant(env):
    client, Session, port = env
    headers = _key(Session, grants=[CONTENT_EXPORT])
    interaction_id = _interaction(Session)
    target_id = _target(Session, port)

    resp = client.post(
        f"/v1/logs/{interaction_id}/content-export",
        json={"view": "full", "target_id": target_id},
        headers=headers,
    )
    assert resp.status_code == 202

    body = json.loads(_Receiver.received[0])
    assert set(body) == {"schema", "attempt_id", "interaction_id", "view", "exported_at", "content"}
    assert body["schema"] == "tidewall.content_export.v1"
    assert body["content"]["messages"][0]["content"] == CANARY

    # Deliberately absent: no receiving system has been shown to need them, and
    # each hands a tenant or control-plane identifier to an external destination.
    flat = json.dumps(body)
    assert "policy-a" not in flat
    assert body.get("policy_id") is None
    assert body.get("exported_by") is None
    assert body.get("request_id") is None

    # The receiver's idempotency token is the server-owned attempt id; the
    # caller's key never leaves.
    assert _Receiver.headers_seen[0]["Idempotency-Key"] == body["attempt_id"]


def test_exported_at_is_when_the_export_happened_not_when_the_content_was_captured(env):
    """Two different times, and the payload carries both.

    They can be days apart. An earlier version set exported_at from the
    projection, so the field named for this request's time always reported the
    capture's -- and the whole payload test passed with it replaced by the
    literal string "not-an-export-time", because nothing looked at the value.
    """
    client, Session, port = env
    headers = _key(Session, grants=[CONTENT_EXPORT])
    captured = datetime(2020, 1, 2, 3, 4, 5, tzinfo=UTC)
    interaction_id = _interaction(Session, captured_at=captured)
    target_id = _target(Session, port)

    before = datetime.now(UTC)
    resp = client.post(
        f"/v1/logs/{interaction_id}/content-export",
        json={"view": "full", "target_id": target_id},
        headers=headers,
    )
    after = datetime.now(UTC)
    assert resp.status_code == 202

    body = json.loads(_Receiver.received[0])
    exported = datetime.fromisoformat(body["exported_at"].replace("Z", "+00:00"))
    stored_capture = datetime.fromisoformat(body["content"]["captured_at"].replace("Z", "+00:00"))

    assert stored_capture == captured, "the capture time is not what was stored"
    assert exported != stored_capture, "exported_at is just the capture time again"
    assert before <= exported <= after, f"exported_at ({exported}) is not the time of this request ({before}..{after})"


def test_the_matches_view_exports_matches_only(env):
    client, Session, port = env
    headers = _key(Session, grants=[CONTENT_EXPORT])
    interaction_id = _interaction(Session)
    target_id = _target(Session, port, views=("matches",))

    resp = client.post(
        f"/v1/logs/{interaction_id}/content-export",
        json={"view": "matches", "target_id": target_id},
        headers=headers,
    )
    assert resp.status_code == 202
    content = json.loads(_Receiver.received[0])["content"]
    assert set(content) == {"captured_at", "expires_at", "matches"}
    assert CANARY not in json.dumps(content)


def test_a_successful_export_settles_the_attempt(env):
    client, Session, port = env
    headers = _key(Session, grants=[CONTENT_EXPORT])
    interaction_id = _interaction(Session)
    target_id = _target(Session, port)

    resp = client.post(
        f"/v1/logs/{interaction_id}/content-export",
        json={"view": "full", "target_id": target_id},
        headers=headers,
    )
    assert resp.status_code == 202
    row = _attempts(Session)[0]
    assert row.state == "succeeded"
    assert row.transport_status == 204
    assert row.settled_at is not None
    assert row.destination_addr == "127.0.0.1"
    assert row.boot_id == "boot-test"
    assert resp.json()["state"] == "succeeded"


@pytest.mark.parametrize("status,state", [(400, "failed"), (500, "failed"), (302, "failed")])
def test_a_rejected_submission_is_502_and_recorded(env, status, state):
    """With redirects disabled a 3xx is the receiver's answer, not a hop."""
    client, Session, port = env
    _Receiver.status = status
    headers = _key(Session, grants=[CONTENT_EXPORT])
    interaction_id = _interaction(Session)
    target_id = _target(Session, port)

    resp = client.post(
        f"/v1/logs/{interaction_id}/content-export",
        json={"view": "full", "target_id": target_id},
        headers=headers,
    )
    assert resp.status_code == 502
    row = _attempts(Session)[0]
    assert row.state == state
    assert row.transport_status == status


def test_a_reservation_failure_sends_nothing(env, monkeypatch):
    """The attempt row is a precondition: no content leaves without one."""
    import app.services.content_export as service

    client, Session, port = env
    headers = _key(Session, grants=[CONTENT_EXPORT])
    interaction_id = _interaction(Session)
    target_id = _target(Session, port)

    def _explode(*args, **kwargs):
        raise RuntimeError("cannot reserve")

    monkeypatch.setattr(service, "reserve", _explode)
    import app.routes.content_export as route

    monkeypatch.setattr(route.attempts, "reserve", _explode)

    resp = client.post(
        f"/v1/logs/{interaction_id}/content-export",
        json={"view": "full", "target_id": target_id},
        headers=headers,
    )
    assert resp.status_code == 503
    assert _Receiver.received == [], "content left without a reserved attempt"


def test_a_repeated_idempotency_key_replays_and_sends_nothing(env):
    client, Session, port = env
    headers = _key(Session, grants=[CONTENT_EXPORT])
    interaction_id = _interaction(Session)
    target_id = _target(Session, port)
    body = {"view": "full", "target_id": target_id}
    keyed = {**headers, "Idempotency-Key": "abc-123"}

    first = client.post(f"/v1/logs/{interaction_id}/content-export", json=body, headers=keyed)
    assert first.status_code == 202
    assert len(_Receiver.received) == 1

    second = client.post(f"/v1/logs/{interaction_id}/content-export", json=body, headers=keyed)
    assert second.status_code == 202
    assert second.json()["attempt_id"] == first.json()["attempt_id"]
    assert len(_Receiver.received) == 1, "the replay sent a second copy"
    assert len(_attempts(Session)) == 1


def test_a_key_reused_for_a_different_export_is_refused(env):
    client, Session, port = env
    headers = _key(Session, grants=[CONTENT_EXPORT])
    first_id = _interaction(Session)
    second_id = _interaction(Session)
    target_id = _target(Session, port)
    keyed = {**headers, "Idempotency-Key": "abc-123"}

    client.post(
        f"/v1/logs/{first_id}/content-export",
        json={"view": "full", "target_id": target_id},
        headers=keyed,
    )
    resp = client.post(
        f"/v1/logs/{second_id}/content-export",
        json={"view": "full", "target_id": target_id},
        headers=keyed,
    )
    assert resp.status_code == 409
    assert resp.json()["reason"] == "idempotency_key_reused"
    assert len(_Receiver.received) == 1


def test_losing_the_reservation_race_with_a_different_export_is_still_409(env, monkeypatch):
    """Same key, two different exports, discovered by the constraint not the lookup.

    Sequentially this is a 409: the replay lookup at step 4 finds the earlier
    attempt, sees a different fingerprint, and refuses. Concurrently, both
    requests can pass that lookup before either has committed, and the loser
    finds out at the unique constraint instead. For a while the loser then
    borrowed step 4's REPLAY without step 4's REFUSAL, and was answered with
    the winner's attempt id, state and view -- for a record it never asked
    about.

    The race is produced by committing the winner inside the window rather than
    by threads: this fixture shares one SQLite connection, so two real threads
    would contend on the connection rather than on the constraint, and would
    prove something else.
    """
    import app.routes.content_export as route
    import app.services.content_export as service

    client, Session, port = env
    headers = _key(Session, grants=[CONTENT_EXPORT])
    mine = _interaction(Session)
    theirs = _interaction(Session)
    target_id = _target(Session, port)
    keyed = {**headers, "Idempotency-Key": "shared-key-1"}

    real_reserve = service.reserve
    planted: list[str] = []

    def _racing_reserve(session_factory, *, attempt_id, attempt):
        if not planted:
            # The winner commits here: after this request's replay lookup found
            # nothing, and before its own insert.
            winner_id = service.new_attempt_id()
            planted.append(winner_id)
            real_reserve(
                session_factory,
                attempt_id=winner_id,
                attempt={
                    **attempt,
                    "interaction_id": theirs,
                    "fingerprint": service.fingerprint_for(
                        policy_id="policy-a", interaction_id=theirs, view="full", target_id=target_id
                    ),
                },
            )
        return real_reserve(session_factory, attempt_id=attempt_id, attempt=attempt)

    monkeypatch.setattr(route.attempts, "reserve", _racing_reserve)

    resp = client.post(
        f"/v1/logs/{mine}/content-export",
        json={"view": "full", "target_id": target_id},
        headers=keyed,
    )

    assert planted, "the race never happened, so this proves nothing"
    assert resp.status_code == 409, (
        f"the loser was answered {resp.status_code} with {resp.text}; a key reused for a "
        "different export is a 409 however the collision is discovered"
    )
    assert resp.json()["reason"] == "idempotency_key_reused"
    assert planted[0] not in resp.text, "the loser was handed the winner's attempt id"
    assert not _Receiver.received, "the loser sent content despite losing the race"


def test_a_replay_is_answered_after_the_content_is_purged(env):
    """Replay sits above every gate that consults current state. Lower down it
    would return 404 after a purge instead of the result it actually had."""
    client, Session, port = env
    headers = _key(Session, grants=[CONTENT_EXPORT])
    interaction_id = _interaction(Session)
    target_id = _target(Session, port)
    keyed = {**headers, "Idempotency-Key": "abc-123"}
    body = {"view": "full", "target_id": target_id}

    first = client.post(f"/v1/logs/{interaction_id}/content-export", json=body, headers=keyed)
    assert first.status_code == 202

    session = Session()
    session.query(InteractionContent).delete()
    session.query(ExportTarget).delete()
    session.commit()
    session.close()

    replay = client.post(f"/v1/logs/{interaction_id}/content-export", json=body, headers=keyed)
    assert replay.status_code == 202, "a replay was refused by a gate it does not depend on"
    assert replay.json()["attempt_id"] == first.json()["attempt_id"]
    assert len(_Receiver.received) == 1


@pytest.mark.parametrize("key", ["", "x" * 256, "has space", "has\ttab", "\x01"])
def test_a_malformed_idempotency_key_is_400(env, key):
    client, Session, port = env
    headers = _key(Session, grants=[CONTENT_EXPORT])
    interaction_id = _interaction(Session)
    target_id = _target(Session, port)
    resp = client.post(
        f"/v1/logs/{interaction_id}/content-export",
        json={"view": "full", "target_id": target_id},
        headers={**headers, "Idempotency-Key": key},
    )
    assert resp.status_code == 400
    assert _attempts(Session) == []


def test_every_response_is_uncacheable(env):
    client, Session, port = env
    headers = _key(Session, grants=[CONTENT_EXPORT])
    interaction_id = _interaction(Session)
    target_id = _target(Session, port)
    for body, expected in (
        ({"view": "full", "target_id": target_id}, 202),
        ({"view": "full", "target_id": "nope"}, 404),
        ({"view": "bogus", "target_id": target_id}, 400),
    ):
        resp = client.post(f"/v1/logs/{interaction_id}/content-export", json=body, headers=headers)
        assert resp.status_code == expected
        assert resp.headers["cache-control"] == "no-store"
        assert resp.headers["x-content-type-options"] == "nosniff"
        assert resp.headers["content-security-policy"] == "frame-ancestors 'none'"


def test_an_unauthenticated_request_is_also_uncacheable(env):
    client, Session, port = env
    interaction_id = _interaction(Session)
    resp = client.post(f"/v1/logs/{interaction_id}/content-export", json={"view": "full", "target_id": "t"})
    assert resp.status_code == 401
    assert resp.headers["cache-control"] == "no-store"


def test_the_canary_appears_in_the_submitted_body_and_nowhere_else(env, caplog):
    """The one place it is expected, and no attempt column, note, response or
    log line."""
    import logging

    from app.db.models import ContentExportNote

    client, Session, port = env
    headers = _key(Session, grants=[CONTENT_EXPORT])
    interaction_id = _interaction(Session)
    target_id = _target(Session, port)

    with caplog.at_level(logging.DEBUG):
        resp = client.post(
            f"/v1/logs/{interaction_id}/content-export",
            json={"view": "full", "target_id": target_id},
            headers=headers,
        )
    assert resp.status_code == 202

    # Expected: exactly here.
    assert any(CANARY in body.decode() for body in _Receiver.received)

    # And nowhere else.
    assert CANARY not in resp.text
    assert CANARY not in caplog.text

    session = Session()
    try:
        for row in session.query(ContentExportAttempt).all():
            serialised = str({c.name: getattr(row, c.name) for c in row.__table__.columns})
            assert CANARY not in serialised, "an attempt row carried content"
        for note in session.query(ContentExportNote).all():
            assert CANARY not in note.detail
    finally:
        session.close()


def test_an_ordinary_guard_export_carries_no_content_even_with_capture_on(env):
    """The isolation that matters: turning capture on must not make the ordinary
    export path start carrying prompts."""
    import asyncio

    from app.services.export_service import ExportService

    client, Session, port = env
    del client

    session = Session()
    session.add(
        ExportTarget(
            name="ordinary",
            type="webhook",
            config={"url": f"http://127.0.0.1:{port}/hook"},
            format="ocsf",
            events=["allowed"],
            enabled=True,
        )
    )
    session.commit()
    session.close()

    captured: list[dict] = []

    class _Svc(ExportService):
        async def _send_webhook(self, target, event):  # type: ignore[override]
            captured.append(event)

    asyncio.run(
        _Svc(session_factory=Session).emit(
            request_id="tw_00000000000000ff",
            timestamp="2026-08-19T00:00:00Z",
            event_type="input",
            status="allowed",
            policy_name="policy-a",
            blocked=False,
            transformed=False,
            latency_ms=1.0,
            detectors={"custom_entity": {"data": {"entities": [{"type": "CUSTOM", "value": CANARY}]}}},
            guard_input={"messages": [{"content": CANARY}]},
        )
    )
    assert captured, "nothing was exported, so this proves nothing"
    for event in captured:
        assert CANARY not in str(event)


def test_expired_content_is_never_exported(env):
    """The gate that was missing entirely: an expired row retention has not yet
    purged would otherwise be sent externally."""
    from datetime import timedelta

    client, Session, port = env
    headers = _key(Session, grants=[CONTENT_EXPORT])
    interaction_id = _interaction(Session, expires_at=datetime.now(UTC) - timedelta(days=1))
    target_id = _target(Session, port)

    resp = client.post(
        f"/v1/logs/{interaction_id}/content-export",
        json={"view": "full", "target_id": target_id},
        headers=headers,
    )
    assert resp.status_code == 404, "expired content was exportable"
    assert _Receiver.received == [], "expired content left the system"
    assert _attempts(Session) == []


def test_content_still_within_its_retention_window_is_exported(env):
    """Otherwise the test above would pass on any 404."""
    from datetime import timedelta

    client, Session, port = env
    headers = _key(Session, grants=[CONTENT_EXPORT])
    interaction_id = _interaction(Session, expires_at=datetime.now(UTC) + timedelta(days=1))
    target_id = _target(Session, port)

    resp = client.post(
        f"/v1/logs/{interaction_id}/content-export",
        json={"view": "full", "target_id": target_id},
        headers=headers,
    )
    assert resp.status_code == 202
    assert len(_Receiver.received) == 1


def test_expiry_is_decided_before_the_target(env):
    """So an expired record cannot be used to probe destination configuration."""
    from datetime import timedelta

    client, Session, port = env
    headers = _key(Session, grants=[CONTENT_EXPORT])
    interaction_id = _interaction(Session, expires_at=datetime.now(UTC) - timedelta(days=1))
    target_id = _target(Session, port, allow=False)

    resp = client.post(
        f"/v1/logs/{interaction_id}/content-export",
        json={"view": "full", "target_id": target_id},
        headers=headers,
    )
    assert resp.status_code == 404, "the target was evaluated before expiry"


def test_the_attempt_records_the_real_payload_size(env):
    """payload_bytes is the schema's deliberate size evidence. Recording zero
    would make every attempt claim the same false thing."""
    client, Session, port = env
    headers = _key(Session, grants=[CONTENT_EXPORT])
    interaction_id = _interaction(Session)
    target_id = _target(Session, port)

    resp = client.post(
        f"/v1/logs/{interaction_id}/content-export",
        json={"view": "full", "target_id": target_id},
        headers=headers,
    )
    assert resp.status_code == 202
    row = _attempts(Session)[0]
    assert row.payload_bytes == len(_Receiver.received[0]), "the recorded size is not the sent size"
    assert row.payload_bytes > 0


def test_an_oversized_projection_costs_neither_a_row_nor_a_connection(env, monkeypatch):
    """413 before admission and before the reservation."""
    import app.routes.content_export as route

    client, Session, port = env
    headers = _key(Session, grants=[CONTENT_EXPORT])
    interaction_id = _interaction(Session)
    target_id = _target(Session, port)

    monkeypatch.setattr(route, "_MAX_PAYLOAD_BYTES", 10)
    resp = client.post(
        f"/v1/logs/{interaction_id}/content-export",
        json={"view": "full", "target_id": target_id},
        headers=headers,
    )
    assert resp.status_code == 413
    assert _attempts(Session) == [], "an oversized projection reserved an attempt"
    assert _Receiver.received == []


def test_a_destination_refused_at_send_time_is_409_before_any_reservation(env, monkeypatch):
    """The SSRF controls have their own suite; this pins where their refusal
    lands in the order."""
    import app.routes.content_export as route
    from app.services.export_transport import DestinationRefused

    client, Session, port = env
    headers = _key(Session, grants=[CONTENT_EXPORT])
    interaction_id = _interaction(Session)
    target_id = _target(Session, port)

    def _refuse(url, posture):
        raise DestinationRefused("the destination resolves to a non-public address")

    monkeypatch.setattr(route, "validate_destination", _refuse)
    resp = client.post(
        f"/v1/logs/{interaction_id}/content-export",
        json={"view": "full", "target_id": target_id},
        headers=headers,
    )
    assert resp.status_code == 409
    assert resp.json()["reason"] == "destination_refused"
    assert _attempts(Session) == []


def test_a_cleanup_failure_is_a_note_and_does_not_change_the_response(env, monkeypatch):
    """Cleanup runs after settlement and outside the thing that owns a state, so
    it cannot contradict one. Before this, CLEANUP_BUDGET_SECONDS was dead code
    and cleanup_failed could never be written."""
    import app.services.export_transport as transport
    from app.db.models import ContentExportNote

    client, Session, port = env
    headers = _key(Session, grants=[CONTENT_EXPORT])
    interaction_id = _interaction(Session)
    target_id = _target(Session, port)

    original = transport.send_payload

    async def _send_then_break_cleanup(**kwargs):
        result = await original(**kwargs)
        real_closer = result.closer

        async def _boom():
            if real_closer is not None:
                await real_closer()
            raise RuntimeError("close failed")

        result.closer = _boom
        return result

    monkeypatch.setattr(transport, "send_payload", _send_then_break_cleanup)
    import app.routes.content_export as route

    monkeypatch.setattr(route, "send_payload", _send_then_break_cleanup)

    resp = client.post(
        f"/v1/logs/{interaction_id}/content-export",
        json={"view": "full", "target_id": target_id},
        headers=headers,
    )
    assert resp.status_code == 202, "a cleanup failure changed the response"
    row = _attempts(Session)[0]
    assert row.state == "succeeded", "a cleanup failure changed the state"

    session = Session()
    try:
        kinds = [n.kind for n in session.query(ContentExportNote).all()]
    finally:
        session.close()
    assert "cleanup_failed" in kinds


def test_cleanup_is_bounded(env, monkeypatch):
    """An unbounded close would hold the handler and its admission permit
    indefinitely."""
    import asyncio
    import time

    import app.routes.content_export as route
    import app.services.export_transport as transport

    client, Session, port = env
    headers = _key(Session, grants=[CONTENT_EXPORT])
    interaction_id = _interaction(Session)
    target_id = _target(Session, port)

    monkeypatch.setattr(route, "CLEANUP_BUDGET_SECONDS", 0.2)
    original = transport.send_payload

    async def _send_then_hang_cleanup(**kwargs):
        result = await original(**kwargs)
        real_closer = result.closer

        async def _hang():
            if real_closer is not None:
                await real_closer()
            await asyncio.sleep(30)

        result.closer = _hang
        return result

    monkeypatch.setattr(route, "send_payload", _send_then_hang_cleanup)

    started = time.monotonic()
    resp = client.post(
        f"/v1/logs/{interaction_id}/content-export",
        json={"view": "full", "target_id": target_id},
        headers=headers,
    )
    elapsed = time.monotonic() - started

    assert resp.status_code == 202
    assert _attempts(Session)[0].state == "succeeded"
    # The wall clock is the assertion. Without it the test cannot tell a bounded
    # close from one that merely finished eventually -- the hang is 30s and an
    # unbounded close would still return 202, just much later.
    assert elapsed < 5, f"cleanup was not bounded: {elapsed:.1f}s"


@pytest.mark.parametrize("api_key_id", [None, ""])
def test_a_credential_without_an_api_key_id_cannot_export(env, api_key_id):
    """The uniqueness the idempotency contract rests on.

    SQLite does not make (NULL, digest) unique, so an attempt row with a null
    api_key_id constrains nothing: one key could reserve twice and disclose
    twice. No current middleware branch grants admin without an APIKey row --
    its primary key is NOT NULL -- so this is defence in depth. The route
    relies on the property, so the route checks it, and this drives the handler
    directly because no supported credential can produce the state.
    """
    import asyncio

    import app.routes.content_export as route

    client, Session, port = env
    interaction_id = _interaction(Session)
    target_id = _target(Session, port)

    payload = json.dumps({"view": "full", "target_id": target_id}).encode()
    path = f"/v1/logs/{interaction_id}/content-export"

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
            "app": client.app,
            "path_params": {"interaction_id": str(interaction_id)},
        }
        request = Request(scope, _receive)
        # Everything else that authorises this request still holds.
        request.state.role = "admin"
        request.state.grants = frozenset({CONTENT_EXPORT})
        request.state.policy_id = "policy-a"
        request.state.api_key_id = api_key_id
        return await route._authorize_and_export(request)

    resp = asyncio.run(_go())
    assert resp.status_code == 403, bytes(resp.body)
    assert not _Receiver.received, "content was exported without a credential id to bind it to"


# ---------------------------------------------------------------------------
# NAT64: the declared posture must reach the real boundary, through the route
#
# Unit tests of `validate_destination` prove the validator. They do not prove
# the route hands it the posture the operator declared, and a wiring mistake
# there is a live bypass on a green tree.
# ---------------------------------------------------------------------------

_NSP_PRIVATE = "2600:1f00:a01:203::"  # 10.1.2.3 under 2600:1f00::/32
_NSP = "2600:1f00::/32"
_FILLER = ("2001:db8:1::/48", "2001:db8:2::/48", "2001:db8:3::/48", "2001:db8:4::/48")


@pytest.mark.parametrize("position", [0, 1, 2, 3])
def test_a_real_export_refuses_a_translated_address_at_every_list_position(env, monkeypatch, position):
    """The matching prefix in each position of a list of four.

    "A later entry" binds one non-first element. A parser or wiring path that
    retains only the first and last passes a last-position fixture while an
    omitted middle prefix stays a live bypass.
    """
    import app.routes.content_export as route
    import app.services.export_transport as transport
    from app.config import Settings

    client, Session, port = env
    prefixes = list(_FILLER[:3])
    prefixes.insert(position, _NSP)
    client.app.state.settings = Settings(PREF64=",".join(prefixes))
    monkeypatch.setattr(transport, "_resolve", lambda host, p: [_NSP_PRIVATE])
    monkeypatch.setattr(route, "validate_destination", transport.validate_destination)

    headers = _key(Session, grants=[CONTENT_EXPORT])
    interaction_id = _interaction(Session)
    target_id = _target(Session, port, allow=True, url="https://receiver.example/hook")
    resp = client.post(
        f"/v1/logs/{interaction_id}/content-export",
        json={"view": "full", "target_id": target_id},
        headers=headers,
    )
    assert resp.status_code == 409, resp.text
    assert "translates to a non-public address" in resp.text


def test_a_real_export_refuses_when_the_posture_is_unset(env, monkeypatch):
    """Distinct from the configured case.

    Without this, `validate_destination(url, NONE if posture.is_unset else
    posture)` survives: the direct tests still show the validator refuses an
    unset posture, and real exports quietly get the permissive one.
    """
    import app.routes.content_export as route
    import app.services.export_transport as transport
    from app.config import Settings

    client, Session, port = env
    client.app.state.settings = Settings(PREF64=None)
    monkeypatch.setattr(transport, "_resolve", lambda host, p: ["93.184.216.34"])
    monkeypatch.setattr(route, "validate_destination", transport.validate_destination)

    headers = _key(Session, grants=[CONTENT_EXPORT])
    interaction_id = _interaction(Session)
    target_id = _target(Session, port, allow=True, url="https://receiver.example/hook")
    resp = client.post(
        f"/v1/logs/{interaction_id}/content-export",
        json={"view": "full", "target_id": target_id},
        headers=headers,
    )
    assert resp.status_code == 409, resp.text

    # The message poses the deployment question and suggests NO value.
    # "does not contain 'none'" is strictly weaker: "set PREF64=64:ff9b::/96 to
    # continue" passes that while handing the operator something to paste.
    body = resp.text
    assert "PREF64" in body
    assert "confirmed which is true for this network" in body
    assert "PREF64=" not in body
    assert "none" not in body
