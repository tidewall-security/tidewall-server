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

from app.auth.grants import CONTENT_EXPORT, CONTENT_READ, MATCHES_READ
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

    monkeypatch.setattr(route, "validate_destination", lambda url: ("127.0.0.1", port, ["127.0.0.1"]))

    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)

    app = FastAPI()
    app.add_middleware(AuthMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)
    app.state.session_factory = Session
    app.state.boot_id = "boot-test"
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


def _interaction(Session, *, policy_id="policy-a", content=True, expires_at=None):
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
                captured_at=datetime.now(UTC),
                expires_at=expires_at,
            )
        )
    session.commit()
    session.close()
    return interaction_id


def _target(Session, port, *, allow=True, policy="policy-a", views=("full",), enabled=True, type_="webhook"):
    session = Session()
    target = ExportTarget(
        name="siem",
        type=type_,
        config={"url": f"http://127.0.0.1:{port}/hook"},
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
