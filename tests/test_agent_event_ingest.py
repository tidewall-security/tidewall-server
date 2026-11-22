"""File-backed collector writes through the production router and authentication."""

import asyncio
import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Barrier
from uuid import uuid4

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from httpx import ASGITransport, AsyncClient
from sqlalchemy import event, text
from sqlalchemy.exc import OperationalError

from app.agent_events import Batch, Heartbeat
from app.auth.key_utils import hash_key
from app.db.engine import get_engine, get_session_factory
from app.db.models import AccessToken, Base, CollectorOutcome, Device, Policy
from app.main import create_app
from app.services.collector_identity import CollectorPrincipal

VECTORS = json.loads((Path(__file__).parent / "fixtures/collector_v1.json").read_text())
DEVICE = json.loads(VECTORS["batch"])["enrollment_id"]
NOW = datetime(2026, 1, 1, tzinfo=UTC)
EVENTS = "/v1/collector/observations"
HEALTH = "/v1/collector/heartbeat"
COLLECTION = ("agent_sessions", "agent_observations", "collector_outcomes", "collector_progress")


def observation(index=0):
    return json.loads(VECTORS["observation_vectors"][index]["canonical"])


def batch(*rows, device=DEVICE):
    return {
        "version": 1,
        "enrollment_id": device,
        "batch_id": str(uuid4()),
        "rows": [{"ordinal": number, "observation": obs} for number, obs in rows],
    }


def provision(sessions, device=DEVICE):
    token = f"at_{uuid4().hex}"
    with sessions.begin() as session:
        session.add(
            Device(
                id=device,
                policy_id="A",
                installation_id=str(uuid4()),
                device_name="fixture",
                user_name="",
                user_email="",
                purpose="collector_write",
                collector_approved_at=NOW,
            )
        )
        session.flush()
        session.add(AccessToken(token_hash=hash_key(token), device_id=device, expires_at=datetime(2099, 1, 1)))
    return {"Authorization": f"Bearer {token}"}, CollectorPrincipal(device, "A", hash_key(token))


@pytest.fixture(name="store")
def collector_store_fixture(tmp_path):
    engine = get_engine(f"sqlite:///{tmp_path}/events.db")
    Base.metadata.create_all(engine)
    sessions = get_session_factory(engine)
    with sessions.begin() as session:
        session.add_all([Policy(id=p, name=p) for p in ["A", "B"]])
    headers, principal = provision(sessions)
    app = create_app()
    app.state.session_factory = sessions
    client = TestClient(app)
    yield client, headers, sessions, principal
    client.close()
    engine.dispose()


def counts(sessions, tables=COLLECTION):
    with sessions() as session:
        return [session.scalar(text(f"SELECT COUNT(*) FROM {table}")) for table in tables]


def test_lost_ack_mixed_replay_and_scoped_source_keys(store):
    client, headers, sessions, _ = store
    one, two, orphan = (observation(i) for i in range(3))
    first = batch((1, one), (2, two))

    # Simulate a transport dropping the real response after the app commits.
    class DropResponse:
        async def __call__(self, scope, receive, send):
            async def disconnected(message):
                if message["type"] == "http.response.start":
                    raise ConnectionResetError("lost response")
                await send(message)

            await client.app(scope, receive, disconnected)

    with pytest.raises(ConnectionResetError):
        TestClient(DropResponse()).post(EVENTS, headers=headers, json=first)
    with sessions() as session:
        first_id, first_time, first_bytes = session.execute(
            text("SELECT event_id, received_at, observation_json FROM agent_observations WHERE digest=:digest"),
            {"digest": VECTORS["observation_vectors"][0]["sha256"]},
        ).one()
    assert first_bytes == VECTORS["observation_vectors"][0]["canonical"]
    changed = {**two, "availability": "redacted"}
    mixed = batch((1, one), (3, changed), (4, orphan))
    response = client.post(EVENTS, headers=headers, json=mixed)
    assert response.status_code == 200
    duplicate, conflict, inserted = response.json()["results"]
    assert duplicate == {
        "ordinal": 1,
        "digest": VECTORS["observation_vectors"][0]["sha256"],
        "outcome": "duplicate",
        "event_id": first_id,
    }
    assert conflict["outcome"] == "rejected" and conflict["reason"] == "identity_conflict"
    assert inserted["outcome"] == "accepted"
    retry = client.post(EVENTS, headers=headers, json=mixed).json()["results"]
    assert retry[1] == conflict
    assert retry[2]["event_id"] == inserted["event_id"] and retry[2]["outcome"] == "duplicate"
    occupied = client.post(EVENTS, headers=headers, json=batch((1, orphan))).json()["results"][0]
    assert occupied["reason"] == "identity_conflict"

    hook = {
        **orphan,
        "native_session_token": one["native_session_token"],
        "native_tool_call_token": one["native_tool_call_token"],
        "tool_name": "Read",
        "gaps": [],
        "source": {**orphan["source"], "collector_observation_id": str(uuid4())},
    }
    hook_id = client.post(EVENTS, headers=headers, json=batch((5, hook))).json()["results"][0]["event_id"]
    other = str(uuid4())
    other_headers, _ = provision(sessions, other)
    foreign = client.post(EVENTS, headers=other_headers, json=batch((1, one), device=other))
    assert len({first_id, hook_id, foreign.json()["results"][0]["event_id"]}) == 3
    with sessions() as session:
        original = session.execute(
            text("SELECT received_at,observation_json,session_id FROM agent_observations " "WHERE event_id=:id"),
            {"id": first_id},
        ).one()
        assert original[:2] == (first_time, first_bytes)
        assert (
            session.scalar(text("SELECT session_id FROM agent_observations WHERE event_id=:id"), {"id": hook_id})
            == original[2]
        )
        assert session.scalar(text("SELECT COUNT(*) FROM agent_observations WHERE session_id IS NULL")) == 1
    assert counts(sessions) == [3, 5, 7, 2]
    assert counts(sessions, ("interactions", "interaction_contents", "vaults", "activity_log")) == [0, 0, 0, 0]


def test_ordinal_retirement_and_duplicate_expiry_before_purge(store):
    from app.services.agent_event_service import ingest

    _, _, sessions, principal = store
    one = {**observation(), "source_at": "2099-01-01T00:00:00Z"}

    def submit(ordinal, payload, days):
        with sessions() as session:
            return ingest(
                session, principal, Batch.model_validate(batch((ordinal, payload))), lambda: NOW + timedelta(days=days)
            ).results[0]

    first = submit(8, one, 0)
    assert submit(5, observation(1), 0).reason == "retired_ordinal"
    assert submit(9, one, 29).event_id == first.event_id
    with sessions() as session:
        expiry = session.scalars(
            text("SELECT expires_at FROM collector_outcomes WHERE event_id=:id"), {"id": first.event_id}
        ).all()
        assert len(expiry) == 2 and all(datetime.fromisoformat(x) == datetime(2026, 1, 31) for x in expiry)
    for ordinal in [8, 9]:
        assert submit(ordinal, one, 30).reason == "retired_ordinal"
    with sessions() as session:
        dates = []
        for ordinal in [8, 9]:
            outcome = session.get(CollectorOutcome, (DEVICE, ordinal, first.digest))
            dates.append((outcome.received_at, outcome.expires_at))
        assert dates == [
            (datetime(2026, 1, 1), datetime(2026, 1, 31)),
            (datetime(2026, 1, 30), datetime(2026, 1, 31)),
        ]
    fresh = submit(10, one, 30)
    assert fresh.outcome == "accepted" and fresh.event_id != first.event_id


@pytest.mark.parametrize(
    ("path", "body", "status", "code"),
    [
        (EVENTS, {"version": True}, 422, "invalid_envelope"),
        (EVENTS, {"version": 2}, 422, "unsupported_version"),
        (
            EVENTS,
            batch((40, observation()), (41, {**observation(1), "content": "private"}), (42, observation(2))),
            422,
            "invalid_row",
        ),
        (EVENTS, batch((1, observation()), (2, observation())), 422, "invalid_envelope"),
        (EVENTS, batch((1, observation()), device=str(uuid4())), 403, None),
        (HEALTH, {**json.loads(VECTORS["heartbeat"]), "enrollment_id": str(uuid4())}, 403, None),
    ],
)
def test_http_refusal_never_acknowledges_or_writes(store, path, body, status, code):
    client, headers, sessions, _ = store
    result = client.post(path, headers=headers, json=body)
    assert result.status_code == status
    if code:
        assert result.json() == {"code": code} and len(result.content) <= 128
    assert counts(sessions) == [0, 0, 0, 0]


@pytest.mark.parametrize(("path", "cap"), [(EVENTS, 65536), (HEALTH, 2048)])
def test_streaming_caps_and_media(store, path, cap):
    client, headers, sessions, _ = store
    for media, encoding in [
        ("text/plain", "identity"),
        ("application/json", "gzip"),
        ("application/json;charset=latin-1", "identity"),
    ]:
        result = client.post(
            path, headers={**headers, "content-type": media, "content-encoding": encoding}, content=b"x"
        )
        assert result.status_code == 415

    async def stream():
        yield b" " * cap
        yield b"x"
        raise AssertionError("read beyond the first over-budget chunk")

    async def post_stream():
        async with AsyncClient(transport=ASGITransport(app=client.app), base_url="http://test") as transport:
            return await transport.post(path, headers={**headers, "content-type": "application/json"}, content=stream())

    result = asyncio.run(post_stream())
    assert result.status_code == 413
    assert counts(sessions) == [0, 0, 0, 0]


def test_mid_batch_storage_failure_rolls_back_and_busy_returns_no_ack(store):
    client, headers, sessions, _ = store
    engine = sessions.kw["bind"]
    with engine.begin() as conn:
        conn.exec_driver_sql(
            "CREATE TRIGGER injected_failure BEFORE INSERT ON collector_outcomes "
            "WHEN NEW.ordinal=2 BEGIN SELECT RAISE(ABORT,'synthetic failure'); END"
        )
    body = batch((1, observation()), (2, observation(1)))

    def unavailable():
        response = client.post(EVENTS, headers=headers, json=body)
        assert response.status_code == 503
        assert "results" not in response.json() and "synthetic" not in response.text
        assert counts(sessions) == [0, 0, 0, 0]

    unavailable()
    with engine.begin() as conn:
        conn.exec_driver_sql("DROP TRIGGER injected_failure")

    @event.listens_for(engine, "checkout")
    def no_wait(dbapi_connection, *_):
        dbapi_connection.execute("PRAGMA busy_timeout=0")

    with engine.connect() as owner:
        owner.exec_driver_sql("BEGIN IMMEDIATE")
        unavailable()
    assert client.post(EVENTS, headers=headers, json=body).status_code == 200


def test_simultaneous_retries_share_one_event_and_one_outcome(store):
    client, headers, sessions, _ = store
    start = Barrier(2)
    body = batch((1, observation()))

    def post():
        start.wait(timeout=5)
        response = client.post(EVENTS, headers=headers, json=body)
        assert response.status_code == 200
        return response.json()["results"][0]

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = [future.result() for future in [pool.submit(post), pool.submit(post)]]
    assert {r["outcome"] for r in results} == {"accepted", "duplicate"}
    assert results[0]["event_id"] == results[1]["event_id"]
    assert counts(sessions) == [1, 1, 1, 1]


@pytest.mark.parametrize("operation", ["batch", "heartbeat"])
@pytest.mark.parametrize(("change", "status"), [("status='revoked'", 401), ("policy_id='B'", 403)])
@pytest.mark.parametrize("admin_first", [True, False])
def test_admin_change_and_collection_serialize(store, operation, change, status, admin_first):
    from app.services.agent_event_service import heartbeat, ingest

    _, _, sessions, principal = store

    def write(clock):
        with sessions() as session:
            if operation == "batch":
                return ingest(session, principal, Batch.model_validate(batch((1, observation()))), clock)
            return heartbeat(session, principal, Heartbeat.model_validate_json(VECTORS["heartbeat"]), clock)

    def admin():
        with sessions.begin() as session:
            session.connection().exec_driver_sql("PRAGMA busy_timeout=0")
            session.execute(text(f"UPDATE devices SET {change} WHERE id=:id"), {"id": DEVICE})

    if admin_first:
        admin()
        with pytest.raises(HTTPException) as refusal:
            write(lambda: NOW)
        assert refusal.value.status_code == status
        assert counts(sessions) == [0, 0, 0, 0]
    else:

        def clock():
            # Exercise both the initial authorization and the finalization
            # boundary. The independent writer must already be excluded.
            with pytest.raises(OperationalError) as busy:
                admin()
            assert getattr(busy.value.orig, "sqlite_errorcode", None) == sqlite3.SQLITE_BUSY
            return NOW

        write(clock)
        admin()
        assert counts(sessions) == ([1, 1, 1, 1] if operation == "batch" else [0, 0, 0, 1])
        with pytest.raises(HTTPException) as refusal:
            write(lambda: NOW)
        assert refusal.value.status_code == status


@pytest.mark.parametrize("operation", ["batch", "heartbeat"])
def test_actual_expiry_rechecked_before_commit(store, operation):
    from app.services.agent_event_service import heartbeat, ingest

    _, _, sessions, principal = store
    times = iter([NOW, datetime(2099, 1, 1, tzinfo=UTC)])
    with sessions() as session, pytest.raises(HTTPException) as refusal:
        if operation == "batch":
            ingest(session, principal, Batch.model_validate(batch((1, observation()))), lambda: next(times))
        else:
            heartbeat(session, principal, Heartbeat.model_validate_json(VECTORS["heartbeat"]), lambda: next(times))
    assert refusal.value.status_code == 401
    assert counts(sessions) == [0, 0, 0, 0]


def test_unavailable_authentication_storage_returns_retryable_no_ack(store):
    client, headers, sessions, _ = store
    with sessions.begin() as session:
        session.execute(text("ALTER TABLE access_tokens RENAME TO unavailable"))
    response = client.post(EVENTS, headers=headers, json=batch((1, observation())))
    assert response.status_code == 503
    assert "results" not in response.json()
    assert counts(sessions) == [0, 0, 0, 0]


@pytest.mark.parametrize(
    ("path", "body"), [(EVENTS, batch((1, observation()))), (HEALTH, json.loads(VECTORS["heartbeat"]))]
)
def test_guard_credential_cannot_use_write_routes(store, path, body):
    client, headers, sessions, _ = store
    with sessions.begin() as session:
        session.get(Device, DEVICE).purpose = "guard_device"
    assert client.post(path, headers=headers, json=body).status_code == 403
    assert counts(sessions) == [0, 0, 0, 0]


def test_newly_authenticated_policy_cannot_inherit_old_receipts_or_health(store):
    client, headers, sessions, _ = store
    original = batch((1, observation()))
    assert client.post(EVENTS, headers=headers, json=original).status_code == 200
    with sessions.begin() as session:
        session.get(Device, DEVICE).policy_id = "B"
    for path, body in [(EVENTS, original), (HEALTH, json.loads(VECTORS["heartbeat"]))]:
        assert client.post(path, headers=headers, json=body).status_code == 403
    assert counts(sessions) == [1, 1, 1, 1]


def test_retired_ordinal_stays_retired_with_live_rejection_after_original_event_purge(store):
    from app.services.agent_event_service import ingest

    _, _, sessions, principal = store
    original = Batch.model_validate(batch((1, observation())))
    conflict = Batch.model_validate(batch((1, observation(2))))

    def submit(body, day):
        with sessions() as session:
            return ingest(session, principal, body, lambda: NOW + timedelta(days=day)).results[0]

    assert submit(original, 0).outcome == "accepted"
    assert submit(conflict, 29).reason == "identity_conflict"
    # This simulates the expiry worker's FK cascade; the unrelated rejection
    # has 29 days left and must still answer its own exact replay.
    with sessions.begin() as session:
        session.execute(text("DELETE FROM agent_observations WHERE device_id=:device"), {"device": DEVICE})
    assert submit(original, 30).reason == "retired_ordinal"
    assert submit(conflict, 30).reason == "identity_conflict"
    expired = submit(conflict, 59)
    assert expired.reason == "retired_ordinal"
    with sessions() as session:
        outcome = session.get(CollectorOutcome, (DEVICE, 1, expired.digest))
        assert (outcome.received_at, outcome.expires_at) == (datetime(2026, 1, 30), datetime(2026, 3, 1))
