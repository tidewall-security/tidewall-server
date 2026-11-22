"""Read the actual HTTP projections under separate policy credentials."""

import asyncio
import json
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import select

from app.agent_events import Batch, Heartbeat
from app.db.models import AgentSession, CollectorProgress, Device, DeviceTombstone
from app.services.agent_event_service import heartbeat, ingest
from tests.test_agent_event_ingest import (
    DEVICE,
    EVENTS,
    HEALTH,
    VECTORS,
    batch,
    collector_store_fixture,
    counts,
    observation,
    provision,
)
from tests.test_content_api import _key

store = collector_store_fixture
SESSIONS = "/v1/agent-sessions"
UNASSIGNED = "/v1/agent-observations?unassigned=true"
COLLECTORS = "/v1/collector-health"


def read(client, path, headers):
    response = client.get(path, headers=headers)
    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "no-store"
    return response.json()


def prepare(store, policy="A"):
    client, writer, sessions, _ = store
    device = DEVICE
    if policy != "A":
        device = str(uuid4())
        writer, _ = provision(sessions, device)
        with sessions.begin() as db:
            db.get(Device, device).policy_id = policy
    payload = batch((1, observation()), (2, observation(2)), device=device)
    assert client.post(EVENTS, headers=writer, json=payload).status_code == 200
    report = {**json.loads(VECTORS["heartbeat"]), "enrollment_id": device}
    assert client.post(HEALTH, headers=writer, json=report).status_code == 200
    return device


def test_scoped_sessions_and_unassigned(store):
    client, writer, sessions, _ = store
    devices = {p: prepare(store, p) for p in ("A", "B")}
    for role, scope, visible in [("viewer", "A", ["A"]), ("admin", "B", ["B"]), ("admin", None, ["A", "B"])]:
        reader = _key(sessions, role=role, policy_id=scope)
        for path in (SESSIONS, UNASSIGNED, COLLECTORS):
            rows = read(client, path, reader)["items"]
            assert sorted(row["device_id"] for row in rows) == sorted(devices[p] for p in visible)
        listed = read(client, SESSIONS, reader)["items"]
        for row in listed:
            assert row["observation_count"] == 1
            detail = read(client, f"{SESSIONS}/{row['session_id']}/observations", reader)["items"]
            assert len(detail) == 1 and detail[0]["session_id"] == row["session_id"]
        orphan = read(client, UNASSIGNED, reader)["items"][0]
        assert orphan["session_id"] is None and "missing_native_session_id" in orphan["gaps"]
        assert all(r["assessment_status"] == "not_assessed" for r in [*detail, orphan])
        assert orphan["agent_version"] == "unknown" and orphan["availability"] == observation(2)["availability"]
        assert orphan["received_at"].endswith("Z") and orphan["source_at"] is None
    with sessions() as db:
        foreign = db.scalar(select(AgentSession.session_id).where(AgentSession.policy_id == "B"))
    reader = _key(sessions, policy_id="A")
    guessed = [client.get(f"{SESSIONS}/{key}/observations", headers=reader) for key in (foreign, str(uuid4()), "bad")]
    assert [r.status_code for r in guessed] == [404] * 3 and len({r.content for r in guessed}) == 1
    for path in (SESSIONS, UNASSIGNED, COLLECTORS, f"{SESSIONS}/{foreign}/observations"):
        for headers, status in [
            ({}, 401),
            (writer, 403),
            (_key(sessions, role="api", policy_id="A"), 403),
            (_key(sessions, policy_id=None), 403),
        ]:
            refusal = client.get(path, headers=headers)
            assert refusal.status_code == status and refusal.headers["Cache-Control"] == "no-store"


def test_keyset_pages_bound_to_scope_and_query(store):
    client, writer, sessions, _ = store
    prepare(store)
    prepare(store, "B")
    headers = _key(sessions, policy_id="A")
    sample = observation(2)

    def hook():
        return {**sample, "source": {**sample["source"], "collector_observation_id": str(uuid4())}}

    assert client.post(EVENTS, headers=writer, json=batch((3, hook()), (4, hook()), (5, hook()))).status_code == 200
    first = read(client, UNASSIGNED + "&limit=2", headers)
    token = first["next_cursor"]
    assert token
    url = UNASSIGNED + "&limit=2&cursor=" + token
    second = read(client, url, headers)
    ordered = read(client, UNASSIGNED, headers)["items"]
    assert first["items"] + second["items"] == ordered
    assert len({r["event_id"] for r in ordered}) == 4 and second["next_cursor"] is None
    assert [(r["received_at"], r["event_id"]) for r in ordered] == sorted(
        [(r["received_at"], r["event_id"]) for r in ordered], reverse=True
    )
    for path, reader in [
        (url, _key(sessions, policy_id="B")),
        (SESSIONS + "?cursor=" + token, headers),
        (UNASSIGNED + "&cursor=invalid", headers),
    ]:
        assert client.get(path, headers=reader).status_code == 400
    for limit in (0, 101):
        assert client.get(SESSIONS + f"?limit={limit}", headers=headers).status_code == 422
    assert client.get("/v1/agent-observations", headers=headers).status_code in (400, 422)


def test_expiry_and_device_delete(store):
    client, _, sessions, principal = store
    now = datetime.now(UTC)
    first = now - timedelta(days=30)
    obs = {**observation(), "source_at": "2099-02-04T00:00:00Z"}

    def submit(ordinal, at):
        with sessions() as db:
            return ingest(db, principal, Batch.model_validate(batch((ordinal, obs))), lambda: at).results[0]

    assert submit(1, first).outcome == "accepted"
    assert submit(2, now - timedelta(days=1)).outcome == "duplicate"
    report = Heartbeat.model_validate_json(VECTORS["heartbeat"])
    with sessions() as db:
        heartbeat(db, principal, report, lambda: first)
        session_id = db.scalar(select(AgentSession.session_id))
        digest = db.get(CollectorProgress, DEVICE).heartbeat_digest
    reader = _key(sessions, policy_id="A")
    assert counts(sessions) == [1, 1, 2, 1]
    assert read(client, SESSIONS, reader)["items"] == []
    assert client.get(f"{SESSIONS}/{session_id}/observations", headers=reader).status_code == 404

    def check_health():
        (row,) = read(client, COLLECTORS, reader)["items"]
        assert row["received_at"] is None and row["heartbeat"] is None
        assert row["totals"] == report.totals.model_dump() and row["heartbeat_revision"] == report.revision

    check_health()
    from app.services.scheduler import Scheduler, collection_retention_job

    async def run_job():
        await collection_retention_job(sessions, scheduler=Scheduler()).run()

    asyncio.run(run_job())
    assert counts(sessions) == [0, 0, 0, 1]
    with sessions() as db:
        p = db.get(CollectorProgress, DEVICE)
        assert p.high_water == 2 and p.heartbeat_digest == digest and p.heartbeat_expires_at is None
    for ordinal in (1, 2):
        assert submit(ordinal, now).reason == "retired_ordinal"
    with sessions() as db:
        heartbeat(db, principal, report, lambda: now)
    check_health()
    assert submit(3, now).outcome == "accepted"
    admin = _key(sessions, role="admin", policy_id="A")
    device_path = f"/v1/devices/{DEVICE}"
    assert client.patch(device_path, headers=admin, json={"status": "revoked"}).is_success
    assert client.delete(device_path, headers=admin).is_success
    assert counts(sessions) == [0, 0, 0, 0]
    with sessions() as db:
        assert db.scalar(select(DeviceTombstone).where(DeviceTombstone.device_id == DEVICE)) is not None


def test_expired_session_cannot_reappear_while_scheduler_is_stopped(store):
    client, _, sessions, principal = store
    now = datetime.now(UTC)
    # Different source keys in the same session; the first is expired but still on disk.
    first = observation()
    changed = {**first, "source": {**first["source"], "parser_observation_token": "e" * 64}}
    with sessions() as db:
        ingest(db, principal, Batch.model_validate(batch((1, first))), lambda: now - timedelta(days=32))
        old_id = db.scalar(select(AgentSession.session_id))
    reader = _key(sessions, policy_id="A")
    assert read(client, SESSIONS, reader)["items"] == []
    with sessions() as db:
        ingest(db, principal, Batch.model_validate(batch((2, changed))), lambda: now)
    (fresh,) = read(client, SESSIONS, reader)["items"]
    assert fresh["session_id"] != old_id
    assert fresh["observation_count"] == 1 and fresh["received_at"] == now.isoformat().replace("+00:00", "Z")
    assert client.get(f"{SESSIONS}/{old_id}/observations", headers=reader).status_code == 404
    assert counts(sessions) == [1, 1, 1, 1]


def test_collection_serializes_policy_delete(store):
    import sqlite3

    from sqlalchemy import delete
    from sqlalchemy.exc import IntegrityError, OperationalError

    from app.db.models import Policy

    _, _, sessions, principal = store

    def remove_policy():
        with sessions.begin() as db:
            db.connection().exec_driver_sql("PRAGMA busy_timeout=0")
            db.execute(delete(Policy).where(Policy.id == "A"))

    def clock():
        with pytest.raises(OperationalError) as busy:
            remove_policy()
        assert getattr(busy.value.orig, "sqlite_errorcode", None) == sqlite3.SQLITE_BUSY
        return datetime.now(UTC)

    with sessions() as db:
        ingest(db, principal, Batch.model_validate(batch((1, observation()))), clock)
    with pytest.raises(IntegrityError):
        remove_policy()
    assert counts(sessions) == [1, 1, 1, 1]
