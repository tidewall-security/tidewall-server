import json

from sqlalchemy import text

from tests.test_agent_event_ingest import DEVICE, EVENTS, HEALTH, VECTORS, batch, observation
from tests.test_agent_event_ingest import collector_store_fixture as collector_store_fixture


def test_snapshot_replay_and_conflicts_preserve_progress(store):
    client, headers, sessions, _ = store
    assert client.post(EVENTS, headers=headers, json=batch((17, observation()))).status_code == 200
    original = json.loads(VECTORS["heartbeat"])
    original["totals"]["expired"] = 6

    def send(body):
        return client.post(HEALTH, headers=headers, json=body)

    def snapshot():
        with sessions() as session:
            return session.execute(text("SELECT * FROM collector_progress")).mappings().one()

    expected = {
        "version": 1,
        "enrollment_id": DEVICE,
        "revision": 1,
        "capture": "metadata_only",
        "retain_content": False,
    }
    assert send(original).json() == expected
    before = snapshot()
    assert send(original).json() == expected and snapshot() == before
    overrides: list[dict] = [{"capture": "enabled"}, {"retain_content": True}, {"policy_id": "B"}]
    for extra in overrides:
        refusal = send({**original, **extra})
        assert refusal.status_code == 422 and refusal.json() == {"code": "invalid_envelope"}
        assert snapshot() == before
    newer = {**original, "revision": 2, "pending": 0, "queue_bytes": 0, "state": "source_incomplete"}
    assert send(newer).json() == {**expected, "revision": 2}
    current = snapshot()
    assert current["high_water"] == 17
    assert json.loads(current["heartbeat_json"]) == newer
    assert json.loads(current["totals"]) == newer["totals"]
    for invalid in [
        original,
        {**newer, "state": "ready"},
        {**newer, "revision": 3, "totals": {**newer["totals"], "expired": 5}},
    ]:
        assert send(invalid).status_code == 409 and snapshot() == current


def test_expired_heartbeat_replay_never_refreshes_detail_or_device_seen(store):
    from datetime import timedelta, timezone

    from app.agent_events import Heartbeat
    from app.db.models import CollectorProgress, Device
    from app.services.agent_event_service import heartbeat
    from tests.test_agent_event_ingest import NOW

    _, _, sessions, principal = store
    report = Heartbeat.model_validate_json(VECTORS["heartbeat"])
    for day in (0, 30):
        instant = (NOW + timedelta(days=day)).astimezone(timezone(timedelta(hours=4)))
        with sessions() as session:
            ack = heartbeat(session, principal, report, lambda: instant)
            assert ack.revision == 1
    with sessions() as session:
        progress = session.get(CollectorProgress, DEVICE)
        assert progress.heartbeat_received_at == NOW.replace(tzinfo=None)
        assert progress.heartbeat_expires_at == NOW.replace(tzinfo=None) + timedelta(days=30)
        assert session.get(Device, DEVICE).last_seen == NOW.replace(tzinfo=None)
        assert progress.high_water == 0
