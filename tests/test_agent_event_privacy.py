"""The collection path cannot create or expose guard evidence or content."""

from app.auth.grants import CONTENT_READ
from app.interaction_log import InteractionLog
from tests.test_agent_event_ingest import EVENTS, batch, counts, observation
from tests.test_agent_session_routes import (
    COLLECTORS,
    SESSIONS,
    UNASSIGNED,
    _key,
    collector_store_fixture,
    prepare,
    read,
)

store = collector_store_fixture


def test_metadata_only_on_every_surface(store, caplog):
    client, writer, sessions, _ = store
    client.app.state.interaction_log = InteractionLog(sessions)
    reader = _key(sessions, policy_id="A")
    sentinel = "private-fixture-body-4172"
    rejected = client.post(EVENTS, headers=writer, json=batch((1, {**observation(), "body": sentinel})))
    assert rejected.status_code == 422
    prepare(store)
    shell = client.get("/ui/sessions")
    assert shell.is_success and "/static/js/sessions.js" in shell.text
    session_id = read(client, SESSIONS, reader)["items"][0]["session_id"]
    for path in (SESSIONS, UNASSIGNED, COLLECTORS, f"{SESSIONS}/{session_id}/observations"):
        response = client.get(path, headers=reader)
        assert response.is_success
        for private in (
            sentinel,
            "source_key",
            "native_session_token",
            "parser_observation_token",
            "collector_observation_id",
            "stream_token",
            "heartbeat_digest",
            "content_ref",
        ):
            assert private not in response.text
    assert session_id not in shell.text
    assert client.get("/v1/logs", headers=reader).json() == []
    protected = _key(sessions, policy_id="A", grants=[CONTENT_READ])
    assert client.get("/v1/logs/1/content?view=full", headers=protected).status_code == 404
    assert counts(sessions, ("interactions", "interaction_contents", "content_export_attempts", "vaults")) == [0] * 4
    with sessions() as db:
        snapshot = "\n".join(db.connection().connection.driver_connection.iterdump())
    assert all(sentinel not in surface for surface in (snapshot, rejected.text, shell.text, caplog.text))
