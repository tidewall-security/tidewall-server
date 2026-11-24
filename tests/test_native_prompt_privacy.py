"""Real native callback and dashboard/export reads against a file-backed WAL database."""

import hashlib
import logging
from unittest.mock import AsyncMock

import pytest

from app.auth.grants import CONTENT_EXPORT, CONTENT_READ
from app.db.models import NativePromptDecision, NativePromptGrant, Policy
from app.interaction_log import InteractionLog
from app.services.export_service import ExportService
from tests import test_native_prompt_decisions as decisions
from tests.test_agent_event_ingest import counts
from tests.test_agent_session_routes import COLLECTORS, SESSIONS, UNASSIGNED
from tests.test_content_api import _key
from tests.test_native_prompt_decisions import AUDIT, DECIDE, request_body
from tests.test_native_prompt_grants import OBS
from tests.test_native_prompt_reads import path, report

store = decisions.store
fleet = decisions.fleet
native = decisions.native


@pytest.mark.parametrize("ordinary_capture", [False, True])
def test_native_content_never_reaches_retained_or_viewer_surfaces(native, tmp_path, caplog, ordinary_capture):
    client, writer, sessions, grant, _, service = native
    client.app.state.interaction_log = InteractionLog(sessions)
    exporter = ExportService(session_factory=sessions)
    exporter.emit = AsyncMock()
    client.app.state.export_service = exporter
    caplog.set_level(logging.INFO)
    with sessions.begin() as db:
        db.get(Policy, "A").raw_content_enabled = ordinary_capture
    viewer = _key(sessions, policy_id="A")
    protected = _key(sessions, role="admin", policy_id="A", grants=[CONTENT_READ, CONTENT_EXPORT])
    prompt = "synthetic-native-prompt-7f1019"
    source = "/synthetic/transcript-6ba552"
    body = {**request_body(), "prompt": prompt}
    rejected = client.post(OBS, headers=writer, json={**body["observation"], "transcript_path": source})
    assert rejected.status_code == 422
    callback = client.post(DECIDE, headers=writer, json=body)
    assert callback.is_success
    reply = callback.json()
    report(native, reply)
    binding = service._binding((grant["device_id"], reply["request_id"]))
    raw = [
        prompt.encode(),
        source.encode(),
        hashlib.sha256(prompt.encode()).digest(),
        hashlib.sha256(prompt.encode()).hexdigest().encode(),
        binding.digest,
        binding.digest.hex().encode(),
        service._key,
        service._key.hex().encode(),
    ]
    sid = reply["session_id"]
    surfaces = [
        client.get(url, headers=viewer)
        for url in [
            "/ui/sessions",
            SESSIONS,
            path(sid),
            f"{SESSIONS}/{sid}/observations",
            UNASSIGNED,
            COLLECTORS,
            "/v1/logs",
        ]
    ]
    assert all(r.is_success for r in surfaces)
    assert surfaces[-1].json() == []
    assert client.get("/v1/logs/1/content?view=full", headers=protected).status_code == 404
    exported = client.post(
        "/v1/logs/1/content-export", json={"target_id": "synthetic", "view": "full"}, headers=protected
    )
    assert exported.status_code == 404
    exporter.emit.assert_not_called()
    assert counts(sessions, (*AUDIT, "collector_outcomes", "activity_log")) == [0] * (len(AUDIT) + 2)
    with sessions() as db:
        snapshot = "\n".join(db.connection().connection.driver_connection.iterdump()).encode()
        record = db.get(NativePromptDecision, reply["decision_id"])
        internal = [
            record.owner_nonce,
            record.process_id,
            record.inference_request_id,
            record.session_token,
            db.get(NativePromptGrant, grant["grant_id"]).capability_hash,
            grant["capability"],
        ]
    files = [tmp_path / "events.db", tmp_path / "events.db-wal"]
    assert all(p.stat().st_size for p in files)
    artifacts = [
        snapshot,
        *(p.read_bytes() for p in tmp_path.glob("events.db*")),
        *(r.content for r in [*surfaces, callback, rejected, exported]),
        caplog.text.encode(),
    ]
    assert all(value not in surface for value in raw for surface in artifacts)
    native_page = surfaces[2].json()
    historical_identity = native_page["items"][0]["decision"]["assessment"]["model_identity"]
    assert historical_identity == reply["assessment"]["model_identity"]
    assert historical_identity["prompt_sha256"] != hashlib.sha256(prompt.encode()).hexdigest()
    viewer_bytes = b" ".join(r.content for r in surfaces)
    for private in [
        *internal,
        "content_ref",
        "capability_hash",
        "owner_nonce",
        "inference_request_id",
        "session_token",
        "process_id",
        "raw_content",
    ]:
        assert private.encode() not in viewer_bytes
