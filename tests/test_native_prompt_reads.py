"""Native investigations use a policy-scoped session, first receipt and reported evidence."""

import asyncio
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import update

from app.db.models import (
    AgentObservation,
    AgentSession,
    Device,
    NativePromptAssessment,
    NativePromptDecision,
    NativePromptDelivery,
    NativePromptGrant,
    NativePromptObservation,
    Policy,
)
from app.services.scheduler import Scheduler, collection_retention_job
from tests import test_native_prompt_decisions as decisions
from tests.test_agent_event_ingest import EVENTS, batch, counts, observation
from tests.test_agent_session_routes import SESSIONS, read
from tests.test_content_api import _key
from tests.test_native_prompt_contract import META
from tests.test_native_prompt_decisions import DECIDE, DELIVER, request_body
from tests.test_native_prompt_grants import CAP, OBS, issue

store = decisions.store
fleet = decisions.fleet
native = decisions.native
DETAILS = ("native_prompt_decisions", "native_prompt_assessments", "native_prompt_deliveries")


def path(session_id):
    return f"{SESSIONS}/{session_id}/native-prompts"


def decision(native, state="complete"):
    c, h, *_ = native
    response = c.post(DECIDE, headers=h, json=request_body(state))
    assert response.status_code == 200, response.text
    return response.json()


def report(native, reply, stage="stdout_flushed", source="hook", **evidence):
    c, h, *_ = native
    body = {
        **{k: reply[k] for k in ("occurrence_id", "request_id", "decision_id")},
        "report_id": str(uuid4()),
        "evidence_source": source,
        "stage": stage,
        **evidence,
    }
    assert c.post(DELIVER, headers=h, json=body).status_code == 200
    return body["report_id"]


def test_authentication_scope_and_session_existence_precede_pagination(native, fleet):
    c, writer, s, grant, *_ = native
    reply = decision(native)
    session_id = reply["session_id"]
    for role, policy in (("viewer", "A"), ("admin", "A"), ("admin", None)):
        reader = _key(s, role=role, policy_id=policy)
        (listed,) = read(c, SESSIONS, reader)["items"]
        assert listed["session_id"] == session_id and listed["observation_count"] == 2
        assert len(read(c, path(session_id), reader)["items"]) == 2
    for headers, status in (
        ({}, 401),
        (writer, 403),
        ({CAP: grant["capability"]}, 401),
        (_key(s, role="api", policy_id="A"), 403),
        (_key(s, policy_id=None), 403),
    ):
        refusal = c.get(path(session_id), headers=headers)
        assert refusal.status_code == status and refusal.headers["cache-control"] == "no-store"
    for role in ("viewer", "admin"):
        foreign = _key(s, role=role, policy_id="B")
        refused = [
            c.get(path(guess) + "?limit=bad&cursor=bad", headers=foreign)
            for guess in (session_id, grant["grant_id"], reply["occurrence_id"], str(uuid4()))
        ]
        assert {r.status_code for r in refused} == {404}
        assert len({r.content for r in refused}) == 1
        assert all(r.headers["cache-control"] == "no-store" for r in refused)
    viewer = fleet[4]["viewer", "A"]
    for guess in (grant["grant_id"], reply["occurrence_id"], reply["event_id"], META["session_token"]):
        assert c.get(path(guess), headers=viewer).status_code == 404
    for invalid in ("0", "101", "bad"):
        assert c.get(path(session_id) + "?limit=" + invalid, headers=viewer).status_code == 422


def test_tied_receipts_page_by_occurrence_and_bind_cursors(native, fleet):
    c, h, s, grant, *_ = native
    sid = grant["session_id"]
    for _ in range(4):
        assert c.post(OBS, headers=h, json={**META, "occurrence_id": str(uuid4())}).is_success
    with s.begin() as db:
        db.execute(update(NativePromptObservation).values(received_at=datetime.now(UTC)))
    reader = fleet[4]["viewer", "A"]
    first = read(c, path(sid) + "?limit=2", reader)
    second = read(c, path(sid) + "?limit=2&cursor=" + first["next_cursor"], reader)
    last = read(c, path(sid) + "?limit=2&cursor=" + second["next_cursor"], reader)
    ids = [r["event_id"] for page in (first, second, last) for r in page["items"]]
    assert ids == sorted(ids, reverse=True) and len(set(ids)) == 5 and last["next_cursor"] is None
    cursor = first["next_cursor"]
    assert c.get(path(sid) + "?cursor=" + cursor, headers=fleet[4]["admin", None]).status_code == 400
    assert c.get(f"{SESSIONS}/{sid}/observations?cursor=" + cursor, headers=reader).status_code == 400
    assert c.post(EVENTS, headers=fleet[1], json=batch((1, observation()))).is_success
    other = next(r["session_id"] for r in read(c, SESSIONS, reader)["items"] if r["session_id"] != sid)
    assert read(c, path(other), reader)["items"] == []
    assert c.get(path(other) + "?cursor=" + cursor, headers=reader).status_code == 400


def test_historical_preparation_and_bounded_stage_source_assertions(native, fleet):
    c, _, s, *_ = native
    with s.begin() as db:
        db.get(Policy, "A").report_only = True
    reply = decision(native)
    reader = fleet[4]["viewer", "A"]
    url = path(reply["session_id"])
    assessed, bootstrap = read(c, url, reader)["items"]
    assert bootstrap["decision"] is None
    d = assessed["decision"]
    assert (d["status"], d["mode"], d["policy_revision"]) == ("committed", "report", reply["policy_revision"])
    assert (d["evaluated_action"], d["prepared_action"], d["response_prepared"]) == ("deny", "allow", True)
    assert d["delivery_reports"] == [] and d["assessment"]["unsafe_score"] == 0.75
    assert d["assessment"]["score_kind"] == "two_class_softmax_uncalibrated"
    ids = [report(native, reply, "allow_no_output", token_count=i) for i in range(3)]
    report(native, reply, "stdout_failed")
    report(native, reply, "native_ack_blocked", "controlled_observer")
    report(native, reply, "effect_deny_no_effect_verified", "controlled_observer", marker_present=False, tool_count=0)
    report(native, reply, "unknown")
    report(native, reply, "unknown", "controlled_observer")
    with s.begin() as db:
        db.execute(update(NativePromptDelivery).values(received_at=datetime.now(UTC)))
        db.get(Policy, "A").report_only = False
    result = read(c, url, reader)["items"][0]["decision"]
    assert result["policy_revision"] == reply["policy_revision"] and result["mode"] == "report"
    rows = {(r["stage"], r["evidence_source"]): r for r in result["delivery_reports"]}
    assert len(rows) == 6
    latest = rows["allow_no_output", "hook"]
    assert (latest["report_count"], latest["token_count"]) == (3, ids.index(max(ids)))
    effect = rows["effect_deny_no_effect_verified", "controlled_observer"]
    assert effect["marker_present"] is False and effect["tool_count"] == 0
    for state in ("unsupported", "capture_disabled"):
        partial = decision(native, state)
        newest = read(c, url, reader)["items"][0]["decision"]
        assert newest["assessment"] == partial["assessment"] and newest["delivery_reports"] == []


@pytest.mark.parametrize("state", ["pending", "abandoned"])
def test_unfinished_or_abandoned_decisions_preserve_unknowns(native, fleet, state):
    c, _, s, *_ = native
    reply = decision(native)
    with s.begin() as db:
        db.delete(db.get(NativePromptAssessment, reply["decision_id"]))
        d = db.get(NativePromptDecision, reply["decision_id"])
        d.status, d.response_prepared = state, False
        d.evaluated_action = d.returned_action = None
        d.reason = "deadline_exceeded" if state == "abandoned" else None
    item = read(c, path(reply["session_id"]), fleet[4]["viewer", "A"])["items"][0]["decision"]
    assert item["status"] == state and item["response_prepared"] is False
    assert item["evaluated_action"] is item["prepared_action"] is item["assessment"] is None
    assert item["delivery_reports"] == [] and item["reason"] == d.reason


@pytest.mark.parametrize("live", ["native", "legacy"])
def test_common_session_visibility_and_purge_keep_either_live_family(native, fleet, live):
    c, _, s, *_ = native
    reply = decision(native)
    report(native, reply)
    sid, viewer = reply["session_id"], fleet[4]["viewer", "A"]
    legacy = {**observation(), "native_session_token": META["session_token"]}
    assert c.post(EVENTS, headers=fleet[1], json=batch((1, legacy))).is_success
    assert read(c, SESSIONS, viewer)["items"][0]["observation_count"] == 3
    with s.begin() as db:
        expired = datetime.now(UTC) - timedelta(seconds=1)
        db.execute(update(AgentObservation if live == "native" else NativePromptObservation).values(expires_at=expired))
    for _ in range(2):
        (session,) = read(c, SESSIONS, viewer)["items"]
        assert session["session_id"] == sid and session["observation_count"] == (2 if live == "native" else 1)
        if live == "native":
            assert read(c, f"{SESSIONS}/{sid}/observations", viewer)["items"] == []
            assert len(read(c, path(sid), viewer)["items"]) == 2
        else:
            assert read(c, path(sid), viewer)["items"] == []
            (legacy_row,) = read(c, f"{SESSIONS}/{sid}/observations", viewer)["items"]
            assert legacy_row["assessment_status"] == "not_assessed"
        asyncio.run(collection_retention_job(s, scheduler=Scheduler()).run())
    assert counts(s, DETAILS) == ([1, 1, 1] if live == "native" else [0, 0, 0])


def test_first_receipt_controls_nested_expiry_and_grant_retention(native, fleet):
    c, h, s, *_ = native
    reply = decision(native)
    r_id = report(native, reply)
    with s.begin() as db:
        o = db.get(NativePromptObservation, reply["event_id"])
        d = db.get(NativePromptDecision, reply["decision_id"])
        delivery = db.get(NativePromptDelivery, r_id)
        assert delivery.expires_at == d.expires_at == o.expires_at == o.received_at + timedelta(days=30)
        # An old grant may still parent an otherwise live decision.
        old = datetime.now(UTC) - timedelta(days=30, minutes=1)
        db.execute(update(NativePromptGrant).values(issued_at=old, expires_at=old + timedelta(minutes=10)))
        delivery.expires_at = datetime.now(UTC)
    assert c.post(DECIDE, headers=h, json=request_body()).json()["code"] == "grant_expired"
    viewer = fleet[4]["viewer", "A"]
    url = path(reply["session_id"])
    assert read(c, url, viewer)["items"][0]["decision"]["delivery_reports"] == []
    asyncio.run(collection_retention_job(s, scheduler=Scheduler()).run())
    assert counts(s, ("native_prompt_grants", *DETAILS)) == [1, 1, 1, 0]
    with s.begin() as db:
        db.get(NativePromptDecision, reply["decision_id"]).expires_at = datetime.now(UTC)
    assert read(c, url, viewer)["items"][0]["decision"] is None
    asyncio.run(collection_retention_job(s, scheduler=Scheduler()).run())
    assert counts(s, ("native_prompt_grants", *DETAILS)) == [0, 0, 0, 0]


@pytest.mark.parametrize("purge_first", [False, True])
def test_fresh_source_after_full_expiry_gets_new_session_without_old_grant_or_directive(native, fleet, purge_first):
    c, h, s, *_ = native
    body = request_body()
    reply = c.post(DECIDE, headers=h, json=body).json()
    report(native, reply)
    sid = reply["session_id"]
    now = datetime.now(UTC)
    with s.begin() as db:
        db.execute(update(AgentSession).values(received_at=now - timedelta(days=31)))
        db.execute(update(NativePromptObservation).values(received_at=now - timedelta(days=31), expires_at=now))
        db.execute(update(NativePromptDecision).values(expires_at=now))
        db.execute(update(NativePromptDelivery).values(expires_at=now))
    viewer = fleet[4]["viewer", "A"]
    assert read(c, SESSIONS, viewer)["items"] == [] and c.get(path(sid), headers=viewer).status_code == 404
    assert issue(fleet, capture_allowed=True, session_id=sid).status_code == 403
    if purge_first:
        asyncio.run(collection_retention_job(s, scheduler=Scheduler()).run())
        assert counts(s, ("agent_sessions", "native_prompt_observations", *DETAILS)) == [0] * 5
    fresh_grant = issue(fleet).json()
    fresh = c.post(
        OBS, headers={**fleet[1], CAP: fresh_grant["capability"]}, json={**META, "occurrence_id": str(uuid4())}
    ).json()
    assert fresh["session_id"] != sid and c.get(path(sid), headers=viewer).status_code == 404
    assert c.post(DECIDE, headers=h, json=body).status_code in (401, 403)
    assert counts(s, DETAILS) == [0, 0, 0]


@pytest.mark.parametrize("parent", ["observation", "session", "device_recovery"])
def test_deleting_parent_cascades_all_native_outcomes(native, fleet, parent):
    from app.auth.key_utils import hash_key
    from app.services.device_service import DeviceService

    c, _, s, grant, *_ = native
    reply = decision(native)
    report(native, reply)
    with s() as db:
        if parent == "device_recovery":
            device_id = grant["device_id"]
            installation = db.get(Device, device_id).installation_id
            devices = DeviceService(db, actor_policy_id="A")
            devices.update_device_status(device_id, "revoked")
            devices.delete_device(device_id)
            secret = devices.authorise_recovery(device_id)
            key, _ = devices.create_registration_token(
                "test recovery", "A", purpose="collector_write", expires_at=datetime.now(UTC) + timedelta(hours=1)
            )
            replacement = devices.enrol_device(
                hash_key(key), installation, "test", "", "", "native", "test", "1", recovery_secret=secret
            )["result"]
            assert replacement["device_id"] != device_id
        elif parent == "session":
            db.delete(db.get(AgentSession, reply["session_id"]))
        else:
            db.delete(db.get(NativePromptObservation, reply["event_id"]))
        db.commit()
    assert counts(s, DETAILS) == [0, 0, 0]
    response = c.get(path(reply["session_id"]), headers=fleet[4]["viewer", "A"])
    if parent == "observation":
        assert [r["decision"] for r in response.json()["items"]] == [None]
    else:
        assert response.status_code == 404
