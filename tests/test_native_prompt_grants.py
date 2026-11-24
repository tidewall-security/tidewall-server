from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import text

from app.auth.key_utils import hash_key
from app.db.models import AccessToken, APIKey, Device, DeviceTombstone, RuleSet
from tests.test_agent_event_ingest import collector_store_fixture, counts, provision
from tests.test_native_prompt_contract import META

CFG = "/v1/policies/A/native-prompt"
GRANT = "/v1/native-prompt/grants"
OBS = "/v1/native-prompt/observations"
CAP = "X-Tidewall-Inline-Capability"
TABLES = (
    "agent_sessions",
    "native_prompt_observations",
    "native_prompt_decisions",
    "native_prompt_assessments",
    "interactions",
)
store = collector_store_fixture


@pytest.fixture
def fleet(store):
    client, h, s, p = store
    keys = {}
    with s.begin() as db:
        db.add(RuleSet(policy_id="A", event_type="input", detectors={"malicious_prompt": {"action": "block"}}))
        for role, scope in [("admin", "A"), ("admin", "B"), ("viewer", "A"), ("admin", None)]:
            key = "ak_" + uuid4().hex
            db.add(APIKey(name=key[:7], key_prefix=key[:8], key_hash=hash_key(key), role=role, policy_id=scope))
            keys[role, scope] = {"Authorization": "Bearer " + key}
    admin = keys["admin", "A"]
    return client, h, s, p, keys, admin


def issue(f, **extra):
    client, _, _, p, _, admin = f
    return client.post(
        GRANT,
        headers=admin,
        json=dict(
            device_id=p.device_id,
            session_token=META["session_token"],
            native_profile=META["native_profile"],
            ttl_seconds=1800,
            **extra,
        ),
    )


def enable(f):
    client, _, _, _, _, admin = f
    assert client.put(CFG, headers=admin, json={"enabled": True}).status_code == 200


def test_rotation_requires_real_observed_session_and_freezes_scope(fleet):
    c, h, s, p, k, admin = fleet
    enable(fleet)
    assert issue(fleet, capture_allowed=True, session_id=str(uuid4())).status_code >= 400
    initial = issue(fleet)
    assert initial.status_code == 201, initial.text
    grant = initial.json()
    both = {**h, CAP: grant["capability"]}
    for headers in [h, admin, {CAP: grant["capability"]}, {**k["viewer", "A"], CAP: grant["capability"]}]:
        assert c.post(OBS, headers=headers, json=META).status_code in (401, 403)
    assert counts(s, TABLES) == [0, 0, 0, 0, 0]
    r = c.post(OBS, headers=both, json=META)
    assert r.status_code == 200, r.text
    receipt = r.json()
    assert set(receipt) == {"version", "occurrence_id", "event_id", "session_id"}
    assert c.post(OBS, headers=both, json=META).json() == receipt
    assert counts(s, TABLES) == [1, 1, 0, 0, 0]
    newer = issue(fleet, capture_allowed=True, session_id=receipt["session_id"]).json()
    assert newer["grant_generation"] > grant["grant_generation"]
    assert c.post(OBS, headers=both, json=META).json()["code"] == "grant_revoked"
    assert c.delete(GRANT + "/" + newer["grant_id"], headers=k["admin", "B"]).status_code == 403
    other, _ = provision(s, str(uuid4()))
    both[CAP] = newer["capability"]
    assert c.post(OBS, headers={**other, CAP: newer["capability"]}, json=META).status_code in (401, 403)
    assert c.post(OBS, headers=both, json={**META, "session_token": "b" * 64}).status_code in (401, 403)
    assert c.delete(GRANT + "/" + newer["grant_id"], headers=admin).status_code == 204
    assert c.post(OBS, headers=both, json=META).json()["code"] == "grant_revoked"
    with s() as db:
        assert grant["capability"] not in str(db.execute(text("SELECT * FROM native_prompt_grants")).all())


@pytest.mark.parametrize("change", ["pending", "revoked", "access_expired", "tombstone", "rebound", "expired", "ABA"])
def test_fresh_authority_no_writes(fleet, change):
    c, h, s, p, _, admin = fleet
    enable(fleet)
    grant = issue(fleet).json()
    with s.begin() as db:
        d = db.get(Device, p.device_id)
        if change in ("pending", "revoked"):
            d.status = change
        elif change == "access_expired":
            db.query(AccessToken).filter_by(device_id=p.device_id).one().expires_at = datetime.now(UTC) - timedelta(
                seconds=1
            )
        elif change == "tombstone":
            db.add(DeviceTombstone(device_id=d.id, installation_id=d.installation_id, reason="retired"))
        elif change == "rebound":
            d.policy_id = "B"
        elif change == "expired":
            db.execute(
                text("UPDATE native_prompt_grants SET issued_at='2020-01-01 00:00:00',expires_at='2020-01-01 00:01:00'")
            )
    if change == "ABA":
        for threshold in [0.7, 0.5]:
            assert c.put(CFG, headers=admin, json={"enabled": True, "threshold": threshold}).status_code == 200
    response = c.post(OBS, headers={**h, CAP: grant["capability"]}, json=META)
    assert response.status_code in (401, 403)
    assert set(response.json()) == {"code", "version", "request_id"}
    assert counts(s, TABLES) == [0, 0, 0, 0, 0]


def test_scoped_admin_and_sanitized_metadata(fleet):
    c, h, s, p, k, admin = fleet
    assert c.put(CFG, headers=k["admin", "B"], json={"enabled": True}).status_code == 403
    assert c.put(CFG, headers=k["viewer", "A"], json={"enabled": True}).status_code == 403
    enable(fleet)
    base = dict(
        device_id=p.device_id,
        session_token=META["session_token"],
        native_profile=META["native_profile"],
        ttl_seconds=100,
    )
    assert c.post(GRANT, headers=k["admin", "B"], json=base).status_code == 403
    grant = issue(fleet).json()
    headers = {**h, CAP: grant["capability"], "Content-Type": "application/json"}
    for raw in [b'{"prompt":"synthetic-private"}', b"\xff", b'{"version":1,"version":1}', b" " * 16385]:
        response = c.post(OBS, headers=headers, content=raw)
        assert response.status_code >= 400
        assert response.json() == dict(version=1, request_id=None, code="invalid_request")
        assert len(response.content) <= 256
    assert counts(s, TABLES) == [0, 0, 0, 0, 0]


def test_native_and_legacy_children_each_keep_their_session_alive(fleet):
    from app.services.agent_event_service import _retire_session
    from app.services.collection_retention import purge_collection
    from tests.test_agent_event_ingest import EVENTS, batch, observation

    c, h, s, _, _, _ = fleet
    enable(fleet)
    grant = issue(fleet).json()
    receipt = c.post(OBS, headers={**h, CAP: grant["capability"]}, json=META).json()
    legacy = c.post(EVENTS, headers=h, json=batch((1, observation())))
    assert legacy.status_code == 200
    now = datetime.now(UTC)
    with s() as db:
        purge_collection(db, now)
    assert counts(s, ("agent_sessions", "native_prompt_observations", "agent_observations")) == [2, 1, 1]
    with s.begin() as db:
        assert not _retire_session(db, receipt["session_id"], now)


def test_admin_scope_rechecked_after_request_body(fleet):
    import json

    from sqlalchemy import update

    c, _, s, p, _, admin = fleet
    enable(fleet)
    raw = admin["Authorization"].removeprefix("Bearer ")

    def body():
        with s.begin() as db:
            db.execute(update(APIKey).where(APIKey.key_hash == hash_key(raw)).values(policy_id="B"))
        yield json.dumps(
            dict(
                device_id=p.device_id,
                session_token=META["session_token"],
                native_profile=META["native_profile"],
                ttl_seconds=1800,
            )
        ).encode()

    result = c.post(GRANT, headers={**admin, "Content-Type": "application/json"}, content=body())
    assert result.status_code == 403
    assert counts(s, ("native_prompt_grants",)) == [0]


def test_exact_native_routes_and_mixed_credentials(fleet):
    c, h, s, _, keys, _ = fleet
    assert issue(fleet).status_code == 409
    enable(fleet)
    grant = issue(fleet).json()
    both = {**h, CAP: grant["capability"]}
    for path in (OBS, "/v1/native-prompt/decisions", "/v1/native-prompt/deliveries"):
        assert c.post(path, headers=h, json=META).json() == {"version": 1, "request_id": None, "code": "unauthorized"}
        for method in ("GET", "PUT", "DELETE"):
            assert c.request(method, path, headers=both).status_code == 403
        for dup in ("Authorization", CAP):
            assert c.post(path, headers=[*both.items(), (dup, both[dup])], json=META).status_code == 401
    for path in (
        "/v1/guard",
        "/v1/native-prompt/observations/",
        "/v1/native-prompt/grants",
        "/v1/collector/observations/extra",
    ):
        assert c.post(path, headers=both, json=META, follow_redirects=False).status_code == 403
    assert c.post(OBS, headers={**keys["admin", None], CAP: grant["capability"]}, json=META).status_code == 401
    assert counts(s, TABLES) == [0, 0, 0, 0, 0]


def test_disabled_or_unsupported_policy_creates_no_grants(fleet):
    c, _, s, _, _, admin = fleet
    assert issue(fleet).json()["code"] == "policy_unsupported"
    with s.begin() as db:
        db.query(RuleSet).filter_by(policy_id="A").one().detectors = {"pii": {"enabled": True}}
    result = c.put(CFG, headers=admin, json={"enabled": True})
    assert result.status_code == 409
    assert result.json() == {"version": 1, "request_id": None, "code": "policy_unsupported"}
    assert counts(s, ("native_prompt_policy_configs", "native_prompt_grants")) == [0, 0]


def test_grant_setup_result_repr_hides_its_only_secret(fleet):
    from app.native_prompt import NativeGrantRequest
    from app.services.native_prompt_grants import issue_native_grant

    _, _, sessions, principal, _, _ = fleet
    enable(fleet)
    req = NativeGrantRequest(
        device_id=principal.device_id,
        native_profile="claude-code.user-prompt-submit.1",
        session_token=META["session_token"],
        ttl_seconds=60,
    )
    with sessions.begin() as db:
        db.execute(text("BEGIN IMMEDIATE"))
        issued = issue_native_grant(db, req, "A", now=datetime.now(UTC))
        assert "capability" not in repr(issued)
        assert issued.capability not in repr(issued)
        assert hash_key(issued.capability) == db.scalar(text("SELECT capability_hash FROM native_prompt_grants"))
