"""Collector authority at registration, the HTTP boundary, and transaction time."""

from datetime import UTC, datetime, timedelta, timezone
from uuid import uuid4

import pytest
from fastapi import Depends, Request

from app.auth.key_utils import hash_key
from app.db.models import AccessToken, APIKey, Device, DeviceTombstone, Policy, RegistrationToken
from tests.test_device_routes import TEST_POLICY_ID, _make_app_and_client

POLICY_A = TEST_POLICY_ID
POLICY_B = "other-policy"
REGISTRATIONS = "/v1/registration-tokens"
DEVICES = "/v1/devices"
WRITES = ("/v1/collector/observations", "/v1/collector/heartbeat")


def bearer(token):
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def fleet():
    client, admin, sessions = _make_app_and_client()
    keys = {"deployment": admin}
    with sessions.begin() as session:
        session.add(Policy(id=POLICY_B, name=POLICY_B, type="application"))
        for scope, policy in [("a", POLICY_A), ("b", POLICY_B), ("unbound", None)]:
            for role in ("viewer", "admin", "api"):
                raw = f"ak_{uuid4()}"
                session.add(APIKey(name=role, role=role, policy_id=policy, key_hash=hash_key(raw), key_prefix=raw[:8]))
                keys[f"{scope}-{role}"] = raw
    yield client, keys, sessions
    client.close()


def register(client, admin, policy=POLICY_A, **overrides):
    payload = {
        "name": "fixture",
        "policy_id": policy,
        "purpose": "collector_write",
        "expires_at": (datetime.now(UTC) + timedelta(days=1)).isoformat(),
        **overrides,
    }
    return client.post(REGISTRATIONS, headers=bearer(admin), json=payload)


def enrol(client, rt, installation=None, **extra):
    return client.post(
        f"{DEVICES}/enrol",
        headers=bearer(rt),
        json={
            "installation_id": installation or str(uuid4()),
            "device_name": "fixture",
            "user_name": "",
            "user_email": "",
            **extra,
        },
    )


def approve(client, admin, device):
    return client.post(
        f"{DEVICES}/{device['device_id']}/approve",
        headers=bearer(admin),
        json={"confirmation_code": device["confirmation_code"]},
    )


def test_only_scoped_non_preauthorized_collector_registration(fleet):
    client, keys, _ = fleet
    assert register(client, keys["a-admin"], POLICY_B).status_code == 403
    assert register(client, keys["a-admin"], pre_authorized=True).status_code == 400
    assert register(client, keys["a-viewer"]).status_code == 403
    assert register(client, keys["deployment"], "unknown").status_code == 400
    assert register(client, keys["a-admin"], purpose="other").status_code in (400, 422)


@pytest.mark.parametrize("overrides", [{"policy_id": POLICY_B}, {"purpose": "guard_device"}, {"tenant_id": "other"}])
def test_enrolling_client_cannot_supply_authority(fleet, overrides):
    client, keys, _ = fleet
    token = register(client, keys["deployment"]).json()["token"]
    response = enrol(client, token, recovery_secret="synthetic-private-recovery-secret", **overrides)
    assert response.status_code == 422
    assert "synthetic-private-recovery-secret" not in response.text


def test_readers_only_list_authorized_collector_rows_and_keep_legacy_projection(fleet):
    client, keys, _ = fleet
    registrations, devices = {}, {}
    for scope, policy, kwargs in [
        ("a", POLICY_A, {}),
        ("b", POLICY_B, {}),
        ("guard", POLICY_B, {"purpose": "guard_device"}),
    ]:
        rt = register(client, keys["deployment"], policy, **kwargs).json()
        device = enrol(client, rt["token"]).json()["result"]
        registrations[scope], devices[scope] = rt["id"], device["device_id"]

    for actor, visible in [
        ("unbound-viewer", ["guard"]),
        ("a-viewer", ["a", "guard"]),
        ("b-viewer", ["b", "guard"]),
        ("a-admin", ["a", "guard"]),
        ("b-admin", ["b", "guard"]),
        ("deployment", ["a", "b", "guard"]),
    ]:
        headers = bearer(keys[actor])
        device_list = client.get(DEVICES, headers=headers)
        assert device_list.status_code == 200
        by_id = {d["id"]: d for d in device_list.json()}
        assert set(by_id) == {devices[s] for s in visible}
        assert set(by_id[devices["guard"]]) == {
            "id",
            "installation_id",
            "fingerprint",
            "device_name",
            "user_name",
            "user_email",
            "browser",
            "os",
            "ext_version",
            "reg_token_id",
            "policy_id",
            "status",
            "last_seen",
            "created_at",
        }
        for scope in set(visible) - {"guard"}:
            assert by_id[devices[scope]]["purpose"] == "collector_write"
            assert "confirmation_code" not in by_id[devices[scope]]
        result = client.get(REGISTRATIONS, headers=headers)
        if actor.endswith("viewer"):
            assert result.status_code == 403
        else:
            assert result.status_code == 200
            by_id = {r["id"]: r for r in result.json()}
            assert set(by_id) == {registrations[s] for s in visible}
            assert set(by_id[registrations["guard"]]) == {
                "id",
                "name",
                "token_prefix",
                "policy_id",
                "created_by",
                "created_at",
                "expires_at",
                "max_uses",
                "uses",
                "pre_authorized",
                "revoked_at",
            }


def test_scoped_lifecycle_and_recovery_after_deletion(fleet):
    client, keys, sessions = fleet
    admin, wrong = keys["a-admin"], keys["b-admin"]
    original = register(client, admin).json()
    installation = str(uuid4())
    device = enrol(client, original["token"], installation).json()["result"]
    assert device["config"] == {"sites": {}}
    assert set(device) == {"device_id", "device_status", "config", "confirmation_code", "access_token", "refresh_token"}
    path = f"{DEVICES}/{device['device_id']}"
    for key in (admin, wrong):
        assert client.patch(path, headers=bearer(key), json={"status": "active"}).status_code == 403
    assert approve(client, wrong, device).status_code == 403
    assert approve(client, admin, device).status_code == 200
    refreshed = client.post(f"{path}/refresh", headers=bearer(device["refresh_token"]["token"]), json={}).json()
    assert refreshed["result"]["device_id"] == device["device_id"]
    assert refreshed["result"]["config"] == {"sites": {}}
    reg_path = f"{REGISTRATIONS}/{original['id']}"
    assert client.delete(reg_path, headers=bearer(wrong)).status_code == 403
    assert client.post(f"{reg_path}/revoke", headers=bearer(wrong), json={"cascade": True}).status_code == 403
    assert client.patch(path, headers=bearer(wrong), json={"status": "revoked"}).status_code == 403
    assert client.delete(path, headers=bearer(wrong)).status_code == 403
    assert client.patch(path, headers=bearer(admin), json={"status": "revoked"}).status_code == 200
    assert client.patch(path, headers=bearer(admin), json={"status": "active"}).status_code == 403
    assert client.delete(path, headers=bearer(admin)).status_code == 204
    assert client.post(f"{path}/authorise-recovery", headers=bearer(wrong)).status_code == 403
    secret = client.post(f"{path}/authorise-recovery", headers=bearer(admin)).json()["recovery_secret"]
    wrong_policy = register(client, wrong, POLICY_B).json()["token"]
    guard = register(client, admin, purpose="guard_device").json()["token"]
    for token in [original["token"], wrong_policy, guard]:
        assert enrol(client, token, installation, recovery_secret=secret).status_code == 403
    fresh = register(client, admin).json()["token"]
    replacement = enrol(client, fresh, installation, recovery_secret=secret).json()["result"]
    assert replacement["device_id"] != device["device_id"]
    assert replacement["device_status"] == "pending"
    assert approve(client, admin, {**replacement, "confirmation_code": device["confirmation_code"]}).status_code == 403
    assert approve(client, admin, replacement).status_code == 200
    assert enrol(client, fresh, installation, recovery_secret=secret).status_code == 409
    with sessions() as session:
        tombstone = session.get(DeviceTombstone, device["device_id"])
        assert tombstone.consumed_at is not None
        assert tombstone.collector_policy_id == POLICY_A


def install_write_probes(app):
    # Exercise the actual dependencies on the two reserved paths without
    # providing a product ingest route in the identity-only changeset.
    from app.auth.dependencies import require_collector
    from app.services.collector_identity import authorize_collector

    def write_probe(request: Request, enrollment_id: str, principal=Depends(require_collector)):
        with app.state.session_factory() as session:
            verified = authorize_collector(session, principal.token_hash, enrollment_id, datetime.now(UTC))
        return [verified.device_id, verified.policy_id, request.state.role, sorted(request.state.grants)]

    for path in WRITES:
        app.post(path)(write_probe)


def test_collector_write_credential_is_exactly_scoped(fleet):
    client, keys, sessions = fleet
    install_write_probes(client.app)
    rt = register(client, keys["a-admin"]).json()
    device = enrol(client, rt["token"]).json()["result"]
    access, refresh = device["access_token"]["token"], device["refresh_token"]["token"]
    params = {"enrollment_id": device["device_id"]}
    guard_rt = register(client, keys["deployment"], purpose="guard_device", pre_authorized=True).json()
    guard = enrol(client, guard_rt["token"]).json()["result"]
    assert guard["config"]["sites"]["claude"] == "block"
    for path in WRITES:
        assert client.post(path, params=params).status_code == 401
        assert client.post(path, params=params, headers=bearer("at_unknown")).status_code == 401
        assert client.post(path, params=params, headers=bearer(access)).status_code == 401
    assert approve(client, keys["a-admin"], device).status_code == 200
    for path in WRITES:
        for invalid in [
            keys["deployment"],
            keys["a-viewer"],
            keys["a-api"],
            rt["token"],
            refresh,
            guard["access_token"]["token"],
        ]:
            assert client.post(path, params=params, headers=bearer(invalid)).status_code == 403
        assert client.post(path, params=params, headers=bearer(access)).json() == [
            device["device_id"],
            POLICY_A,
            None,
            [],
        ]
        assert (
            client.post(path, params={"enrollment_id": guard["device_id"]}, headers=bearer(access)).status_code == 403
        )
        assert client.get(path, headers=bearer(access)).status_code == 403
        assert client.post(path + "/", headers=bearer(access), follow_redirects=False).status_code == 403
    for method, path in [
        ("post", "/v1/guard"),
        ("post", "/v1/unredact"),
        ("get", "/v1/agent-sessions"),
        ("get", "/v1/logs/1/content"),
        ("get", "/v1/settings/prompt-lists"),
        ("get", DEVICES),
        ("get", REGISTRATIONS),
    ]:
        assert client.request(method, path, headers=bearer(access)).status_code == 403
    with sessions.begin() as session:
        session.query(AccessToken).filter_by(token_hash=hash_key(access)).update({"expires_at": datetime.now(UTC)})
    assert client.post(WRITES[0], params=params, headers=bearer(access)).status_code == 401
    path = f"{DEVICES}/{device['device_id']}"
    renewed = client.post(f"{path}/refresh", headers=bearer(refresh), json={}).json()["result"]["access_token"]["token"]
    assert client.post(WRITES[1], params=params, headers=bearer(renewed)).status_code == 200
    assert (
        client.post(
            f"{REGISTRATIONS}/{rt['id']}/revoke", headers=bearer(keys["a-admin"]), json={"cascade": True}
        ).json()["devices_revoked"]
        == 1
    )
    assert client.post(WRITES[1], params=params, headers=bearer(renewed)).status_code == 401


@pytest.mark.parametrize(
    ("corruption", "status"), [("approval", 401), ("tombstone", 401), ("null_policy", 403), ("missing_policy", 403)]
)
def test_stored_authority_checked_even_with_inconsistent_imported_rows(fleet, corruption, status):
    client, keys, sessions = fleet
    install_write_probes(client.app)
    rt = register(client, keys["deployment"]).json()["token"]
    device = enrol(client, rt).json()["result"]
    assert approve(client, keys["deployment"], device).status_code == 200
    with sessions.begin() as session:
        row = session.get(Device, device["device_id"])
        if corruption == "approval":
            row.collector_approved_at = None
        elif corruption == "tombstone":
            session.add(DeviceTombstone(device_id=row.id, installation_id=row.installation_id, reason="fixture"))
        else:
            row.policy_id = None if corruption == "null_policy" else "missing"
    response = client.post(
        WRITES[0], params={"enrollment_id": device["device_id"]}, headers=bearer(device["access_token"]["token"])
    )
    assert response.status_code == status


def test_malformed_imported_registration_cannot_mint_collector(fleet):
    client, keys, sessions = fleet
    rt = register(client, keys["deployment"]).json()
    with sessions.begin() as session:
        session.get(RegistrationToken, rt["id"]).pre_authorized = True
    assert enrol(client, rt["token"]).status_code == 400


def test_cascade_and_new_collector_enrollment_serialize(tmp_path):
    """Attempt enrollment on another connection as the cascade loads its first device."""
    import sqlite3

    from sqlalchemy import event
    from sqlalchemy.exc import OperationalError

    from app.db.engine import get_engine, get_session_factory
    from app.db.models import Base
    from app.services.device_service import DeviceService

    engine = get_engine(f"sqlite:///{tmp_path}/cascade.db")
    Base.metadata.create_all(engine)
    factory = get_session_factory(engine)
    with factory() as setup:
        setup.add(Policy(id=POLICY_A, name=POLICY_A, type="application"))
        setup.commit()
        service = DeviceService(setup)
        raw, rt = service.create_registration_token(
            "fixture", POLICY_A, expires_at=datetime.now(UTC) + timedelta(days=1), purpose="collector_write"
        )
        token_id = rt.id

        def enroll_once(service: DeviceService):
            return service.enrol_device(
                rt_token_hash=hash_key(raw),
                installation_id=str(uuid4()),
                device_name="fixture",
                user_name="",
                user_email="",
                browser="",
                os="",
                ext_version="",
            )

        enroll_once(service)

    attempts: list[str] = []
    with factory() as revoker:

        @event.listens_for(revoker, "loaded_as_persistent")
        def concurrent_enrollment(session, row):
            if not isinstance(row, Device) or attempts:
                return
            with factory() as competing:
                competing.connection().exec_driver_sql("PRAGMA busy_timeout=0")
                try:
                    outcome = enroll_once(DeviceService(competing))
                    attempts.append(outcome["status"])
                except OperationalError as exc:
                    assert getattr(exc.orig, "sqlite_errorcode", None) == sqlite3.SQLITE_BUSY
                    attempts.append("writer busy")

        DeviceService(revoker).revoke_registration_token(token_id, cascade=True)

    with factory() as check:
        assert attempts == ["writer busy"]
        assert {d.status for d in check.query(Device).all()} == {"revoked"}
        assert check.query(AccessToken).count() == 0
    engine.dispose()


@pytest.mark.parametrize("lost_policy", [None, "missing-policy"])
@pytest.mark.parametrize("terminal", ["revoke_then_delete", "delete"])
def test_collector_with_lost_scope_cannot_recover_as_guard(fleet, lost_policy, terminal):
    client, keys, sessions = fleet
    admin = keys["deployment"]
    rt = register(client, admin).json()["token"]
    installation = str(uuid4())
    device = enrol(client, rt, installation).json()["result"]
    assert approve(client, admin, device).status_code == 200
    device_id = device["device_id"]
    path = f"{DEVICES}/{device_id}"
    with sessions.begin() as session:
        session.get(Device, device_id).policy_id = lost_policy
    if terminal == "revoke_then_delete":
        assert client.patch(path, headers=bearer(admin), json={"status": "revoked"}).status_code == 200
    assert client.delete(path, headers=bearer(admin)).status_code == 204
    for actor in (keys["a-admin"], admin):
        assert client.post(f"{path}/authorise-recovery", headers=bearer(actor)).status_code == 403
    # An outstanding grant cannot override the absent binding either.
    with sessions.begin() as session:
        tombstone = session.get(DeviceTombstone, device_id)
        assert tombstone.recovery_secret_hash is None
        tombstone.recovery_secret_hash = hash_key("synthetic-test-grant")
    for purpose in ("guard_device", "collector_write"):
        fresh = register(client, admin, purpose=purpose).json()["token"]
        response = enrol(client, fresh, installation, recovery_secret="synthetic-test-grant")
        assert response.status_code == 403
    with sessions() as session:
        tombstone = session.get(DeviceTombstone, device_id)
        assert tombstone.purpose == "collector_write"
        assert tombstone.consumed_at is None
        assert session.query(Device).filter_by(installation_id=installation).count() == 0


def test_approval_wins_before_reaper_writes_without_losing_device_or_quota(tmp_path):
    from sqlalchemy import event

    from app.db.engine import get_engine, get_session_factory
    from app.db.models import Base, DeviceRefreshToken
    from app.services.collector_identity import authorize_collector
    from app.services.device_service import DeviceService

    engine = get_engine(f"sqlite:///{tmp_path}/reaper.db")
    Base.metadata.create_all(engine)
    factory = get_session_factory(engine)
    with factory() as setup:
        setup.add(Policy(id=POLICY_A, name=POLICY_A, type="application"))
        setup.commit()
        service = DeviceService(setup)
        raw, rt = service.create_registration_token(
            "fixture", POLICY_A, expires_at=datetime.now(UTC) + timedelta(days=1), purpose="collector_write"
        )
        token_id = rt.id
        devices = [
            service.enrol_device(
                rt_token_hash=hash_key(raw),
                installation_id=str(uuid4()),
                device_name="fixture",
                user_name="",
                user_email="",
                browser="",
                os="",
                ext_version="",
            )["result"]
            for _ in range(2)
        ]
        expiring, fresh = devices
        device_id = expiring["device_id"]
        setup.query(Device).filter_by(id=device_id).update({"created_at": datetime.now(UTC) - timedelta(days=4)})
        now = datetime.now(UTC)
        setup.query(Device).filter_by(id=fresh["device_id"]).update({"created_at": now - timedelta(hours=71)})
        setup.commit()

    with factory() as reaper:
        approvals: list[str] = []

        @event.listens_for(reaper, "do_orm_execute")
        def approve_before_first_write(statement):
            if approvals or not (statement.is_update or statement.is_delete):
                return
            with factory() as admin:
                row = DeviceService(admin).approve_device(device_id, expiring["confirmation_code"])
                approvals.append(row.status)

        # The same instant in an offset timezone must retain the other
        # device's remaining hour and quota slot.
        reaped = DeviceService(reaper).reap_pending_devices(now=now.astimezone(timezone(timedelta(hours=2))))
        assert approvals == ["active"]
        assert reaped == 0

    with factory() as verify:
        pending = verify.get(Device, fresh["device_id"])
        registration = verify.get(RegistrationToken, token_id)
        assert pending is not None and pending.status == "pending"
        assert registration is not None and registration.pending_count == 1
        principal = authorize_collector(
            verify, hash_key(expiring["access_token"]["token"]), device_id, datetime.now(UTC)
        )
        assert principal.policy_id == POLICY_A
        assert verify.query(DeviceRefreshToken).filter_by(device_id=device_id).count() == 1
    engine.dispose()


def test_existing_guard_tombstone_cannot_reclassify_imported_collector_on_deletion(fleet):
    client, keys, sessions = fleet
    admin = keys["deployment"]
    token = register(client, admin).json()["token"]
    installation = str(uuid4())
    device = enrol(client, token, installation).json()["result"]
    device_id = device["device_id"]
    path = f"{DEVICES}/{device_id}"
    guard = register(client, admin, purpose="guard_device").json()["token"]
    with sessions.begin() as session:
        session.get(Device, device_id).policy_id = None
        session.add(
            DeviceTombstone(
                device_id=device_id,
                installation_id=installation,
                reason="incomplete import",
                recovery_secret_hash=hash_key("synthetic-test-grant"),
            )
        )
    for deleted in (False, True):
        if deleted:
            assert client.delete(path, headers=bearer(admin)).status_code == 204
        assert enrol(client, guard, installation, recovery_secret="synthetic-test-grant").status_code == 403
        assert client.post(f"{path}/authorise-recovery", headers=bearer(admin)).status_code == 403
    with sessions() as session:
        assert session.get(DeviceTombstone, device_id).purpose == "collector_write"
