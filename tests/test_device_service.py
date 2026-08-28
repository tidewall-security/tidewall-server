"""Device enrolment and refresh.

P0-11: refresh looked a device up by caller-supplied `fingerprint` alone. It
checked the caller held *a* registration token but never that the token owned
that device, so any token holder plus a guessed fingerprint could revoke the
victim's session and obtain an access token bound to their device and policy.

Enrolment and refresh are now separate flows with separate credentials, and
nothing authorises against a client-supplied value.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from app.auth.key_utils import generate_key, hash_key, key_prefix
from app.db.engine import get_engine, get_session_factory
from app.db.models import (
    AccessToken,
    Base,
    Device,
    DeviceRefreshToken,
    DeviceTombstone,
    Policy,
    RegistrationToken,
)
from app.services.device_service import DeviceService


@pytest.fixture
def db_session():
    engine = get_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    SessionLocal = get_session_factory(engine)
    session = SessionLocal()
    yield session
    session.close()


def _reg_token(session, name="onboarding", policy_id=None) -> tuple[str, RegistrationToken]:
    raw = generate_key(prefix="rt")
    rt = RegistrationToken(
        name=name,
        token_hash=hash_key(raw),
        token_prefix=key_prefix(raw),
        policy_id=policy_id,
        # Required since keys became bounded. Constructed directly here rather
        # than through the service, so the column has to be supplied.
        expires_at=datetime.now(UTC) + timedelta(days=30),
        # Pre-authorized so the tests that use this helper stay about what they
        # test -- refresh, revocation, policy inheritance -- rather than each
        # growing an approval step. The pending default is pinned separately by
        # the approval tests, which build their tokens WITHOUT this flag and so
        # exercise the real default.
        pre_authorized=True,
    )
    session.add(rt)
    session.commit()
    return raw, rt


def _enrol(session, raw_rt, installation_id, **kw):
    return DeviceService(session).enrol_device(
        rt_token_hash=hash_key(raw_rt),
        installation_id=installation_id,
        device_name=kw.get("device_name", "Laptop"),
        user_name=kw.get("user_name", "Alice"),
        user_email=kw.get("user_email", "alice@example.com"),
        browser=kw.get("browser", "chrome"),
        os=kw.get("os", "macos"),
        ext_version=kw.get("ext_version", "1.0.0"),
        fingerprint=kw.get("fingerprint"),
    )


# ---------------------------------------------------------------------------
# The takeover
# ---------------------------------------------------------------------------


def test_a_registration_token_cannot_refresh_someone_elses_device(db_session):
    """The P0-11 regression, stated as the attack.

    Mallory holds a valid onboarding token and learns Alice's fingerprint.
    Previously that was enough to revoke Alice's session and receive an access
    token bound to her device. Enrolment can now only ever create.
    """
    alice_rt, _ = _reg_token(db_session, "alice-onboarding")
    alice = _enrol(db_session, alice_rt, "inst-alice", fingerprint="fp-shared")
    alice_device_id = alice["result"]["device_id"]
    alice_token_count = db_session.query(AccessToken).filter_by(device_id=alice_device_id).count()

    mallory_rt, _ = _reg_token(db_session, "mallory-onboarding")
    result = _enrol(db_session, mallory_rt, "inst-mallory", fingerprint="fp-shared")

    # A separate device, not Alice's.
    assert result["status"] == "Success"
    assert result["result"]["device_id"] != alice_device_id
    # Alice's session is untouched.
    assert db_session.query(AccessToken).filter_by(device_id=alice_device_id).count() == alice_token_count
    assert db_session.get(Device, alice_device_id).installation_id == "inst-alice"


def test_refresh_requires_a_token_for_that_device(db_session):
    """A valid access token for a different device must not authorise."""
    raw_rt, _ = _reg_token(db_session)
    alice = _enrol(db_session, raw_rt, "inst-alice")
    mallory = _enrol(db_session, raw_rt, "inst-mallory")

    result = DeviceService(db_session).refresh_device(
        device_id=alice["result"]["device_id"],
        refresh_token_hash=hash_key(mallory["result"]["refresh_token"]["token"]),
    )
    # Not distinguished from an unknown credential: telling them apart tells a
    # caller whether the target device exists.
    assert result["status"] == "credential_unknown"


def test_refresh_rejects_an_unknown_token(db_session):
    raw_rt, _ = _reg_token(db_session)
    alice = _enrol(db_session, raw_rt, "inst-alice")

    result = DeviceService(db_session).refresh_device(
        device_id=alice["result"]["device_id"],
        refresh_token_hash=hash_key("dr_not_a_real_token"),
    )
    assert result["status"] == "credential_unknown"


def test_fingerprint_no_longer_selects_a_device(db_session):
    """Two devices may report the same fingerprint; it is advisory only."""
    raw_rt, _ = _reg_token(db_session)
    _enrol(db_session, raw_rt, "inst-one", fingerprint="identical")
    _enrol(db_session, raw_rt, "inst-two", fingerprint="identical")

    assert db_session.query(Device).filter_by(fingerprint="identical").count() == 2


# ---------------------------------------------------------------------------
# Enrolment
# ---------------------------------------------------------------------------


def test_enrol_creates_a_device_and_issues_a_token(db_session):
    raw_rt, rt = _reg_token(db_session)

    result = _enrol(db_session, raw_rt, "inst-1")

    assert result["status"] == "Success"
    device = db_session.get(Device, result["result"]["device_id"])
    assert device.installation_id == "inst-1"
    assert device.reg_token_id == rt.id
    assert result["result"]["access_token"]["token"].startswith("at_")


# Enrolment's inheritance of the token's policy is asserted by
# `test_a_token_created_through_the_service_carries_its_policy_to_enrolment`,
# which builds the token the way the product does. The version that lived here
# injected a RegistrationToken row with the policy already set, so it passed
# while nothing in the application could produce one.


def test_enrol_refuses_an_already_enrolled_installation(db_session):
    """The client holds credentials and should refresh, not re-enrol."""
    raw_rt, _ = _reg_token(db_session)
    _enrol(db_session, raw_rt, "inst-dup")

    result = _enrol(db_session, raw_rt, "inst-dup")

    assert result["status"] == "InstallationIdAlreadyEnrolled"
    assert db_session.query(Device).filter_by(installation_id="inst-dup").count() == 1


def test_enrol_rejects_an_invalid_registration_token(db_session):
    with pytest.raises(ValueError, match="Invalid registration token"):
        _enrol(db_session, "rt_nonexistent", "inst-x")


# ---------------------------------------------------------------------------
# Refresh and rotation
# ---------------------------------------------------------------------------


def test_refresh_updates_metadata(db_session):
    raw_rt, _ = _reg_token(db_session)
    enrolled = _enrol(db_session, raw_rt, "inst-1", device_name="Old")

    DeviceService(db_session).refresh_device(
        device_id=enrolled["result"]["device_id"],
        refresh_token_hash=hash_key(enrolled["result"]["refresh_token"]["token"]),
        device_name="New",
    )

    assert db_session.get(Device, enrolled["result"]["device_id"]).device_name == "New"


def test_refresh_of_an_inactive_device_is_refused(db_session):
    raw_rt, _ = _reg_token(db_session)
    enrolled = _enrol(db_session, raw_rt, "inst-1")
    device = db_session.get(Device, enrolled["result"]["device_id"])
    device.status = "revoked"
    db_session.commit()

    result = DeviceService(db_session).refresh_device(
        device_id=device.id,
        refresh_token_hash=hash_key(enrolled["result"]["refresh_token"]["token"]),
    )

    assert result["status"] == "device_revoked"


def test_registration_token_model_round_trips(db_session):
    raw, rt = _reg_token(db_session, "Q1 Onboarding")

    stored = db_session.query(RegistrationToken).one()
    assert stored.name == "Q1 Onboarding"
    assert stored.token_hash == hash_key(raw)
    # Was `is None`: an unbounded key is no longer expressible. This assertion
    # is what kept the expiring path out of the suite entirely, and with it the
    # timezone defect in the middleware that made expiring keys unusable.
    assert stored.expires_at is not None


# ---------------------------------------------------------------------------
# Rotation is one-time
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Policy scope is actually produced, not only consumed
# ---------------------------------------------------------------------------


def test_creating_a_registration_token_requires_a_policy_that_exists(db_session):
    with pytest.raises(ValueError, match="not found"):
        DeviceService(db_session).create_registration_token(name="onboarding", policy_id="no-such-policy")


def test_a_token_created_through_the_service_carries_its_policy_to_enrolment(db_session):
    """The end-to-end producer/consumer path.

    The earlier test for this injected a `RegistrationToken(policy_id=...)`
    directly, so it passed while no code anywhere could create such a token:
    the service had no parameter for it and the admin route had no field. Every
    real device enrolled with policy_id NULL and silently used the default
    policy. Build the token the way the product does.
    """
    policy = Policy(name="engineering", type="application")
    db_session.add(policy)
    db_session.commit()

    raw_rt, record = DeviceService(db_session).create_registration_token(
        name="engineering-onboarding", policy_id=policy.id, expires_at=_soon(30)
    )
    assert record.policy_id == policy.id

    result = _enrol(db_session, raw_rt, "inst-scoped")

    assert db_session.get(Device, result["result"]["device_id"]).policy_id == policy.id


# ---------------------------------------------------------------------------
# Bounded registration keys
#
# An enrolment key with no deadline is a permanent capability to create
# devices, and one with no ceiling enrols a fleet inside its window. Both
# bounds land together because either alone still leaves the key unbounded in
# the other dimension.
# ---------------------------------------------------------------------------

_META = {
    "device_name": "Laptop",
    "user_name": "Alice",
    "user_email": "alice@example.com",
    "browser": "chrome",
    "os": "macos",
    "ext_version": "1.0.0",
}


def _soon(days: int = 1) -> datetime:
    return datetime.now(UTC) + timedelta(days=days)


def _seed_policy(session, policy_id: str = "test-policy") -> str:
    if session.get(Policy, policy_id) is None:
        session.add(Policy(id=policy_id, name=policy_id, type="application"))
        session.commit()
    return policy_id


def test_registration_token_requires_an_expiry(db_session):
    """A key with no deadline is a permanent enrolment capability."""
    policy_id = _seed_policy(db_session)
    with pytest.raises(ValueError, match="expiry"):
        DeviceService(db_session).create_registration_token(name="unbounded", policy_id=policy_id, expires_at=None)


def test_registration_token_expiry_is_capped(db_session):
    """Mandatory but unlimited is the same permanent capability, spelled longer."""
    policy_id = _seed_policy(db_session)
    with pytest.raises(ValueError, match="90 days"):
        DeviceService(db_session).create_registration_token(
            name="too-far", policy_id=policy_id, expires_at=datetime.now(UTC) + timedelta(days=91)
        )


def test_max_uses_is_enforced_across_enrolments(db_session):
    """The ceiling bounds devices created, not requests made."""
    policy_id = _seed_policy(db_session)
    service = DeviceService(db_session)
    raw, _rt = service.create_registration_token(name="two-only", policy_id=policy_id, expires_at=_soon(), max_uses=2)

    for n in range(2):
        assert _enrol(db_session, raw, f"inst-cap-{n}")["status"] == "Success", f"enrolment {n}"

    third = _enrol(db_session, raw, "inst-cap-over")

    assert third["status"] == "RegistrationTokenExhausted"
    assert db_session.query(Device).count() == 2, "a device row survived the refusal"


def test_a_refused_enrolment_does_not_consume_a_use(db_session):
    """A duplicate installation id must not burn the ceiling.

    The use is claimed before the insert. If the claim does not roll back with
    the insert, anyone who knows an installation id already enrolled can
    exhaust that key by replaying it.
    """
    policy_id = _seed_policy(db_session)
    service = DeviceService(db_session)
    raw, rt = service.create_registration_token(name="k", policy_id=policy_id, expires_at=_soon(), max_uses=2)
    rt_id = rt.id

    assert _enrol(db_session, raw, "inst-dup")["status"] == "Success"
    assert _enrol(db_session, raw, "inst-dup")["status"] == "InstallationIdAlreadyEnrolled"

    # expire_all() first. The counter is claimed with synchronize_session=False
    # and the factory sets expire_on_commit=False, so the instance in the
    # identity map still reports the value it was loaded with -- reading it
    # directly would assert against a stale copy and report a failure the
    # database does not have.
    db_session.expire_all()
    assert db_session.get(RegistrationToken, rt_id).uses == 1, "the rejected duplicate consumed a use"


def test_two_concurrent_enrolments_cannot_share_the_last_use(tmp_path):
    """The conditional write is the guarantee; the pre-check is a fast path.

    A FILE-backed database, not :memory:. An in-memory SQLite with a shared
    connection would let both sessions see one another's uncommitted state, so
    the threads never actually contend and this passes against the very
    read-modify-write it exists to catch.
    """
    import threading

    engine = get_engine(f"sqlite:///{tmp_path}/race.db")
    Base.metadata.create_all(engine)
    SessionLocal = get_session_factory(engine)

    setup = SessionLocal()
    policy_id = _seed_policy(setup)
    raw, _rt = DeviceService(setup).create_registration_token(
        name="one-left", policy_id=policy_id, expires_at=_soon(), max_uses=1
    )
    setup.close()

    barrier = threading.Barrier(2)
    results: list[str] = []
    lock = threading.Lock()

    def enrol(label: str) -> None:
        session = SessionLocal()
        try:
            service = DeviceService(session)
            service.lookup_registration_token(hash_key(raw))  # both read before either claims
            barrier.wait(timeout=10)
            outcome = service.enrol_device(rt_token_hash=hash_key(raw), installation_id=f"inst-{label}", **_META)[
                "status"
            ]
        except Exception as exc:  # a lock timeout is a legitimate third outcome
            outcome = type(exc).__name__
        finally:
            session.close()
        with lock:
            results.append(outcome)

    threads = [threading.Thread(target=enrol, args=(f"racer{n}",)) for n in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=20)

    verify = SessionLocal()
    try:
        assert results.count("Success") == 1, f"exactly one enrolment may win: {results}"
        assert verify.query(Device).count() == 1
        assert verify.query(RegistrationToken).one().uses == 1
    finally:
        verify.close()


# ---------------------------------------------------------------------------
# Approval by default
#
# Enrolment used to set status="active" unconditionally, so possession of a key
# was possession of a working device. It now yields a PENDING device: it holds
# credentials and carries no api role until an admin confirms it.
#
# Approval needs an independent confirmation because every descriptive field is
# supplied by the claimant. A key holder copies the expected user, email, device
# name, browser and OS and the row is indistinguishable from a real one. Time
# and source address are server-derived, but a shared egress address is not an
# identity.
# ---------------------------------------------------------------------------


def test_enrolment_yields_a_pending_device_by_default(db_session):
    policy_id = _seed_policy(db_session)
    service = DeviceService(db_session)
    raw, _rt = service.create_registration_token(name="k", policy_id=policy_id, expires_at=_soon())

    result = _enrol(db_session, raw, "inst-pending")

    device = db_session.query(Device).one()
    assert device.status == "pending"
    assert device.confirmation_code is not None
    assert len(device.confirmation_code) == 8
    assert result["result"]["device_status"] == "pending"
    assert result["result"]["confirmation_code"] == device.confirmation_code


def test_pre_authorized_token_yields_an_active_device(db_session):
    """Fleet deployment, where the delivery channel is already trusted.

    Set per key and never globally: the flag makes the key sufficient on its
    own, which is exactly what makes the flag worth protecting.
    """
    policy_id = _seed_policy(db_session)
    service = DeviceService(db_session)
    raw, _rt = service.create_registration_token(
        name="fleet", policy_id=policy_id, expires_at=_soon(), pre_authorized=True
    )

    result = _enrol(db_session, raw, "inst-fleet")

    device = db_session.query(Device).one()
    assert device.status == "active"
    assert device.confirmation_code is None, "an active device has nothing to confirm"
    assert "confirmation_code" not in result["result"]


def test_approval_requires_the_matching_confirmation_code(db_session):
    """Approval on device id alone is approval on a claimant-supplied row."""
    policy_id = _seed_policy(db_session)
    service = DeviceService(db_session)
    raw, _rt = service.create_registration_token(name="k", policy_id=policy_id, expires_at=_soon())
    device_id = _enrol(db_session, raw, "inst-approve")["result"]["device_id"]
    real_code = db_session.get(Device, device_id).confirmation_code

    with pytest.raises(PermissionError, match="[Cc]onfirmation code"):
        service.approve_device(device_id, confirmation_code="WRONGXXX")

    db_session.expire_all()
    assert db_session.get(Device, device_id).status == "pending", "a failed match activated the device"

    service.approve_device(device_id, confirmation_code=real_code)

    db_session.expire_all()
    approved = db_session.get(Device, device_id)
    assert approved.status == "active"
    assert approved.confirmation_code is None, "the code must be single-use"


def test_an_already_approved_device_cannot_be_approved_again(db_session):
    """The code is cleared on approval, so a replay has nothing to match."""
    policy_id = _seed_policy(db_session)
    service = DeviceService(db_session)
    raw, _rt = service.create_registration_token(name="k", policy_id=policy_id, expires_at=_soon())
    device_id = _enrol(db_session, raw, "inst-replay-approve")["result"]["device_id"]
    code = db_session.get(Device, device_id).confirmation_code
    service.approve_device(device_id, confirmation_code=code)

    with pytest.raises(PermissionError, match="not pending"):
        service.approve_device(device_id, confirmation_code=code)


# ---------------------------------------------------------------------------
# Enrolment lineage and cascade revocation
#
# Expiring or deleting a key stops future enrolments and does nothing about the
# devices already minted from it -- the whole exposure of a pre_authorized leak.
#
# Worse, reg_token_id is ondelete=SET NULL, so deleting the key destroys the
# attribution needed to find those devices at all. Containment has to survive
# the administrator's first instinct, which is to delete the key.
# ---------------------------------------------------------------------------


def _key_with_devices(session, count: int, *, name: str, label: str):
    policy_id = _seed_policy(session)
    service = DeviceService(session)
    raw, rt = service.create_registration_token(name=name, policy_id=policy_id, expires_at=_soon(), pre_authorized=True)
    for n in range(count):
        assert (
            service.enrol_device(rt_token_hash=hash_key(raw), installation_id=f"inst-{label}-{n}", **_META)["status"]
            == "Success"
        )
    return raw, rt


def test_revoking_a_key_does_not_erase_which_devices_came_from_it(db_session):
    """The FK is SET NULL, and a revoked key is exactly when attribution matters."""
    _raw, rt = _key_with_devices(db_session, 1, name="k", label="lineage")
    rt_id, prefix = rt.id, rt.token_prefix

    DeviceService(db_session).revoke_registration_token(rt_id, cascade=False)

    db_session.expire_all()
    device = db_session.query(Device).one()
    assert device.reg_token_prefix == prefix, "lineage lost; the fleet is unattributable"


def test_cascade_revocation_deactivates_every_device_from_the_key(db_session):
    _raw, rt = _key_with_devices(db_session, 3, name="leaked", label="cascade")
    _other_raw, other_rt = _key_with_devices(db_session, 1, name="clean", label="untouched")

    result = DeviceService(db_session).revoke_registration_token(rt.id, cascade=True)

    db_session.expire_all()
    assert result["devices_revoked"] == 3
    assert {d.status for d in db_session.query(Device).filter_by(reg_token_id=rt.id)} == {"revoked"}
    assert (
        db_session.query(Device).filter_by(reg_token_id=other_rt.id).one().status == "active"
    ), "cascade reached a device from a different key"


def test_cascade_revocation_destroys_the_credentials_too(db_session):
    """Status alone leaves the fleet usable for the rest of the token's hour."""
    _raw, rt = _key_with_devices(db_session, 2, name="leaked", label="creds")
    device_ids = [d.id for d in db_session.query(Device).filter_by(reg_token_id=rt.id)]
    assert db_session.query(AccessToken).filter(AccessToken.device_id.in_(device_ids)).count() == 2

    DeviceService(db_session).revoke_registration_token(rt.id, cascade=True)

    db_session.expire_all()
    assert db_session.query(AccessToken).filter(AccessToken.device_id.in_(device_ids)).count() == 0


def test_cascade_revocation_reaches_pending_devices_too(db_session):
    """A pending device from a leaked key is still a device the key created.

    Left pending it is one admin mistake away from being active, and the
    approval console gives no sign the key behind it was revoked.
    """
    policy_id = _seed_policy(db_session)
    service = DeviceService(db_session)
    raw, rt = service.create_registration_token(name="k", policy_id=policy_id, expires_at=_soon())
    service.enrol_device(rt_token_hash=hash_key(raw), installation_id="inst-pending-cascade", **_META)
    assert db_session.query(Device).one().status == "pending"

    service.revoke_registration_token(rt.id, cascade=True)

    db_session.expire_all()
    assert db_session.query(Device).one().status == "revoked"


def test_a_revoked_key_cannot_enrol(db_session):
    _raw, rt = _key_with_devices(db_session, 0, name="k", label="norol")
    raw = _raw
    DeviceService(db_session).revoke_registration_token(rt.id, cascade=False)

    assert DeviceService(db_session).lookup_registration_token(hash_key(raw)) is None


def test_revocation_is_refused_for_an_unknown_key(db_session):
    with pytest.raises(LookupError):
        DeviceService(db_session).revoke_registration_token("no-such-token", cascade=False)


def test_there_is_no_way_to_hard_delete_a_registration_token(db_session):
    """Revocation is soft on purpose, and nothing should offer the alternative.

    A hard delete nulls reg_token_id on every device the key created, so the
    fleet becomes unattributable at the exact moment attribution is needed.
    Leaving such a method available is leaving the defect available.
    """
    assert not hasattr(DeviceService(db_session), "delete_registration_token")


# ---------------------------------------------------------------------------
# A per-device refresh credential that does not rotate
#
# The original problem: a device offline for an hour is locked out, because
# refresh required an unexpired, unrotated access token with a 3600s TTL. After
# approval-by-default, re-enrolment needs an admin, so the lockout is worse.
#
# It does not rotate. Rotation cannot both survive a lost response and detect
# reuse: the client retrying after a committed-but-lost rotation is
# indistinguishable from a thief. Under a non-hostile host, a credential that
# cannot lock its owner out is worth more than one that pretends to catch a
# thief it cannot catch. The cost, stated: a stolen refresh token is usable
# until it expires or an admin revokes it.
# ---------------------------------------------------------------------------


def _active_device(session, label: str):
    """An enrolled, active device. Returns (device_id, raw_refresh_token)."""
    raw_rt, _rt = _reg_token(session, f"rt-{label}", policy_id=_seed_policy(session))
    result = _enrol(session, raw_rt, f"inst-{label}")
    assert result["status"] == "Success", result
    return result["result"]["device_id"], result["result"]["refresh_token"]["token"]


def test_refresh_works_after_the_access_token_has_expired(db_session):
    """The whole point. An hour offline must not mean re-enrolment."""
    device_id, raw_dr = _active_device(db_session, "offline")
    db_session.query(AccessToken).filter_by(device_id=device_id).update(
        {"expires_at": datetime.now(UTC) - timedelta(hours=2)}, synchronize_session=False
    )
    db_session.commit()

    result = DeviceService(db_session).refresh_device(device_id=device_id, refresh_token_hash=hash_key(raw_dr))

    assert result["status"] == "ok"
    assert result["result"]["access_token"]["token"].startswith("at_")


def test_the_refresh_token_does_not_rotate(db_session):
    """Fixed for its life. A client that loses a response can simply retry."""
    device_id, raw_dr = _active_device(db_session, "norotate")
    service = DeviceService(db_session)

    first = service.refresh_device(device_id=device_id, refresh_token_hash=hash_key(raw_dr))
    second = service.refresh_device(device_id=device_id, refresh_token_hash=hash_key(raw_dr))

    assert first["status"] == "ok" and second["status"] == "ok"
    assert first["result"]["access_token"]["token"] != second["result"]["access_token"]["token"]
    assert db_session.query(DeviceRefreshToken).filter_by(device_id=device_id).count() == 1


def test_a_refresh_token_cannot_refresh_another_device(db_session):
    mine, raw_mine = _active_device(db_session, "mine")
    theirs, _raw_theirs = _active_device(db_session, "theirs")

    result = DeviceService(db_session).refresh_device(device_id=theirs, refresh_token_hash=hash_key(raw_mine))
    assert result["status"] == "credential_unknown"


def test_an_expired_refresh_token_is_refused(db_session):
    device_id, raw_dr = _active_device(db_session, "expired")
    db_session.query(DeviceRefreshToken).filter_by(device_id=device_id).update(
        {"expires_at": datetime.now(UTC) - timedelta(seconds=1)}, synchronize_session=False
    )
    db_session.commit()

    result = DeviceService(db_session).refresh_device(device_id=device_id, refresh_token_hash=hash_key(raw_dr))
    assert result["status"] == "credential_expired"


def test_reissuing_revokes_the_previous_refresh_token(db_session):
    """Otherwise "issue new" simply leaves two usable credentials."""
    device_id, old_raw = _active_device(db_session, "reissue")
    service = DeviceService(db_session)

    new_raw = service.reissue_refresh_token(device_id)

    assert new_raw != old_raw
    assert (
        service.refresh_device(device_id=device_id, refresh_token_hash=hash_key(old_raw))["status"]
        == "credential_expired"
    )
    assert service.refresh_device(device_id=device_id, refresh_token_hash=hash_key(new_raw))["status"] == "ok"


def test_cascade_revocation_destroys_refresh_tokens_too(db_session):
    """A 30-day credential outliving a cascade makes the revocation cosmetic."""
    policy_id = _seed_policy(db_session)
    service = DeviceService(db_session)
    raw, rt = service.create_registration_token(
        name="leaked", policy_id=policy_id, expires_at=_soon(), pre_authorized=True
    )
    service.enrol_device(rt_token_hash=hash_key(raw), installation_id="inst-dr-cascade", **_META)
    assert db_session.query(DeviceRefreshToken).count() == 1

    service.revoke_registration_token(rt.id, cascade=True)

    db_session.expire_all()
    assert db_session.query(DeviceRefreshToken).count() == 0


def test_revoking_a_device_kills_every_credential_it_holds(db_session):
    """Carried over from the rotation-era test that this replaces.

    That test asserted revocation left no ACCESS token behind. A refresh
    credential outlives an access token by thirty days, so revocation that
    spares it means a device later re-activated silently regains a credential
    issued before it was revoked.
    """
    device_id, _raw_dr = _active_device(db_session, "revoke-creds")
    assert db_session.query(AccessToken).filter_by(device_id=device_id).count() == 1
    assert db_session.query(DeviceRefreshToken).filter_by(device_id=device_id).count() == 1

    DeviceService(db_session).update_device_status(device_id, "revoked")

    db_session.expire_all()
    assert db_session.query(AccessToken).filter_by(device_id=device_id).count() == 0
    assert db_session.query(DeviceRefreshToken).filter_by(device_id=device_id).count() == 0


def test_deleting_a_device_takes_its_refresh_credential_with_it(db_session):
    device_id, _raw_dr = _active_device(db_session, "delete-creds")

    DeviceService(db_session).delete_device(device_id)

    db_session.expire_all()
    assert db_session.query(DeviceRefreshToken).filter_by(device_id=device_id).count() == 0


# ---------------------------------------------------------------------------
# The refresh failure taxonomy, and its precedence
#
# Refresh answered with whatever check failed first, and the order was wrong in
# a way that matters: credential state was resolved before device state, so a
# REVOKED device whose credential had also lapsed was told to re-enrol -- and a
# compliant client did exactly that, undoing its own revocation. Reachable by
# waiting.
#
# Device state now dominates. The cases below each construct TWO simultaneously
# true conditions and assert the dominant one wins; a test with only one
# condition true cannot detect an ordering defect at all.
# ---------------------------------------------------------------------------


def _revoked_device_with_expired_credential(session):
    device_id, raw_dr = _active_device(session, "rev-exp")
    session.query(DeviceRefreshToken).filter_by(device_id=device_id).update(
        {"expires_at": datetime.now(UTC) - timedelta(days=1)}, synchronize_session=False
    )
    session.get(Device, device_id).status = "revoked"
    session.commit()
    return device_id, raw_dr


def _revoked_device_with_valid_credential(session):
    device_id, raw_dr = _active_device(session, "rev-ok")
    session.get(Device, device_id).status = "revoked"
    session.commit()
    return device_id, raw_dr


def _pending_device_with_expired_credential(session):
    device_id, raw_dr = _active_device(session, "pend-exp")
    session.query(DeviceRefreshToken).filter_by(device_id=device_id).update(
        {"expires_at": datetime.now(UTC) - timedelta(days=1)}, synchronize_session=False
    )
    session.get(Device, device_id).status = "pending"
    session.commit()
    return device_id, raw_dr


def _pending_device_with_valid_credential(session):
    device_id, raw_dr = _active_device(session, "pend-ok")
    session.get(Device, device_id).status = "pending"
    session.commit()
    return device_id, raw_dr


def _unknown_credential(session):
    device_id, _raw = _active_device(session, "unknown-cred")
    return device_id, "dr_not_a_real_token_at_all"


def _credential_for_another_device(session):
    _mine, raw_mine = _active_device(session, "other-mine")
    theirs, _raw = _active_device(session, "other-theirs")
    return theirs, raw_mine


@pytest.mark.parametrize(
    "make_state, expected",
    [
        # Both conditions true; device state must win.
        (_revoked_device_with_expired_credential, "device_revoked"),
        (_revoked_device_with_valid_credential, "device_revoked"),
        (_unknown_credential, "credential_unknown"),
        (_credential_for_another_device, "credential_unknown"),
        # Expiry above pending: a pending device with a dead credential must be
        # told to re-enrol, not to poll for an approval it can never use.
        (_pending_device_with_expired_credential, "credential_expired"),
        (_pending_device_with_valid_credential, "device_pending"),
    ],
)
def test_refresh_failure_precedence(db_session, make_state, expected):
    device_id, raw_dr = make_state(db_session)

    result = DeviceService(db_session).refresh_device(device_id=device_id, refresh_token_hash=hash_key(raw_dr))

    assert result["status"] == expected


def test_a_revoked_device_is_never_told_to_re_enrol(db_session):
    """The bypass, named.

    Revoked AND expired must answer device_revoked. credential_expired sends a
    compliant client to enrol again, which is precisely what revocation was
    meant to stop -- and the client does it by itself, without the attacker
    doing anything but wait.
    """
    device_id, raw_dr = _revoked_device_with_expired_credential(db_session)

    result = DeviceService(db_session).refresh_device(device_id=device_id, refresh_token_hash=hash_key(raw_dr))

    assert result["status"] == "device_revoked"


# ---------------------------------------------------------------------------
# Tombstones, and a recovery that authorises a consumer
#
# device_revoked means "stop permanently", and that is only true for as long as
# the evidence lasts. Revocation deletes the credentials, so a device that comes
# back later presents something unknown, is told to re-enrol, and does.
# ---------------------------------------------------------------------------


def _tombstoned(session, label: str):
    """A revoked, tombstoned device. Returns (device_id, installation_id, raw_key)."""
    policy_id = _seed_policy(session)
    service = DeviceService(session)
    raw, _rt = service.create_registration_token(
        name=f"k-{label}", policy_id=policy_id, expires_at=_soon(), pre_authorized=True
    )
    installation_id = f"inst-{label}"
    device_id = service.enrol_device(rt_token_hash=hash_key(raw), installation_id=installation_id, **_META)["result"][
        "device_id"
    ]
    service.update_device_status(device_id, "revoked")
    return device_id, installation_id, raw


def test_a_deleted_device_still_answers_revoked(db_session):
    """Deletion must not become amnesia.

    Without the tombstone the device row and its credentials are both gone, so
    refresh answers credential_unknown and a compliant client re-enrols.
    """
    device_id, raw_dr = _active_device(db_session, "deleted-tomb")
    service = DeviceService(db_session)
    service.delete_device(device_id)

    result = service.refresh_device(device_id=device_id, refresh_token_hash=hash_key(raw_dr))

    assert result["status"] == "device_revoked"


def test_a_revoked_device_answers_revoked_even_with_no_credential_left(db_session):
    """Revocation deletes the credentials, so this is the ordinary case."""
    device_id, _installation_id, _raw = _tombstoned(db_session, "revoked-nocred")

    result = DeviceService(db_session).refresh_device(
        device_id=device_id, refresh_token_hash=hash_key("dr_whatever_it_still_holds")
    )

    assert result["status"] == "device_revoked"


def test_a_tombstoned_installation_cannot_re_enrol(db_session):
    """Otherwise revocation is a delay, not a decision."""
    _device_id, installation_id, raw = _tombstoned(db_session, "reenrol")

    again = DeviceService(db_session).enrol_device(
        rt_token_hash=hash_key(raw), installation_id=installation_id, **_META
    )

    assert again["status"] == "InstallationTombstoned"


def test_recovery_requires_the_secret_the_admin_issued(db_session):
    device_id, installation_id, raw = _tombstoned(db_session, "recovery")
    service = DeviceService(db_session)

    without = service.enrol_device(rt_token_hash=hash_key(raw), installation_id=installation_id, **_META)
    assert without["status"] == "InstallationTombstoned"

    guessed = service.enrol_device(
        rt_token_hash=hash_key(raw),
        installation_id=installation_id,
        recovery_secret="not-the-secret",
        **_META,
    )
    assert guessed["status"] == "InstallationTombstoned", "a wrong secret must be indistinguishable from no secret"

    secret = service.authorise_recovery(device_id)
    ok = service.enrol_device(
        rt_token_hash=hash_key(raw),
        installation_id=installation_id,
        recovery_secret=secret,
        **_META,
    )
    assert ok["status"] == "Success"


def test_a_recovery_secret_is_single_use(db_session):
    """Consumed with the insert, or two devices recover on one grant."""
    device_id, installation_id, raw = _tombstoned(db_session, "singleuse")
    service = DeviceService(db_session)
    secret = service.authorise_recovery(device_id)

    first = service.enrol_device(
        rt_token_hash=hash_key(raw), installation_id=installation_id, recovery_secret=secret, **_META
    )
    assert first["status"] == "Success"

    replay = service.enrol_device(
        rt_token_hash=hash_key(raw), installation_id="inst-someone-else", recovery_secret=secret, **_META
    )
    assert replay["status"] == "Success", "an unrelated installation was never blocked"

    # The grant itself is spent: the tombstoned installation cannot use it twice.
    service.update_device_status(first["result"]["device_id"], "revoked")
    again = service.enrol_device(
        rt_token_hash=hash_key(raw), installation_id=installation_id, recovery_secret=secret, **_META
    )
    assert again["status"] == "InstallationTombstoned"


def test_every_terminal_transition_leaves_a_tombstone(db_session):
    """A path that removes a device without one reopens the hole."""
    service = DeviceService(db_session)

    revoked_id, _dr = _active_device(db_session, "term-revoke")
    service.update_device_status(revoked_id, "revoked")

    deleted_id, _dr2 = _active_device(db_session, "term-delete")
    service.delete_device(deleted_id)

    stones = {t.device_id for t in db_session.query(DeviceTombstone).all()}
    assert revoked_id in stones, "update_device_status(revoked) left no tombstone"
    assert deleted_id in stones, "delete_device left no tombstone"
