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
from app.db.models import AccessToken, Base, Device, Policy, RegistrationToken
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

    with pytest.raises(PermissionError, match="not valid for this device"):
        DeviceService(db_session).refresh_device(
            device_id=alice["result"]["device_id"],
            access_token_hash=hash_key(mallory["result"]["access_token"]["token"]),
        )


def test_refresh_rejects_an_unknown_token(db_session):
    raw_rt, _ = _reg_token(db_session)
    alice = _enrol(db_session, raw_rt, "inst-alice")

    with pytest.raises(PermissionError, match="Invalid access token"):
        DeviceService(db_session).refresh_device(
            device_id=alice["result"]["device_id"],
            access_token_hash=hash_key("at_not_a_real_token"),
        )


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


def test_enrol_inherits_the_registration_token_policy(db_session):
    """Enrolment previously conferred no scope at all."""
    policy = Policy(name="engineering", type="application")
    db_session.add(policy)
    db_session.commit()
    raw_rt, _ = _reg_token(db_session, policy_id=policy.id)

    result = _enrol(db_session, raw_rt, "inst-scoped")

    assert db_session.get(Device, result["result"]["device_id"]).policy_id == policy.id


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


def test_refresh_rotates_the_token_with_an_overlap(db_session):
    """The old token stays briefly valid so an in-flight request survives.

    Refresh used to delete every access token for the device, which failed any
    request already running.
    """
    raw_rt, _ = _reg_token(db_session)
    enrolled = _enrol(db_session, raw_rt, "inst-1")
    old_raw = enrolled["result"]["access_token"]["token"]

    refreshed = DeviceService(db_session).refresh_device(
        device_id=enrolled["result"]["device_id"],
        access_token_hash=hash_key(old_raw),
    )

    assert refreshed["status"] == "Success"
    new_raw = refreshed["result"]["access_token"]["token"]
    assert new_raw != old_raw

    old = db_session.query(AccessToken).filter_by(token_hash=hash_key(old_raw)).one()
    assert old.replaced_by_id is not None, "rotation must be traceable"
    expires = old.expires_at.replace(tzinfo=UTC) if old.expires_at.tzinfo is None else old.expires_at
    assert expires > datetime.now(UTC), "the replaced token must remain briefly valid"
    assert expires < datetime.now(UTC) + timedelta(seconds=120)


def test_refresh_updates_metadata(db_session):
    raw_rt, _ = _reg_token(db_session)
    enrolled = _enrol(db_session, raw_rt, "inst-1", device_name="Old")

    DeviceService(db_session).refresh_device(
        device_id=enrolled["result"]["device_id"],
        access_token_hash=hash_key(enrolled["result"]["access_token"]["token"]),
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
        access_token_hash=hash_key(enrolled["result"]["access_token"]["token"]),
    )

    assert result["status"] == "InactiveDevice"


def test_registration_token_model_round_trips(db_session):
    raw, rt = _reg_token(db_session, "Q1 Onboarding")

    stored = db_session.query(RegistrationToken).one()
    assert stored.name == "Q1 Onboarding"
    assert stored.token_hash == hash_key(raw)
    assert stored.expires_at is None
