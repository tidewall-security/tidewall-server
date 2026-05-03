"""Tests for device registration models and service."""

import pytest
from datetime import datetime, timezone, timedelta

from app.db.models import Base, RegistrationToken, Device, AccessToken
from app.db.engine import get_engine, get_session_factory


@pytest.fixture
def db_session():
    engine = get_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    SessionLocal = get_session_factory(engine)
    session = SessionLocal()
    yield session
    session.close()


def test_create_registration_token(db_session):
    token = RegistrationToken(
        name="Q1 Onboarding",
        token_hash="abc123hash",
        token_prefix="rt_abcd...",
        created_by="admin-key-id-1",
    )
    db_session.add(token)
    db_session.commit()
    result = db_session.query(RegistrationToken).first()
    assert result is not None
    assert result.name == "Q1 Onboarding"
    assert result.token_hash == "abc123hash"
    assert result.expires_at is None


def test_create_device(db_session):
    device = Device(
        fingerprint="fp-uuid-1234",
        device_name="Jon's MacBook",
        user_name="Jon W",
        user_email="jon@company.com",
        browser="Chrome 131",
        os="macOS 15.3",
        ext_version="1.0.0",
    )
    db_session.add(device)
    db_session.commit()
    result = db_session.query(Device).filter_by(fingerprint="fp-uuid-1234").first()
    assert result is not None
    assert result.status == "active"
    assert result.device_name == "Jon's MacBook"


def test_create_access_token(db_session):
    device = Device(
        fingerprint="fp-1",
        device_name="test",
        user_name="test",
        user_email="test@test.com",
        browser="Chrome",
        os="macOS",
        ext_version="1.0.0",
    )
    db_session.add(device)
    db_session.commit()
    token = AccessToken(
        token_hash="token-hash-1",
        device_id=device.id,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    db_session.add(token)
    db_session.commit()
    result = db_session.query(AccessToken).first()
    assert result is not None
    assert result.device_id == device.id


from app.services.device_service import DeviceService
from app.auth.key_utils import generate_key, hash_key


@pytest.fixture
def reg_token(db_session):
    """Create a registration token and return (raw_token, db_record)."""
    raw = generate_key(prefix="rt")
    token = RegistrationToken(
        name="test-token",
        token_hash=hash_key(raw),
        token_prefix=raw[:7] + "...",
        created_by="admin-1",
    )
    db_session.add(token)
    db_session.commit()
    return raw, token


def test_register_new_device(db_session, reg_token):
    raw_rt, _ = reg_token
    svc = DeviceService(db_session)
    result = svc.check_device(
        rt_token_hash=hash_key(raw_rt),
        fingerprint="fp-new-device",
        device_name="Test MacBook",
        user_name="Test User",
        user_email="test@co.com",
        browser="Chrome 131",
        os="macOS 15.3",
        ext_version="1.0.0",
    )
    assert result["status"] == "Success"
    assert "access_token" in result["result"]
    assert result["result"]["access_token"]["token"].startswith("at_")
    assert result["result"]["access_token"]["expires_in"] == 3600
    device = db_session.query(Device).filter_by(fingerprint="fp-new-device").first()
    assert device is not None
    assert device.user_email == "test@co.com"


def test_refresh_existing_device(db_session, reg_token):
    raw_rt, _ = reg_token
    svc = DeviceService(db_session)
    result1 = svc.check_device(
        rt_token_hash=hash_key(raw_rt), fingerprint="fp-existing",
        device_name="MacBook", user_name="Jon", user_email="jon@co.com",
        browser="Chrome", os="macOS", ext_version="1.0.0",
    )
    token1 = result1["result"]["access_token"]["token"]
    result2 = svc.check_device(
        rt_token_hash=hash_key(raw_rt), fingerprint="fp-existing",
        device_name="MacBook", user_name="Jon", user_email="jon@co.com",
        browser="Chrome", os="macOS", ext_version="1.0.0",
    )
    token2 = result2["result"]["access_token"]["token"]
    assert token2 != token1
    count = db_session.query(Device).filter_by(fingerprint="fp-existing").count()
    assert count == 1


def test_check_device_invalid_rt(db_session):
    svc = DeviceService(db_session)
    with pytest.raises(ValueError, match="Invalid registration token"):
        svc.check_device(
            rt_token_hash="nonexistent-hash", fingerprint="fp-1",
            device_name="test", user_name="test", user_email="t@t.com",
            browser="Chrome", os="macOS", ext_version="1.0.0",
        )


def test_check_device_revoked_returns_inactive(db_session, reg_token):
    raw_rt, _ = reg_token
    svc = DeviceService(db_session)
    svc.check_device(
        rt_token_hash=hash_key(raw_rt), fingerprint="fp-revoked",
        device_name="test", user_name="test", user_email="t@t.com",
        browser="Chrome", os="macOS", ext_version="1.0.0",
    )
    device = db_session.query(Device).filter_by(fingerprint="fp-revoked").first()
    device.status = "revoked"
    db_session.commit()
    result = svc.check_device(
        rt_token_hash=hash_key(raw_rt), fingerprint="fp-revoked",
        device_name="test", user_name="test", user_email="t@t.com",
        browser="Chrome", os="macOS", ext_version="1.0.0",
    )
    assert result["status"] == "InactiveDevice"
    assert result["result"] is None


def test_resolve_device_from_access_token(db_session, reg_token):
    raw_rt, _ = reg_token
    svc = DeviceService(db_session)
    result = svc.check_device(
        rt_token_hash=hash_key(raw_rt), fingerprint="fp-resolve",
        device_name="test", user_name="test", user_email="t@t.com",
        browser="Chrome", os="macOS", ext_version="1.0.0",
    )
    raw_at = result["result"]["access_token"]["token"]
    device = svc.resolve_access_token(hash_key(raw_at))
    assert device is not None
    assert device.fingerprint == "fp-resolve"


def test_resolve_expired_access_token_returns_none(db_session, reg_token):
    raw_rt, _ = reg_token
    svc = DeviceService(db_session)
    result = svc.check_device(
        rt_token_hash=hash_key(raw_rt), fingerprint="fp-expired",
        device_name="test", user_name="test", user_email="t@t.com",
        browser="Chrome", os="macOS", ext_version="1.0.0",
    )
    raw_at = result["result"]["access_token"]["token"]
    at_record = db_session.query(AccessToken).filter_by(token_hash=hash_key(raw_at)).first()
    at_record.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
    db_session.commit()
    device = svc.resolve_access_token(hash_key(raw_at))
    assert device is None


def test_list_devices(db_session, reg_token):
    raw_rt, _ = reg_token
    svc = DeviceService(db_session)
    svc.check_device(
        rt_token_hash=hash_key(raw_rt), fingerprint="fp-list-1",
        device_name="Device 1", user_name="User 1", user_email="u1@co.com",
        browser="Chrome", os="macOS", ext_version="1.0.0",
    )
    svc.check_device(
        rt_token_hash=hash_key(raw_rt), fingerprint="fp-list-2",
        device_name="Device 2", user_name="User 2", user_email="u2@co.com",
        browser="Firefox", os="Windows", ext_version="1.0.0",
    )
    devices = svc.list_devices()
    assert len(devices) == 2
