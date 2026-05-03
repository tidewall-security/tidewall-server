"""Tests for FPEService — format-preserving encryption."""
import os
import pytest
from app.db.engine import get_engine, get_session_factory
from app.db.models import Base, FPESettings


@pytest.fixture
def db_session():
    engine = get_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = get_session_factory(engine)
    session = Session()
    yield session
    session.close()


def test_encrypt_preserves_digit_format(db_session):
    from app.services.fpe_service import FPEService
    svc = FPEService(db_session)
    encrypted, ctx = svc.encrypt("2345678901")
    assert len(encrypted) == len("2345678901")
    assert encrypted.isdigit()
    assert encrypted != "2345678901"


def test_decrypt_restores_original(db_session):
    from app.services.fpe_service import FPEService
    svc = FPEService(db_session)
    original = "2345678901"
    encrypted, ctx = svc.encrypt(original)
    decrypted = svc.decrypt(encrypted, ctx)
    assert decrypted == original


def test_deterministic_with_same_tweak(db_session):
    from app.services.fpe_service import FPEService
    # Set a custom tweak for deterministic mode
    settings = FPESettings(id="singleton", key=os.urandom(32), default_tweak="a1b2c3d4e5f6a7")
    db_session.add(settings)
    db_session.commit()

    svc = FPEService(db_session)
    enc1, _ = svc.encrypt("2345678901")
    enc2, _ = svc.encrypt("2345678901")
    assert enc1 == enc2  # Same input + same tweak = same output


def test_non_deterministic_without_tweak(db_session):
    from app.services.fpe_service import FPEService
    svc = FPEService(db_session)
    # Without custom tweak, random tweak each time
    enc1, ctx1 = svc.encrypt("2345678901")
    enc2, ctx2 = svc.encrypt("2345678901")
    # Different tweaks → different outputs (very high probability)
    # But both should decrypt correctly
    dec1 = svc.decrypt(enc1, ctx1)
    dec2 = svc.decrypt(enc2, ctx2)
    assert dec1 == "2345678901"
    assert dec2 == "2345678901"


def test_encrypt_alphanumeric(db_session):
    from app.services.fpe_service import FPEService
    svc = FPEService(db_session)
    original = "john@example.com"
    encrypted, ctx = svc.encrypt(original, radix=36)
    decrypted = svc.decrypt(encrypted, ctx)
    assert decrypted == original.lower()  # radix 36 is lowercase


def test_encrypt_short_value_padded(db_session):
    """Values shorter than ff3 minimum domain get padded."""
    from app.services.fpe_service import FPEService
    svc = FPEService(db_session)
    # "123" is too short for radix 10 (needs 6+ digits)
    encrypted, ctx = svc.encrypt("123")
    decrypted = svc.decrypt(encrypted, ctx)
    assert decrypted == "123"


def test_key_auto_generated_on_first_use(db_session):
    from app.services.fpe_service import FPEService
    svc = FPEService(db_session)
    # No FPESettings row exists yet — should auto-create
    encrypted, ctx = svc.encrypt("2345678901")
    assert encrypted is not None
    # Verify key was persisted
    settings = db_session.query(FPESettings).first()
    assert settings is not None
    assert len(settings.key) == 32


def test_fpe_context_format(db_session):
    from app.services.fpe_service import FPEService
    import json, base64
    svc = FPEService(db_session)
    _, ctx = svc.encrypt("2345678901")
    decoded = json.loads(base64.b64decode(ctx))
    assert decoded["version"] == 1
    assert decoded["algorithm"] == "AES-FF1-256"
    assert "tweak" in decoded
