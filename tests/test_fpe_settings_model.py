"""Tests for FPESettings ORM model."""
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


def test_create_fpe_settings(db_session):
    settings = FPESettings(
        id="singleton",
        key=b"\x00" * 32,
    )
    db_session.add(settings)
    db_session.commit()
    assert settings.id == "singleton"
    assert len(settings.key) == 32


def test_fpe_settings_with_custom_tweak(db_session):
    settings = FPESettings(
        id="singleton",
        key=b"\x00" * 32,
        default_tweak="a1b2c3d4e5f6a7",
    )
    db_session.add(settings)
    db_session.commit()
    assert settings.default_tweak == "a1b2c3d4e5f6a7"


def test_fpe_settings_tweak_nullable(db_session):
    settings = FPESettings(
        id="singleton",
        key=b"\x00" * 32,
    )
    db_session.add(settings)
    db_session.commit()
    assert settings.default_tweak is None
