"""Tests for DB-backed VaultManager."""

from datetime import UTC, datetime, timedelta

import pytest

from app.db.engine import get_engine, get_session_factory
from app.db.models import Base
from app.db.models import Vault as VaultModel


@pytest.fixture
def session_factory():
    engine = get_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return get_session_factory(engine)


def test_create_vault_returns_id_and_instance(session_factory):
    from app.vault_manager import VaultManager

    mgr = VaultManager(session_factory)
    vault_id, vault = mgr.create_vault()
    assert vault_id is not None
    assert vault is not None


def test_create_vault_persists_to_db(session_factory):
    from app.vault_manager import VaultManager

    mgr = VaultManager(session_factory)
    vault_id, _ = mgr.create_vault()
    with session_factory() as session:
        row = session.get(VaultModel, vault_id)
        assert row is not None
        assert row.data is not None


def test_get_vault_returns_persisted_vault(session_factory):
    from app.vault_manager import VaultManager

    mgr = VaultManager(session_factory)
    vault_id, original = mgr.create_vault()
    # Clear in-memory cache to force DB lookup
    mgr._cache.clear()
    retrieved = mgr.get_vault(vault_id)
    assert retrieved is not None


def test_get_vault_expired_returns_none(session_factory):
    from app.vault_manager import VaultManager

    mgr = VaultManager(session_factory)
    vault_id, _ = mgr.create_vault()
    # Manually expire it in the DB
    with session_factory() as session:
        row = session.get(VaultModel, vault_id)
        row.expires_at = datetime.now(UTC) - timedelta(hours=2)
        session.commit()
    mgr._cache.clear()
    assert mgr.get_vault(vault_id) is None


def test_get_vault_nonexistent_returns_none(session_factory):
    from app.vault_manager import VaultManager

    mgr = VaultManager(session_factory)
    assert mgr.get_vault("nonexistent-id") is None


def test_encode_decode_fpe_context(session_factory):
    from app.vault_manager import VaultManager

    mgr = VaultManager(session_factory)
    vault_id, _ = mgr.create_vault()
    encoded = mgr.encode_fpe_context(vault_id)
    decoded = mgr.decode_fpe_context(encoded)
    assert decoded == vault_id
