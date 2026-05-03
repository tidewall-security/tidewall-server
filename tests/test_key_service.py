"""Tests for KeyService — key CRUD and bootstrap."""
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.engine import get_engine, get_session_factory
from app.db.models import Base, APIKey, Policy


@pytest.fixture
def db_session():
    engine = get_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = get_session_factory(engine)
    session = Session()
    # Create a default policy for key binding
    policy = Policy(name="default", type="application", is_default=True)
    session.add(policy)
    session.commit()
    yield session
    session.close()


def test_create_key(db_session):
    from app.services.key_service import KeyService

    svc = KeyService(db_session)
    raw_key, api_key = svc.create_key(
        name="test-collector",
        role="api",
        collector_type="application",
    )
    assert raw_key.startswith("ak_")
    assert api_key.id is not None
    assert api_key.role == "api"
    assert api_key.key_prefix.startswith("ak_")


def test_create_key_with_policy_binding(db_session):
    from app.services.key_service import KeyService

    svc = KeyService(db_session)
    policy = db_session.query(Policy).first()
    raw_key, api_key = svc.create_key(
        name="bound-collector",
        role="api",
        policy_id=policy.id,
    )
    assert api_key.policy_id == policy.id


def test_list_keys(db_session):
    from app.services.key_service import KeyService

    svc = KeyService(db_session)
    svc.create_key(name="key1", role="admin")
    svc.create_key(name="key2", role="viewer")
    keys = svc.list_keys()
    assert len(keys) == 2


def test_delete_key(db_session):
    from app.services.key_service import KeyService

    svc = KeyService(db_session)
    _, api_key = svc.create_key(name="deletable", role="api")
    svc.delete_key(api_key.id)
    assert db_session.query(APIKey).filter_by(id=api_key.id).first() is None


def test_lookup_by_raw_key(db_session):
    from app.services.key_service import KeyService

    svc = KeyService(db_session)
    raw_key, _ = svc.create_key(name="lookup-test", role="viewer")
    found = svc.lookup_key(raw_key)
    assert found is not None
    assert found.name == "lookup-test"
    assert found.role == "viewer"


def test_lookup_invalid_key_returns_none(db_session):
    from app.services.key_service import KeyService

    svc = KeyService(db_session)
    found = svc.lookup_key("ak_nonexistent_key_value_here")
    assert found is None


def test_bootstrap_creates_admin_key_when_empty(db_session):
    from app.services.key_service import KeyService

    svc = KeyService(db_session)
    raw_key = svc.bootstrap_admin_key()
    assert raw_key is not None
    assert raw_key.startswith("ak_")

    # Verify it's in the DB
    found = svc.lookup_key(raw_key)
    assert found is not None
    assert found.role == "admin"
    assert found.name == "bootstrap-admin"


def test_bootstrap_skips_when_keys_exist(db_session):
    from app.services.key_service import KeyService

    svc = KeyService(db_session)
    svc.create_key(name="existing", role="admin")
    raw_key = svc.bootstrap_admin_key()
    assert raw_key is None  # Already have keys, skip bootstrap
