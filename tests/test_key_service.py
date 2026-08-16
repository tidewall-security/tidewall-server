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


def test_bootstrap_installs_operator_supplied_key_when_empty(db_session):
    from app.services.key_service import KeyService

    svc = KeyService(db_session)
    assert svc.has_any_key() is False

    assert svc.install_bootstrap_admin_key("ak_operator_supplied_secret") is True

    found = svc.lookup_key("ak_operator_supplied_secret")
    assert found is not None
    assert found.role == "admin"
    assert found.name == "bootstrap-admin"


def test_bootstrap_key_never_reaches_logs(db_session, caplog):
    """P0-7 canary: the raw key must not appear in any log record.

    The previous implementation logged it at warning level, putting a
    permanent administrator bearer token into whatever collects container
    logs.
    """
    import logging

    from app.services.key_service import KeyService

    secret = "ak_canary_must_not_be_logged_8f3a2b"
    with caplog.at_level(logging.DEBUG):
        KeyService(db_session).install_bootstrap_admin_key(secret)

    assert secret not in caplog.text
    for record in caplog.records:
        assert secret not in record.getMessage()


def test_bootstrap_skips_when_keys_exist(db_session):
    from app.services.key_service import KeyService

    svc = KeyService(db_session)
    svc.create_key(name="existing", role="admin")
    assert svc.install_bootstrap_admin_key("ak_should_be_ignored") is False
    assert svc.lookup_key("ak_should_be_ignored") is None
