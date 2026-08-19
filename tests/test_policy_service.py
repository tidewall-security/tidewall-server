"""Tests for PolicyService — CRUD and engine cache."""

import pytest

from app.db.engine import get_engine, get_session_factory
from app.db.models import Base, Policy, RuleSet


@pytest.fixture
def db_session():
    engine = get_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = get_session_factory(engine)
    session = Session()
    yield session
    session.close()


@pytest.fixture
def seeded_session(db_session):
    """Session with one default policy and rule sets."""
    policy = Policy(
        name="default_policy",
        type="application",
        report_only=False,
        is_default=True,
    )
    db_session.add(policy)
    db_session.flush()
    for et in ("input", "output"):
        rs = RuleSet(
            policy_id=policy.id,
            event_type=et,
            detectors={"emoji": {"enabled": True, "action": "report"}},
        )
        db_session.add(rs)
    db_session.commit()
    return db_session


def test_list_policies(seeded_session):
    from app.services.policy_service import PolicyService

    svc = PolicyService(seeded_session)
    policies = svc.list_policies()
    assert len(policies) == 1
    assert policies[0].name == "default_policy"


def test_get_policy(seeded_session):
    from app.services.policy_service import PolicyService

    svc = PolicyService(seeded_session)
    policy = seeded_session.query(Policy).first()
    result = svc.get_policy(policy.id)
    assert result is not None
    assert result.name == "default_policy"


def test_create_policy(db_session):
    from app.services.policy_service import PolicyService

    svc = PolicyService(db_session)
    policy = svc.create_policy(
        name="new-policy",
        type="browser",
        detectors={"malicious_prompt": {"enabled": True, "action": "block"}},
    )
    assert policy.id is not None
    assert policy.name == "new-policy"
    # Should have input and output rule sets
    rule_sets = db_session.query(RuleSet).filter_by(policy_id=policy.id).all()
    assert len(rule_sets) == 2


def test_update_policy(seeded_session):
    from app.services.policy_service import PolicyService

    svc = PolicyService(seeded_session)
    policy = seeded_session.query(Policy).first()
    updated = svc.update_policy(policy.id, name="renamed-policy", report_only=True)
    assert updated.name == "renamed-policy"
    assert updated.report_only is True


def test_update_rule_set_detectors(seeded_session):
    from app.services.policy_service import PolicyService

    svc = PolicyService(seeded_session)
    policy = seeded_session.query(Policy).first()
    rs = svc.update_rule_set(
        policy.id,
        event_type="input",
        detectors={"malicious_prompt": {"enabled": True, "action": "block"}},
    )
    assert rs.detectors["malicious_prompt"]["action"] == "block"


def test_delete_policy(seeded_session):
    from app.services.policy_service import PolicyService

    svc = PolicyService(seeded_session)
    # First create a non-default policy to delete
    policy2 = svc.create_policy(name="deletable", type="application", detectors={})
    svc.delete_policy(policy2.id)
    assert seeded_session.query(Policy).filter_by(name="deletable").first() is None


def test_delete_default_policy_raises(seeded_session):
    from app.services.policy_service import PolicyService

    svc = PolicyService(seeded_session)
    policy = seeded_session.query(Policy).first()
    assert policy.is_default is True
    with pytest.raises(ValueError, match="Cannot delete the default policy"):
        svc.delete_policy(policy.id)


def test_get_default_policy(seeded_session):
    from app.services.policy_service import PolicyService

    svc = PolicyService(seeded_session)
    default = svc.get_default_policy()
    assert default is not None
    assert default.is_default is True


def test_get_engine_for_rule_set(seeded_session):
    from app.services.policy_service import PolicyService

    svc = PolicyService(seeded_session)
    policy = seeded_session.query(Policy).first()
    engine = svc.get_engine(policy.id, "input")
    assert engine is not None

    # Second call should return cached engine
    engine2 = svc.get_engine(policy.id, "input")
    assert engine is engine2  # Same object — cached


def test_engine_invalidated_on_update(seeded_session):
    from app.services.policy_service import PolicyService

    svc = PolicyService(seeded_session)
    policy = seeded_session.query(Policy).first()

    engine1 = svc.get_engine(policy.id, "input")
    svc.update_rule_set(
        policy.id,
        event_type="input",
        detectors={"malicious_prompt": {"enabled": True, "action": "report"}},
    )
    engine2 = svc.get_engine(policy.id, "input")
    assert engine1 is not engine2  # Rebuilt — different object


def test_deleting_a_policy_bound_to_a_device_is_refused(seeded_session):
    """Deletion must not silently rebind devices to the default policy.

    Both foreign keys to a policy are ON DELETE SET NULL, and guard reads a
    null binding as "use the default". Deleting a policy in use would therefore
    quietly move its devices onto different rules with nothing in the request
    saying so — and a device's scope is meant to be fixed at enrolment.
    """
    from app.db.models import Device
    from app.services.policy_service import PolicyInUseError, PolicyService

    svc = PolicyService(seeded_session)
    scoped = svc.create_policy(name="engineering", type="application")
    seeded_session.add(
        Device(
            installation_id="6ba7b810-9dad-11d1-80b4-00c04fd430c8",
            device_name="Laptop",
            user_name="alice",
            user_email="alice@example.com",
            policy_id=scoped.id,
            status="active",
        )
    )
    seeded_session.commit()

    with pytest.raises(PolicyInUseError, match="still bound"):
        svc.delete_policy(scoped.id)

    assert svc.get_policy(scoped.id) is not None


def test_deleting_a_policy_bound_to_a_registration_token_is_refused(seeded_session):
    """Same for a token: devices enrolled later would inherit a dead policy."""
    from app.db.models import RegistrationToken
    from app.services.policy_service import PolicyInUseError, PolicyService

    svc = PolicyService(seeded_session)
    scoped = svc.create_policy(name="contractors", type="application")
    seeded_session.add(
        RegistrationToken(name="onboarding", token_hash="h", token_prefix="rt_ab...", policy_id=scoped.id)
    )
    seeded_session.commit()

    with pytest.raises(PolicyInUseError, match="still bound"):
        svc.delete_policy(scoped.id)


def test_an_unused_policy_still_deletes(seeded_session):
    from app.services.policy_service import PolicyService

    svc = PolicyService(seeded_session)
    unused = svc.create_policy(name="unused", type="application")

    svc.delete_policy(unused.id)

    assert svc.get_policy(unused.id) is None


def test_the_database_refuses_the_delete_even_if_the_count_is_bypassed(seeded_session):
    """The count is a message; ON DELETE RESTRICT is the guarantee.

    The service counts references and then deletes, which is not atomic — an
    enrolment landing between the two would otherwise null the new device's
    scope and drop it onto the default policy. Deleting the row directly skips
    the count entirely, which is what that race amounts to.
    """
    from sqlalchemy.exc import IntegrityError

    from app.db.models import Device, Policy
    from app.services.policy_service import PolicyService

    svc = PolicyService(seeded_session)
    scoped = svc.create_policy(name="engineering", type="application")
    seeded_session.add(
        Device(
            installation_id="6ba7b811-9dad-11d1-80b4-00c04fd430c8",
            device_name="Laptop",
            user_name="alice",
            user_email="alice@example.com",
            policy_id=scoped.id,
            status="active",
        )
    )
    seeded_session.commit()

    with pytest.raises(IntegrityError):
        seeded_session.delete(seeded_session.get(Policy, scoped.id))
        seeded_session.commit()
    seeded_session.rollback()

    assert seeded_session.get(Policy, scoped.id) is not None


def test_deleting_a_policy_bound_to_an_api_key_is_refused(seeded_session):
    """Otherwise deleting a policy silently promotes a scoped administrator.

    APIKey.policy_id is ON DELETE SET NULL and an unbound admin reads and
    deletes globally, so an unrelated administrative action escalated a
    policy-scoped admin to an organisation-wide one.
    """
    from app.auth.key_utils import generate_key, hash_key, key_prefix
    from app.db.models import APIKey
    from app.services.policy_service import PolicyInUseError, PolicyService

    svc = PolicyService(seeded_session)
    scoped = svc.create_policy(name="engineering-keys", type="application")
    raw = generate_key(prefix="ak")
    seeded_session.add(
        APIKey(
            name="bound-admin",
            key_hash=hash_key(raw),
            key_prefix=key_prefix(raw),
            role="admin",
            policy_id=scoped.id,
        )
    )
    seeded_session.commit()

    with pytest.raises(PolicyInUseError, match="API key"):
        svc.delete_policy(scoped.id)
