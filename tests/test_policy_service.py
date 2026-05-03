"""Tests for PolicyService — CRUD and engine cache."""
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

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
