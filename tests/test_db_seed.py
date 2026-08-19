"""Tests for first-boot policy seeding."""

import pytest

from app.db.engine import get_engine, get_session_factory
from app.db.models import Base, Policy, RuleSet


@pytest.fixture
def empty_db():
    """Create an in-memory database with tables but no data."""
    engine = get_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = get_session_factory(engine)
    session = Session()
    yield session
    session.close()


def test_seed_creates_default_policy(empty_db):
    from app.db.seed import seed_from_yaml

    seed_from_yaml(empty_db, "policy.yaml")

    policies = empty_db.query(Policy).all()
    assert len(policies) == 1
    assert policies[0].name == "default_policy"
    assert policies[0].is_default is True


def test_seed_creates_input_and_output_rule_sets(empty_db):
    from app.db.seed import seed_from_yaml

    seed_from_yaml(empty_db, "policy.yaml")

    policy = empty_db.query(Policy).first()
    rule_sets = empty_db.query(RuleSet).filter_by(policy_id=policy.id).all()
    event_types = {rs.event_type for rs in rule_sets}
    assert "input" in event_types
    assert "output" in event_types


def test_seed_detectors_populated(empty_db):
    from app.db.seed import seed_from_yaml

    seed_from_yaml(empty_db, "policy.yaml")

    rs = empty_db.query(RuleSet).filter_by(event_type="input").first()
    assert rs.detectors is not None
    assert "malicious_prompt" in rs.detectors


def test_seed_skips_if_policies_exist(empty_db):
    """Seed should not overwrite existing policies."""
    existing = Policy(name="existing", type="application", is_default=True)
    empty_db.add(existing)
    empty_db.commit()

    from app.db.seed import seed_from_yaml

    seed_from_yaml(empty_db, "policy.yaml")

    policies = empty_db.query(Policy).all()
    assert len(policies) == 1
    assert policies[0].name == "existing"
