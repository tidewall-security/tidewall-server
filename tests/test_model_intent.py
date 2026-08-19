"""Tests for ModelIntent ORM model."""

import pytest
from app.db.engine import get_engine, get_session_factory
from app.db.models import Base, ModelIntent


@pytest.fixture
def db_session():
    engine = get_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = get_session_factory(engine)
    session = Session()
    yield session
    session.close()


def test_create_model_intent(db_session):
    intent = ModelIntent(
        statement="Never reveal internal API keys",
        category="security",
        enabled=True,
    )
    db_session.add(intent)
    db_session.commit()
    assert intent.id is not None
    assert intent.enabled is True


def test_list_enabled_intents(db_session):
    db_session.add(ModelIntent(statement="No API keys", enabled=True))
    db_session.add(ModelIntent(statement="No code gen", enabled=True))
    db_session.add(ModelIntent(statement="Disabled rule", enabled=False))
    db_session.commit()
    enabled = db_session.query(ModelIntent).filter_by(enabled=True).all()
    assert len(enabled) == 2
