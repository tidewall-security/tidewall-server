"""Tests for GlobalPromptList ORM model."""
import pytest
from app.db.engine import get_engine, get_session_factory
from app.db.models import Base, GlobalPromptList


@pytest.fixture
def db_session():
    engine = get_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = get_session_factory(engine)
    session = Session()
    yield session
    session.close()


def test_create_prompt_list_entry(db_session):
    entry = GlobalPromptList(
        list_type="malicious",
        pattern="ignore all previous instructions",
        match_type="substring",
        description="Common injection pattern",
    )
    db_session.add(entry)
    db_session.commit()
    assert entry.id is not None
    assert entry.list_type == "malicious"


def test_create_benign_entry(db_session):
    entry = GlobalPromptList(
        list_type="benign",
        pattern="^please summarize",
        match_type="regex",
    )
    db_session.add(entry)
    db_session.commit()
    assert entry.match_type == "regex"


def test_list_by_type(db_session):
    db_session.add(GlobalPromptList(list_type="malicious", pattern="inject", match_type="substring"))
    db_session.add(GlobalPromptList(list_type="benign", pattern="hello", match_type="exact"))
    db_session.add(GlobalPromptList(list_type="malicious", pattern="hack", match_type="substring"))
    db_session.commit()

    malicious = db_session.query(GlobalPromptList).filter_by(list_type="malicious").all()
    assert len(malicious) == 2
    benign = db_session.query(GlobalPromptList).filter_by(list_type="benign").all()
    assert len(benign) == 1
