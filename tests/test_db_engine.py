"""Tests for database engine initialization."""
import os
import tempfile

import pytest


def test_engine_creates_database_file():
    """Engine should create SQLite database at the given path."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test.db")

        from app.db.engine import get_engine

        engine = get_engine(f"sqlite:///{db_path}")
        assert engine is not None

        from sqlalchemy import text
        with engine.connect() as conn:
            result = conn.execute(text("SELECT 1"))
            assert result.scalar() == 1


def test_get_session_factory():
    """Session factory should produce working sessions."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test.db")

        from app.db.engine import get_engine, get_session_factory

        engine = get_engine(f"sqlite:///{db_path}")
        SessionLocal = get_session_factory(engine)

        session = SessionLocal()
        assert session is not None
        session.close()
