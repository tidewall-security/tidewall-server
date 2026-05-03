"""SQLAlchemy engine and session factory."""

from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool


def get_engine(db_url: str, echo: bool = False) -> Engine:
    """Create a SQLAlchemy engine for the given database URL.

    For SQLite, enables WAL mode and foreign keys.
    For SQLite in-memory databases, uses StaticPool so all sessions share
    the same underlying connection (required for testing).
    """
    connect_args = {}
    kwargs: dict = {}
    if db_url.startswith("sqlite"):
        connect_args["check_same_thread"] = False
        # In-memory SQLite: use StaticPool so multiple sessions share one connection
        if ":memory:" in db_url:
            kwargs["poolclass"] = StaticPool

    engine = create_engine(db_url, echo=echo, connect_args=connect_args, **kwargs)

    if db_url.startswith("sqlite"):
        from sqlalchemy import event

        @event.listens_for(engine, "connect")
        def _set_sqlite_pragma(dbapi_conn, connection_record):
            cursor = dbapi_conn.cursor()
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

    return engine


def get_session_factory(engine: Engine) -> sessionmaker[Session]:
    """Create a session factory bound to the engine."""
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
