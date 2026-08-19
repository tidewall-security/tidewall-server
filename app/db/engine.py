"""SQLAlchemy engine and session factory."""

from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool


def require_sqlite(db_url: str) -> None:
    """SQLite is the supported database, and now says so.

    It was already the only one that worked: there is no other driver in
    pyproject.toml, no dialect handling anywhere in app/, and the migrations use
    batch_alter_table for SQLite's lack of ALTER. A different URL failed at
    driver import with whatever message SQLAlchemy happened to produce.

    Stated explicitly because correctness now depends on it. Content expiry is
    compared against the exact text SQLite stores, which is SQLAlchemy's
    fixed-width naive form -- fixed width being what makes lexicographic order
    chronological order. On a database with a real datetime type that reasoning
    does not apply and the comparison would need revisiting.
    """
    if not db_url.startswith("sqlite"):
        raise RuntimeError(
            "SQLite is the only supported database. "
            f"DB_URL must begin with 'sqlite', got {db_url.split(':', 1)[0]!r}."
        )


def get_engine(db_url: str, echo: bool = False) -> Engine:
    """Create a SQLAlchemy engine for the given database URL.

    For SQLite, enables WAL mode and foreign keys.
    For SQLite in-memory databases, uses StaticPool so all sessions share
    the same underlying connection (required for testing).
    """
    require_sqlite(db_url)
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
