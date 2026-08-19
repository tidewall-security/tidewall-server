"""Tidewall — FastAPI application entry point.

Startup sequence (in ``lifespan``):
    1. Read settings from environment variables
    2. Create SQLite database engine and session factory
    3. Run Alembic migrations (auto-upgrade to latest schema)
    4. Seed default policy from YAML on first boot
    5. Initialize PolicyService (caches scanner engines per policy)
    6. Bootstrap admin API key if auth is enabled and no keys exist
    7. Initialize VaultManager, InteractionLog, ExportService

Imports inside ``lifespan`` are intentionally deferred to avoid circular
imports and to keep startup fast when modules aren't needed (e.g. auth
services are unused).
"""

from __future__ import annotations

import asyncio
import logging
import os
import pathlib
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.config import Settings
from app.interaction_log import InteractionLog
from app.vault_manager import VaultManager

_PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _has_existing_api_keys(db_url: str) -> bool:
    """Read-only probe for existing API keys, without migrating anything.

    The bootstrap refusal used to run after migrations, seeding and service
    construction, so rejecting a clean configuration still left a fully
    migrated and seeded database behind — 159KB of state written for a startup
    that then refused to serve. Answering the question read-only lets the
    refusal happen before any write.

    Returns False when the database, or the table, does not exist yet: both
    mean there is no key, which is the condition that requires a bootstrap
    secret.
    """
    from sqlalchemy import create_engine, inspect, text

    # Connecting to a SQLite URL creates the file, so a refusal would still
    # leave a zero-byte artefact behind. Absent file means absent keys.
    if db_url.startswith("sqlite"):
        path = db_url.split("///")[-1]
        if path not in (":memory:", "") and not pathlib.Path(path).exists():
            return False

    probe = create_engine(db_url)
    try:
        if "api_keys" not in inspect(probe).get_table_names():
            return False
        with probe.connect() as conn:
            return conn.execute(text("SELECT 1 FROM api_keys LIMIT 1")).first() is not None
    except Exception:
        # An unreadable database is not evidence that a key exists, and
        # refusing here would be wrong for a genuine connectivity problem, so
        # defer to the later check rather than guessing.
        return True
    finally:
        probe.dispose()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Application lifespan: startup and shutdown logic."""
    settings = Settings.from_env()

    logging.basicConfig(level=getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO))

    # Validate authentication configuration BEFORE touching the database.
    # This previously ran after directory creation, migrations, seeding and
    # service construction, so an invalid configuration created and migrated a
    # database and only then refused to serve — a rejected config should not
    # leave persistent state behind.
    # Before ANY database access, including the read-only probe below and the
    # Alembic migration further down. A migration running before the lock is a
    # second writer by another name, and a read taken while another process
    # writes is exactly what the lock exists to order.
    #
    # Acquired here rather than at import so a forked worker takes its own: a
    # lock inherited from a pre-fork parent is shared through the same open file
    # description and excludes nothing.
    #
    # It does create a lockfile beside the database even for a configuration
    # that is about to be refused. That is one empty file rather than the
    # migrated, seeded database the refusal below exists to avoid.
    from app.services.process_lock import ProcessLock

    process_lock = ProcessLock()
    process_lock.acquire(settings.DB_URL)
    app.state.process_lock = process_lock
    app.state.boot_id = process_lock.boot_id

    try:
        refuse = not settings.BOOTSTRAP_KEY and not _has_existing_api_keys(settings.DB_URL)
    except Exception:
        process_lock.release()
        raise
    if refuse:
        # Released before raising: a refused startup must not leave the database
        # locked against the next attempt.
        process_lock.release()
        # Checked before any database work: a configuration that will be
        # refused must not leave a migrated, seeded database behind.
        raise RuntimeError(
            "No API keys exist and BOOTSTRAP_KEY is not set. Set it to a secret you "
            "generate to install the first admin key. Tidewall does not generate one "
            "because it would have to be emitted to logs or stdout to reach you, where "
            "it would persist as an administrator credential."
        )

    # --- Database setup ---
    from app.db.engine import get_engine, get_session_factory
    from app.db.seed import seed_from_yaml

    os.makedirs(_PROJECT_ROOT / "data", exist_ok=True)

    engine = get_engine(settings.DB_URL)
    SessionLocal = get_session_factory(engine)

    # Run Alembic migrations on every startup so the schema is always
    # up-to-date without requiring a manual migration step.  Safe for
    # production because Alembic is idempotent (no-op if already at head).
    from alembic import command
    from alembic.config import Config as AlembicConfig

    alembic_cfg = AlembicConfig(str(_PROJECT_ROOT / "alembic.ini"))
    alembic_cfg.set_main_option("sqlalchemy.url", settings.DB_URL)
    command.upgrade(alembic_cfg, "head")

    # Seed the default policy from YAML on first boot.  seed_from_yaml
    # is idempotent — it skips if policies already exist in the DB.
    with SessionLocal() as session:
        seed_from_yaml(session, settings.POLICY_FILE)

    app.state.engine = engine
    app.state.session_factory = SessionLocal
    app.state.settings = settings

    # --- NEW: PolicyService (DB-backed policy resolution) ---
    from app.services.policy_service import PolicyService

    app.state.policy_service = PolicyService(session_factory=SessionLocal)

    # Install the operator-supplied first admin key if the database has none.
    # The refusal for a missing key happened earlier, before any database
    # write; this is the install, which only runs when a key was supplied.
    from app.services.key_service import KeyService

    key_session = SessionLocal()
    try:
        key_svc = KeyService(key_session)
        if not key_svc.has_any_key() and settings.BOOTSTRAP_KEY:
            key_svc.install_bootstrap_admin_key(settings.BOOTSTRAP_KEY)
    finally:
        key_session.close()

    # --- EXISTING: VaultManager and InteractionLog still needed ---
    app.state.vault_manager = VaultManager(SessionLocal)
    app.state.interaction_log = InteractionLog(SessionLocal)

    from app.services.export_service import ExportService

    app.state.export_service = ExportService(session_factory=SessionLocal)

    # Retention runs on a schedule now. The three partial mechanisms it
    # replaces each had a real gap: startup only helps if the process restarts,
    # post-write only runs while traffic arrives, and the read gate protects
    # disclosure without ever reclaiming disk — so a server that captured
    # content and then went quiet would hold it indefinitely.
    #
    # The read gate stays regardless: expiry is a promise about what gets
    # disclosed, and that must not depend on a background task having run.
    # Installing it is capture-only work, so it cannot decide whether the
    # server serves. Unguarded, an import or task-creation failure aborted
    # startup even with capture disabled on every policy — no enforcement at
    # all, because of a subsystem with nothing to do.
    #
    # A failure here does not leave content exposed: the read gate denies
    # expired content whether or not a purge ran. It does mean expired rows
    # stay on disk, so it logs at error rather than passing quietly.
    #
    # /health is unauthenticated, so it is deliberately not reported there —
    # "retention is not running" tells an unauthenticated caller that captured
    # content is accumulating. Operator-visible reporting on an authenticated
    # surface is worth adding and is not here yet.
    from app.services.safe_logging import report

    scheduler = None
    try:
        from app.services.scheduler import Scheduler, export_abandon_job, retention_job

        # Assigned before start(), so a partial start is still stoppable. If
        # start() creates one task and then fails, dropping the reference would
        # leave that task running while shutdown believes there is no
        # background work — and decides whether to dispose the engine on that
        # belief.
        scheduler = Scheduler()
        scheduler.start(
            [
                retention_job(SessionLocal, scheduler=scheduler),
                # Resolves export attempts left pending by a process that is
                # gone. It never sends anything.
                export_abandon_job(SessionLocal, boot_id=process_lock.boot_id, scheduler=scheduler),
            ]
        )
    except Exception:
        report(
            logging.getLogger(__name__),
            "error",
            "retention scheduler did not start; expired content will not be reclaimed from disk "
            "(it remains undisclosable through the read gate)",
            # Infrastructure, not a scan: the traceback carries no request
            # content and is the most useful thing here.
            exc_info=True,
        )
        # Deliberately not reset to None: if start() got far enough to create a
        # task, that task is running and shutdown must still stop and drain it.
    app.state.scheduler = scheduler
    # Settlement tasks this process started. A bare create_task is owned by
    # nothing: the handler holds a strong reference only while it runs, and at
    # shutdown the loop can close with one still in flight.
    app.state.export_settlements = set()

    logging.info("Tidewall ready")

    try:
        yield
    finally:
        # In a finally: an exception thrown into the lifespan context would
        # otherwise skip both, leaving the scheduler running against a disposed
        # engine.
        # The order the lock's meaning depends on:
        #   1. stop the scheduler
        #   2. drain the settlement-task set
        #   3. drain_workers()
        #   4. release the lock
        #   5. dispose the engine
        #
        # Two conditions gate 4 and 5, and they answer different questions.
        #
        # stop() must return WITHOUT RAISING: that is what establishes no
        # scheduler task can still call run_in_worker. If it raises, tasks may
        # be live, and a worker registered after drain_workers() observed zero
        # would be missed entirely.
        #
        # Its return VALUE is advisory. It reports whether its own drain
        # completed and can say False for a worker drain_workers() then drains
        # successfully -- two answers to one question -- so it gates nothing. It
        # is logged rather than discarded, because a stop() failure unrelated to
        # live workers still deserves attention.
        quiesced = scheduler is None
        if scheduler is not None:
            try:
                if not await scheduler.stop():
                    report(
                        logging.getLogger(__name__),
                        "warning",
                        "scheduler stop reported work still running; re-draining before release",
                    )
                quiesced = True
            except Exception:
                report(
                    logging.getLogger(__name__),
                    "error",
                    "scheduler stop raised, so producers may still be live; " "the database lock will not be released",
                    exc_info=True,
                )

        # 2. Settlements this process started, which may not have reached a
        #    worker yet. Awaited rather than cancelled: cancelling a coroutine
        #    that awaits a thread detaches the thread.
        settlements = list(getattr(app.state, "export_settlements", ()) or ())
        if settlements:
            await asyncio.gather(*settlements, return_exceptions=True)

        # 3. The single predicate for "nothing is still writing". Separate from
        #    the drain stop() performs, which ran before step 2.
        #
        #    Not INDEPENDENTLY killable, and that is worth saying rather than
        #    implying otherwise: it is redundant with the worker drain inside
        #    stop(), so removing either one alone leaves every test green.
        #    Removing BOTH fails
        #    test_shutdown_waits_for_a_settlement_thread_whose_task_was_cancelled,
        #    which is the case they exist for -- a worker DETACHED by a
        #    cancelled await, where the task is done and only the thread is
        #    still writing. Step 2 cannot see that: the task it awaits has
        #    already completed as cancelled.
        #
        #    Step 2 is not redundant with either of them, and has its own test
        #    (test_shutdown_waits_for_a_settlement_that_has_not_reached_a_worker):
        #    before a settlement takes its first step no worker is registered,
        #    so both drains correctly report idle while the work is pending.
        workers_drained = True
        if scheduler is not None:
            workers_drained = await scheduler.drain_workers()

        if quiesced and workers_drained:
            # Released only now. Closing it earlier would let a replacement
            # instance start while this process was still writing.
            process_lock.release()
            engine.dispose()
        else:
            # Holding the lock keeps a replacement from starting while a thread
            # may still be writing, which is the whole point of holding it.
            # Leaking both on a shutdown path is the lesser fault.
            report(
                logging.getLogger(__name__),
                "error",
                "not releasing the database lock or disposing the engine: "
                f"quiesced={quiesced} workers_drained={workers_drained}",
            )


def create_app() -> FastAPI:
    """Build and configure the Tidewall FastAPI application."""

    # Swagger UI fetches /openapi.json from the browser with no Authorization
    # header, so a protected schema leaves the stock docs page permanently
    # broken. Authentication is now unconditional, so the routes are simply not
    # registered; the schema remains available to an API client through the
    # OpenAPI object.
    app = FastAPI(
        title="Tidewall",
        description="Open-source AI security guard API server",
        version="0.3.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )

    from starlette.middleware.cors import CORSMiddleware

    from app.auth.middleware import AuthMiddleware

    # Starlette processes middleware in reverse add order (last added = outermost).
    # Auth must be added first so CORS wraps it and handles preflight OPTIONS
    # requests (which have no Authorization header) before auth runs.
    from app.security_headers import SecurityHeadersMiddleware

    app.add_middleware(AuthMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.get("/health")
    async def health() -> dict:
        return {"status": "ok"}

    from app.routes import (
        activity,
        content,
        content_export,
        content_export_admin,
        dashboard,
        devices,
        guard,
        keys,
        logs,
        me,
        policies,
        registration,
        settings,
        unredact,
    )

    app.include_router(guard.router)
    app.include_router(unredact.router)
    app.include_router(logs.router)
    app.include_router(content.router)
    app.include_router(content_export.router)
    app.include_router(content_export_admin.router)
    app.include_router(me.router)
    app.include_router(dashboard.router)
    app.include_router(policies.router)
    app.include_router(keys.router)
    app.include_router(activity.router)
    app.include_router(settings.router)
    app.include_router(registration.router)
    app.include_router(devices.router)

    app.mount("/static", StaticFiles(directory="app/static"), name="static")

    return app


app = create_app()
