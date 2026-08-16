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
services when ``AUTH_ENABLED=false``).
"""

from __future__ import annotations

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


def _is_loopback(host: str) -> bool:
    """True if *host* can only be reached from this machine.

    Parsed structurally rather than by string prefix: "127.0.0.1.evil.com"
    starts with "127.0.0.1" and is not loopback, and "0.0.0.0" binds every
    interface despite looking local.
    """
    import ipaddress

    candidate = (host or "").strip().strip("[]")
    if candidate in ("localhost", ""):
        return candidate == "localhost"
    try:
        return ipaddress.ip_address(candidate).is_loopback
    except ValueError:
        return False


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
    if not settings.AUTH_ENABLED:
        # Running without authentication means every caller is an
        # administrator: log reads, policy mutation, key minting, export
        # targets that can be pointed at internal addresses. It is a local
        # development convenience and must not be reachable off-host, so it
        # requires an unmistakable opt-in AND a loopback bind.
        if not settings.TIDEWALL_INSECURE_NO_AUTH:
            raise RuntimeError(
                "AUTH_ENABLED is false. Running without authentication makes every "
                "caller an administrator. If that is genuinely what you want for local "
                "development, set TIDEWALL_INSECURE_NO_AUTH=1 as well — and note it is "
                "refused on any non-loopback bind address."
            )
        if not _is_loopback(settings.HOST):
            raise RuntimeError(
                f"AUTH_ENABLED is false and HOST is {settings.HOST!r}, which is not "
                "loopback. Unauthenticated mode would expose an administrative control "
                "plane to the network. Bind to 127.0.0.1 or enable authentication."
            )
        logging.getLogger(__name__).warning(
            "Running WITHOUT AUTHENTICATION on %s — every caller has the admin role",
            settings.HOST,
        )


    if settings.AUTH_ENABLED and not settings.BOOTSTRAP_KEY and not _has_existing_api_keys(settings.DB_URL):
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

    app.state.policy_service = PolicyService(session_factory=SessionLocal, use_onnx=settings.USE_ONNX)

    app.state.auth_enabled = settings.AUTH_ENABLED

    if settings.AUTH_ENABLED:
        from app.services.key_service import KeyService

        key_session = SessionLocal()
        try:
            key_svc = KeyService(key_session)
            if not key_svc.has_any_key():
                # No keys exist and auth is on, so the deployment is
                # unreachable unless the operator supplies the first
                # credential. We refuse to start rather than generating one:
                # a generated key has to be communicated somehow, and every
                # available channel (logs, stdout) is collected and retained.
                if not settings.BOOTSTRAP_KEY:
                    raise RuntimeError(
                        "AUTH_ENABLED is set but no API keys exist. Set "
                        "BOOTSTRAP_KEY to a secret you generate to install the "
                        "first admin key. Tidewall does not generate it for you "
                        "because it would have to be emitted to logs or stdout "
                        "to reach you, where it would persist as an "
                        "administrator credential."
                    )
                key_svc.install_bootstrap_admin_key(settings.BOOTSTRAP_KEY)
        finally:
            key_session.close()

    # --- EXISTING: VaultManager and InteractionLog still needed ---
    app.state.vault_manager = VaultManager(SessionLocal)
    app.state.interaction_log = InteractionLog(SessionLocal)

    from app.services.export_service import ExportService

    app.state.export_service = ExportService(session_factory=SessionLocal)

    logging.info("Tidewall ready")

    yield
    engine.dispose()


def create_app() -> FastAPI:
    """Build and configure the Tidewall FastAPI application."""

    settings = Settings.from_env()

    # Swagger UI fetches /openapi.json from the browser without an
    # Authorization header, so a protected schema makes the stock docs page
    # permanently broken. Shipping a visibly configured route that cannot work
    # is worse than not having it: the routes are disabled when auth is on, and
    # the schema stays available to an API client via the OpenAPI object.
    _docs_enabled = not settings.AUTH_ENABLED
    app = FastAPI(
        title="Tidewall",
        description="Open-source AI security guard API server",
        version="0.3.0",
        docs_url="/docs" if _docs_enabled else None,
        redoc_url="/redoc" if _docs_enabled else None,
        openapi_url="/openapi.json" if _docs_enabled else None,
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

    from app.routes import activity, dashboard, devices, guard, keys, logs, policies, registration, settings, unredact

    app.include_router(guard.router)
    app.include_router(unredact.router)
    app.include_router(logs.router)
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
