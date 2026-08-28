"""Tests for multi-prefix token generation and hashing."""

import inspect
from datetime import UTC, datetime, timedelta

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.auth.key_utils import generate_key, hash_key, key_prefix
from app.auth.middleware import AuthMiddleware
from app.db.models import APIKey, Base, RegistrationToken


def test_generate_key_default_ak_prefix():
    key = generate_key()
    assert key.startswith("ak_")
    assert len(key) == 35  # "ak_" + 32 hex chars


def test_generate_key_rt_prefix():
    key = generate_key(prefix="rt")
    assert key.startswith("rt_")
    assert len(key) == 35


def test_generate_key_at_prefix():
    key = generate_key(prefix="at")
    assert key.startswith("at_")
    assert len(key) == 35


def test_hash_key_deterministic():
    key = "ak_abc123"
    assert hash_key(key) == hash_key(key)


def test_hash_key_different_for_different_keys():
    assert hash_key("ak_abc") != hash_key("ak_def")


def test_key_prefix_extracts_display_prefix():
    assert key_prefix("ak_abcdef1234567890") == "ak_abcd..."
    assert key_prefix("rt_abcdef1234567890") == "rt_abcd..."
    assert key_prefix("at_abcdef1234567890") == "at_abcd..."


# ------------------------------------------------------------------
# Auth middleware prefix-dispatch tests
# ------------------------------------------------------------------


def _make_test_app():
    """Minimal app with auth middleware for unit-level middleware tests."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine)

    app = FastAPI()
    app.add_middleware(AuthMiddleware)
    app.state.session_factory = SessionLocal

    @app.get("/health")
    async def health():
        return {"status": "ok"}

    @app.get("/v1/test")
    async def test_endpoint(request: Request):
        return {
            "role": request.state.role,
            "device_id": getattr(request.state, "device_id", None),
        }

    from app.routes import devices

    app.include_router(devices.router)

    return app, SessionLocal


def test_middleware_ak_sets_device_id_none():
    """ak_ tokens should set device_id=None in request.state."""
    app, SessionLocal = _make_test_app()
    session = SessionLocal()
    raw = generate_key(prefix="ak")
    ak = APIKey(
        name="mw-test",
        key_hash=hash_key(raw),
        key_prefix=key_prefix(raw),
        role="admin",
    )
    session.add(ak)
    session.commit()
    session.close()

    client = TestClient(app)
    resp = client.get("/v1/test", headers={"Authorization": f"Bearer {raw}"})
    assert resp.status_code == 200
    assert resp.json()["role"] == "admin"
    assert resp.json()["device_id"] is None


def test_middleware_rejects_an_uncredentialed_request():
    """This test used to assert the opposite.

    It verified that with authentication disabled an uncredentialed request
    received the admin role. That mode is gone: its loopback guard could not
    be enforced from inside an ASGI application, because uvicorn binds its
    socket after lifespan startup completes. There is no configuration value
    that produces the old behaviour, so the assertion inverts.
    """
    app, _ = _make_test_app()

    resp = TestClient(app).get("/v1/test")

    assert resp.status_code == 401


def test_middleware_rt_prefix_routes_to_enrol_only():
    """rt_ tokens are constrained to enrolment; they must not reach anything else."""
    app, SessionLocal = _make_test_app()
    session = SessionLocal()
    raw_rt = generate_key(prefix="rt")
    rt = RegistrationToken(
        name="mw-rt",
        token_hash=hash_key(raw_rt),
        token_prefix=key_prefix(raw_rt),
        expires_at=datetime.now(UTC) + timedelta(days=30),
    )
    session.add(rt)
    session.commit()
    session.close()

    client = TestClient(app)
    # Non-check path should be 403
    resp = client.get("/v1/test", headers={"Authorization": f"Bearer {raw_rt}"})
    assert resp.status_code == 403

    # /v1/devices/enrol passes middleware (route logic may still fail)
    resp2 = client.post(
        "/v1/devices/enrol",
        json={
            "installation_id": "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
            "fingerprint": "fp-mw-test",
            "device_name": "MWTest",
            "user_name": "bob",
            "user_email": "bob@example.com",
            "browser": "Firefox",
            "os": "Linux",
            "extension_version": "1.0.0",
        },
        headers={"Authorization": f"Bearer {raw_rt}"},
    )
    # Should reach the route handler (200) not be blocked by middleware
    assert resp2.status_code == 201  # enrolment creates


def test_a_dr_token_is_granted_no_role_at_all():
    """Pins the role assignment independently of the path restriction.

    A dr_ credential is blocked from other routes by _REFRESH_PATH, so a reach
    test cannot tell whether the role assignment does anything: granting it
    role="api" leaves every reach test green because the path check fires first.

    Two independent controls, and only one of them was pinned. This probes AT a
    refresh-shaped path -- past the path check -- so what it observes is the
    role and nothing else. It matters because if a second dr_-reachable route
    is ever added, this assignment becomes the only thing standing between a
    thirty-day credential and the api role.
    """
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine)

    app = FastAPI()
    app.add_middleware(AuthMiddleware)
    app.state.session_factory = SessionLocal

    # Matches ^/v1/devices/[^/]+/refresh$, so the credential gets past the path
    # restriction and the handler can report what the middleware assigned.
    @app.get("/v1/devices/probe/refresh")
    async def probe(request: Request):
        return {
            "role": request.state.role,
            "device_id": getattr(request.state, "device_id", None),
            "policy_id": getattr(request.state, "policy_id", None),
            "dr_token_hash_set": getattr(request.state, "dr_token_hash", None) is not None,
        }

    raw_dr = generate_key(prefix="dr")
    body = TestClient(app).get("/v1/devices/probe/refresh", headers={"Authorization": f"Bearer {raw_dr}"}).json()

    assert body["role"] is None, "a refresh token was granted a role"
    assert body["device_id"] is None, "device_id marks an access credential; a dr_ must not carry it"
    assert body["policy_id"] is None
    assert body["dr_token_hash_set"] is True, "the middleware did not identify the credential"


def test_an_api_key_with_an_expiry_can_authenticate():
    """The third instance of one bug, in the third branch of one file.

    The registration-token branch compared a naive column against an aware
    now() and raised instead of answering. This branch did the same, and was
    missed when that one was fixed -- the sweep for it covered the access-token
    branch and stopped there.

    It is worse here: API keys are the primary administrative credential, so an
    administrator who sets an expiry locks themselves out with a 500 on every
    request.
    """
    app, SessionLocal = _make_test_app()
    session = SessionLocal()
    raw = generate_key(prefix="ak")
    session.add(
        APIKey(
            name="expiring",
            key_hash=hash_key(raw),
            key_prefix=key_prefix(raw),
            role="admin",
            expires_at=datetime.now(UTC) + timedelta(days=30),
        )
    )
    session.commit()
    session.close()

    resp = TestClient(app).get("/v1/test", headers={"Authorization": f"Bearer {raw}"})

    assert resp.status_code == 200
    assert resp.json()["role"] == "admin"


def test_an_expired_api_key_is_refused_not_crashed():
    app, SessionLocal = _make_test_app()
    session = SessionLocal()
    raw = generate_key(prefix="ak")
    session.add(
        APIKey(
            name="expired",
            key_hash=hash_key(raw),
            key_prefix=key_prefix(raw),
            role="admin",
            expires_at=datetime.now(UTC) - timedelta(seconds=1),
        )
    )
    session.commit()
    session.close()

    resp = TestClient(app).get("/v1/test", headers={"Authorization": f"Bearer {raw}"})

    assert resp.status_code == 401
    assert "expired" in resp.json()["detail"].lower()


def test_every_expiry_comparison_in_the_middleware_normalises_first():
    """Pins the whole file, so there is no fourth instance.

    Three credential branches each compare a stored expiry against an aware
    now(). Two of them were written correctly and one was not, twice, because
    the fix was applied per-branch rather than to the file. This fails on the
    next branch that forgets, at the moment it is written.
    """
    import re

    from app.auth import middleware

    source = inspect.getsource(middleware)
    comparisons = [
        line.strip() for line in source.splitlines() if re.search(r"expires_at.*<.*datetime\.now\(UTC\)", line)
    ]

    assert comparisons, "no expiry comparisons found; this guard has lost its target"
    unguarded = [line for line in comparisons if "as_utc(" not in line]
    assert not unguarded, f"expiry comparisons that do not normalise first: {unguarded}"
