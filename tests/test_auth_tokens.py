"""Tests for multi-prefix token generation and hashing."""

from app.auth.key_utils import generate_key, hash_key, key_prefix


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

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.auth.middleware import AuthMiddleware
from app.db.models import APIKey, Base, RegistrationToken


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
            "installation_id": "inst-mw-test",
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
