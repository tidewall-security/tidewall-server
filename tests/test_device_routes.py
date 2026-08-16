"""Integration tests for device management routes and auth middleware token handling."""
from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.auth.key_utils import generate_key, hash_key, key_prefix
from app.auth.middleware import AuthMiddleware
from app.db.models import APIKey, Base


def _make_app_and_client():
    """Create an in-memory SQLite app with all routers and auth middleware."""
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

    from app.routes import registration, devices, keys, guard
    app.include_router(registration.router)
    app.include_router(devices.router)
    app.include_router(keys.router)

    # Create an admin API key
    raw_admin_key = generate_key(prefix="ak")
    session = SessionLocal()
    admin_key = APIKey(
        name="test-admin",
        key_hash=hash_key(raw_admin_key),
        key_prefix=key_prefix(raw_admin_key),
        role="admin",
    )
    session.add(admin_key)
    session.commit()
    session.close()

    client = TestClient(app)
    return client, raw_admin_key, SessionLocal


@pytest.fixture
def setup():
    client, admin_key, session_factory = _make_app_and_client()
    return client, admin_key, session_factory


# ------------------------------------------------------------------
# Registration token CRUD
# ------------------------------------------------------------------


def test_create_registration_token_admin(setup):
    client, admin_key, _ = setup
    resp = client.post(
        "/v1/registration-tokens",
        json={"name": "test-rt"},
        headers={"Authorization": f"Bearer {admin_key}"},
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["name"] == "test-rt"
    assert "token" in data
    assert data["token"].startswith("rt_")
    assert "token_prefix" in data


def test_create_registration_token_viewer_forbidden(setup):
    client, admin_key, session_factory = setup
    # Create a viewer key
    raw_viewer = generate_key(prefix="ak")
    session = session_factory()
    viewer_key = APIKey(
        name="test-viewer",
        key_hash=hash_key(raw_viewer),
        key_prefix=key_prefix(raw_viewer),
        role="viewer",
    )
    session.add(viewer_key)
    session.commit()
    session.close()

    resp = client.post(
        "/v1/registration-tokens",
        json={"name": "nope"},
        headers={"Authorization": f"Bearer {raw_viewer}"},
    )
    assert resp.status_code == 403


def test_list_registration_tokens(setup):
    client, admin_key, _ = setup
    # Create two tokens
    client.post(
        "/v1/registration-tokens",
        json={"name": "rt-1"},
        headers={"Authorization": f"Bearer {admin_key}"},
    )
    client.post(
        "/v1/registration-tokens",
        json={"name": "rt-2"},
        headers={"Authorization": f"Bearer {admin_key}"},
    )
    resp = client.get(
        "/v1/registration-tokens",
        headers={"Authorization": f"Bearer {admin_key}"},
    )
    assert resp.status_code == 200
    assert len(resp.json()) >= 2


def test_delete_registration_token(setup):
    client, admin_key, _ = setup
    create_resp = client.post(
        "/v1/registration-tokens",
        json={"name": "to-delete"},
        headers={"Authorization": f"Bearer {admin_key}"},
    )
    token_id = create_resp.json()["id"]
    del_resp = client.delete(
        f"/v1/registration-tokens/{token_id}",
        headers={"Authorization": f"Bearer {admin_key}"},
    )
    assert del_resp.status_code == 204


# ------------------------------------------------------------------
# Device check (register + refresh)
# ------------------------------------------------------------------


def _create_rt_token(client, admin_key):
    """Helper: create an rt_ token and return the raw token string."""
    resp = client.post(
        "/v1/registration-tokens",
        json={"name": "device-rt"},
        headers={"Authorization": f"Bearer {admin_key}"},
    )
    return resp.json()["token"]


def _check_device(client, rt_token, fingerprint="fp-abc-123"):
    return client.post(
        "/v1/devices/check",
        json={
            "fingerprint": fingerprint,
            "device_name": "Test Laptop",
            "user_name": "alice",
            "user_email": "alice@example.com",
            "browser": "Chrome",
            "os": "macOS",
            "extension_version": "1.0.0",
        },
        headers={"Authorization": f"Bearer {rt_token}"},
    )


def test_device_check_registers_new_device(setup):
    client, admin_key, _ = setup
    rt_token = _create_rt_token(client, admin_key)
    resp = _check_device(client, rt_token)
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "Success"
    assert "access_token" in data["result"]
    at = data["result"]["access_token"]
    assert at["token"].startswith("at_")
    assert at["expires_in"] == 3600


def test_device_check_refresh_returns_new_at(setup):
    client, admin_key, _ = setup
    rt_token = _create_rt_token(client, admin_key)
    resp1 = _check_device(client, rt_token, fingerprint="fp-refresh-1")
    at1 = resp1.json()["result"]["access_token"]["token"]

    resp2 = _check_device(client, rt_token, fingerprint="fp-refresh-1")
    at2 = resp2.json()["result"]["access_token"]["token"]

    assert at1 != at2  # Each check issues a new token


def test_at_token_works_for_guard_like_call(setup):
    """An at_ token should resolve to role=api and allow viewer-level access."""
    client, admin_key, _ = setup
    rt_token = _create_rt_token(client, admin_key)
    resp = _check_device(client, rt_token)
    at_token = resp.json()["result"]["access_token"]["token"]

    # Use the at_ token to list devices (requires viewer role; at_ gives api role)
    # api role (level 1) < viewer (level 2) — so this should be 403
    resp2 = client.get(
        "/v1/devices",
        headers={"Authorization": f"Bearer {at_token}"},
    )
    assert resp2.status_code == 403  # api < viewer


def test_list_devices_with_admin(setup):
    client, admin_key, _ = setup
    rt_token = _create_rt_token(client, admin_key)
    _check_device(client, rt_token)

    resp = client.get(
        "/v1/devices",
        headers={"Authorization": f"Bearer {admin_key}"},
    )
    assert resp.status_code == 200
    devices = resp.json()
    assert len(devices) >= 1
    assert devices[0]["fingerprint"] == "fp-abc-123"


def test_patch_device_status(setup):
    client, admin_key, _ = setup
    rt_token = _create_rt_token(client, admin_key)
    _check_device(client, rt_token)

    devices = client.get(
        "/v1/devices",
        headers={"Authorization": f"Bearer {admin_key}"},
    ).json()
    device_id = devices[0]["id"]

    resp = client.patch(
        f"/v1/devices/{device_id}",
        json={"status": "revoked"},
        headers={"Authorization": f"Bearer {admin_key}"},
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "revoked"


def test_delete_device(setup):
    client, admin_key, _ = setup
    rt_token = _create_rt_token(client, admin_key)
    _check_device(client, rt_token)

    devices = client.get(
        "/v1/devices",
        headers={"Authorization": f"Bearer {admin_key}"},
    ).json()
    device_id = devices[0]["id"]

    resp = client.delete(
        f"/v1/devices/{device_id}",
        headers={"Authorization": f"Bearer {admin_key}"},
    )
    assert resp.status_code == 204


# ------------------------------------------------------------------
# Auth middleware guards
# ------------------------------------------------------------------


def test_rt_token_rejected_for_non_check_path(setup):
    client, admin_key, _ = setup
    rt_token = _create_rt_token(client, admin_key)

    # Try to list devices with an rt_ token — should be 403
    resp = client.get(
        "/v1/devices",
        headers={"Authorization": f"Bearer {rt_token}"},
    )
    assert resp.status_code == 403


def test_rt_token_rejected_for_keys_path(setup):
    client, admin_key, _ = setup
    rt_token = _create_rt_token(client, admin_key)

    resp = client.get(
        "/v1/keys",
        headers={"Authorization": f"Bearer {rt_token}"},
    )
    assert resp.status_code == 403


def test_at_token_rejected_for_admin_only_paths(setup):
    """at_ tokens resolve to role=api which should not access admin endpoints."""
    client, admin_key, _ = setup
    rt_token = _create_rt_token(client, admin_key)
    resp = _check_device(client, rt_token)
    at_token = resp.json()["result"]["access_token"]["token"]

    # Try to create a registration token (admin only)
    resp2 = client.post(
        "/v1/registration-tokens",
        json={"name": "nope"},
        headers={"Authorization": f"Bearer {at_token}"},
    )
    assert resp2.status_code == 403


def test_revoked_device_at_token_rejected(setup):
    """After revoking a device, its at_ token should be rejected."""
    client, admin_key, _ = setup
    rt_token = _create_rt_token(client, admin_key)
    resp = _check_device(client, rt_token)
    at_token = resp.json()["result"]["access_token"]["token"]

    # Revoke the device
    devices = client.get(
        "/v1/devices",
        headers={"Authorization": f"Bearer {admin_key}"},
    ).json()
    device_id = devices[0]["id"]
    client.patch(
        f"/v1/devices/{device_id}",
        json={"status": "revoked"},
        headers={"Authorization": f"Bearer {admin_key}"},
    )

    # Try using the at_ token — should fail because device is inactive
    resp2 = client.get(
        "/v1/devices",
        headers={"Authorization": f"Bearer {at_token}"},
    )
    assert resp2.status_code == 401


def test_invalid_token_rejected(setup):
    client, _, _ = setup
    resp = client.get(
        "/v1/devices",
        headers={"Authorization": "Bearer ak_bogus_invalid_key"},
    )
    assert resp.status_code == 401


def test_missing_auth_header_rejected(setup):
    client, _, _ = setup
    resp = client.get("/v1/devices")
    assert resp.status_code == 401


def test_health_bypasses_auth(setup):
    client, _, _ = setup
    resp = client.get("/health")
    assert resp.status_code == 200
