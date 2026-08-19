"""Tests for auth middleware and role dependencies."""

import pytest
from fastapi import FastAPI, Depends
from fastapi.testclient import TestClient

from app.db.engine import get_engine, get_session_factory
from app.db.models import Base, Policy
from app.services.key_service import KeyService


@pytest.fixture
def app_with_auth():
    """Create a test app with auth enabled."""
    engine = get_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    SessionLocal = get_session_factory(engine)

    session = SessionLocal()
    policy = Policy(name="default", type="application", is_default=True)
    session.add(policy)
    session.commit()

    key_svc = KeyService(session)
    admin_key, _ = key_svc.create_key(name="admin", role="admin")
    # Bound: an unbound viewer is refused at creation, because it would
    # authenticate successfully and then see nothing.
    viewer_key, _ = key_svc.create_key(name="viewer", role="viewer", policy_id=policy.id)
    api_key, _ = key_svc.create_key(name="collector", role="api")

    from app.auth.middleware import AuthMiddleware
    from app.auth.dependencies import require_role

    app = FastAPI()
    app.state.session_factory = SessionLocal

    app.add_middleware(AuthMiddleware)

    @app.get("/public")
    async def public():
        return {"msg": "public"}

    @app.get("/health")
    async def health():
        return {"status": "ok"}

    @app.get("/admin-only")
    async def admin_only(role=Depends(require_role("admin"))):
        return {"msg": "admin"}

    @app.get("/viewer-plus")
    async def viewer_plus(role=Depends(require_role("viewer"))):
        return {"msg": "viewer"}

    @app.get("/api-plus")
    async def api_plus(role=Depends(require_role("api"))):
        return {"msg": "api"}

    @app.get("/ui/{page}")
    async def ui_page(page: str):
        return {"msg": f"ui-{page}"}

    @app.get("/static/{path:path}")
    async def static_file(path: str):
        return {"msg": f"static-{path}"}

    client = TestClient(app)
    return client, admin_key, viewer_key, api_key


def test_health_no_auth_required(app_with_auth):
    client, _, _, _ = app_with_auth
    resp = client.get("/health")
    assert resp.status_code == 200


def test_no_token_returns_401(app_with_auth):
    client, _, _, _ = app_with_auth
    resp = client.get("/admin-only")
    assert resp.status_code == 401


def test_invalid_token_returns_401(app_with_auth):
    client, _, _, _ = app_with_auth
    resp = client.get("/admin-only", headers={"Authorization": "Bearer ak_invalid"})
    assert resp.status_code == 401


def test_admin_can_access_admin_route(app_with_auth):
    client, admin_key, _, _ = app_with_auth
    resp = client.get("/admin-only", headers={"Authorization": f"Bearer {admin_key}"})
    assert resp.status_code == 200


def test_viewer_cannot_access_admin_route(app_with_auth):
    client, _, viewer_key, _ = app_with_auth
    resp = client.get("/admin-only", headers={"Authorization": f"Bearer {viewer_key}"})
    assert resp.status_code == 403


def test_admin_can_access_viewer_route(app_with_auth):
    client, admin_key, _, _ = app_with_auth
    resp = client.get("/viewer-plus", headers={"Authorization": f"Bearer {admin_key}"})
    assert resp.status_code == 200


def test_viewer_can_access_viewer_route(app_with_auth):
    client, _, viewer_key, _ = app_with_auth
    resp = client.get("/viewer-plus", headers={"Authorization": f"Bearer {viewer_key}"})
    assert resp.status_code == 200


def test_api_cannot_access_viewer_route(app_with_auth):
    client, _, _, api_key = app_with_auth
    resp = client.get("/viewer-plus", headers={"Authorization": f"Bearer {api_key}"})
    assert resp.status_code == 403


def test_api_can_access_api_route(app_with_auth):
    client, _, _, api_key = app_with_auth
    resp = client.get("/api-plus", headers={"Authorization": f"Bearer {api_key}"})
    assert resp.status_code == 200


# --- UI and static bypass tests ---


def test_ui_pages_bypass_auth(app_with_auth):
    """UI pages must load without auth so the client-side key prompt can appear."""
    client, _, _, _ = app_with_auth
    resp = client.get("/ui/visibility")
    assert resp.status_code == 200
    assert resp.json()["msg"] == "ui-visibility"


def test_ui_pages_bypass_auth_all_pages(app_with_auth):
    client, _, _, _ = app_with_auth
    for page in ["visibility", "findings", "policies", "sandbox"]:
        resp = client.get(f"/ui/{page}")
        assert resp.status_code == 200, f"/ui/{page} should bypass auth"


def test_static_files_bypass_auth(app_with_auth):
    client, _, _, _ = app_with_auth
    resp = client.get("/static/js/auth.js")
    assert resp.status_code == 200


def test_api_endpoints_still_require_auth(app_with_auth):
    """Ensure the UI bypass doesn't accidentally open API endpoints."""
    client, _, _, _ = app_with_auth
    resp = client.get("/admin-only")
    assert resp.status_code == 401
    resp = client.get("/viewer-plus")
    assert resp.status_code == 401
