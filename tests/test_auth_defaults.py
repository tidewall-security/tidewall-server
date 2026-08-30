"""Authentication was off by default, and bypasses minted admins.

`AUTH_ENABLED` defaulted to False, docker-compose set it false explicitly, and
the middleware handled that state by assigning `role = "admin"`. So the shipped
container exposed its entire control plane — log reads, policy mutation, key
and registration-token minting, device administration, export targets that can
be aimed at internal addresses — to anyone who could reach the port.

Two further bypasses assigned admin even with auth enabled: `_PUBLIC_PATHS`
(which included /docs and /openapi.json) and the /static/ + /ui/ prefixes.
"""

from __future__ import annotations

import pytest

from app.auth.middleware import _PUBLIC_PATHS


def test_api_docs_are_no_longer_public():
    """The full surface of a security control plane should not be anonymous."""
    for path in ("/docs", "/openapi.json", "/redoc"):
        assert path not in _PUBLIC_PATHS


def test_public_paths_are_minimal():
    assert _PUBLIC_PATHS == {"/health", "/favicon.ico"}


def test_unauthenticated_requests_get_no_role():
    """The core of it: "skip auth" must not mean "become admin"."""
    from starlette.requests import Request

    from app.auth.middleware import AuthMiddleware

    request = Request({"type": "http", "path": "/static/x.js", "headers": []})
    AuthMiddleware._anonymous(request)

    assert request.state.role is None
    assert request.state.api_key_id is None
    assert request.state.device_id is None


def test_require_role_rejects_an_anonymous_request():
    """What makes assigning no role safe rather than merely different."""
    import asyncio

    from fastapi import HTTPException
    from starlette.requests import Request

    from app.auth.dependencies import require_role
    from app.auth.middleware import AuthMiddleware

    request = Request({"type": "http", "path": "/v1/logs", "headers": []})
    AuthMiddleware._anonymous(request)

    with pytest.raises(HTTPException) as exc:
        asyncio.run(require_role("viewer")(request))
    assert exc.value.status_code == 401


# ---------------------------------------------------------------------------
# The bind must be the value the guard checks
# ---------------------------------------------------------------------------


def test_dockerfile_does_not_bind_independently_of_settings():
    """A CMD that passes --host would reintroduce the disconnect."""
    from pathlib import Path

    dockerfile = (Path(__file__).resolve().parent.parent / "Dockerfile").read_text()
    cmd = [ln for ln in dockerfile.splitlines() if ln.startswith("CMD")]

    assert cmd, "Dockerfile has no CMD"
    assert "--host" not in cmd[-1], "CMD binds an address independently of Settings.HOST"
    assert "python" in cmd[-1] and "app" in cmd[-1]


# ---------------------------------------------------------------------------
# Anti-framing
# ---------------------------------------------------------------------------


def test_dashboard_shells_cannot_be_framed():
    """Anonymous pages plus an admin key in localStorage are framable.

    A hostile origin embeds /ui/policies; script in that same-origin frame
    reads the stored key and issues authenticated writes. No cookie is
    involved, so SameSite does not help and CORS does not apply — the request
    comes from Tidewall's own origin.
    """
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.security_headers import SecurityHeadersMiddleware

    app = FastAPI()
    app.add_middleware(SecurityHeadersMiddleware)

    @app.get("/ui/policies")
    async def page():
        return {"ok": True}

    resp = TestClient(app).get("/ui/policies")

    assert "frame-ancestors 'none'" in resp.headers["content-security-policy"]
    assert resp.headers["x-frame-options"] == "DENY"
    assert resp.headers["x-content-type-options"] == "nosniff"


def test_rejected_bootstrap_config_leaves_no_database_state(tmp_path):
    """A configuration that will be refused must not migrate or seed first.

    The check previously ran after directory creation, every migration, policy
    seeding and service construction, so refusing still left a fully migrated
    159KB database behind. It is answered read-only now, before any write.
    """
    import asyncio
    import os
    from unittest.mock import patch

    from app.main import create_app, lifespan

    db = tmp_path / "refused.db"
    env = {"AUTH_ENABLED": "true", "DB_URL": f"sqlite:///{db}"}

    with patch.dict(os.environ, env, clear=False):
        os.environ.pop("BOOTSTRAP_KEY", None)
        app = create_app()
        with pytest.raises(RuntimeError, match="BOOTSTRAP_KEY is not set"):
            asyncio.run(lifespan(app).__aenter__())

    assert not db.exists(), "a refused configuration created a database"


# ---------------------------------------------------------------------------
# The invariant that replaced the mode
# ---------------------------------------------------------------------------


def test_no_setting_can_disable_authentication():
    """The strongest form of the fix: the mode does not exist.

    AUTH_ENABLED and TIDEWALL_INSECURE_NO_AUTH are gone. The loopback guard
    that was supposed to confine unauthenticated mode could not work: a
    directly launched ASGI server binds whatever address it is given, and
    uvicorn awaits lifespan startup *before* creating its socket, so the
    application cannot inspect its own listener in time to refuse. Rather than
    defend that, the mode was removed.
    """
    from app.config import Settings

    fields = set(Settings.model_fields)
    assert "AUTH_ENABLED" not in fields
    assert "TIDEWALL_INSECURE_NO_AUTH" not in fields


def test_middleware_has_no_bypass_branch():
    """No code path assigns a role without validating a credential."""
    import inspect

    from app.auth import middleware

    source = inspect.getsource(middleware)
    assert "auth_enabled" not in source
    # The only role assignments left are from a validated credential.
    assert source.count('request.state.role = "admin"') == 0


def test_protected_route_rejects_every_construction_path():
    """401 without a credential, whichever way the app was built."""
    import asyncio

    from fastapi import HTTPException
    from starlette.requests import Request

    from app.auth.dependencies import require_role
    from app.auth.middleware import AuthMiddleware

    for role_name in ("viewer", "api", "admin"):
        request = Request({"type": "http", "path": "/v1/logs", "headers": []})
        AuthMiddleware._anonymous(request)
        with pytest.raises(HTTPException) as exc:
            asyncio.run(require_role(role_name)(request))
        assert exc.value.status_code == 401
