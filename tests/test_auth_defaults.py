"""P0-1: authentication was off by default and bypasses minted admins.

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
from app.config import Settings
from app.main import _is_loopback


def test_authentication_is_on_by_default():
    assert Settings().AUTH_ENABLED is True


def test_insecure_mode_is_not_implied_by_disabling_auth():
    """Disabling auth alone is not enough; the opt-in is separate."""
    assert Settings().TIDEWALL_INSECURE_NO_AUTH is False


@pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "::1"])
def test_loopback_addresses_are_recognised(host):
    assert _is_loopback(host) is True


@pytest.mark.parametrize(
    "host",
    [
        "0.0.0.0",  # binds every interface despite looking local
        "127.0.0.1.evil.com",  # string-prefix bypass
        "10.0.0.5",
        "",
    ],
)
def test_non_loopback_addresses_are_rejected(host):
    assert _is_loopback(host) is False


def test_api_docs_are_no_longer_public():
    """The full surface of a security control plane should not be anonymous."""
    for path in ("/docs", "/openapi.json", "/redoc"):
        assert path not in _PUBLIC_PATHS


def test_public_paths_are_minimal():
    assert _PUBLIC_PATHS == {"/health", "/favicon.ico"}


def test_unauthenticated_requests_get_no_role():
    """The core of P0-1: "skip auth" must not mean "become admin"."""
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


def test_entry_point_binds_the_validated_host():
    """The guard checked HOST while the Dockerfile bound 0.0.0.0.

    Startup logged "Running WITHOUT AUTHENTICATION on 127.0.0.1" while the
    socket listened on every interface, so the insecure-mode restriction was
    theatre. `python -m app` now launches uvicorn from validated settings, so
    HOST governs the socket that is actually opened.
    """
    import os
    from unittest.mock import patch

    from app.__main__ import serve

    with patch.dict(os.environ, {"HOST": "127.0.0.1", "PORT": "9331"}, clear=False):
        with patch("uvicorn.run") as run:
            serve()

    assert run.call_args.kwargs["host"] == "127.0.0.1"
    assert run.call_args.kwargs["port"] == 9331


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


def test_docs_routes_are_disabled_when_auth_is_on():
    """Swagger UI cannot authenticate its own /openapi.json fetch.

    A visibly configured route that can never work is worse than no route.
    """
    import os
    from unittest.mock import patch

    from app.main import create_app

    with patch.dict(os.environ, {"AUTH_ENABLED": "true"}, clear=False):
        app = create_app()
    paths = {r.path for r in app.routes}

    assert "/docs" not in paths
    assert "/openapi.json" not in paths
