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
