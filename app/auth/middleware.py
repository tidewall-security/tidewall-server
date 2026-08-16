"""FastAPI middleware for API key authentication."""

from __future__ import annotations

from datetime import UTC

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from app.auth.key_utils import hash_key
from app.db.models import AccessToken, APIKey, Device, RegistrationToken

# Paths served without a credential. Deliberately minimal: /docs, /redoc and
# /openapi.json used to be here, which published the full surface of a security
# control plane to anyone who could reach the port. The schema is still
# retrievable with a bearer token.
_PUBLIC_PATHS = {"/health", "/favicon.ico"}


class AuthMiddleware(BaseHTTPMiddleware):
    """Validates Bearer tokens against the api_keys, registration_tokens,
    or access_tokens table depending on the token prefix.

    Unauthenticated requests are never given a role. Three branches here used
    to assign ``admin`` — auth-disabled, public paths, and static/UI paths —
    which meant "skip authentication" and "become an administrator" were the
    same code path. ``require_role`` rejects a missing role, so anything
    protected stays protected even if this bypass list is wrong.
    """

    @staticmethod
    def _anonymous(request: Request) -> None:
        """Pass a request through with no identity and no role."""
        request.state.role = None
        request.state.policy_id = None
        request.state.api_key_id = None
        request.state.device_id = None

    async def dispatch(self, request: Request, call_next):
        # Check if auth is enabled
        auth_enabled = getattr(request.app.state, "auth_enabled", False)
        if not auth_enabled:
            # Auth disabled: an explicitly opted-in local development mode.
            # Startup refuses this unless TIDEWALL_INSECURE_NO_AUTH=1 and the
            # bind address is loopback, so it cannot be reached off-host.
            request.state.role = "admin"
            request.state.policy_id = None
            request.state.api_key_id = None
            request.state.device_id = None
            return await call_next(request)

        # Public paths carry no identity.
        if request.url.path in _PUBLIC_PATHS:
            self._anonymous(request)
            return await call_next(request)

        # Static assets and dashboard page shells are public and carry no
        # identity either. The pages contain no data: app/static/js/auth.js
        # collects an API key and attaches it to the XHR calls that do, so the
        # shell being anonymous costs nothing and removes the need to
        # authenticate a browser navigation that sends no bearer header.
        if (
            request.url.path == "/dashboard"
            or request.url.path.startswith("/static/")
            or request.url.path.startswith("/ui/")
        ):
            self._anonymous(request)
            return await call_next(request)

        # Extract Bearer token
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return JSONResponse(
                status_code=401,
                content={"detail": "Missing or invalid Authorization header"},
            )

        raw_key = auth_header[7:]  # Strip "Bearer "
        hashed = hash_key(raw_key)

        # Dispatch based on token prefix
        if raw_key.startswith("rt_"):
            return await self._handle_rt_token(request, call_next, hashed)
        elif raw_key.startswith("at_"):
            return await self._handle_at_token(request, call_next, hashed)
        else:
            return await self._handle_ak_token(request, call_next, hashed)

    async def _handle_ak_token(self, request: Request, call_next, hashed: str):
        """Handle ak_ prefix API keys — existing behavior."""
        session = request.app.state.session_factory()
        try:
            from datetime import datetime

            api_key = session.query(APIKey).filter_by(key_hash=hashed).first()
            if api_key is None:
                return JSONResponse(status_code=401, content={"detail": "Invalid API key"})

            if api_key.expires_at and api_key.expires_at < datetime.now(UTC):
                return JSONResponse(status_code=401, content={"detail": "API key expired"})

            request.state.role = api_key.role
            request.state.policy_id = api_key.policy_id
            request.state.api_key_id = api_key.id
            request.state.device_id = None
        finally:
            session.close()

        return await call_next(request)

    async def _handle_rt_token(self, request: Request, call_next, hashed: str):
        """Handle rt_ prefix registration tokens.

        Only allowed for /v1/devices/check; returns 403 for anything else.
        """
        if request.url.path != "/v1/devices/check":
            return JSONResponse(
                status_code=403,
                content={"detail": "Registration tokens can only access /v1/devices/check"},
            )

        session = request.app.state.session_factory()
        try:
            from datetime import datetime

            rt = session.query(RegistrationToken).filter_by(token_hash=hashed).first()
            if rt is None:
                return JSONResponse(status_code=401, content={"detail": "Invalid registration token"})

            if rt.expires_at and rt.expires_at < datetime.now(UTC):
                return JSONResponse(status_code=401, content={"detail": "Registration token expired"})

            request.state.role = "rt"
            request.state.rt_token_hash = hashed
            request.state.policy_id = None
            request.state.api_key_id = None
            request.state.device_id = None
        finally:
            session.close()

        return await call_next(request)

    async def _handle_at_token(self, request: Request, call_next, hashed: str):
        """Handle at_ prefix access tokens.

        Resolves to a device. Sets role=api with the device's policy_id.
        """
        session = request.app.state.session_factory()
        try:
            from datetime import datetime

            at = session.query(AccessToken).filter_by(token_hash=hashed).first()
            if at is None:
                return JSONResponse(status_code=401, content={"detail": "Invalid access token"})

            expires = at.expires_at
            if expires.tzinfo is None:
                expires = expires.replace(tzinfo=UTC)
            if expires < datetime.now(UTC):
                return JSONResponse(status_code=401, content={"detail": "Access token expired"})

            device = session.query(Device).filter_by(id=at.device_id).first()
            if device is None or device.status != "active":
                return JSONResponse(status_code=401, content={"detail": "Device inactive or not found"})

            request.state.role = "api"
            request.state.policy_id = device.policy_id
            request.state.device_id = device.id
            request.state.api_key_id = None
        finally:
            session.close()

        return await call_next(request)
