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

    Authentication is unconditional. There is no configuration value that
    turns it off.

    Three branches here used to assign ``admin`` — an auth-disabled mode, the
    public path list, and the static/UI prefixes — so "skip authentication" and
    "become an administrator" were the same code path. The disabled mode is
    gone entirely: its loopback guard was bypassable because a directly
    launched ASGI server binds whatever address it is given, and uvicorn binds
    *after* lifespan runs, so the application cannot inspect its own listener
    in time to refuse. Rather than defend that, the mode was removed.

    What remains anonymous is health, favicon, and the data-free dashboard
    shells, all with ``role=None``. ``require_role`` rejects a missing role, so
    anything protected stays protected even if this list is wrong.
    """

    @staticmethod
    def _anonymous(request: Request) -> None:
        """Pass a request through with no identity and no role."""
        request.state.role = None
        request.state.policy_id = None
        request.state.api_key_id = None
        request.state.device_id = None

    async def dispatch(self, request: Request, call_next):
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

        Only allowed for enrolment. A registration token is a shared onboarding
        secret: it can create a device but must never be able to act on an
        existing one, which is what /v1/devices/check allowed (P0-11).
        """
        if request.url.path != "/v1/devices/enrol":
            return JSONResponse(
                status_code=403,
                content={"detail": "Registration tokens can only access /v1/devices/enrol"},
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
            request.state.at_token_hash = hashed
            request.state.device_id = device.id
            request.state.api_key_id = None
        finally:
            session.close()

        return await call_next(request)
