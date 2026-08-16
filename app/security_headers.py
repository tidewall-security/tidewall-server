"""Response security headers.

The dashboard shells are served anonymously and recover an admin-capable API
key from ``localStorage``. That combination is framable: a hostile origin can
embed ``/ui/policies``, and script running inside that same-origin frame reads
the stored key and issues authenticated writes. Cookies are not involved, so
SameSite does not help and CORS does not apply — the request originates from
Tidewall's own origin.

``frame-ancestors 'none'`` is the control that actually prevents it.
"""

from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Adds framing and content-type protections to every response."""

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        # frame-ancestors is the modern control; X-Frame-Options is kept for
        # clients that do not implement CSP.
        response.headers.setdefault("Content-Security-Policy", "frame-ancestors 'none'")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        return response
