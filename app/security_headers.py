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

import re

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

#: The content endpoint and the capability endpoint that describes access to it.
#: Everything they can return must be uncacheable, including
#: a 401 short-circuited by authentication -- which is why this lives here
#: rather than in the route: this middleware is registered after AuthMiddleware
#: and middleware runs in reverse registration order, so it is the outer of the
#: two and already sees those responses.
#:
#: An exact segment matcher, never a prefix. A trailing slash selects redirect
#: or 404 behaviour rather than this route and is outside the contract.
_CONTENT_PATH = re.compile(r"^(/v1/logs/[^/]+/content|/v1/logs/[^/]+/content-export|/v1/me/capabilities)$")


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

        # Retained prompt content must not sit in a shared cache or a proxy.
        # setdefault throughout, so nothing here removes or contradicts the
        # framing policy above.
        if _CONTENT_PATH.match(request.url.path):
            response.headers.setdefault("Cache-Control", "no-store")
            response.headers.setdefault("Pragma", "no-cache")
        return response
