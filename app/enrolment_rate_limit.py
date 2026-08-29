"""Rate limiting for the device endpoints, applied before the body is read.

A FastAPI route dependency does NOT run before body parsing. Verified against
the installed FastAPI: a malformed body returns 422 with the dependency never
running, because JSON decoding precedes dependency solving and only schema
validation follows.

Since the flood case IS malformed and oversized bodies, a limiter placed in a
dependency would be measured by a test asserting a control it does not have.
Starlette middleware sees the request before the route handler decodes anything.
"""

from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from app.services.enrolment_limits import RateLimited, is_bounded_path, source_ip


class EnrolmentRateLimitMiddleware(BaseHTTPMiddleware):
    """Bounds enrolment and refresh. Scoped, not global.

    A guard flood from a legitimate fleet must not be throttled by the same
    counter as an enrolment flood from a stranger.
    """

    async def dispatch(self, request: Request, call_next):
        if not is_bounded_path(request.url.path):
            return await call_next(request)

        limits = getattr(request.app.state, "enrolment_limits", None)
        if limits is None:
            return await call_next(request)

        source = source_ip(
            request.client.host if request.client else None,
            request.headers.get("x-forwarded-for"),
            getattr(request.app.state, "trusted_proxy_hops", 0),
        )
        try:
            limits.check(source, request.url.path)
        except RateLimited:
            return JSONResponse(status_code=429, content={"detail": "Too many requests"})
        return await call_next(request)
