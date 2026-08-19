"""What the authenticated caller may do, so the UI can offer only that.

Effective operation booleans, not grant strings. Returning the raw grants would
couple the front end to the authorization vocabulary and force it to reimplement
the full-implies-matches rule that ``allows_view`` exists to own.

Advisory only. The content endpoint stays authoritative: a grant revoked after
this call still yields 403 there, and the UI updates from that answer rather
than trusting what it loaded.
"""

from __future__ import annotations

from fastapi import APIRouter, Request, Response
from fastapi.responses import JSONResponse

from app.auth.grants import allows_view

_NO_STORE = {"Cache-Control": "no-store", "Pragma": "no-cache"}

router = APIRouter()

_VIEWER_OR_ABOVE = frozenset({"viewer", "admin"})


@router.get("/v1/me/capabilities")
async def capabilities(request: Request) -> Response:
    """Report the caller's own effective content capabilities.

    Takes no parameter naming a key or subject: there is no form of this that
    asks about somebody else.

    An unbound admin gets 200 with both false rather than 401 or 403. The
    credential is valid; it simply has no content capability, which is the same
    answer the content endpoint gives that key, delivered in advance.
    """
    role = getattr(request.state, "role", None)
    if role is None:
        return JSONResponse(status_code=401, content={"detail": "Not authenticated"}, headers=_NO_STORE)
    if role not in _VIEWER_OR_ABOVE:
        return JSONResponse(status_code=403, content={"detail": "Requires viewer role"}, headers=_NO_STORE)

    grants: frozenset[str] = getattr(request.state, "grants", frozenset())
    return JSONResponse(
        status_code=200,
        content={"content": {"matches": allows_view(grants, "matches"), "full": allows_view(grants, "full")}},
        headers=_NO_STORE,
    )
