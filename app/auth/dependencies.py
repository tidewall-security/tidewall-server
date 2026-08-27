"""FastAPI dependencies for role-based access control."""

from __future__ import annotations

from fastapi import HTTPException, Request

# Role hierarchy: admin > viewer > api > rt
_ROLE_HIERARCHY = {"admin": 3, "viewer": 2, "api": 1, "rt": 0}

#: The closed role vocabulary. Authentication rejects a credential whose
#: persisted role is not in it, so an unknown role never reaches a dependency.
KNOWN_ROLES = frozenset(_ROLE_HIERARCHY)


def require_role(minimum_role: str):
    """FastAPI dependency that enforces a minimum role level.

    Usage:
        @router.get("/admin-only")
        async def admin_only(role=Depends(require_role("admin"))):
            ...

    Three failures that used to be one. ``_ROLE_HIERARCHY.get(role, 0)`` mapped
    an unknown role to level zero -- the ``rt`` level -- so a typo or a tampered
    row became the lowest *valid* role rather than no role at all:

    - an unknown *persisted* role is rejected by AuthMiddleware as invalid
      authentication, before request state is trusted, and never gets here;
    - an unknown ``minimum_role`` is a programmer error, so it raises at
      construction time, at import, where it is a test failure rather than a
      runtime response whose shape a caller can influence;
    - a known but insufficient role is 403, unchanged.
    """
    if minimum_role not in _ROLE_HIERARCHY:
        raise ValueError(f"unknown minimum_role {minimum_role!r}; expected one of {sorted(_ROLE_HIERARCHY)}")
    min_level = _ROLE_HIERARCHY[minimum_role]

    async def _check(request: Request) -> str:
        role = getattr(request.state, "role", None)
        if role is None:
            raise HTTPException(status_code=401, detail="Not authenticated")

        if role not in _ROLE_HIERARCHY:
            # Defence in depth: authentication should already have refused this.
            raise HTTPException(status_code=403, detail="Unknown role")

        if _ROLE_HIERARCHY[role] < min_level:
            raise HTTPException(
                status_code=403,
                detail=f"Requires {minimum_role} role, you have {role}",
            )
        return str(role)

    return _check


def deny_device_credentials(request: Request) -> None:
    """Refuse a route to credentials issued to an enrolled device.

    The ``api`` role is not a fine enough boundary. Every enrolled device holds
    it, because it is what lets an extension call the guard -- so a route that
    asks only for ``api`` is reachable by every laptop in the fleet.

    That is right for the guard and wrong for anything that discloses what a
    redaction concealed. A device credential should be able to ask whether a
    prompt is allowed; it should not be able to ask what was removed from one.

    Denial happens as a DEPENDENCY, before the body is parsed and before any
    lookup, so the route cannot become an existence oracle for identifiers the
    caller is guessing.
    """
    if getattr(request.state, "device_id", None) is not None:
        raise HTTPException(
            status_code=403,
            detail="Device credentials may not reverse redactions",
        )
