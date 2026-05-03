"""FastAPI dependencies for role-based access control."""

from __future__ import annotations

from fastapi import HTTPException, Request

# Role hierarchy: admin > viewer > api > rt
_ROLE_HIERARCHY = {"admin": 3, "viewer": 2, "api": 1, "rt": 0}


def require_role(minimum_role: str):
    """FastAPI dependency that enforces a minimum role level.

    Usage:
        @router.get("/admin-only")
        async def admin_only(role=Depends(require_role("admin"))):
            ...
    """
    min_level = _ROLE_HIERARCHY.get(minimum_role, 0)

    async def _check(request: Request) -> str:
        role = getattr(request.state, "role", None)
        if role is None:
            raise HTTPException(status_code=401, detail="Not authenticated")

        user_level = _ROLE_HIERARCHY.get(role, 0)
        if user_level < min_level:
            raise HTTPException(
                status_code=403,
                detail=f"Requires {minimum_role} role, you have {role}",
            )
        return str(role)

    return _check
