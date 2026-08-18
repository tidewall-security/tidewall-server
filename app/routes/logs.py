"""GET /v1/logs and /v1/logs/stats — interaction log query endpoints."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from starlette.responses import Response

from app.auth.dependencies import require_role

router = APIRouter()


def _read_scope(request: Request) -> tuple[bool, str | None]:
    """Which rows this caller may see.

    Returns (allowed, policy_id). An administrator sees everything, including
    when its key has no binding — the dashboard has to work. A viewer sees only
    its bound policy, and a viewer with **no** binding sees nothing.

    That last case is the important one: treating a null binding as a wildcard
    is exactly how one credential becomes an organisation-wide disclosure
    credential, which is half of why this finding is a P0. Refusing the read is
    the safe direction; the fix for the operator is to bind the key.
    """
    role = getattr(request.state, "role", None)
    if role == "admin":
        return True, getattr(request.state, "policy_id", None)
    bound = getattr(request.state, "policy_id", None)
    if not bound:
        return False, None
    return True, bound


@router.get("/v1/logs", dependencies=[Depends(require_role("viewer"))])
async def get_logs(
    request: Request,
    limit: int = Query(default=50, ge=1, le=100),
    detector: str | None = None,
    action: str | None = None,
    device_id: str | None = None,
) -> list[dict]:
    allowed, scope = _read_scope(request)
    if not allowed:
        # An unbound viewer, which is not the same as an empty database.
        return []

    log = request.app.state.interaction_log
    # Filters go to the query, not to the page. Filtering after ORDER BY LIMIT
    # returns a false empty result whenever the matches are past the first
    # page, which reads as "nothing happened".
    return log.get_recent(  # type: ignore[no-any-return]
        limit=limit, policy_id=scope, action=action, device_id=device_id, detector=detector
    )


@router.delete("/v1/logs", status_code=204, dependencies=[Depends(require_role("admin"))])
async def clear_logs(request: Request):
    """Delete interaction logs within the caller's scope.

    Scoped like every other read. Unscoped, an administrator bound to policy A
    destroyed policy B's audit trail — which is worse than disclosure, because
    the evidence that it happened goes with it.
    """
    from app.db.models import Interaction

    bound = getattr(request.state, "policy_id", None)
    session = request.app.state.session_factory()
    try:
        query = session.query(Interaction)
        if bound:
            query = query.filter(Interaction.policy_id == bound)
        query.delete(synchronize_session=False)
        session.commit()
    finally:
        session.close()
    return Response(status_code=204)


@router.get("/v1/logs/stats", dependencies=[Depends(require_role("viewer"))])
async def get_stats(request: Request) -> dict:
    allowed, scope = _read_scope(request)
    if not allowed:
        return {"total": 0, "blocked": 0, "transformed": 0, "clean": 0, "avg_latency_ms": 0, "detector_counts": {}}
    log = request.app.state.interaction_log
    return log.get_stats(policy_id=scope)  # type: ignore[no-any-return]


@router.get("/v1/logs/flows", dependencies=[Depends(require_role("viewer"))])
async def get_flows(request: Request):
    """Return aggregated flow data for the Sankey diagram."""
    allowed, scope = _read_scope(request)
    if not allowed:
        return {"nodes": [], "links": []}
    log = request.app.state.interaction_log
    events = log.get_recent(limit=500, policy_id=scope)

    # Aggregate actor -> app -> model flows
    nodes: dict[str, dict[str, str]] = {}
    links: dict[tuple[str, str], dict[str, Any]] = {}

    for event in events:
        actor = event.get("user_id") or "unknown"
        app = event.get("app_id") or "unknown"
        model = event.get("model") or "unknown"
        blocked = event.get("blocked", 0)
        transformed = event.get("transformed", 0)

        # Register nodes
        for nid, cat in [
            (f"actor:{actor}", "actor"),
            (f"app:{app}", "application"),
            (f"model:{model}", "model"),
        ]:
            if nid not in nodes:
                nodes[nid] = {"id": nid, "name": nid.split(":", 1)[1], "category": cat}

        # Aggregate links
        for src, tgt in [
            (f"actor:{actor}", f"app:{app}"),
            (f"app:{app}", f"model:{model}"),
        ]:
            key = (src, tgt)
            if key not in links:
                links[key] = {
                    "source": src,
                    "target": tgt,
                    "value": 0,
                    "blocked": 0,
                    "transformed": 0,
                    "clean": 0,
                }
            links[key]["value"] += 1
            if blocked:
                links[key]["blocked"] += 1
            elif transformed:
                links[key]["transformed"] += 1
            else:
                links[key]["clean"] += 1

    return {
        "nodes": list(nodes.values()),
        "links": list(links.values()),
    }
