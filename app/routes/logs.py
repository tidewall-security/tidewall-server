"""GET /v1/logs and /v1/logs/stats — interaction log query endpoints."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Request
from starlette.responses import Response

from app.auth.dependencies import require_role

router = APIRouter()


@router.get("/v1/logs", dependencies=[Depends(require_role("viewer"))])
async def get_logs(
    request: Request,
    limit: int = 50,
    detector: str | None = None,
    action: str | None = None,
    device_id: str | None = None,
) -> list[dict]:
    log = request.app.state.interaction_log
    events = log.get_recent(limit=limit)

    # Optional client-side filtering (simpler than SQL for POC)
    if detector:
        events = [
            e
            for e in events
            if isinstance(e.get("detectors_json"), dict)
            and detector in e["detectors_json"]
            and e["detectors_json"][detector].get("detected")
        ]

    if action:
        if action == "blocked":
            events = [e for e in events if e.get("blocked")]
        elif action == "transformed":
            events = [e for e in events if e.get("transformed")]
        elif action == "clean":
            events = [e for e in events if not e.get("blocked") and not e.get("transformed")]

    if device_id:
        events = [e for e in events if e.get("device_id") == device_id]

    return events  # type: ignore[no-any-return]


@router.delete("/v1/logs", status_code=204, dependencies=[Depends(require_role("admin"))])
async def clear_logs(request: Request):
    """Delete all interaction logs."""
    from app.db.models import Interaction

    session = request.app.state.session_factory()
    try:
        session.query(Interaction).delete()
        session.commit()
    finally:
        session.close()
    return Response(status_code=204)


@router.get("/v1/logs/stats", dependencies=[Depends(require_role("viewer"))])
async def get_stats(request: Request) -> dict:
    log = request.app.state.interaction_log
    return log.get_stats()  # type: ignore[no-any-return]


@router.get("/v1/logs/flows", dependencies=[Depends(require_role("viewer"))])
async def get_flows(request: Request):
    """Return aggregated flow data for the Sankey diagram."""
    log = request.app.state.interaction_log
    events = log.get_recent(limit=500)

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
