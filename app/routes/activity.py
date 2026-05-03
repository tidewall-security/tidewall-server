"""Activity log query endpoint."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from app.auth.dependencies import require_role

router = APIRouter(tags=["activity"])


@router.get("/v1/activity", dependencies=[Depends(require_role("admin"))])
async def get_activity(request: Request, limit: int = 50) -> list[dict]:
    session = request.app.state.session_factory()
    try:
        from app.services.activity_service import ActivityService

        svc = ActivityService(session)
        entries = svc.list_recent(limit=limit)
        return [
            {
                "id": e.id,
                "timestamp": str(e.timestamp),
                "actor": e.actor,
                "action": e.action,
                "target_type": e.target_type,
                "target_id": e.target_id,
                "old_value": e.old_value,
                "new_value": e.new_value,
            }
            for e in entries
        ]
    finally:
        session.close()
