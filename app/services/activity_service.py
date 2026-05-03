"""Activity audit log service."""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy.orm import Session

from app.db.models import ActivityLog

logger = logging.getLogger(__name__)


class ActivityService:
    """Records configuration changes for audit trail."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def log(
        self,
        actor: str,
        action: str,
        target_type: str,
        target_id: str,
        old_value: dict[str, Any] | None = None,
        new_value: dict[str, Any] | None = None,
    ) -> ActivityLog:
        entry = ActivityLog(
            actor=actor,
            action=action,
            target_type=target_type,
            target_id=target_id,
            old_value=old_value,
            new_value=new_value,
        )
        self._session.add(entry)
        self._session.commit()
        logger.debug("Activity: %s %s %s/%s", actor, action, target_type, target_id)
        return entry

    def list_recent(self, limit: int = 50) -> list[ActivityLog]:
        return self._session.query(ActivityLog).order_by(ActivityLog.timestamp.desc()).limit(limit).all()
