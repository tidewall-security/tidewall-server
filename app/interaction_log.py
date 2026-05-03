"""Interaction logging via SQLAlchemy ORM.

Every guard evaluation writes one row to the ``interactions`` table via
``log_event()``.  This is called from ``guard.py`` in ``asyncio.to_thread``
so it doesn't block the event loop.

The ``get_stats()`` and ``get_recent()`` methods power the dashboard UI
(visibility page stats cards and findings table respectively).
"""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy import func
from sqlalchemy.orm import Session, sessionmaker

from app.db.models import Interaction

logger = logging.getLogger(__name__)


class InteractionLog:
    """Logs guard interactions using the SQLAlchemy Interaction model."""

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    def log_event(
        self,
        *,
        request_id: str,
        timestamp: str,
        event_type: str,
        policy: str,
        blocked: bool,
        transformed: bool,
        status: str = "allowed",
        latency_ms: float,
        summary: str | None = None,
        input_messages: Any = None,
        output_messages: Any = None,
        detectors_json: Any = None,
        app_id: str | None = None,
        user_id: str | None = None,
        llm_provider: str | None = None,
        model: str | None = None,
        source_ip: str | None = None,
        device_id: str | None = None,
    ) -> None:
        """Insert a single interaction row."""
        with self._session_factory() as session:
            row = Interaction(
                request_id=request_id,
                timestamp=timestamp,
                event_type=event_type,
                policy_name=policy,
                blocked=blocked,
                transformed=transformed,
                status=status,
                latency_ms=latency_ms,
                summary=summary,
                input_messages=input_messages,
                output_messages=output_messages,
                detectors_json=detectors_json,
                app_id=app_id,
                user_id=user_id,
                llm_provider=llm_provider,
                model=model,
                source_ip=source_ip,
                device_id=device_id,
            )
            session.add(row)
            session.commit()

    def get_recent(self, limit: int = 50) -> list[dict]:
        """Return the most recent interactions as dicts."""
        with self._session_factory() as session:
            rows = session.query(Interaction).order_by(Interaction.timestamp.desc()).limit(limit).all()
            results = []
            for row in rows:
                results.append(
                    {
                        "id": row.id,
                        "request_id": row.request_id,
                        "timestamp": row.timestamp,
                        "event_type": row.event_type,
                        "policy": row.policy_name,
                        "policy_id": row.policy_id,
                        "api_key_id": row.api_key_id,
                        "blocked": row.blocked,
                        "transformed": row.transformed,
                        "status": row.status,
                        "latency_ms": row.latency_ms,
                        "summary": row.summary,
                        "input_messages": row.input_messages,
                        "output_messages": row.output_messages,
                        "detectors_json": row.detectors_json,
                        "app_id": row.app_id,
                        "user_id": row.user_id,
                        "llm_provider": row.llm_provider,
                        "model": row.model,
                        "source_ip": row.source_ip,
                        "device_id": row.device_id,
                    }
                )
            return results

    def get_stats(self) -> dict:
        """Return aggregate statistics for the dashboard visibility page.

        Returns total/blocked/transformed/clean counts, average latency,
        and a per-detector detection count breakdown.
        """
        with self._session_factory() as session:
            total = session.query(func.count(Interaction.id)).scalar() or 0
            blocked = session.query(func.count(Interaction.id)).filter(Interaction.blocked.is_(True)).scalar() or 0
            transformed = (
                session.query(func.count(Interaction.id))
                .filter(Interaction.blocked.is_(False), Interaction.transformed.is_(True))
                .scalar()
                or 0
            )
            clean = total - blocked - transformed

            avg_latency = session.query(func.avg(Interaction.latency_ms)).scalar() or 0

            # Per-detector breakdown
            rows = session.query(Interaction.detectors_json).filter(Interaction.detectors_json.isnot(None)).all()

        detector_counts: dict[str, int] = {}
        for (dj,) in rows:
            if isinstance(dj, dict):
                for det_name, det_info in dj.items():
                    if isinstance(det_info, dict) and det_info.get("detected"):
                        detector_counts[det_name] = detector_counts.get(det_name, 0) + 1

        return {
            "total": total,
            "blocked": blocked,
            "transformed": transformed,
            "clean": clean,
            "avg_latency_ms": round(avg_latency, 2),
            "detector_counts": detector_counts,
        }
