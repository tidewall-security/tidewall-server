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
from app.services.safe_export_evidence import EVIDENCE_SCHEMA_VERSION

# Caller-supplied metadata is bounded and normalised. Without this, content
# just moves into a different column — an integration is free to put a prompt
# fragment in `user_id`, and nothing would stop it being stored and served.
_MAX_METADATA_LENGTH = 200


def _scoped(query: Any, policy_id: str | None) -> Any:
    """Apply the policy filter in SQL.

    `None` means unscoped, which the route only ever passes for an
    administrator. A null *binding* is never widened to a wildcard here — the
    route turns that into an empty result instead.
    """
    return query if policy_id is None else query.filter(Interaction.policy_id == policy_id)


def _validated(value: str | None, field: str) -> str | None:
    """Bound a caller-supplied metadata string.

    Truncates rather than rejects: these are identifiers on an audit record,
    and failing a guard request because an integration sent a long user ID
    would turn a logging concern into an outage.
    """
    if value is None:
        return None
    if not isinstance(value, str):
        return None
    trimmed = value.strip()[:_MAX_METADATA_LENGTH]
    # Control characters make log and dashboard output ambiguous, and are not
    # part of any legitimate identifier.
    return "".join(c for c in trimmed if c.isprintable()) or None


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
        policy_id: str,
        blocked: bool,
        transformed: bool,
        status: str = "allowed",
        latency_ms: float,
        evidence: dict[str, Any] | None = None,
        api_key_id: str | None = None,
        app_id: str | None = None,
        user_id: str | None = None,
        llm_provider: str | None = None,
        model: str | None = None,
        source_ip: str | None = None,
        device_id: str | None = None,
    ) -> None:
        """Insert one safe audit row.

        ``input_messages``, ``output_messages``, ``detectors_json`` and
        ``summary`` are gone from the signature rather than accepted and
        ignored. A parameter that is accepted and dropped is how a caller keeps
        believing content is stored, and how a later edit quietly reconnects it.

        ``policy_id`` is required and is the policy actually used to evaluate,
        not the caller's binding — which may be null. Reads are scoped by it,
        so a null would make the row invisible to every viewer: a silent audit
        gap rather than a loud one.
        """
        if not policy_id:
            raise ValueError("policy_id is required: an unscoped row is invisible to every reader")

        with self._session_factory() as session:
            row = Interaction(
                request_id=_validated(request_id, "request_id"),
                timestamp=timestamp,
                event_type=_validated(event_type, "event_type"),
                policy_name=_validated(policy, "policy"),
                policy_id=policy_id,
                api_key_id=api_key_id,
                blocked=blocked,
                transformed=transformed,
                status=status,
                latency_ms=latency_ms,
                evidence_json=evidence,
                evidence_schema_version=EVIDENCE_SCHEMA_VERSION,
                content_available=False,
                # Caller-supplied metadata. Bounded and normalised, because
                # otherwise content simply moves into a different column: an
                # integration is free to put a prompt fragment in `user_id`.
                app_id=_validated(app_id, "app_id"),
                user_id=_validated(user_id, "user_id"),
                llm_provider=_validated(llm_provider, "llm_provider"),
                model=_validated(model, "model"),
                source_ip=_validated(source_ip, "source_ip"),
                device_id=_validated(device_id, "device_id"),
            )
            session.add(row)
            session.commit()

    def get_recent(self, limit: int = 50, *, policy_id: str | None = None) -> list[dict]:
        """Return recent events as safe DTOs.

        ``policy_id`` scopes the query in SQL rather than filtering afterwards.
        ``None`` means unscoped and is only ever passed for an administrator;
        the route decides that, and a null *binding* is never widened to a
        wildcard here.
        """
        with self._session_factory() as session:
            query = session.query(
                Interaction.id,
                Interaction.request_id,
                Interaction.timestamp,
                Interaction.event_type,
                Interaction.policy_name,
                Interaction.policy_id,
                Interaction.api_key_id,
                Interaction.blocked,
                Interaction.transformed,
                Interaction.status,
                Interaction.latency_ms,
                Interaction.evidence_json,
                Interaction.evidence_schema_version,
                Interaction.content_available,
                Interaction.app_id,
                Interaction.user_id,
                Interaction.llm_provider,
                Interaction.model,
                Interaction.source_ip,
                Interaction.device_id,
            )
            if policy_id is not None:
                query = query.filter(Interaction.policy_id == policy_id)
            rows = query.order_by(Interaction.timestamp.desc()).limit(limit).all()

            # Built field by field, not by serialising the row: a column added
            # later must not start being returned because nobody updated this.
            return [
                {
                    "id": r.id,
                    "request_id": r.request_id,
                    "timestamp": r.timestamp,
                    "event_type": r.event_type,
                    "policy": r.policy_name,
                    "policy_id": r.policy_id,
                    "api_key_id": r.api_key_id,
                    "blocked": r.blocked,
                    "transformed": r.transformed,
                    "status": r.status,
                    "latency_ms": r.latency_ms,
                    "evidence": r.evidence_json or {},
                    "evidence_schema_version": r.evidence_schema_version,
                    "content_available": r.content_available,
                    "app_id": r.app_id,
                    "user_id": r.user_id,
                    "llm_provider": r.llm_provider,
                    "model": r.model,
                    "source_ip": r.source_ip,
                    "device_id": r.device_id,
                }
                for r in rows
            ]

    def get_stats(self, *, policy_id: str | None = None) -> dict:
        """Return aggregate statistics for the dashboard visibility page.

        Returns total/blocked/transformed/clean counts, average latency,
        and a per-detector detection count breakdown.
        """
        with self._session_factory() as session:
            total = _scoped(session.query(func.count(Interaction.id)), policy_id).scalar() or 0
            blocked = (
                _scoped(session.query(func.count(Interaction.id)), policy_id)
                .filter(Interaction.blocked.is_(True))
                .scalar()
                or 0
            )
            transformed = (
                _scoped(session.query(func.count(Interaction.id)), policy_id)
                .filter(Interaction.blocked.is_(False), Interaction.transformed.is_(True))
                .scalar()
                or 0
            )
            clean = total - blocked - transformed

            avg_latency = _scoped(session.query(func.avg(Interaction.latency_ms)), policy_id).scalar() or 0

            # Per-detector breakdown, from the safe evidence rather than the
            # removed payload.
            rows = (
                _scoped(session.query(Interaction.evidence_json), policy_id)
                .filter(Interaction.evidence_json.isnot(None))
                .all()
            )

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
