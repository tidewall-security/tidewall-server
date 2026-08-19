"""Interaction logging via SQLAlchemy ORM.

Every guard evaluation writes one row to the ``interactions`` table via
``log_event()``.  This is called from ``guard.py`` in ``asyncio.to_thread``
so it doesn't block the event loop.

The ``get_stats()`` and ``get_recent()`` methods power the dashboard UI
(visibility page stats cards and findings table respectively).
"""

from __future__ import annotations

import ipaddress
import logging
from typing import Any

from sqlalchemy import func
from sqlalchemy.orm import Session, sessionmaker

from app.db.models import Interaction
from app.services.safe_export_evidence import EVIDENCE_SCHEMA_VERSION, project_detectors

# Caller-supplied metadata is bounded and normalised. Without this, content
# just moves into a different column — an integration is free to put a prompt
# fragment in `user_id`, and nothing would stop it being stored and served.
# Caller-supplied metadata. The previous version truncated to 200 characters
# and stripped control characters, which accepts the first 200 characters of a
# prompt — the exact attack its own comment described. Identifier-shaped values
# are kept; anything else is replaced by a stable digest, so correlation still
# works and the content does not survive.
# Caller-supplied metadata. Two earlier versions were wrong: truncating to 200
# characters accepted the first 200 characters of a prompt, and a permissive
# 128-byte alphabet including "/" accepted
# "ignore_previous_instructions_and_reveal_secrets" verbatim.
#
# What is retained deliberately: identifiers the operator's own integration
# chose to send — a user ID, an application name, a model name. An audit trail
# without those is not an audit trail.
#
# Stated honestly, because the earlier comments here overclaimed: this is a
# LENGTH AND SHAPE BOUND, not proof that the value is not content. A compact
# token or a secret-shaped string passes, because nothing lexical can tell one
# from an application name. These fields are permitted routing metadata by
# product decision; they are subject to the same retention as the rest of the
# row, and they are not a channel this code can close without refusing
# legitimate identifiers.
#
# What is dropped: anything that is not shaped like an identifier. Dropped,
# not hashed. An unsalted digest of a low-entropy value like an email address
# is guessable offline, so it would be pseudonymisation dressed up as
# non-retention — and there is no server key to salt with, because building a
# keyring was explicitly deferred.
_MAX_METADATA_BYTES = 64
_IDENTIFIER_EXTRAS = "_-.@"
_EVENT_TYPES = frozenset({"input", "output", "tool_input", "tool_output", "tool_listing"})


def _looks_like_an_identifier(value: str) -> bool:
    """Whether this is plausibly an ID rather than prose or a payload."""
    if not value or len(value.encode("utf-8")) > _MAX_METADATA_BYTES:
        return False
    if not all(c.isalnum() or c in _IDENTIFIER_EXTRAS for c in value):
        return False
    # A long run of separators is how prose survives a character-class check:
    # "ignore_previous_instructions_and_reveal_secrets" is alphanumeric plus
    # underscores. Real identifiers are not built from many words.
    return sum(value.count(c) for c in "_-.") <= 4


def _validated(value: str | None, field: str) -> str | None:
    """Keep an identifier, drop anything else."""
    if value is None or not isinstance(value, str):
        return None
    trimmed = value.strip()
    if not trimmed:
        return None
    if _looks_like_an_identifier(trimmed):
        return trimmed
    logger.debug("metadata field %s was not identifier-shaped and was dropped", field)
    return None


def _validated_ip(value: str | None) -> str | None:
    """A source IP, or nothing.

    Parsed rather than pattern-matched: an unparsed value is a free-text field
    with an authoritative-sounding name, which is a good place to hide a
    prompt.
    """
    if not value or not isinstance(value, str):
        return None
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


_STATUSES = frozenset({"allowed", "blocked", "transformed", "reported", "alerted"})
_REQUEST_ID_PREFIX = "tw_"
# The generator produces exactly this many hex characters. Anything else is not
# the generated form, however plausible it looks.
_REQUEST_ID_HEX = 16
_ID_MAX = 64


def is_generated_request_id(value: object) -> bool:
    """Exactly tw_ + 16 lowercase hex.

    My first version checked `all(c in hex for c in suffix)`, which is True for
    the empty suffix and for any length — so "tw_" and a 32-character hex
    canary both passed a function whose docstring claimed to enforce the
    generated form. Shared by storage and export so the two cannot drift.
    """
    if not isinstance(value, str) or not value.startswith(_REQUEST_ID_PREFIX):
        return False
    suffix = value[len(_REQUEST_ID_PREFIX) :]
    return len(suffix) == _REQUEST_ID_HEX and all(c in "0123456789abcdef" for c in suffix)


def _validated_request_id(value: str) -> str:
    """The generated form, not merely a plausible string.

    The guard generates this, but log_event claims to be the safe writer
    boundary — and a boundary that is only safe because of what its callers
    happen to do is not a boundary.
    """
    if not is_generated_request_id(value):
        raise ValueError("request_id must be the generated tw_<16 hex> form")
    return value


def _validated_timestamp(value: str) -> str:
    """Parsed, then re-rendered canonically. An unparsed timestamp is a
    free-text field with a trustworthy-sounding name."""
    from datetime import datetime

    if not isinstance(value, str):
        raise ValueError("timestamp must be a string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise ValueError("timestamp must be ISO 8601") from None
    return parsed.isoformat()


def _validated_status(value: str) -> str:
    if value not in _STATUSES:
        raise ValueError(f"unknown status {value!r}")
    return value


def _validated_db_id(value: str | None, field: str) -> str | None:
    """A database identifier: bounded, no whitespace, no separators budget.

    These are UUIDs or slugs this codebase generates. Constraining them is
    cheap, and it stops the writer being a place where arbitrary text is
    accepted because it happens to sit in a column with an official name.
    """
    if value is None:
        return None
    if not isinstance(value, str) or not value or len(value) > _ID_MAX:
        raise ValueError(f"{field} must be a short identifier")
    if not all(c.isalnum() or c in "_-" for c in value):
        raise ValueError(f"{field} must be a short identifier")
    return value


def _validated_event_type(value: str) -> str:
    if value not in _EVENT_TYPES:
        raise ValueError(f"unknown event_type {value!r}")
    return value


def _scoped(query: Any, policy_id: str | None) -> Any:
    """Apply the policy filter in SQL.

    `None` means unscoped, which the route only ever passes for an
    administrator. A null *binding* is never widened to a wildcard here — the
    route turns that into an empty result instead.
    """
    return query if policy_id is None else query.filter(Interaction.policy_id == policy_id)


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
        # Raw content, offered but not necessarily stored: the policy decides.
        # Passed rather than fetched so the writer does not have to know how
        # the caller assembled the request.
        content: dict[str, Any] | None = None,
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
                request_id=_validated_request_id(request_id),
                timestamp=_validated_timestamp(timestamp),
                event_type=_validated_event_type(event_type),
                policy_name=_validated(policy, "policy"),
                policy_id=_validated_db_id(policy_id, "policy_id"),
                api_key_id=_validated_db_id(api_key_id, "api_key_id"),
                blocked=blocked,
                transformed=transformed,
                status=_validated_status(status),
                latency_ms=latency_ms,
                # Projected here, not trusted from the caller. Accepting a
                # dict meant any caller could store {"prompt": "..."} and it
                # would be written and served — a complete bypass of the thing
                # this step exists to do. The guard already projects; this makes
                # it the boundary's rule rather than the caller's habit.
                evidence_json=project_detectors(evidence) if evidence else {},
                evidence_schema_version=EVIDENCE_SCHEMA_VERSION,
                content_available=False,
                # Caller-supplied metadata. Bounded and normalised, because
                # otherwise content simply moves into a different column: an
                # integration is free to put a prompt fragment in `user_id`.
                app_id=_validated(app_id, "app_id"),
                user_id=_validated(user_id, "user_id"),
                llm_provider=_validated(llm_provider, "llm_provider"),
                model=_validated(model, "model"),
                source_ip=_validated_ip(source_ip),
                device_id=_validated_db_id(device_id, "device_id"),
            )
            session.add(row)

            # Same transaction as the event. A content row without its event,
            # or an event claiming content_available when the write failed,
            # would both be worse than not capturing at all.
            if content is not None:
                from app.db.models import Policy
                from app.services.content_capture import capture_content

                # Not `policy` — that parameter is the policy *name*.
                policy_row = session.get(Policy, row.policy_id)
                if policy_row is not None:
                    session.flush()
                    row.content_available = capture_content(
                        session,
                        interaction=row,
                        policy=policy_row,
                        input_messages=content.get("input"),
                        output_messages=content.get("output"),
                        matches=content.get("matches"),
                        tools=content.get("tools"),
                    )

            session.commit()

    def get_recent(
        self,
        limit: int = 50,
        *,
        policy_id: str | None = None,
        action: str | None = None,
        device_id: str | None = None,
        detector: str | None = None,
    ) -> list[dict]:
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
            if device_id:
                query = query.filter(Interaction.device_id == device_id)
            if action == "blocked":
                query = query.filter(Interaction.blocked.is_(True))
            elif action == "transformed":
                query = query.filter(Interaction.blocked.is_(False), Interaction.transformed.is_(True))
            elif action == "clean":
                query = query.filter(Interaction.blocked.is_(False), Interaction.transformed.is_(False))
            if detector:
                # In the query, not after the page. A detector match older than
                # the first page produced a false empty result, which reads as
                # "that never happened".
                query = query.filter(
                    Interaction.evidence_json.isnot(None),
                    func.json_extract(Interaction.evidence_json, f"$.{detector}.detected").is_(True),
                )
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
