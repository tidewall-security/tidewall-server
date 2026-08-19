"""Event export service — dispatches to webhooks and syslog.

Builds events in OCSF, AIDR-style, or raw format and sends them to
configured export targets. Fire-and-forget — failures are logged, never
block the guard response.
"""

from __future__ import annotations

import asyncio
import json
import logging
import socket
from typing import Any

import httpx
from sqlalchemy.orm import Session

from app.db.models import ExportTarget
from app.interaction_log import _validated as _safe_meta
from app.interaction_log import _validated_ip as _safe_ip
from app.interaction_log import is_generated_request_id
from app.services.ocsf_builder import build_aidr_compat_event, build_ocsf_event
from app.services.safe_export_evidence import project_detectors
from app.services.safe_logging import describe

_STATUSES = frozenset({"allowed", "blocked", "transformed", "reported", "alerted"})
_EVENT_TYPES = frozenset({"input", "output", "tool_input", "tool_output", "tool_listing"})
# The complete set an export may carry. Closed, so a new keyword argument is
# invisible until someone decides it is safe to send.
_EXPORTABLE_FIELDS = frozenset(
    {
        "status",
        "request_id",
        "timestamp",
        "summary",
        "policy_name",
        "event_type",
        "detectors",
        "user_id",
        "app_id",
        "model",
        "llm_provider",
        "source_ip",
        "device_id",
    }
)


def _safe_request_id(value: object) -> str | None:
    """The same check storage uses, so the two boundaries cannot drift."""
    return value if is_generated_request_id(value) else None  # type: ignore[return-value]


def _safe_timestamp(value: object) -> str | None:
    from datetime import datetime

    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).isoformat()
    except ValueError:
        return None


def _fixed_summary(status: object, detectors: object) -> str:
    """A summary built from closed codes, never from caller or operator text.

    It used to be an f-string over the matched access-rule name, which is an
    arbitrary control-plane value — operators put tenant names, customer
    identifiers and incident references in them — and it crossed webhook and
    syslog verbatim plus OCSF message and AIDR Vendor.summary.
    """
    verdict = (
        status
        if isinstance(status, str) and status in {"allowed", "blocked", "transformed", "reported", "alerted"}
        else "allowed"
    )
    # Restricted to real detector names even though emit() projects first.
    # A helper that is only safe because of what its caller did is a trap for
    # the next caller.
    from app.scanner_engine import _DETECTOR_REGISTRY

    names = (
        sorted(
            k
            for k, v in (detectors or {}).items()
            if isinstance(v, dict) and v.get("detected") and k in _DETECTOR_REGISTRY
        )
        if isinstance(detectors, dict)
        else []
    )
    if not names:
        return verdict
    return f"{verdict}: " + ", ".join(names[:5])


logger = logging.getLogger(__name__)


class ExportService:
    """Dispatches guard events to configured export targets.

    Accepts either a pre-existing session (backward compat with tests) or
    a session_factory.  When session_factory is provided, a fresh session
    is created per operation to avoid stale-session bugs.
    """

    def __init__(self, session: Session | None = None, *, session_factory: Any = None) -> None:
        self._session = session
        self._session_factory = session_factory

    def _get_session(self) -> tuple[Session, bool]:
        """Return (session, should_close)."""
        if self._session_factory is not None:
            return self._session_factory(), True
        if self._session is not None:
            return self._session, False
        raise RuntimeError("ExportService has no session or session_factory")

    def _get_matching_targets(self, status: str) -> list[ExportTarget]:
        """Get enabled targets whose events filter matches the status."""
        session, should_close = self._get_session()
        try:
            targets = session.query(ExportTarget).filter_by(enabled=True).all()
            return [t for t in targets if status in (t.events or [])]
        finally:
            if should_close:
                session.close()

    def _build_event(self, format: str, **kwargs: Any) -> dict[str, Any]:
        """Build event in the requested format."""
        if format == "ocsf":
            return build_ocsf_event(**kwargs)
        elif format == "aidr_compat":
            return build_aidr_compat_event(**kwargs)
        else:
            # Raw format — flat dict
            return {
                "status": kwargs.get("status"),
                "request_id": kwargs.get("request_id"),
                "timestamp": kwargs.get("timestamp"),
                "summary": kwargs.get("summary"),
                "policy_name": kwargs.get("policy_name"),
                "event_type": kwargs.get("event_type"),
                "detectors": kwargs.get("detectors"),
                "user_id": kwargs.get("user_id"),
                "app_id": kwargs.get("app_id"),
                "model": kwargs.get("model"),
                "llm_provider": kwargs.get("llm_provider"),
            }

    async def emit(self, **kwargs: Any) -> None:
        """Build and dispatch events to all matching targets. Fire-and-forget.

        Detector payloads are projected here rather than by the caller. Doing
        it at the call site left the invariant one edit away from being lost:
        any future caller could pass the raw structure and nothing would fail.
        The service owns what may cross this boundary (P0-6).
        """
        kwargs["detectors"] = project_detectors(kwargs.get("detectors"))
        # Every textual field, not just detectors. Normalising at one call site
        # leaves the invariant one caller away from being lost, and the summary
        # in particular was built from an arbitrary control-plane rule name.
        for field in ("user_id", "app_id", "model", "llm_provider", "device_id", "policy_name"):
            if field in kwargs:
                kwargs[field] = _safe_meta(kwargs[field], field)
        if "source_ip" in kwargs:
            kwargs["source_ip"] = _safe_ip(kwargs["source_ip"])
        kwargs["summary"] = _fixed_summary(kwargs.get("status"), kwargs.get("detectors"))

        # Generated/resolved fields, normalised here too. Sanitising only the
        # obviously-caller-supplied keys left request_id, timestamp, status and
        # event_type forwarded verbatim, and a direct caller of emit() is as
        # real a boundary as the guard route.
        kwargs["status"] = kwargs.get("status") if kwargs.get("status") in _STATUSES else "allowed"
        kwargs["event_type"] = kwargs.get("event_type") if kwargs.get("event_type") in _EVENT_TYPES else "input"
        kwargs["request_id"] = _safe_request_id(kwargs.get("request_id"))
        kwargs["timestamp"] = _safe_timestamp(kwargs.get("timestamp"))

        # Anything not in the closed set is dropped rather than forwarded. An
        # open kwargs bag means every builder-only field — collector_type,
        # api_key_name, fpe_context — sits outside the sink invariant.
        kwargs = {k: v for k, v in kwargs.items() if k in _EXPORTABLE_FIELDS}
        status = kwargs.get("status", "allowed")
        targets = self._get_matching_targets(status)

        if not targets:
            return

        for target in targets:
            try:
                event = self._build_event(format=target.format, **kwargs)

                if target.type == "webhook":
                    await self._send_webhook(target, event)
                elif target.type == "syslog":
                    await self._send_syslog(target, event)
            except Exception as exc:
                logger.warning(
                    "Export to '%s' failed (status=%s): %s",
                    target.name,
                    status,
                    describe(exc),
                )

    async def _send_webhook(self, target: ExportTarget, event: dict) -> None:
        """HTTP POST event as JSON to webhook URL."""
        config = target.config or {}
        url = config.get("url")
        if not url:
            logger.warning("Webhook target '%s' has no URL", target.name)
            return

        headers = config.get("headers", {})
        headers.setdefault("Content-Type", "application/json")

        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(url, json=event, headers=headers)
            if resp.status_code >= 400:
                # Deliberately not the response body: a receiver can echo
                # back what we posted, which puts the exported event into our
                # own logs by a route nobody would think to audit.
                logger.warning(
                    "Webhook '%s' returned %d",
                    target.name,
                    resp.status_code,
                )
            else:
                logger.debug("Exported to webhook '%s' (status=%d)", target.name, resp.status_code)

    async def _send_syslog(self, target: ExportTarget, event: dict) -> None:
        """Send event as JSON to syslog endpoint via UDP or TCP.

        Socket operations are blocking, so they are dispatched to a thread
        to avoid stalling the async event loop.
        """
        config = target.config or {}
        host = config.get("host", "localhost")
        port = config.get("port", 514)
        protocol = config.get("protocol", "udp")

        message = json.dumps(event)
        # RFC 5424 facility=local0 (16), severity=info (6) → priority = 16*8+6 = 134
        syslog_msg = f"<134>1 - tidewall - - - - {message}"
        encoded = syslog_msg.encode("utf-8")

        def _blocking_send() -> None:
            if protocol == "tcp":
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(5.0)
                    sock.connect((host, port))
                    sock.sendall(encoded + b"\n")
            else:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.sendto(encoded, (host, port))

        try:
            await asyncio.to_thread(_blocking_send)
            logger.debug("Exported to syslog '%s' (%s:%d)", target.name, host, port)
        except Exception as exc:
            logger.warning("Syslog export to '%s' (%s:%d) failed: %s", target.name, host, port, describe(exc))
