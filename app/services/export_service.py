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
from app.services.ocsf_builder import build_aidr_compat_event, build_ocsf_event

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
        """Build and dispatch events to all matching targets. Fire-and-forget."""
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
            except Exception:
                logger.warning(
                    "Export to '%s' failed (status=%s)",
                    target.name,
                    status,
                    exc_info=True,
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
                logger.warning(
                    "Webhook '%s' returned %d: %s",
                    target.name,
                    resp.status_code,
                    resp.text[:200],
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
        except Exception:
            logger.warning("Syslog export to '%s' (%s:%d) failed", target.name, host, port, exc_info=True)
