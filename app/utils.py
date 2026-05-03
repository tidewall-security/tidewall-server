"""Shared utility helpers for Tidewall."""

from __future__ import annotations

from datetime import UTC, datetime


def now_iso() -> str:
    """Return the current UTC time as an ISO 8601 string."""
    t = datetime.now(UTC)
    return t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}Z"
