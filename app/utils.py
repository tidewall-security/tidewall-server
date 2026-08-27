"""Shared utility helpers for Tidewall."""

from __future__ import annotations

from datetime import UTC, datetime


def now_iso() -> str:
    """Return the current UTC time as an ISO 8601 string."""
    t = datetime.now(UTC)
    return t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}Z"


def as_utc(value: datetime) -> datetime:
    """Tag a naive datetime as UTC, leaving aware ones alone.

    SQLite has no timezone type, so every datetime read back from it is naive
    even though it was written as UTC. Comparing one to ``datetime.now(UTC)``
    raises TypeError instead of returning a verdict, which surfaces as a 500 on
    a path whose whole job is to answer yes or no.

    One definition, so a third comparison cannot be written without it.
    """
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)
