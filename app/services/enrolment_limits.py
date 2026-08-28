"""Bounds on the two device endpoints that a stranger can reach.

Approval-by-default converted a leaked enrolment key from "a working fleet" into
"unbounded pending rows". Rate limiting alone only slows unbounded state; it does
not bound it. Quotas bound it, reaping recovers it, and the rate limit keeps the
path from being a cheap write amplifier.

Refresh is covered as well as enrolment. Its middleware branch deliberately does
not adjudicate the credential -- the service does, so device state can dominate
credential state -- which leaves the route reachable with a token that does not
exist. Bounding it here is what keeps that from being an unmetered oracle.

Counter state is in-process. A single-writer SQLite deployment is a single
process, and persisting a counter would add a write to the very path being
flooded. Stated rather than discovered: this resets on restart and does not
apply across processes.
"""

from __future__ import annotations

import re
import threading
import time
from collections import defaultdict, deque

#: POST /v1/devices/enrol
ENROL_PATH = "/v1/devices/enrol"
#: POST /v1/devices/{device_id}/refresh
REFRESH_PATH = re.compile(r"^/v1/devices/[^/]+/refresh$")


class RateLimited(Exception):
    """The caller has exceeded its allowance for this path."""


def is_bounded_path(path: str) -> bool:
    return path == ENROL_PATH or REFRESH_PATH.match(path) is not None


class EnrolmentLimits:
    """A fixed-window counter per (source, path family).

    Deliberately simple. The threat is a leaked key creating unbounded state,
    not a distributed flood, and a precise limiter here would be more code to
    get wrong than the thing it protects.
    """

    def __init__(self, per_minute: int) -> None:
        self._per_minute = per_minute
        self._hits: dict[tuple[str, str], deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, source: str | None, path: str, *, now: float | None = None) -> None:
        """Raise RateLimited if this source has used up its allowance."""
        moment = time.monotonic() if now is None else now
        # An unattributable caller shares one bucket rather than escaping the
        # limit: no source is not a licence.
        key = (source or "-unattributed-", ENROL_PATH if path == ENROL_PATH else "refresh")
        with self._lock:
            hits = self._hits[key]
            while hits and moment - hits[0] >= 60.0:
                hits.popleft()
            if len(hits) >= self._per_minute:
                raise RateLimited(path)
            hits.append(moment)


def source_ip(client_host: str | None, forwarded_for: str | None, trusted_hops: int) -> str | None:
    """Attribute a request to a source, honouring only trusted proxies.

    X-Forwarded-For is caller-supplied. Trusting it unconditionally means every
    request can claim a fresh identity and the limit bounds nothing at all. Only
    `trusted_hops` entries from the RIGHT are believed, because those are the
    ones appended by proxies this deployment actually runs.

    Default is zero hops: the ASGI peer and nothing else, matching the existing
    decision recorded in the content routes.
    """
    if trusted_hops <= 0 or not forwarded_for:
        return client_host
    hops = [h.strip() for h in forwarded_for.split(",") if h.strip()]
    if not hops:
        return client_host
    index = max(0, len(hops) - trusted_hops)
    return hops[index]
