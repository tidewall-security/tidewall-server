"""Sending one content payload to one destination, safely.

An admin-configured URL becomes a request this server makes on demand, driven by
a credential that may belong to someone else. That is a server-side fetch
primitive, and every control here exists so it does not become one.

Deliberately not reusing ``ExportService._send_webhook``: it treats a missing
URL as a logged return, every status below 400 as success, mutates the target's
persisted header dict with ``setdefault``, and returns no outcome at all. This
path has to report what happened.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import ssl
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

import httpcore
import httpx

#: Only 443. A non-standard port is a destination nobody expects this server to
#: reach, and an allowlist is easier to reason about than a denylist.
ALLOWED_PORTS = frozenset({443})

#: Refused in a configured header. Host and Content-Length would let a caller
#: retarget or desynchronise the request; the hop-by-hop ones are not the
#: caller's to set.
_FORBIDDEN_HEADERS = frozenset(
    {
        "host",
        "content-length",
        "connection",
        "transfer-encoding",
        "upgrade",
        "te",
        "trailer",
        "proxy-authorization",
        "proxy-connection",
    }
)

PHASES = ("not_started", "connection_acquired", "request_started", "headers_received")


class DestinationRefused(ValueError):
    """The destination, or a configured header, is not safe to send to."""


def _resolve(host: str, port: int) -> list[str]:
    """Every address the name answers with, in order.

    A separate function so a test can substitute it without patching the socket
    module for the whole process.
    """
    infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    seen: list[str] = []
    for info in infos:
        addr = str(info[4][0])
        if addr not in seen:
            seen.append(addr)
    return seen


def _is_public(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        # ::ffff:127.0.0.1 is loopback wearing an IPv6 hat.
        ip = ip.ipv4_mapped
    return not (
        ip.is_loopback
        or ip.is_link_local  # includes 169.254.169.254, the cloud metadata address
        or ip.is_private
        or ip.is_multicast
        or ip.is_unspecified
        or ip.is_reserved
    )


def validate_destination(url: str) -> tuple[str, int, list[str]]:
    """Refuse anything that is not a public HTTPS endpoint.

    Returns the host, the port, and the ordered set of validated addresses. The
    connection is made to one of *those*, so a name that answers differently on a
    second lookup cannot rebind past this check.

    The URL shape is checked before resolving, so a hostile URL cannot even make
    this server perform a DNS lookup of the attacker's choosing.
    """
    parts = urlsplit(url)
    if parts.scheme != "https":
        raise DestinationRefused("content export requires an https destination")
    if parts.username or parts.password:
        raise DestinationRefused("credentials in the destination URL are not permitted")
    if parts.fragment:
        raise DestinationRefused("a fragment in the destination URL is not permitted")

    try:
        host = parts.hostname
    except ValueError as exc:
        raise DestinationRefused("the destination URL could not be parsed") from exc
    if not host:
        raise DestinationRefused("the destination URL has no host")

    try:
        port = parts.port or 443
    except ValueError as exc:
        raise DestinationRefused("the destination port could not be parsed") from exc
    if port not in ALLOWED_PORTS:
        raise DestinationRefused(f"port {port} is not permitted for content export")

    # A literal address skips resolution but not validation.
    try:
        addresses = _resolve(host, port)
    except OSError as exc:
        raise DestinationRefused("the destination could not be resolved") from exc
    if not addresses:
        raise DestinationRefused("the destination resolved to no addresses")

    # EVERY address, not just the first: a name answering with one public and one
    # private address would otherwise pass.
    for addr in addresses:
        if not _is_public(addr):
            raise DestinationRefused("the destination resolves to a non-public address")
    return host, port, addresses


def validate_headers(headers: dict[str, str] | None) -> dict[str, str]:
    """A validated copy. The persisted target config is never mutated."""
    out: dict[str, str] = {}
    for name, value in (headers or {}).items():
        if not isinstance(name, str) or not isinstance(value, str):
            raise DestinationRefused("header names and values must be strings")
        if name.lower() in _FORBIDDEN_HEADERS:
            raise DestinationRefused(f"header {name!r} is not permitted")
        if any(c in name or c in value for c in ("\r", "\n", "\0")):
            raise DestinationRefused("a control character in a header")
        out[name] = value
    return out


@dataclass
class SendResult:
    """What the sender observed, in phase terms.

    ``phase`` is the authority. An exception class cannot tell you whether
    request bytes were written -- with a pooled connection, a failure found while
    checking a stale one does not -- so the class is recorded for the operator
    and decides nothing.
    """

    phase: str = "not_started"
    status: int | None = None
    peer: str | None = None
    error: str | None = None


def state_for_phase(result: SendResult) -> str:
    """The phase decides. There is no class-based default.

    An earlier design had a class table and a phase table both claiming
    authority, which produced two different answers for the same failure.
    """
    if result.phase == "headers_received":
        return "succeeded" if result.status is not None and 200 <= result.status < 300 else "failed"
    if result.phase in ("not_started", "connection_acquired"):
        # The phase establishes that no request bytes were written.
        return "failed"
    # request_started, or anything unrecognised: bytes may have arrived. Never
    # guess `failed` -- that under-reports disclosure, and this is the one step
    # where content leaves.
    return "indeterminate"


class _PinnedStream(httpcore.AsyncNetworkStream):
    """Wraps a stream so the sender can observe where it got to.

    ``AsyncClient.send()`` exposes no connection or request-start event, and this
    is the only layer where those boundaries are visible.
    """

    def __init__(self, inner: httpcore.AsyncNetworkStream, owner: PinnedBackend) -> None:
        self._inner = inner
        self._owner = owner

    async def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        return await self._inner.read(max_bytes, timeout)

    async def write(self, buffer: bytes, timeout: float | None = None) -> None:
        # The first write marks request_started. It does not prove bytes left the
        # process, but it does establish that they may have -- which is the
        # conservative direction and the one that matters here.
        if self._owner.phase == "connection_acquired":
            self._owner.phase = "request_started"
        await self._inner.write(buffer, timeout)

    async def aclose(self) -> None:
        await self._inner.aclose()

    async def start_tls(
        self,
        ssl_context: ssl.SSLContext,
        server_hostname: str | None = None,
        timeout: float | None = None,
    ) -> httpcore.AsyncNetworkStream:
        # server_hostname is the NAME, never the pinned address, so SNI and
        # certificate hostname verification are unaffected by the pinning. That
        # separation is the whole reason this is implementable: connect_tcp and
        # start_tls are distinct calls in httpcore.
        inner = await self._inner.start_tls(ssl_context, server_hostname, timeout)
        return _PinnedStream(inner, self._owner)

    def get_extra_info(self, info: str) -> Any:
        return self._inner.get_extra_info(info)


class PinnedBackend(httpcore.AnyIOBackend):
    """Connects only to addresses validated before the request began.

    Constructed per export, holding that request's validated set, so one
    request's pin can never be applied to another's hostname -- which is the
    concurrency hazard a shared client would create.
    """

    def __init__(self, addresses: list[str]) -> None:
        self._addresses = list(addresses)
        self.phase = "not_started"
        self.peer: str | None = None

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Any = None,
    ) -> httpcore.AsyncNetworkStream:
        last: Exception | None = None
        # In the validated order. Failing over is not a second resolution: the
        # set was fixed before the first connect, so a name that answers
        # differently later cannot enter it.
        for addr in self._addresses:
            try:
                inner = await super().connect_tcp(addr, port, timeout, local_address, socket_options)
            except Exception as exc:
                last = exc
                continue
            self.phase = "connection_acquired"
            self.peer = addr
            return _PinnedStream(inner, self)
        raise last if last is not None else OSError("no validated address could be reached")


async def send_payload(
    *,
    url: str,
    headers: dict[str, str],
    body: bytes,
    addresses: list[str],
    deadline_seconds: float,
    max_response_bytes: int = 64 * 1024,
) -> SendResult:
    """One request to one validated destination, reporting what it observed.

    The deadline is an outer monotonic bound around the whole submission.
    httpx's connect, write, read and pool timeouts are per-operation and
    inactivity timeouts, not a wall clock: several addresses multiply the
    connect bound, and a peer dripping bytes just under the read timeout stays
    alive indefinitely.
    """
    backend = PinnedBackend(addresses)
    result = SendResult()

    transport = httpx.AsyncHTTPTransport(retries=0)
    # The pool carrying the pinned backend. retries=0 above and here, so httpx
    # cannot silently reattempt across phases and blur the observation.
    transport._pool = httpcore.AsyncConnectionPool(
        network_backend=backend,
        retries=0,
        ssl_context=httpx.create_ssl_context(),
    )
    # trust_env=False so an ambient proxy or netrc cannot move the boundary;
    # follow_redirects=False so a 302 to a private address is not followed.
    client = httpx.AsyncClient(transport=transport, trust_env=False, follow_redirects=False)

    try:
        async with asyncio.timeout(deadline_seconds):
            request = client.build_request(
                "POST", url, headers={**headers, "Content-Type": "application/json"}, content=body
            )
            response = await client.send(request, stream=True)
            result.phase = "headers_received"
            result.status = response.status_code
            result.peer = backend.peer
            try:
                read = 0
                async for chunk in response.aiter_raw():
                    read += len(chunk)
                    if read > max_response_bytes:
                        break
            except Exception as exc:
                # A failure reading the body does NOT un-settle a status already
                # received: defaulting that to indeterminate would understate a
                # receiver response we actually saw. Recorded as a note by the
                # caller instead.
                result.error = type(exc).__name__
            finally:
                await response.aclose()
    except Exception as exc:
        result.phase = backend.phase
        result.peer = backend.peer
        result.error = type(exc).__name__
    finally:
        # Bounded and best effort: a close failure never changes a state.
        try:
            await client.aclose()
        except Exception:
            pass
    return result
