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
        "proxy-authenticate",
        "proxy-connection",
        "keep-alive",
        "expect",
    }
)

#: Prefixes the IANA special-purpose registries mark as not globally
#: reachable, which this Python's `ipaddress` tables nonetheless report as
#: global. Determined by sweeping both registries against the predicate below;
#: everything else in them is already rejected by it.
#:
#: This list is a snapshot of a registry that changes. It is not a substitute
#: for the general rule beneath it, and it needs revisiting when either the
#: registry or the runtime's tables move.
_REFUSED_NETWORKS = (
    # 6to4 relay anycast, deprecated by RFC 7526. Reaches whichever relay the
    # local network routes it to.
    ipaddress.ip_network("192.88.99.0/24"),
    # ORCHIDv2 (RFC 7343): not routable addresses at all.
    ipaddress.ip_network("2001:20::/28"),
)

#: NAT64, stated rather than implied.
#:
#: 64:ff9b::/96 (RFC 6052 well-known prefix) and 64:ff9b:1::/48 (RFC 8215
#: local use) are refused, the first because this Python marks it reserved and
#: the second because it is local by definition. That is deliberately
#: conservative: a NAT64-only deployment cannot export through the well-known
#: prefix and needs an IPv4 or dual-stack route to its receiver.
#:
#: What this predicate CANNOT see is a Network-Specific Prefix. An operator's
#: own NAT64 prefix is ordinary global IPv6 as far as any classification can
#: tell, and the IPv4 address behind it may be internal. No address predicate
#: can close that; it is a property of the network the server runs on, not of
#: the address. It is a residual risk, and the runbook says so rather than
#: this module implying otherwise.

#: Headers this server sets itself on a content export. They are refused in a
#: target's configuration rather than allowed to lose a merge, because HTTP
#: field names are case-insensitive while dict keys are not: a configured
#: ``idempotency-key`` does not collide with the server's ``Idempotency-Key``
#: in the dict, so both reach the wire. The receiver then chooses, and a
#: receiver that honours the configured one can collapse two distinct attempts
#: into one acknowledgement while this server records the second as succeeded.
#: The attempt id has to be the only idempotency token on the request for the
#: state it settles to mean anything.
_SERVER_OWNED_HEADERS = frozenset({"idempotency-key", "content-type"})

#: RFC 9110 token characters. A header name outside these is not a header name,
#: and some intermediaries will interpret it as something else entirely.
_TOKEN_CHARS = frozenset("!#$%&'*+-.^_`|~0123456789" "abcdefghijklmnopqrstuvwxyz" "ABCDEFGHIJKLMNOPQRSTUVWXYZ")


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
    if any(ip in net for net in _REFUSED_NETWORKS):
        return False
    # Both halves are load-bearing, and neither is sufficient alone.
    #
    # The negative list alone admitted 100.64.0.0/10 (RFC 6598 shared address
    # space): Python reports it as neither private nor reserved, so "not
    # private and not reserved" is not the same question as "routable on the
    # public internet". That range is carrier-grade NAT space and is also a
    # common internal overlay range -- Tailscale uses it -- so accepting it
    # is a live SSRF path into an internal network.
    #
    # is_global alone is wrong in the other direction: Python reports
    # 224.0.0.1 as global (it is globally *scoped* multicast), so the
    # multicast check still has to be here.
    return ip.is_global and not (
        ip.is_loopback
        or ip.is_link_local  # includes 169.254.169.254, the cloud metadata address
        or ip.is_private
        or ip.is_multicast
        or ip.is_unspecified
        or ip.is_reserved
        # IPv6 only; IPv4Address has no such attribute. fec0::/10 is deprecated
        # (RFC 3879) but existing deployments were explicitly allowed to keep
        # using it, and Python reports it as global, private=False,
        # reserved=False -- so nothing else here rejects it.
        or getattr(ip, "is_site_local", False)
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

    # A trailing dot is the same name to a resolver and a different string to
    # anything comparing hostnames, so it is a way to spell one destination
    # twice. Refused rather than normalised: a target's URL should say what it
    # means.
    if host.endswith("."):
        raise DestinationRefused("a trailing dot in the destination host is not permitted")

    # Non-ASCII resolves through IDNA, so the name that is validated and the
    # name that is connected to can differ in ways nobody reading the config
    # would expect.
    try:
        host.encode("ascii")
    except UnicodeEncodeError as exc:
        raise DestinationRefused("a non-ASCII destination host is not permitted") from exc

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
        # Underscore folds to hyphen before either comparison. `Idempotency_Key`
        # is a DIFFERENT field from `Idempotency-Key` under HTTP, so it does not
        # collide on the wire -- but CGI and WSGI gateways canonicalise hyphens
        # to underscores before the application sees anything, so the receiving
        # application reads one HTTP_IDEMPOTENCY_KEY holding both values. A
        # receiver that takes the first is back to a configured token deciding
        # idempotency for a disclosure this server thinks it owns.
        canonical = name.lower().replace("_", "-")
        if canonical in _FORBIDDEN_HEADERS:
            raise DestinationRefused(f"header {name!r} is not permitted")
        if canonical in _SERVER_OWNED_HEADERS:
            raise DestinationRefused(f"header {name!r} is set by this server and cannot be configured")
        if not name or any(c not in _TOKEN_CHARS for c in name):
            raise DestinationRefused(f"header name {name!r} is not a valid HTTP token")
        # Every control character, not just CR, LF and NUL: the others are no
        # more meaningful in a header value and some proxies act on them.
        if any(ord(c) < 0x20 or ord(c) == 0x7F for c in value):
            raise DestinationRefused("a control character in a header value")
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
    #: The client is NOT closed here. Cleanup is the caller's, as its own task
    #: with its own budget and its own cancellation-resistant join -- closing it
    #: inside the submission would put an unbounded await inside a cancellable
    #: region, where a cancellation can interrupt it and leak the connection.
    closer: Any = None


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
    max_request_bytes: int = 8 * 1024 * 1024,
    max_response_bytes: int = 64 * 1024,
) -> SendResult:
    """One request to one validated destination, reporting what it observed.

    The deadline is an outer monotonic bound around the whole submission.
    httpx's connect, write, read and pool timeouts are per-operation and
    inactivity timeouts, not a wall clock: several addresses multiply the
    connect bound, and a peer dripping bytes just under the read timeout stays
    alive indefinitely.
    """
    if len(body) > max_request_bytes:
        # Before anything is connected: a payload that cannot be sent should not
        # cost a connection to the destination.
        return SendResult(phase="not_started", error="PayloadTooLarge")

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
    except BaseException as exc:
        # Once a final status is observed the attempt is settled from it. A
        # deadline firing during the body drain arrives here as a TimeoutError
        # -- and CancelledError is a BaseException, so it does not even reach
        # the inner handler -- and overwriting the phase would turn a receiver
        # response we actually saw into `indeterminate`.
        if result.phase != "headers_received":
            result.phase = backend.phase
            result.peer = backend.peer
        result.error = result.error or type(exc).__name__
        if isinstance(exc, BaseException) and not isinstance(exc, Exception):
            # Genuine cancellation is not ours to swallow.
            raise
    result.closer = client.aclose
    return result
