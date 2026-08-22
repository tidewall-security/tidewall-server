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
import logging
import socket
import ssl
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

import httpcore
import httpx

from app.services.cancellation import join_and_drain
from app.services.nat64 import Pref64Posture, embedded_ipv4
from app.services.safe_logging import report

logger = logging.getLogger(__name__)

#: How long a client may take to close on the cancellation path. Bounded
#: because the cancellation behind it is already waiting on this.
CLOSE_BUDGET_SECONDS = 5.0

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

#: Prefixes refused by name, because the general rule below lets them through.
#:
#: Neither is as simple as "IANA says non-global", and an earlier version of
#: this comment claimed exactly that about both. What the registry actually
#: says, checked against the CSVs on 2026-08-19:
#:
#: - 192.88.99.0/24 carries no reachability value at all; it is marked
#:   deprecated (RFC 7526). Only the more specific 192.88.99.2/32, the 6a44
#:   relay anycast address, is marked not globally reachable. The whole /24 is
#:   refused here because a deprecated anycast prefix reaches whichever relay
#:   the local network happens to route it to, which is not a destination
#:   anyone configured.
#: - 2001:20::/28 is marked globally REACHABLE. It is refused anyway: ORCHIDv2
#:   addresses (RFC 7343) are cryptographic identifiers, not destinations, so
#:   a resolver answering with one is not describing somewhere to send content.
#:
#: Both are therefore policy, not transcription. The registry is a source, not
#: the rule.
_REFUSED_NETWORKS = (
    ipaddress.ip_network("192.88.99.0/24"),
    ipaddress.ip_network("2001:20::/28"),
)

#: NAT64, stated rather than implied.
#:
#: 64:ff9b::/96 (RFC 6052 well-known prefix) and 64:ff9b:1::/48 (RFC 8215
#: local use) are both refused: the first because this runtime marks it
#: reserved, the second because it is local by definition. Note that IANA
#: marks the well-known prefix globally reachable and RFC 6052 requires it to
#: carry only global IPv4, so refusing it is a conservative policy rather than
#: a classification -- a NAT64-only deployment cannot export through it and
#: needs an IPv4 or dual-stack route to its receiver.
#:
#: A Network-Specific Prefix is ordinary global IPv6, and the IPv4 address
#: behind it may be internal. No generic address-scope predicate WITHOUT
#: deployment prefix knowledge can detect that -- so `_refuse_translated_non_public`
#: is given the knowledge, from `PREF64`, and decodes RFC 6052 translation for
#: every matching prefix.
#:
#: The residual is now the declaration, not the absence of a control. This is
#: defeated by a `PREF64` that is false, incomplete, stale after a network
#: change, or mistyped into a different valid prefix, and by a translator that
#: does not follow RFC 6052. The posture is read once per application lifespan
#: and is not refreshed while it runs.
#:
#: `docs/operations/content-runbook.md` section 12 carries this for operators.

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


def validate_destination(url: str, posture: Pref64Posture) -> tuple[str, int, list[str]]:
    """Refuse a destination that fails the enumerated address policy.

    Every resolved address must pass the address policy below, and RFC 6052
    translation is checked against the deployment's DECLARED posture. This does
    NOT establish that the endpoint is public: address scope plus Pref64
    decoding cannot say where the host's effective routes send an ordinary
    global address, nor whether an internal service is deliberately numbered
    from global space.

    *posture* is required, not defaulted. A default is how this silently
    reverts.

    Returns the host, the port, and the ordered set of validated addresses. The
    connection is made to one of *those*, so a name that answers differently on a
    second lookup cannot rebind past this check.

    The URL shape is checked before resolving, so a hostile URL cannot even make
    this server perform a DNS lookup of the attacker's choosing.
    """
    # Unset is not a default, and this is checked FIRST -- before the URL is
    # even parsed. Nobody has declared this deployment's NAT64 posture, so the
    # claim this function makes cannot be evaluated at all, whatever the URL
    # says. Refusing here also means no resolution, reservation or send occurs.
    # release:component export_destination/posture_unset -- refuses before the URL is parsed
    if posture.is_unset:
        raise DestinationRefused(
            "content export requires this deployment's NAT64 posture: set PREF64 to "
            "the translation prefixes reachable from this server, or to the value "
            "meaning no NAT64 translation is reachable, once you have confirmed "
            "which is true for this network"
        )

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
    # private address would otherwise pass. NAT64 checking happens INSIDE this
    # loop, never as a post-pass over one selected address -- a post-pass over
    # addresses[0] passes every per-length, overlap and route case, because they
    # can all use a single resolved address.
    for addr in addresses:
        # release:component export_destination/generic_address_policy -- pre-existing scope check, every answer
        if not _is_public(addr):
            raise DestinationRefused("the destination resolves to a non-public address")
        _refuse_translated_non_public(addr, posture)
    return host, port, addresses


def _refuse_translated_non_public(addr: str, posture: Pref64Posture) -> None:
    """Refuse an address whose embedded IPv4 is not public, under ANY match.

    Every matching prefix is decoded, not the longest -- longest-match models
    the routing table, and the premise of this control is that the declared
    posture and the actual routing may disagree. Refusing on any non-public
    interpretation is order-independent and fails safe.
    """
    try:
        parsed = ipaddress.ip_address(addr)
    except ValueError:
        return
    if not isinstance(parsed, ipaddress.IPv6Address):
        return

    for prefix in posture.prefixes:
        if parsed not in prefix:
            continue
        embedded = embedded_ipv4(parsed, prefix)
        # release:component export_destination/malformed_translation -- refused, never treated as a non-match
        if embedded is None:
            # Matched a translation prefix but is not a well-formed RFC 6052
            # address. REFUSED, not skipped: `continue` here would treat a
            # malformed translated address as an ordinary global one, which is
            # exactly the shape that reaches an internal host.
            raise DestinationRefused(
                "the destination matches a configured NAT64 prefix but is not a " "well-formed translated address"
            )
        # release:component export_destination/embedded_address_policy -- decoded IPv4 re-checked, every prefix
        if not _is_public(str(embedded)):
            raise DestinationRefused(
                "the destination translates to a non-public address under a " "configured NAT64 prefix"
            )


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
    #: None whenever no client was ever built -- a payload over the size bound
    #: returns before anything is constructed, and there is nothing to close.
    #:
    #: Whenever this IS set, the client behind it is still open, and closing it
    #: is the caller's: its own task, its own budget, its own
    #: cancellation-resistant join. An unbounded plain await inside the
    #: submission would sit in a cancellable region where a cancellation can
    #: interrupt it and leak the connection.
    #:
    #: The one path that closes inside the submission is the one that returns
    #: no result at all: a cancellation mid-send propagates an exception, so
    #: there is no result for anyone to receive a closer on. That close is made
    #: bounded and cancellation-resistant precisely because of the hazard
    #: above.
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
        if not isinstance(exc, Exception):
            # Genuine cancellation is not ours to swallow -- but it is also not
            # a licence to abandon the client. Nothing downstream can clean up
            # here: the caller receives an exception, not a result, so there is
            # no `closer` for it to own. If this simply re-raised, a
            # cancellation landing mid-submission would leave the connection
            # that is carrying the content open for the process's lifetime.
            #
            # So a close is ATTEMPTED here, under the same protocol the route
            # uses for its own joins: its own task, bounded, joined through
            # shields so this second cancellation cannot abandon it either.
            # Then the original cancellation is re-propagated -- deferred by
            # exactly as long as closing one client takes, and no longer.
            #
            # An attempt, not a guarantee, and the difference is worth stating.
            # If aclose() raises, or does not finish inside the budget, the
            # connection may still be open and there is no one left to tell:
            # this path returns an exception rather than a result, so it has
            # no `closer` to hand back. The caller does hold a committed
            # attempt row -- an earlier version of this comment wrongly said no
            # row existed -- but that row records the state of a DISCLOSURE,
            # and whether a socket was confirmed shut is a fact about this
            # process rather than about what the receiver got. So it is
            # reported, not settled into evidence.
            close_errors: list[Exception] = []

            async def _close_bounded() -> None:
                async with asyncio.timeout(CLOSE_BUDGET_SECONDS):
                    await client.aclose()

            close_task = asyncio.create_task(_close_bounded())
            await join_and_drain(close_task, on_error=close_errors.append)
            try:
                if close_errors:
                    # A budget expiry arrives here, not below: asyncio.timeout
                    # converts its own cancellation into a TimeoutError raised
                    # inside the task, so the task completes rather than being
                    # cancelled.
                    reason: str | None = type(close_errors[0]).__name__
                elif close_task.cancelled():
                    # Which leaves only a closer that raised CancelledError
                    # itself. Labelling this "TimeoutError" -- as an earlier
                    # version did -- reports a bound that was never reached.
                    reason = "CancelledError"
                else:
                    reason = None
                if reason is not None:
                    report(
                        logger,
                        "warning",
                        f"content export client was not confirmed closed after a cancellation "
                        f"during submission ({reason}); the connection may remain open",
                    )
            except BaseException:
                # Reporting must not become the thing that propagates. report()
                # is deliberately non-raising but catches only Exception, and
                # CancelledError is not one: an operator's logging Filter that
                # raises it would otherwise REPLACE the cancellation being
                # re-raised below, so the caller would see the logger's
                # cancellation instead of the submission's. Building the reason
                # is inside this guard too, because type().__name__ runs before
                # report() is entered.
                pass
            raise
    result.closer = client.aclose
    return result
