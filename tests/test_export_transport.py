"""Sending one content payload to one destination, safely.

An admin-configured URL becomes a request this server makes on demand, driven by
a credential that may belong to someone else. That is a server-side fetch
primitive, and every control here exists so it does not become one.
"""

from __future__ import annotations

import asyncio
import ipaddress
from unittest.mock import patch

import pytest

from app.services.export_transport import (
    DestinationRefused,
    SendResult,
    state_for_phase,
    validate_destination,
    validate_headers,
)
from app.services.nat64 import parse_pref64

#: An explicit "no NAT64 translation is reachable" declaration.
#:
#: Every pre-existing case uses this rather than an unset posture. Unset is
#: deliberately fail-closed, so passing it here would make each refusal
#: assertion pass because of the new interlock -- before the URL shape,
#: resolver, or address-policy behaviour the case actually names ever runs.
_NONE = parse_pref64("none")


@pytest.mark.parametrize(
    "url,why",
    [
        ("http://example.com/hook", "scheme"),
        ("ftp://example.com/hook", "scheme"),
        ("//example.com/hook", "scheme"),
        ("https://user:pw@example.com/hook", "userinfo"),
        ("https://user@example.com/hook", "userinfo"),
        ("https://example.com/hook#frag", "fragment"),
        ("https://example.com:8443/hook", "port"),
        ("https://example.com:80/hook", "port"),
    ],
)
def test_a_refused_url_shape_never_resolves(url, why, monkeypatch):
    """Refused before any name resolution, so a hostile URL cannot even make
    this server perform a DNS lookup of the attacker's choosing.

    The spy is the point. Without it these cases pass whether or not the guard
    exists, because an unresolvable host raises DestinationRefused anyway -- and
    removing the userinfo check left all eight green.
    """
    import app.services.export_transport as t

    def _must_not_resolve(host, port):
        raise AssertionError(f"resolved {host!r}: the shape check did not refuse first")

    monkeypatch.setattr(t, "_resolve", _must_not_resolve)
    with pytest.raises(DestinationRefused):
        validate_destination(url, _NONE)


#: Every entry in the IANA IPv4 and IPv6 Special-Purpose Address Registries
#: marked ``Globally Reachable = False``, transcribed from the registry CSVs
#: (iana-ipv4-special-registry-1.csv and iana-ipv6-special-registry-1.csv,
#: fetched 2026-08-19), plus the deprecated site-local range, which predates
#: the registry's reachability column.
#:
#: Transcribed rather than fetched: a test that reaches the network to decide
#: what to assert fails for reasons that have nothing to do with this server.
#: The cost is that this list ages, so it records where it came from.
#:
#: Nested entries are listed in their own right even where a broader block
#: already covers them. That is the point of them being here: sampling the
#: edges of 192.0.0.0/24 never touches 192.0.0.8, and forcing that one address
#: public survived the whole transport suite when only the broad block was
#: listed.
#:
#: What this asserts is that the SAMPLED addresses are refused, not that every
#: address under every prefix is. The registry itself has non-global parents
#: with globally reachable children -- 2001:1::1 is inside 2001::/23 -- so the
#: stronger claim would be false about the registry, never mind the code.
_NOT_GLOBALLY_REACHABLE = [
    ("0.0.0.0/8", "this network"),
    ("0.0.0.0/32", "this host on this network"),
    ("10.0.0.0/8", "private use"),
    ("100.64.0.0/10", "shared address space, RFC 6598 -- CGNAT and Tailscale"),
    ("127.0.0.0/8", "loopback"),
    ("169.254.0.0/16", "link local, includes the cloud metadata address"),
    ("172.16.0.0/12", "private use"),
    ("192.0.0.0/24", "IETF protocol assignments"),
    ("192.0.0.0/29", "IPv4 service continuity prefix"),
    ("192.0.0.8/32", "IPv4 dummy address"),
    ("192.0.0.170/32", "NAT64/DNS64 discovery"),
    ("192.0.0.171/32", "NAT64/DNS64 discovery"),
    ("192.0.2.0/24", "documentation, TEST-NET-1"),
    ("192.88.99.2/32", "6a44 relay anycast"),
    ("192.168.0.0/16", "private use"),
    ("198.18.0.0/15", "benchmarking"),
    ("198.51.100.0/24", "documentation, TEST-NET-2"),
    ("203.0.113.0/24", "documentation, TEST-NET-3"),
    ("240.0.0.0/4", "reserved"),
    ("255.255.255.255/32", "limited broadcast"),
    ("::/128", "unspecified"),
    ("::1/128", "loopback"),
    ("::ffff:0.0.0.0/96", "IPv4-mapped -- see the deliberate deviation below"),
    ("64:ff9b:1::/48", "local-use IPv4/IPv6 translation, RFC 8215"),
    ("100::/64", "discard only"),
    ("100:0:0:1::/64", "dummy IPv6 prefix"),
    ("2001::/23", "IETF protocol assignments"),
    ("2001:2::/48", "benchmarking"),
    ("2001:db8::/32", "documentation"),
    ("3fff::/20", "documentation, RFC 9637"),
    ("5f00::/16", "segment routing SIDs"),
    ("fc00::/7", "unique local"),
    ("fe80::/10", "link-local unicast"),
    # Not in the registry's reachability column at all: deprecated by RFC 3879,
    # which explicitly left existing deployments using it. This runtime reports
    # it global, not private and not reserved, so nothing generic rejects it.
    ("fec0::/10", "site local, deprecated"),
]


def _samples(cidr):
    net = ipaddress.ip_network(cidr)
    out = [net.network_address, net.broadcast_address]
    if net.num_addresses > 2:
        out.append(net.network_address + 1)
    return out


@pytest.mark.parametrize(
    "literal",
    [
        pytest.param(
            f"[{addr}]" if addr.version == 6 else str(addr),
            id=f"{cidr}-{addr}",
        )
        for cidr, _why in _NOT_GLOBALLY_REACHABLE
        for addr in _samples(cidr)
    ],
)
def test_a_non_public_address_literal_is_refused(literal, monkeypatch):
    """Every prefix the registry marks unreachable, sampled at its edges.

    Not "every address in that space": the registry itself nests globally
    reachable children under unreachable parents -- 2001:1::1 sits inside
    2001::/23 -- so that claim would be false about the registry before it was
    false about the code.

    A negative rule ("not private, not reserved") is the wrong shape for this
    question: it admitted 100.64.0.0/10, which is carrier-grade NAT space and
    the range Tailscale hands out. A positive rule alone is also wrong -- this
    runtime calls 224.0.0.1 global, because it is globally *scoped* multicast.
    Hence both, plus an explicit list for what the runtime's own tables place
    on the wrong side.
    """
    import app.services.export_transport as t

    # A literal still goes through getaddrinfo, which returns it unchanged; the
    # stub keeps the test off the network without changing what is checked.
    monkeypatch.setattr(t, "_resolve", lambda host, port: [host.strip("[]")])
    with pytest.raises(DestinationRefused):
        validate_destination(f"https://{literal}/hook", _NONE)


@pytest.mark.parametrize(
    "literal,why",
    [
        ("224.0.0.1", "globally scoped multicast: this runtime calls it is_global"),
        ("[ff02::1]", "link-local multicast"),
        ("[::ffff:127.0.0.1]", "loopback wearing an IPv6 hat"),
        ("[::ffff:10.0.0.1]", "private, mapped"),
        ("[::ffff:100.64.0.1]", "shared address space, mapped"),
        ("[64:ff9b::808:808]", "NAT64 well-known prefix: refused as a matter of policy"),
        ("[2002:808:808::1]", "6to4 wrapping a public v4 address"),
        ("[::8.8.8.8]", "IPv4-compatible IPv6, deprecated"),
    ],
)
def test_an_address_that_wears_a_disguise_is_refused(literal, why, monkeypatch):
    """Forms that carry another address family, or another scope, inside them."""
    import app.services.export_transport as t

    monkeypatch.setattr(t, "_resolve", lambda host, port: [host.strip("[]")])
    with pytest.raises(DestinationRefused):
        validate_destination(f"https://{literal}/hook", _NONE)


@pytest.mark.parametrize(
    "literal,accepted,why",
    [
        # IANA marks the whole IPv4-mapped block non-global, and this refuses
        # every mapped address whose embedded IPv4 is non-public -- but it
        # accepts one whose embedded IPv4 is public, because it normalises and
        # re-checks rather than judging the wrapper. The wrapper is not the
        # destination; the address inside it is.
        ("[::ffff:8.8.8.8]", True, "mapped, public inside"),
        ("[::ffff:10.0.0.1]", False, "mapped, private inside"),
        # IANA marks the NAT64 well-known prefix globally reachable, and RFC
        # 6052 requires it to carry only global IPv4. Refused anyway: see the
        # policy note in export_transport, which also records what this cannot
        # see -- an operator's own translation prefix.
        ("[64:ff9b::808:808]", False, "NAT64 well-known prefix, refused as policy"),
        # IANA marks ORCHIDv2 globally reachable. RFC 7343 addresses are
        # cryptographic identifiers rather than destinations, so this refuses
        # them; the registry's column is not the whole question.
        ("[2001:20::1]", False, "ORCHIDv2, refused as policy"),
        # The one that is NOT a decision. IANA marks the DNS-SD Service
        # Registration Protocol anycast address globally reachable; every
        # supported Python reports it is_private, so the general rule refuses
        # it and no policy here says anything about it. Pinned so that a
        # runtime correcting its table shows up as a failing test rather than
        # a silent change in what this server will connect to. Accepting it
        # would also be defensible -- it is an anycast service address, not a
        # webhook receiver -- which is exactly why the change should be
        # noticed and decided rather than inherited.
        ("[2001:1::3]", False, "DNS-SD SRP anycast: refused by the runtime's table, not by policy"),
    ],
)
def test_the_places_this_policy_and_the_registry_disagree(literal, accepted, why, monkeypatch):
    """Stated, not buried.

    Four prefixes get an answer the IANA reachability column would not give on
    its own. Three are deliberate choices; the fourth is inherited from the
    runtime's tables and is labelled as such, because "we decided this" and "we
    happened to get this" are different claims and only one of them should be
    made by a comment. Writing them down here is what stops the table above
    quietly claiming to be the registry.
    """
    import app.services.export_transport as t

    monkeypatch.setattr(t, "_resolve", lambda host, port: [host.strip("[]")])
    if accepted:
        host, port, addrs = validate_destination(f"https://{literal}/hook", _NONE)
        assert addrs == [literal.strip("[]")]
    else:
        with pytest.raises(DestinationRefused):
            validate_destination(f"https://{literal}/hook", _NONE)


def test_a_public_destination_is_accepted(monkeypatch):
    import app.services.export_transport as t

    monkeypatch.setattr(t, "_resolve", lambda host, port: ["93.184.216.34"])
    host, port, addrs = validate_destination("https://example.com/hook", _NONE)
    assert (host, port, addrs) == ("example.com", 443, ["93.184.216.34"])


def test_every_resolved_address_is_checked_not_just_the_first(monkeypatch):
    """A name answering with one public and one private address would otherwise
    pass on the first."""
    import app.services.export_transport as t

    monkeypatch.setattr(t, "_resolve", lambda host, port: ["93.184.216.34", "10.0.0.1"])
    with pytest.raises(DestinationRefused):
        validate_destination("https://example.com/hook", _NONE)


def test_a_name_that_resolves_to_nothing_is_refused(monkeypatch):
    import app.services.export_transport as t

    monkeypatch.setattr(t, "_resolve", lambda host, port: [])
    with pytest.raises(DestinationRefused):
        validate_destination("https://example.com/hook", _NONE)


def test_a_resolution_failure_is_refused_not_raised(monkeypatch):
    import app.services.export_transport as t

    def _boom(host, port):
        raise OSError("no such name")

    monkeypatch.setattr(t, "_resolve", _boom)
    with pytest.raises(DestinationRefused):
        validate_destination("https://example.com/hook", _NONE)


@pytest.mark.parametrize(
    "headers",
    [
        {"Host": "elsewhere"},
        {"host": "elsewhere"},  # case-insensitive
        {"Content-Length": "0"},
        {"Connection": "close"},
        {"Transfer-Encoding": "chunked"},
        {"Proxy-Authorization": "x"},
        {"X-Bad": "a\r\nInjected: 1"},  # response splitting
        {"X-Bad\n": "v"},
        {"X-Bad": "a\x00b"},
        {"X-Bad": 5},
    ],
)
def test_a_refused_header_is_refused(headers):
    with pytest.raises(DestinationRefused):
        validate_headers(headers)


def test_validated_headers_are_a_copy():
    """The persisted target config is never mutated; the existing webhook sender
    does exactly that with setdefault."""
    original = {"X-Api-Key": "secret"}
    out = validate_headers(original)
    out["X-Added"] = "1"
    assert original == {"X-Api-Key": "secret"}


def test_the_phase_decides_the_outcome_not_the_exception_class():
    """Class alone cannot establish whether request bytes were written -- with a
    pooled connection, a failure found while checking a stale one does not say
    that. The phase does."""
    assert state_for_phase(SendResult(phase="not_started")) == "failed"
    assert state_for_phase(SendResult(phase="connection_acquired")) == "failed"
    # Bytes may have arrived. Never guess `failed`: that under-reports
    # disclosure, and this is the one step where content leaves.
    assert state_for_phase(SendResult(phase="request_started")) == "indeterminate"
    for ok in (200, 201, 202, 204, 299):
        assert state_for_phase(SendResult(phase="headers_received", status=ok)) == "succeeded"
    # With redirects disabled a 3xx is not success merely for being below 400,
    # which is what the existing webhook sender assumes.
    for bad in (100, 301, 302, 400, 404, 500, 503):
        assert state_for_phase(SendResult(phase="headers_received", status=bad)) == "failed"


def test_an_unknown_phase_is_indeterminate():
    # Cannot arise -- the phase is set by our own sender -- but if it ever does,
    # the conservative direction is the one that does not under-report
    # disclosure.
    assert state_for_phase(SendResult(phase="something-new")) == "indeterminate"


def test_the_socket_goes_to_the_pinned_address_while_tls_uses_the_hostname(tmp_path):
    """The property the whole pinning design rests on.

    httpcore's connect_tcp(host, port) and start_tls(ctx, server_hostname) are
    separate calls, so the socket can go to a validated address while SNI and
    certificate verification still use the name. If they were one call, pinning
    would mean disabling verification.
    """
    import asyncio
    import ssl
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    cert = tmp_path / "cert.pem"
    key = tmp_path / "key.pem"
    # A name that NEVER resolves: .invalid is reserved for exactly this. If the
    # backend connected by hostname instead of by pinned address, DNS would fail
    # and the request could not happen at all -- which is what makes this prove
    # the pin rather than coincide with it.
    _self_signed(cert, key, "pinned.invalid")

    seen: dict = {}

    class _Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            seen["body"] = self.rfile.read(int(self.headers["Content-Length"]))
            self.send_response(204)
            self.end_headers()

        def log_message(self, *args):
            pass

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()

    client_ctx = ssl.create_default_context(cafile=str(cert))

    async def _go():
        import app.services.export_transport as t

        # A certificate valid for "localhost", connected to 127.0.0.1 by pin.
        original = httpx.create_ssl_context
        httpx.create_ssl_context = lambda *a, **k: client_ctx  # type: ignore[assignment]
        try:
            return await t.send_payload(
                url=f"https://pinned.invalid:{port}/hook",
                headers={},
                body=b'{"a":1}',
                addresses=["127.0.0.1"],
                deadline_seconds=10,
            )
        finally:
            httpx.create_ssl_context = original  # type: ignore[assignment]

    import httpx

    result = asyncio.run(_go())
    server.shutdown()

    assert result.phase == "headers_received", result.error
    assert result.status == 204
    assert result.peer == "127.0.0.1", "the socket did not go to the pinned address"
    assert seen["body"] == b'{"a":1}'


def _self_signed(cert_path, key_path, hostname):
    """A throwaway certificate for the hostname, so verification is real."""
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )


@pytest.mark.parametrize("host", ["example.com.", "exämple.com", "xn--exmple-cua.com."])
def test_a_hostname_spelling_that_means_the_same_destination_is_refused(host, monkeypatch):
    """A trailing dot resolves the same and compares differently; a non-ASCII
    name resolves through IDNA, so the name validated and the name connected to
    can differ."""
    import app.services.export_transport as t

    monkeypatch.setattr(t, "_resolve", lambda h, p: ["93.184.216.34"])
    with pytest.raises(DestinationRefused):
        validate_destination(f"https://{host}/hook", _NONE)


@pytest.mark.parametrize(
    "headers",
    [
        {"Keep-Alive": "timeout=5"},
        {"Proxy-Authenticate": "Basic"},
        {"Expect": "100-continue"},
        {"X Bad": "v"},  # space is not a token character
        {"X:Bad": "v"},
        {"": "v"},
        {"X-Bad": "a\x01b"},  # a control character that is not CR, LF or NUL
        {"X-Bad": "a\x7fb"},  # DEL
    ],
)
def test_more_refused_headers(headers):
    with pytest.raises(DestinationRefused):
        validate_headers(headers)


def test_a_body_over_the_bound_never_opens_a_connection():
    """A payload that cannot be sent should not cost a connection."""
    import asyncio

    from app.services.export_transport import send_payload

    result = asyncio.run(
        send_payload(
            url="https://pinned.invalid/hook",
            headers={},
            body=b"x" * 100,
            addresses=["203.0.113.1"],
            deadline_seconds=5,
            max_request_bytes=10,
        )
    )
    assert result.phase == "not_started"
    assert result.error == "PayloadTooLarge"
    assert state_for_phase(result) == "failed"


def test_a_deadline_during_the_body_drain_keeps_the_status_already_observed():
    """Headers settle the attempt. Overwriting the phase on a drain timeout
    would turn a receiver response we actually saw into `indeterminate`, which
    over-reports uncertainty in the direction that hides a disclosure."""
    import asyncio
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    import app.services.export_transport as t

    stop = threading.Event()

    class _Dripper(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_POST(self):
            self.rfile.read(int(self.headers["Content-Length"]))
            # 200, not 204: a 204 has no body by definition, so httpx never
            # reads one and there is nothing to time out draining. An earlier
            # version used 204 and the test passed in 0.13s without ever
            # exercising the path it names.
            self.send_response(200)
            self.send_header("Content-Length", "1000")
            self.end_headers()
            # Headers are out; the body never finishes.
            self.wfile.write(b"x")
            self.wfile.flush()
            stop.wait(5)

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), _Dripper)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()

    async def _go():
        # Plain HTTP through the same sender: validate_destination refuses http,
        # but send_payload is being exercised directly here for its phase
        # behaviour, not its URL policy.
        return await t.send_payload(
            url=f"http://127.0.0.1:{port}/hook",
            headers={},
            body=b"{}",
            addresses=["127.0.0.1"],
            deadline_seconds=0.5,
        )

    try:
        result = asyncio.run(_go())
    finally:
        stop.set()
        server.shutdown()

    assert result.error is not None, "the drain did not time out, so this proves nothing"
    assert result.phase == "headers_received", "a drain timeout discarded the observed status"
    assert result.status == 200
    assert state_for_phase(result) == "succeeded"


def test_the_sender_does_not_follow_a_redirect():
    """With redirects disabled a 3xx is the receiver's answer, not a hop. A
    redirect to a private address would otherwise defeat every address check."""
    import asyncio
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    import app.services.export_transport as t

    followed: list[str] = []

    class _Redirector(BaseHTTPRequestHandler):
        def do_POST(self):
            followed.append(self.path)
            self.send_response(302)
            self.send_header("Location", "http://169.254.169.254/latest/meta-data/")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), _Redirector)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()

    async def _go():
        return await t.send_payload(
            url=f"http://127.0.0.1:{port}/hook",
            headers={},
            body=b"{}",
            addresses=["127.0.0.1"],
            deadline_seconds=5,
        )

    try:
        result = asyncio.run(_go())
    finally:
        server.shutdown()

    assert followed == ["/hook"], "the redirect was followed"
    assert result.status == 302
    # Below 400 but not success: the existing webhook sender assumes otherwise.
    assert state_for_phase(result) == "failed"


def test_a_refused_connection_is_failed_not_indeterminate():
    """No request bytes were written, so this is definitely-not-delivered."""
    import asyncio
    import socket

    import app.services.export_transport as t

    # A port nothing is listening on.
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    dead_port = probe.getsockname()[1]
    probe.close()

    result = asyncio.run(
        t.send_payload(
            url=f"http://127.0.0.1:{dead_port}/hook",
            headers={},
            body=b"{}",
            addresses=["127.0.0.1"],
            deadline_seconds=5,
        )
    )
    assert result.phase == "not_started"
    assert state_for_phase(result) == "failed"


def test_several_addresses_are_tried_in_the_validated_order():
    """Failing over is not a second resolution: the set was fixed before the
    first connect, so a name answering differently later cannot enter it.

    The connect is stubbed rather than aimed at a real unreachable address:
    whether an OS refuses or silently drops a connection to an unbound loopback
    alias varies, and this is a test of the loop, not of the network stack.
    """
    import asyncio

    import httpcore

    from app.services.export_transport import PinnedBackend

    attempted: list[str] = []

    async def _fake_connect(self, host, port, timeout=None, local_address=None, socket_options=None):
        attempted.append(host)
        if host != "203.0.113.2":
            raise OSError("refused")
        return object()  # stands in for a stream; the wrapper only holds it

    async def _go():
        backend = PinnedBackend(["203.0.113.1", "203.0.113.2", "203.0.113.3"])
        original = httpcore.AnyIOBackend.connect_tcp
        httpcore.AnyIOBackend.connect_tcp = _fake_connect
        try:
            await backend.connect_tcp("example.com", 443)
        finally:
            httpcore.AnyIOBackend.connect_tcp = original
        return backend

    backend = asyncio.run(_go())

    assert attempted == ["203.0.113.1", "203.0.113.2"], "not tried in the validated order"
    assert "example.com" not in attempted, "connected by hostname instead of by pinned address"
    assert backend.peer == "203.0.113.2"
    assert backend.phase == "connection_acquired"


def test_every_address_failing_raises_rather_than_connecting_by_name():
    import asyncio

    import httpcore

    from app.services.export_transport import PinnedBackend

    attempted: list[str] = []

    async def _always_fail(self, host, port, timeout=None, local_address=None, socket_options=None):
        attempted.append(host)
        raise OSError("refused")

    async def _go():
        backend = PinnedBackend(["203.0.113.1", "203.0.113.2"])
        original = httpcore.AnyIOBackend.connect_tcp
        httpcore.AnyIOBackend.connect_tcp = _always_fail
        try:
            with pytest.raises(OSError):
                await backend.connect_tcp("example.com", 443)
        finally:
            httpcore.AnyIOBackend.connect_tcp = original
        return backend

    backend = asyncio.run(_go())
    assert attempted == ["203.0.113.1", "203.0.113.2"]
    assert backend.phase == "not_started", "a failed connect claimed a connection"


@pytest.mark.parametrize(
    "headers",
    [
        {"idempotency-key": "attacker-chosen"},
        {"Idempotency-Key": "attacker-chosen"},
        {"IDEMPOTENCY-KEY": "attacker-chosen"},
        {"IdEmPoTeNcY-kEy": "attacker-chosen"},
        {"Idempotency_Key": "attacker-chosen"},
        {"IDEMPOTENCY_KEY": "attacker-chosen"},
        {"idempotency_key": "attacker-chosen"},
        {"content-type": "text/plain"},
        {"Content-Type": "text/plain"},
        {"CONTENT-TYPE": "text/plain"},
        {"cOnTeNt-TyPe": "text/plain"},
        {"Content_Type": "text/plain"},
        # Hop-by-hop names alias the same way.
        {"Content_Length": "0"},
        {"Transfer_Encoding": "chunked"},
        {"Proxy_Authorization": "Basic x"},
        {"Keep_Alive": "timeout=5"},
    ],
)
def test_a_header_this_server_sets_itself_cannot_be_configured(headers):
    """In any spelling. HTTP field names are case-insensitive and dict keys are
    not, so a configured variant does not overwrite the server's value -- it
    travels alongside it (see the test below for the proof)."""
    with pytest.raises(DestinationRefused):
        validate_headers(headers)


def test_a_case_variant_header_would_otherwise_reach_the_wire_twice():
    """Why the reservation above exists, checked against the real client.

    This asserts the hazard, not a guard: if httpx ever collapsed case-variant
    field names on its own, this test fails and the reservation's stated
    rationale is no longer true. Nothing in production sends unvalidated
    headers -- the route validates before it sends.
    """
    import asyncio
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    import app.services.export_transport as t

    seen: list[list[str]] = []

    class _Echo(BaseHTTPRequestHandler):
        def do_POST(self):
            seen.append(self.headers.get_all("Idempotency-Key") or [])
            self.send_response(204)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), _Echo)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()

    async def _go():
        return await t.send_payload(
            url=f"http://127.0.0.1:{port}/hook",
            headers={"idempotency-key": "attacker-chosen", "Idempotency-Key": "server-owned"},
            body=b"{}",
            addresses=["127.0.0.1"],
            deadline_seconds=5,
        )

    try:
        result = asyncio.run(_go())
    finally:
        server.shutdown()

    if result.closer is not None:
        asyncio.run(result.closer())

    assert seen, "the receiver was never reached, so this proves nothing"
    assert len(seen[0]) == 2, (
        f"expected both spellings on the wire, saw {seen[0]!r}; if this client now "
        "collapses them, the reservation in _SERVER_OWNED_HEADERS needs a new rationale"
    )
    assert "attacker-chosen" in seen[0]


def test_an_underscore_alias_would_otherwise_merge_at_the_gateway():
    """Why the underscore fold exists, checked against a real WSGI gateway.

    `Idempotency_Key` and `Idempotency-Key` are distinct HTTP fields and both
    reach the wire intact. The collision happens one layer further in: CGI and
    WSGI map both to the same environ key, so the receiving application reads a
    single value containing both. This asserts the hazard, not a guard --
    nothing in production sends unvalidated headers.
    """
    import asyncio
    import threading
    from wsgiref.simple_server import WSGIRequestHandler, make_server

    import app.services.export_transport as t

    seen: list[str] = []

    def _app(environ, start_response):
        environ["wsgi.input"].read(int(environ.get("CONTENT_LENGTH") or 0))
        seen.append(environ.get("HTTP_IDEMPOTENCY_KEY", ""))
        start_response("204 No Content", [("Content-Length", "0")])
        return [b""]

    class _Quiet(WSGIRequestHandler):
        def log_message(self, *args):
            pass

    server = make_server("127.0.0.1", 0, _app, handler_class=_Quiet)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()

    async def _go():
        return await t.send_payload(
            url=f"http://127.0.0.1:{port}/hook",
            # BOTH, which is the whole point: an earlier version sent only
            # the underscore form and asserted it arrived, which shows nothing
            # about a merge. The collision is two spellings becoming one value.
            headers={"Idempotency_Key": "configured", "Idempotency-Key": "server-owned"},
            body=b"{}",
            addresses=["127.0.0.1"],
            deadline_seconds=5,
        )

    try:
        result = asyncio.run(_go())
    finally:
        server.shutdown()

    if result.closer is not None:
        asyncio.run(result.closer())

    assert seen, "the receiver was never reached, so this proves nothing"
    assert seen[0] == "configured,server-owned", (
        f"the gateway did not merge the two spellings into one value (saw {seen[0]!r}); if "
        "gateways no longer do this, the underscore fold needs a new rationale"
    )


def test_a_cancellation_during_submission_still_closes_the_client():
    """The connection carrying the content is not abandoned by a cancellation.

    This is the one cleanup path the route cannot own. Everywhere else the
    sender returns a SendResult whose `closer` the route joins and drains --
    but a cancellation mid-submission propagates an exception instead, so there
    is no result and no closer. If the sender did not close here, nothing else
    ever would.
    """
    import asyncio

    import app.services.export_transport as t

    closed = asyncio.Event()
    sending = asyncio.Event()

    class _Client:
        def build_request(self, *args, **kwargs):
            return object()

        async def send(self, request, stream=False):
            sending.set()
            await asyncio.Event().wait()  # never completes; only cancellation ends this

        async def aclose(self):
            closed.set()

    async def _go():
        with patch.object(t.httpx, "AsyncClient", lambda **kwargs: _Client()):
            task = asyncio.create_task(
                t.send_payload(
                    url="https://pinned.invalid/hook",
                    headers={},
                    body=b"{}",
                    addresses=["203.0.113.1"],
                    deadline_seconds=30,
                )
            )
            await asyncio.wait_for(sending.wait(), 5)
            assert task.cancel() is True, "nothing live was cancelled, so this proves nothing"

            with pytest.raises(asyncio.CancelledError):
                await task

            # Asserted in the loop, before teardown could do it for us: the
            # close must already have happened by the time the cancellation
            # reaches the caller.
            assert closed.is_set(), (
                "the client was abandoned: a cancellation during submission left the "
                "connection carrying the content open"
            )

    asyncio.run(_go())


def test_a_cancellation_during_submission_does_not_wait_forever_to_close():
    """The close is bounded. A receiver that will not let go of the connection
    must not turn a cancellation into a hang."""
    import asyncio

    import app.services.export_transport as t

    sending = asyncio.Event()

    class _Client:
        def build_request(self, *args, **kwargs):
            return object()

        async def send(self, request, stream=False):
            sending.set()
            await asyncio.Event().wait()

        async def aclose(self):
            await asyncio.Event().wait()  # never returns

    async def _go():
        with patch.object(t, "CLOSE_BUDGET_SECONDS", 0.05):
            with patch.object(t.httpx, "AsyncClient", lambda **kwargs: _Client()):
                task = asyncio.create_task(
                    t.send_payload(
                        url="https://pinned.invalid/hook",
                        headers={},
                        body=b"{}",
                        addresses=["203.0.113.1"],
                        deadline_seconds=30,
                    )
                )
                await asyncio.wait_for(sending.wait(), 5)
                task.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await asyncio.wait_for(asyncio.shield(task), 5)

    asyncio.run(_go())


@pytest.mark.parametrize(
    "failure,expected",
    [
        ("raises", "RuntimeError"),
        ("hangs", "TimeoutError"),
        # A closer that raises CancelledError is not a budget expiry, and
        # must not be reported as one. A real expiry never reaches that
        # branch: asyncio.timeout converts its own cancellation into a
        # TimeoutError raised inside the task.
        ("cancels", "CancelledError"),
    ],
)
def test_a_close_that_does_not_confirm_is_reported_not_swallowed(failure, expected, caplog):
    """The honest half of the cancellation close.

    It is an attempt. If the client raises on close, or does not finish inside
    its budget, the connection may still be open -- and this path propagates an
    exception rather than a result, so there is no `closer` to hand back.

    The caller does hold a committed attempt row; the evidence goes to the log
    rather than onto that row because the row records the state of a
    DISCLOSURE, and whether a socket was confirmed shut is a fact about this
    process rather than about what the receiver got. An earlier version of this
    docstring justified logging by claiming no row existed, which is simply
    false: it is committed before the send.

    So a build that stops reporting is a build where an operator cannot know.
    """
    import asyncio
    import logging

    import app.services.export_transport as t

    sending = asyncio.Event()

    class _Client:
        def build_request(self, *args, **kwargs):
            return object()

        async def send(self, request, stream=False):
            sending.set()
            await asyncio.Event().wait()

        async def aclose(self):
            if failure == "raises":
                raise RuntimeError("the socket is gone")
            if failure == "cancels":
                raise asyncio.CancelledError("the closer was cancelled")
            await asyncio.Event().wait()

    async def _go():
        with patch.object(t, "CLOSE_BUDGET_SECONDS", 0.05):
            with patch.object(t.httpx, "AsyncClient", lambda **kwargs: _Client()):
                task = asyncio.create_task(
                    t.send_payload(
                        url="https://pinned.invalid/hook",
                        headers={},
                        body=b"{}",
                        addresses=["203.0.113.1"],
                        deadline_seconds=30,
                    )
                )
                await asyncio.wait_for(sending.wait(), 5)
                task.cancel("ORIGINAL")
                # Read off the task rather than awaited through shield() or
                # wait_for(): each of those constructs a fresh CancelledError,
                # discarding the very message this asserts on.
                finished, _still_running = await asyncio.wait({task}, timeout=5)
                assert finished, "the sender never returned, so this proves nothing"
                with pytest.raises(asyncio.CancelledError) as raised:
                    task.result()
                # The SAME cancellation, not merely some cancellation. A
                # replacement raised while reporting would satisfy the plain
                # form of this assertion and lose the caller's.
                assert raised.value.args == (
                    "ORIGINAL",
                ), f"the submission's cancellation was replaced: {raised.value.args!r}"

    with caplog.at_level(logging.WARNING):
        asyncio.run(_go())

    messages = [r.getMessage() for r in caplog.records]
    assert any(
        "not confirmed closed" in m for m in messages
    ), f"an unconfirmed close was silent; records were {messages!r}"
    assert any(expected in m for m in messages), f"the reason was not reported: {messages!r}"


@pytest.mark.parametrize("logger_raises", [RuntimeError("logger"), asyncio.CancelledError("LOGGER")])
def test_reporting_an_unconfirmed_close_cannot_replace_the_cancellation(logger_raises):
    """The report is about a cancellation; it must not become one.

    `safe_logging.report` is deliberately non-raising, but it catches only
    Exception -- and CancelledError is not one. An operator's logging Filter
    that raises it would otherwise substitute the logger's cancellation for the
    submission's, and the caller would be told the wrong thing was cancelled.
    Building the reason string sits inside the same guard, because
    type().__name__ runs before report() is entered.
    """
    import app.services.export_transport as t

    sending = asyncio.Event()

    class _Client:
        def build_request(self, *args, **kwargs):
            return object()

        async def send(self, request, stream=False):
            sending.set()
            await asyncio.Event().wait()

        async def aclose(self):
            raise RuntimeError("the socket is gone")

    class _HostileLogger:
        def warning(self, *args, **kwargs):
            raise logger_raises

    async def _go():
        with patch.object(t, "logger", _HostileLogger()):
            with patch.object(t.httpx, "AsyncClient", lambda **kwargs: _Client()):
                task = asyncio.create_task(
                    t.send_payload(
                        url="https://pinned.invalid/hook",
                        headers={},
                        body=b"{}",
                        addresses=["203.0.113.1"],
                        deadline_seconds=30,
                    )
                )
                await asyncio.wait_for(sending.wait(), 5)
                task.cancel("ORIGINAL")
                finished, _still_running = await asyncio.wait({task}, timeout=5)
                assert finished, "the sender never returned, so this proves nothing"
                with pytest.raises(asyncio.CancelledError) as raised:
                    task.result()
                assert raised.value.args == ("ORIGINAL",), (
                    f"the logger's failure replaced the submission's cancellation: " f"{raised.value.args!r}"
                )

    asyncio.run(_go())


# ---------------------------------------------------------------------------
# NAT64: the declared posture at the destination boundary
#
# An NSP is ordinary global IPv6, so `_is_public` accepts it while the local
# gateway translates it to an embedded IPv4 that may be internal. These bind
# the posture INSIDE the every-answer loop, not as a post-pass.
# ---------------------------------------------------------------------------


def _posture(*prefixes):
    return parse_pref64(",".join(prefixes))


# Twelve per-length boundary cases. Both halves matter: without the refusals a
# boundary omitting /40-/64 checking passes every decoder test, because the
# overlap case binds only /32 and /96. Without the acceptances a boundary that
# refuses EVERY Pref64-matching address passes all the refusals, and `none`
# accepting ordinary IPv6 proves nothing about a translated public IPv4.
_PRIVATE_EMBEDDED = [
    ("2600:1f00::/32", "2600:1f00:a01:203::"),  # -> 10.1.2.3
    ("2600:1f00:1200::/40", "2600:1f00:12ac:1063:7::"),  # -> 172.16.99.7
    ("2600:1f00:122::/48", "2600:1f00:122:7f00:0:100::"),  # -> 127.0.0.1
    ("2600:1f00:122:300::/56", "2600:1f00:122:3a9:fe:101::"),  # -> 169.254.1.1
    ("2600:1f00:122:344::/64", "2600:1f00:122:344:c0:a801:700:0"),  # -> 192.168.1.7
    ("2600:1f00:122:344::/96", "2600:1f00:122:344::a63:584d"),  # -> 10.99.88.77
]

_PUBLIC_EMBEDDED = [
    ("2600:1f00::/32", "2600:1f00:808:808::"),  # -> 8.8.8.8
    ("2600:1f00:1200::/40", "2600:1f00:1201:101:1::"),  # -> 1.1.1.1
    ("2600:1f00:122::/48", "2600:1f00:122:5db8:d8:2200::"),  # -> 93.184.216.34
    ("2600:1f00:122:300::/56", "2600:1f00:122:309:9:909::"),  # -> 9.9.9.9
    ("2600:1f00:122:344::/64", "2600:1f00:122:344:d0:43de:de00:0"),  # -> 208.67.222.222
    ("2600:1f00:122:344::/96", "2600:1f00:122:344::c709:ec9"),  # -> 199.9.14.201
]

# A matched address whose reserved octet is non-zero is REFUSED AT THE
# BOUNDARY, not skipped. The decoder returning None is only half the property:
# a caller doing `if embedded is None: continue` treats a malformed translation
# address as a non-match, and the generic predicate then accepts it because it
# is globally classified.
_BAD_U_OCTET = [
    ("2600:1f00::/32", "2600:1f00:a01:203:100::"),
    ("2600:1f00:1200::/40", "2600:1f00:12ac:1063:107::"),
    ("2600:1f00:122::/48", "2600:1f00:122:7f00:100:100::"),
    ("2600:1f00:122:300::/56", "2600:1f00:122:3a9:1fe:101::"),
    ("2600:1f00:122:344::/64", "2600:1f00:122:344:1c0:a801:700:0"),
]


@pytest.mark.parametrize("prefix,addr", _PRIVATE_EMBEDDED)
def test_a_translated_private_address_is_refused(monkeypatch, prefix, addr):
    import app.services.export_transport as t

    monkeypatch.setattr(t, "_resolve", lambda host, port: [addr])
    with pytest.raises(DestinationRefused):
        validate_destination("https://example.com/hook", _posture(prefix))


@pytest.mark.parametrize("prefix,addr", _PUBLIC_EMBEDDED)
def test_a_translated_public_address_is_accepted(monkeypatch, prefix, addr):
    import app.services.export_transport as t

    monkeypatch.setattr(t, "_resolve", lambda host, port: [addr])
    host, port, addresses = validate_destination("https://example.com/hook", _posture(prefix))
    assert addresses == [addr]


@pytest.mark.parametrize("prefix,addr", _BAD_U_OCTET)
def test_a_matched_address_with_a_non_zero_reserved_octet_is_refused(monkeypatch, prefix, addr):
    import app.services.export_transport as t

    monkeypatch.setattr(t, "_resolve", lambda host, port: [addr])
    with pytest.raises(DestinationRefused):
        validate_destination("https://example.com/hook", _posture(prefix))


def test_pref64_is_checked_on_every_answer_not_just_the_first(monkeypatch):
    """The first answer is public and outside every Pref64; a later one is not.

    The existing every-address test cannot catch a first-address-only check:
    its later answer is raw 10.0.0.1, which the unchanged generic loop already
    refuses. This one needs the Pref64 check to run on the later address.
    """
    import app.services.export_transport as t

    monkeypatch.setattr(t, "_resolve", lambda host, port: ["93.184.216.34", "2600:1f00:a01:203::"])
    with pytest.raises(DestinationRefused):
        validate_destination("https://example.com/hook", _posture("2600:1f00::/32"))


# Overlapping prefixes: decode under EVERY match and refuse if ANY
# interpretation is non-public. Longest-match would model the routing table,
# and the premise of this whole finding is that the declared posture and the
# actual routing may disagree.
_OVERLAP_ADDR = "2600:1f00:a00:1::808:808"  # 10.0.0.1 under /32, 8.8.8.8 under /96
_OVERLAP = ("2600:1f00::/32", "2600:1f00:a00:1::/96")


@pytest.mark.parametrize("order", [_OVERLAP, tuple(reversed(_OVERLAP))])
def test_overlapping_prefixes_refuse_under_any_interpretation(monkeypatch, order):
    """Longest-match ACCEPTS this address; any-match refuses it.

    A fixture that is public under /32 and private under /96 cannot tell them
    apart -- both rules refuse it, in either order.
    """
    import app.services.export_transport as t

    monkeypatch.setattr(t, "_resolve", lambda host, port: [_OVERLAP_ADDR])
    with pytest.raises(DestinationRefused):
        validate_destination("https://example.com/hook", _posture(*order))


def test_an_unset_posture_refuses_before_anything_else(monkeypatch):
    import app.services.export_transport as t

    monkeypatch.setattr(t, "_resolve", lambda host, port: ["93.184.216.34"])
    with pytest.raises(DestinationRefused, match="PREF64"):
        validate_destination("https://example.com/hook", parse_pref64(None))


def test_none_accepts_an_ordinary_public_address(monkeypatch):
    import app.services.export_transport as t

    monkeypatch.setattr(t, "_resolve", lambda host, port: ["2600:1f00:a00:1::808:808"])
    host, port, addresses = validate_destination("https://example.com/hook", _NONE)
    assert addresses == ["2600:1f00:a00:1::808:808"]


def test_an_address_outside_every_configured_prefix_is_untouched(monkeypatch):
    import app.services.export_transport as t

    monkeypatch.setattr(t, "_resolve", lambda host, port: ["2600:1f00::1"])
    host, port, addresses = validate_destination("https://example.com/hook", _posture("2001:db8::/32"))
    assert addresses == ["2600:1f00::1"]


@pytest.mark.parametrize(
    "addr",
    [a for _, a in _PRIVATE_EMBEDDED] + [a for _, a in _PUBLIC_EMBEDDED] + [a for _, a in _BAD_U_OCTET],
)
def test_every_nat64_fixture_is_globally_classified(addr):
    """Otherwise the refusal cases pass for the wrong reason.

    My first fixtures used 2001:db8::/32 -- IPv6 documentation space -- so the
    generic address predicate refused them before any Pref64 decoding ran.
    Twelve boundary cases were green while binding nothing about NAT64.
    """
    import app.services.export_transport as t

    assert t._is_public(addr), f"{addr} is refused by the generic predicate, not by Pref64"
