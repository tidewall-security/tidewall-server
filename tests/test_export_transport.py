"""Sending one content payload to one destination, safely.

An admin-configured URL becomes a request this server makes on demand, driven by
a credential that may belong to someone else. That is a server-side fetch
primitive, and every control here exists so it does not become one.
"""

from __future__ import annotations

import ipaddress

import pytest

from app.services.export_transport import (
    DestinationRefused,
    SendResult,
    state_for_phase,
    validate_destination,
    validate_headers,
)


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
        validate_destination(url)


#: Every entry in the IANA IPv4 and IPv6 Special-Purpose Address Registries
#: that is marked "Globally Reachable: False", plus the deprecated site-local
#: range. Sampled at the first, second and last address of each prefix so an
#: off-by-one at either edge is caught.
#:
#: The point of enumerating the whole set rather than a few interesting cases:
#: only three of these are actually admitted by a naive "not private and not
#: reserved" rule (100.64/10, 192.88.99/24 and fec0::/10, plus ORCHIDv2), and
#: which three depends on the runtime's tables. A runtime that moves an entry
#: out of is_reserved should fail a test, not silently open a hole.
_NOT_GLOBALLY_REACHABLE = [
    ("0.0.0.0/8", "this network"),
    ("10.0.0.0/8", "private"),
    ("100.64.0.0/10", "shared address space, RFC 6598 -- CGNAT and Tailscale"),
    ("127.0.0.0/8", "loopback"),
    ("169.254.0.0/16", "link local, includes the cloud metadata address"),
    ("172.16.0.0/12", "private"),
    ("192.0.0.0/24", "IETF protocol assignments"),
    ("192.0.2.0/24", "TEST-NET-1"),
    ("192.88.99.0/24", "6to4 relay anycast, deprecated by RFC 7526"),
    ("192.168.0.0/16", "private"),
    ("198.18.0.0/15", "benchmarking"),
    ("198.51.100.0/24", "TEST-NET-2"),
    ("203.0.113.0/24", "TEST-NET-3"),
    ("240.0.0.0/4", "reserved for future use"),
    ("255.255.255.255/32", "limited broadcast"),
    ("::/128", "unspecified"),
    ("::1/128", "loopback"),
    ("64:ff9b:1::/48", "local-use NAT64, RFC 8215"),
    ("100::/64", "discard only"),
    ("2001::/32", "Teredo"),
    ("2001:2::/48", "benchmarking"),
    ("2001:20::/28", "ORCHIDv2, RFC 7343 -- not routable at all"),
    ("2001:db8::/32", "documentation"),
    ("3fff::/20", "documentation, RFC 9637"),
    ("5f00::/16", "SRv6 SIDs"),
    ("fc00::/7", "unique local"),
    ("fe80::/10", "link local"),
    ("fec0::/10", "site local, deprecated by RFC 3879 but still deployed"),
    ("ff00::/8", "multicast"),
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
    """The whole not-globally-reachable space, not a selection from it.

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
        validate_destination(f"https://{literal}/hook")


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
        validate_destination(f"https://{literal}/hook")


def test_a_public_destination_is_accepted(monkeypatch):
    import app.services.export_transport as t

    monkeypatch.setattr(t, "_resolve", lambda host, port: ["93.184.216.34"])
    host, port, addrs = validate_destination("https://example.com/hook")
    assert (host, port, addrs) == ("example.com", 443, ["93.184.216.34"])


def test_every_resolved_address_is_checked_not_just_the_first(monkeypatch):
    """A name answering with one public and one private address would otherwise
    pass on the first."""
    import app.services.export_transport as t

    monkeypatch.setattr(t, "_resolve", lambda host, port: ["93.184.216.34", "10.0.0.1"])
    with pytest.raises(DestinationRefused):
        validate_destination("https://example.com/hook")


def test_a_name_that_resolves_to_nothing_is_refused(monkeypatch):
    import app.services.export_transport as t

    monkeypatch.setattr(t, "_resolve", lambda host, port: [])
    with pytest.raises(DestinationRefused):
        validate_destination("https://example.com/hook")


def test_a_resolution_failure_is_refused_not_raised(monkeypatch):
    import app.services.export_transport as t

    def _boom(host, port):
        raise OSError("no such name")

    monkeypatch.setattr(t, "_resolve", _boom)
    with pytest.raises(DestinationRefused):
        validate_destination("https://example.com/hook")


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
        validate_destination(f"https://{host}/hook")


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
            headers={"Idempotency_Key": "attacker-chosen"},
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
    assert "attacker-chosen" in seen[0], (
        f"the gateway did not merge the underscore alias (saw {seen[0]!r}); if that is "
        "now true of gateways generally, the underscore fold needs a new rationale"
    )
