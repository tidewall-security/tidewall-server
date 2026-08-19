"""Sending one content payload to one destination, safely.

An admin-configured URL becomes a request this server makes on demand, driven by
a credential that may belong to someone else. That is a server-side fetch
primitive, and every control here exists so it does not become one.
"""

from __future__ import annotations

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
def test_a_refused_url_shape_never_resolves(url, why):
    # Refused before any name resolution, so a hostile URL cannot even make this
    # server perform a DNS lookup of the attacker's choosing.
    with pytest.raises(DestinationRefused):
        validate_destination(url)


@pytest.mark.parametrize(
    "literal",
    [
        "127.0.0.1",
        "[::1]",
        "10.0.0.5",
        "192.168.1.1",
        "172.16.0.1",
        "169.254.169.254",  # cloud instance metadata
        "[fd00::1]",
        "[::ffff:127.0.0.1]",  # loopback wearing an IPv6 hat
        "0.0.0.0",
        "224.0.0.1",
    ],
)
def test_a_non_public_address_literal_is_refused(literal):
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
