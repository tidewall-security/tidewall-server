"""Outbound transport: the bytes actually submitted, and how many times.

Three things must be recorded at this boundary, and the third is the one that
is usually missing:

  1. THE SUBMITTED BODY BYTES -- what went on the wire, not what a caller
     handed to a client object. Serialisation happens in between;
  2. THE INVOCATION IDENTITY AND COUNT -- a retry is two calls, and a call
     that raised is still a call. Counting responses loses the failed one,
     which is the call most worth counting;
  3. A PRODUCER CONTROL -- proof the recorder would have SEEN an egress if one
     had occurred. Without it, "no outbound call carried the canary" is
     equally true of a recorder that was never attached, and that is the
     shape of a passing test that measures nothing.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field


class TransportNotObserved(Exception):
    """The producer control did not see its own deliberate egress."""


@dataclass(frozen=True)
class Invocation:
    """One outbound call, whether or not it produced a response."""

    method: str
    url: str
    body: bytes
    raised: str | None = None

    @property
    def identity(self) -> str:
        return f"{self.method.upper()} {self.url}"


@dataclass
class TransportRecorder:
    """Every outbound call, in order, including the ones that failed."""

    invocations: list[Invocation] = field(default_factory=list)

    def record(self, invocation: Invocation) -> None:
        self.invocations.append(invocation)

    @property
    def identities(self) -> list[str]:
        return [i.identity for i in self.invocations]

    def count(self, identity: str) -> int:
        return sum(1 for i in self.invocations if i.identity == identity)

    def bodies(self) -> list[bytes]:
        return [i.body for i in self.invocations]

    def carries(self, needle: bytes) -> list[Invocation]:
        return [i for i in self.invocations if needle in i.body]

    def verify_producer_control(self, sentinel: bytes) -> None:
        """Refuse unless a deliberate egress carrying `sentinel` was seen.

        This runs against the SAME recorder the real assertions use. A control
        with its own recorder proves the control's recorder works.
        """
        if not self.carries(sentinel):
            raise TransportNotObserved(
                "the producer control's own egress was not recorded, so an "
                "absence of outbound calls proves nothing here"
            )


@contextmanager
def recording_transport(client_module) -> TransportRecorder:
    """Record every request the module's httpx client sends.

    Patches the transport layer rather than the calling code, so retries,
    redirects and failures are all counted where they actually happen.
    """
    recorder = TransportRecorder()
    original = client_module.Client.send

    def send(self, request, **kwargs):
        body = request.read() if hasattr(request, "read") else b""
        try:
            response = original(self, request, **kwargs)
        except Exception as exc:
            recorder.record(
                Invocation(
                    method=request.method,
                    url=str(request.url),
                    body=body,
                    raised=type(exc).__name__,
                )
            )
            raise
        recorder.record(Invocation(method=request.method, url=str(request.url), body=body))
        return response

    client_module.Client.send = send
    try:
        yield recorder
    finally:
        client_module.Client.send = original
