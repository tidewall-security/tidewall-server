"""Where the vault is written, and the four ways to redact and not write it.

The mapping is saved at the point the response's disposition is settled, not at
the point the scan finishes. `fpe_context` is created after a successful
reconstruction and cleared again by a detector-failure block and by report-only,
so a save placed after the scan would store the placeholder-to-original mapping
-- the PII itself -- for requests that end up carrying no way to retrieve it.

The other direction matters just as much: a token whose vault was never written
promises a reversal that cannot happen. `/v1/unredact` refuses an empty vault,
so the caller does get an error rather than its own redacted text back, but the
promise was already made in the guard response and the data is already gone. So
a save that does not happen clears the token.

The read-path tests at the bottom go through `/v1/unredact` for the same reason
this file exists at all: the manager can classify a wrong key and an altered row
correctly and the route can still answer 404 to both.
"""

from __future__ import annotations

import base64
import json

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.auth.middleware import AuthMiddleware
from app.db.models import Policy
from app.db.models import Vault as VaultModel
from app.detectors.base import BaseDetector, DetectorResult, FailureCode
from app.vault_manager import VaultManager

from .test_guard_failure_enforcement import _install
from .test_guard_routes import _make_app_and_client
from .test_vault_manager import SECRET, _alter_the_ciphertext, _material, _ring, _rows

CONTENT = f"mail {SECRET} now"


class _VaultRedactor(BaseDetector):
    """A redactor that records what it removed, the way the PII detector does.

    Named `confidential_and_pii_entity` deliberately: that is the one detector
    the engine hands a vault to, in both `scan` and `scan_single`.
    """

    @property
    def name(self) -> str:
        return "confidential_and_pii_entity"

    def scan(self, text: str, **kwargs) -> DetectorResult:
        if SECRET not in text:
            return DetectorResult(detected=False)
        vault = kwargs.get("vault")
        assert vault is not None, "the engine handed this redactor no vault"
        placeholder = vault.store("EMAIL", SECRET)
        return DetectorResult(detected=True, sanitized_text=text.replace(SECRET, placeholder))


class _FailingBlocker(BaseDetector):
    """A blocking detector that cannot run, so the request was never protected."""

    @property
    def name(self) -> str:
        return "malicious_prompt"

    def scan(self, text: str, **kwargs) -> DetectorResult:
        return DetectorResult.failed(FailureCode.MODEL_LOAD_FAILED)


class _ExplodingRedactor(BaseDetector):
    """A second redactor that raises, so reconstruction cannot complete."""

    @property
    def name(self) -> str:
        return "secret_and_key_entity"

    def scan(self, text: str, **kwargs) -> DetectorResult:
        raise RuntimeError("redactor exploded")


def _detector(cls, action: str) -> BaseDetector:
    det = cls({"action": action})
    det.action = action
    return det


class _Guard:
    """The guard app, plus everything a test needs to look behind it."""

    def __init__(self, client, key, session_factory, ring):
        self.client = client
        self.key = key
        self.session_factory = session_factory
        self.ring = ring


@pytest.fixture
def guard():
    client, _admin, api_key, _viewer, session_factory = _make_app_and_client()
    ring = _ring()
    client.app.state.vault_manager = VaultManager(session_factory, keyring=ring)
    return _Guard(client, api_key, session_factory, ring)


def _post(guard: _Guard, content: str = CONTENT):
    return guard.client.post(
        "/v1/guard_chat_completions",
        headers={"Authorization": f"Bearer {guard.key}"},
        json={"guard_input": {"messages": [{"role": "user", "content": content}]}, "event_type": "input"},
    )


def _report_only(session_factory) -> None:
    with session_factory() as session:
        session.query(Policy).filter_by(is_default=True).one().report_only = True
        session.commit()


def _redacted_text(body) -> str:
    return body["result"]["guard_output"]["messages"][0]["content"]


# ---------------------------------------------------------------------------
# The positive case
# ---------------------------------------------------------------------------


def test_a_redaction_the_caller_receives_is_saved_and_opens_cold(guard):
    """The response promises a reversal, so another process must be able to
    perform it. A cold manager is the closest a test gets to being one."""
    _install(guard.client, guard.session_factory, [_detector(_VaultRedactor, "redact")])

    body = _post(guard).json()

    assert body["result"]["transformed"] is True
    token = body["result"]["fpe_context"]
    assert token, "a redaction was returned with no way to reverse it"
    assert SECRET not in _redacted_text(body)

    cold = VaultManager(guard.session_factory, keyring=guard.ring)
    recovered = cold.get_vault(cold.decode_fpe_context(token))

    assert recovered is not None, "the token names a vault that was never written"
    assert recovered.unredact(_redacted_text(body)) == CONTENT


def test_a_request_that_redacts_nothing_writes_no_row(guard):
    """No token and no row when there was nothing to record. The table used to
    fill with empty vaults, which later read as data loss."""
    _install(guard.client, guard.session_factory, [_detector(_VaultRedactor, "redact")])

    body = _post(guard, content="nothing to see here").json()

    assert body["result"]["fpe_context"] is None
    assert _rows(guard.session_factory) == []


# ---------------------------------------------------------------------------
# The four ways to redact and not save
# ---------------------------------------------------------------------------


def test_a_request_blocked_by_a_detector_failure_saves_nothing(guard):
    """The scan redacted and the response blocks, so the token is discarded.
    Saving after the scan would keep the mapping for a request nobody can ever
    present a token for."""
    _install(
        guard.client,
        guard.session_factory,
        [_detector(_FailingBlocker, "block"), _detector(_VaultRedactor, "redact")],
        on_detector_failure="block",
    )

    body = _post(guard).json()

    assert body["result"]["blocked"] is True
    assert body["result"]["fpe_context"] is None
    assert _rows(guard.session_factory) == [], "PII was retained for a response that carries no token"


def test_a_failed_reconstruction_saves_nothing(guard):
    """The first redactor populated the vault before the second one raised.
    The caller receives no output and no token, so the mapping is not kept."""
    _install(
        guard.client,
        guard.session_factory,
        [_detector(_VaultRedactor, "redact"), _detector(_ExplodingRedactor, "redact")],
        on_detector_failure="report",
    )

    body = _post(guard).json()

    assert body["result"]["guard_output"] in (None, {})
    assert body["result"]["fpe_context"] is None
    assert _rows(guard.session_factory) == [], "PII was retained for a reconstruction that was discarded"


def test_a_report_only_policy_saves_nothing(guard):
    """Report-only exists so a policy can be trialled without changing traffic.
    The redaction is discarded, so the mapping has nothing to map."""
    _report_only(guard.session_factory)
    _install(guard.client, guard.session_factory, [_detector(_VaultRedactor, "redact")])

    body = _post(guard).json()

    assert body["result"]["transformed"] is False
    assert body["result"]["fpe_context"] is None
    assert _rows(guard.session_factory) == [], "PII was retained for a request that was never transformed"


def test_a_save_that_raises_clears_the_token(guard, monkeypatch):
    """The redaction still stands -- it happened, and the caller gets it. What
    the response must not do is claim it can be reversed."""

    def _explode(*args, **kwargs):
        raise RuntimeError("the database went away")

    monkeypatch.setattr(guard.client.app.state.vault_manager, "save", _explode)
    _install(guard.client, guard.session_factory, [_detector(_VaultRedactor, "redact")])

    response = _post(guard)
    body = response.json()

    assert response.status_code == 200
    assert body["result"]["transformed"] is True
    assert SECRET not in _redacted_text(body)
    assert body["result"]["fpe_context"] is None, "a token was issued for a vault that was never written"


def test_a_save_that_declines_clears_the_token(guard, monkeypatch):
    """A refusal is not an exception. A manager with no key configured returns
    False rather than raising, and the token must go just the same."""
    monkeypatch.setattr(guard.client.app.state.vault_manager, "save", lambda *a, **k: False)
    _install(guard.client, guard.session_factory, [_detector(_VaultRedactor, "redact")])

    body = _post(guard).json()

    assert body["result"]["transformed"] is True
    assert body["result"]["fpe_context"] is None


# ---------------------------------------------------------------------------
# The read path, through the route the caller actually reaches
# ---------------------------------------------------------------------------


def _seal_a_vault(guard: _Guard) -> str:
    mgr = VaultManager(guard.session_factory, keyring=guard.ring)
    vault_id, vault = mgr.create_vault()
    vault.store("EMAIL", SECRET)
    assert mgr.save(vault_id, vault) is True
    return vault_id


def _unredact(guard: _Guard, vault_id: str, keyring=None):
    """Ask `/v1/unredact` for a vault, through a manager that is cold and whose
    ring is whatever this test is about."""
    app = FastAPI()
    app.add_middleware(AuthMiddleware)
    app.state.session_factory = guard.session_factory
    app.state.vault_manager = VaultManager(
        guard.session_factory, keyring=keyring if keyring is not None else guard.ring
    )

    from app.routes import unredact as unredact_route

    app.include_router(unredact_route.router)

    token = base64.b64encode(json.dumps({"vault_id": vault_id}).encode()).decode()
    return TestClient(app, raise_server_exceptions=False).post(
        "/v1/unredact",
        headers={"Authorization": f"Bearer {guard.key}"},
        json={"fpe_context": token, "redacted_data": "[REDACTED_EMAIL_1]"},
    )


def test_unredact_recovers_the_original(guard):
    """The positive control. Without it the two below pass against a route that
    is broken for every input."""
    response = _unredact(guard, _seal_a_vault(guard))

    assert response.status_code == 200
    assert response.json()["result"]["data"] == SECRET


def test_unredact_is_loud_when_the_row_names_a_key_the_ring_no_longer_holds(guard):
    """A server started with the wrong key must not look like a server whose
    data merely expired."""
    vault_id = _seal_a_vault(guard)

    response = _unredact(guard, vault_id, keyring=_ring({"k9": _material()}, current="k9"))

    assert response.status_code == 500, "a withdrawn key was reported as an expired or absent vault"


def test_unredact_is_loud_when_the_ciphertext_was_altered(guard):
    """Tampering must not be disguised as routine expiry."""
    vault_id = _seal_a_vault(guard)
    _alter_the_ciphertext(guard.session_factory, vault_id)

    response = _unredact(guard, vault_id)

    assert response.status_code == 500, "an altered row was reported as an expired or absent vault"


def test_unredact_still_answers_404_for_a_vault_that_is_genuinely_absent(guard):
    """404 stays for a property of the row rather than a selector an attacker
    chooses, or the two loud cases above would prove nothing."""
    response = _unredact(guard, "no-such-vault")

    assert response.status_code == 404


def test_an_expired_row_is_deleted_by_the_unredact_that_finds_it(guard):
    """The read gate reclaims disk as well as refusing disclosure."""
    from datetime import UTC, datetime, timedelta

    mgr = VaultManager(guard.session_factory, keyring=guard.ring)
    vault_id, vault = mgr.create_vault()
    vault.store("EMAIL", SECRET)
    assert mgr.save(vault_id, vault, expires_at=datetime.now(UTC) - timedelta(minutes=1)) is True

    response = _unredact(guard, vault_id)

    assert response.status_code == 404
    with guard.session_factory() as session:
        assert session.get(VaultModel, vault_id) is None


def test_the_token_the_guard_issues_is_the_token_unredact_accepts(guard):
    """The whole feature in one request pair, in the shape a real client uses.

    One test above drives the real guard route and opens the vault with a cold
    MANAGER. Another posts a hand-built token to the real unredact ROUTE. This
    is the only one that takes the `fpe_context` the guard route ACTUALLY ISSUED
    and hands it to the route that consumes it.

    Honest about its strength: I could not construct a mutation this kills and
    the others do not. The encoder, `decode_fpe_context` and the route's own
    inline decoder all share the literal "vault_id", so breaking any one of them
    breaks tests that were already there. This is insurance against a change
    that has not happened yet -- a signature, a version prefix, a second field --
    where the hand-built tokens in the other tests would silently not follow and
    every one of them would keep passing.

    Worth keeping at one cheap test. Not worth claiming more for.
    """
    _install(guard.client, guard.session_factory, [_detector(_VaultRedactor, "redact")])

    redacted = _post(guard).json()
    token = redacted["result"]["fpe_context"]
    assert token, "the guard route returned no token to test the seam with"
    redacted_text = _redacted_text(redacted)
    assert SECRET not in redacted_text

    # A cold manager on a second app, as a different worker would be.
    app = FastAPI()
    app.add_middleware(AuthMiddleware)
    app.state.session_factory = guard.session_factory
    app.state.vault_manager = VaultManager(guard.session_factory, keyring=guard.ring)

    from app.routes import unredact as unredact_route

    app.include_router(unredact_route.router)

    response = TestClient(app, raise_server_exceptions=False).post(
        "/v1/unredact",
        headers={"Authorization": f"Bearer {guard.key}"},
        # The token VERBATIM, not one this test built. That is the point.
        json={"fpe_context": token, "redacted_data": redacted_text},
    )

    assert response.status_code == 200, f"the seam is broken: {response.text}"
    assert response.json()["result"]["data"] == CONTENT
