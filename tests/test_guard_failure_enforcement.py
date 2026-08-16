"""Route-level failure enforcement for P0-2.

The detector-status tests assert that failures become *values*. These assert
that those values reach the HTTP response — which is where the fail-open was
actually observable, and where the first version of this work stopped short:
`ScanResult` carried the failure and the route ignored it, so a failed blocking
detector still returned 200 with "No threats detected."
"""

from __future__ import annotations

import pytest

from app.detectors.base import BaseDetector, DetectorResult, FailureCode

from .test_guard_routes import _make_app_and_client


class _FailingBlocker(BaseDetector):
    """A blocking detector that cannot run."""

    @property
    def name(self) -> str:
        return "malicious_prompt"

    def scan(self, text: str, **kwargs) -> DetectorResult:
        return DetectorResult.failed(FailureCode.MODEL_LOAD_FAILED)


class _FailingRedactor(BaseDetector):
    """A redactor that raises after another has already transformed text."""

    @property
    def name(self) -> str:
        return "secret_and_key_entity"

    def scan(self, text: str, **kwargs) -> DetectorResult:
        raise RuntimeError("redactor exploded")


class _WorkingRedactor(BaseDetector):
    @property
    def name(self) -> str:
        return "confidential_and_pii_entity"

    def scan(self, text: str, **kwargs) -> DetectorResult:
        return DetectorResult(detected=True, sanitized_text=text.replace("Alice", "[NAME]"))


def _install(client, session_factory, detectors, on_detector_failure="block"):
    """Force the live engine to contain *detectors*, and set the failure policy."""
    from app.db.models import Policy

    session = session_factory()
    policy_id = session.query(Policy).filter_by(is_default=True).first().id
    session.close()

    policy_svc = client.app.state.policy_service
    engine = policy_svc.get_engine(policy_id, "input")
    engine._detectors = [(d.name, d) for d in detectors]
    engine._construction_failures = []

    # The failure policy is not yet a first-class policy field — it defaults in
    # the route until the activation preflight lands, at which point the default
    # flips to "block". Patch the default so these tests exercise both branches.
    import app.routes.guard as guard_mod

    guard_mod._DEFAULT_ON_DETECTOR_FAILURE = on_detector_failure
    return engine


def _post(client, key, content="Alice's key is AKIAIOSFODNN7EXAMPLE"):
    return client.post(
        "/v1/guard_chat_completions",
        headers={"Authorization": f"Bearer {key}"},
        json={
            "guard_input": {"messages": [{"role": "user", "content": content}]},
            "event_type": "input",
        },
    )


@pytest.fixture
def guard_client():
    client, _admin, api_key, _viewer, session_factory = _make_app_and_client()
    return client, api_key, session_factory


def test_failed_blocking_detector_blocks_the_request(guard_client):
    """The fail-open this whole workstream exists to close."""
    client, key, session_factory = guard_client
    det = _FailingBlocker({"action": "block"})
    det.action = "block"
    _install(client, session_factory, [det])

    resp = _post(client, key)

    assert resp.status_code == 200
    body = resp.json()
    assert body["result"]["blocked"] is True, "a failed blocker must not allow the request"
    assert "No threats detected" not in body["summary"]


def test_failed_blocking_detector_is_allowed_under_report_policy(guard_client):
    """`on_detector_failure: report` is an explicit operator choice."""
    client, key, session_factory = guard_client
    det = _FailingBlocker({"action": "block"})
    det.action = "block"
    _install(client, session_factory, [det], on_detector_failure="report")

    body = _post(client, key).json()

    assert body["result"]["blocked"] is False


def test_redactor_failure_does_not_emit_original_text(guard_client):
    """The disclosure path.

    The first redactor removes the name; the second raises before removing the
    secret. The route previously did `msg_result.guard_output_text or content`,
    which turned the deliberate None into "emit the original".
    """
    client, key, session_factory = guard_client
    working, failing = _WorkingRedactor({"action": "redact"}), _FailingRedactor({"action": "redact"})
    working.action = failing.action = "redact"
    _install(client, session_factory, [working, failing])

    resp = _post(client, key)
    body = resp.json()

    assert body["result"]["blocked"] is True
    assert body["result"].get("guard_output") in (None, {})
    assert "AKIAIOSFODNN7EXAMPLE" not in resp.text
    assert "Alice" not in resp.text


def test_clean_request_is_unaffected(guard_client):
    """The enforcement path must not break ordinary traffic."""
    client, key, session_factory = guard_client
    _install(client, session_factory, [])

    body = _post(client, key, content="hello there").json()

    assert body["result"]["blocked"] is False
    assert body["summary"] == "No threats detected."


def test_failed_reporter_does_not_block(guard_client):
    """A failed reporter degrades observability, not protection."""
    client, key, session_factory = guard_client
    det = _FailingBlocker({"action": "report"})
    det.action = "report"
    _install(client, session_factory, [det])

    body = _post(client, key).json()

    assert body["result"]["blocked"] is False
