"""Route-level failure enforcement for P0-2.

The detector-status tests assert that failures become *values*. These assert
that those values reach the HTTP response — which is where the fail-open was
actually observable, and where the first version of this work stopped short:
`ScanResult` carried the failure and the route ignored it, so a failed blocking
detector still returned 200 with "No threats detected."
"""

from __future__ import annotations

import pytest

from app.config import OnDetectorFailure
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

    # on_detector_failure is a real policy field; set it on the live engine's
    # policy so both branches are exercised through the same path production
    # uses. It defaults to "report" until the activation preflight lands.
    engine._policy.on_detector_failure = OnDetectorFailure(on_detector_failure)
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


# ---------------------------------------------------------------------------
# Production configuration path
# ---------------------------------------------------------------------------


def test_on_detector_failure_reaches_the_engine_from_the_database(guard_client):
    """The defect the earlier route tests concealed.

    They set `engine._policy.on_detector_failure` directly, so they passed
    while every production engine still took the REPORT default —
    PolicyService.get_engine() never passed the setting to from_detectors(),
    and the field was not persisted at all. This asserts the real path:
    stored on the policy row, read back through get_engine().
    """
    from app.config import OnDetectorFailure
    from app.db.models import Policy

    client, key, session_factory = guard_client

    session = session_factory()
    policy = session.query(Policy).filter_by(is_default=True).first()
    policy.on_detector_failure = "block"
    session.commit()
    policy_id = policy.id
    session.close()

    policy_svc = client.app.state.policy_service
    policy_svc._engine_cache.clear()
    engine = policy_svc.get_engine(policy_id, "input")

    assert engine.on_detector_failure is OnDetectorFailure.BLOCK


def test_failure_blocks_when_configured_through_the_database(guard_client):
    """End to end: persisted setting, real engine build, blocked response."""
    from app.db.models import Policy

    client, key, session_factory = guard_client

    session = session_factory()
    policy = session.query(Policy).filter_by(is_default=True).first()
    policy.on_detector_failure = "block"
    session.commit()
    policy_id = policy.id
    session.close()

    policy_svc = client.app.state.policy_service
    policy_svc._engine_cache.clear()
    engine = policy_svc.get_engine(policy_id, "input")
    det = _FailingBlocker({"action": "block"})
    det.action = "block"
    engine._detectors = [(det.name, det)]

    body = _post(client, key).json()

    assert body["result"]["blocked"] is True
    assert "No threats detected" not in body["summary"]


def test_policy_create_accepts_and_returns_on_detector_failure(guard_client):
    """The setting is reachable through the API, not just the ORM."""
    from app.services.policy_service import PolicyService

    _client, _key, session_factory = guard_client
    session = session_factory()
    try:
        svc = PolicyService(session)
        created = svc.create_policy(name="strict", on_detector_failure="block")
        assert created.on_detector_failure == "block"
    finally:
        session.close()


def test_updating_the_policy_invalidates_cached_engines(guard_client):
    """Engines cache a policy snapshot, so a write must drop them.

    Without this an administrator tightening enforcement gets a 200 and no
    behaviour change until restart. The PATCH route performs exactly the two
    calls below: the write on a request-scoped PolicyService, then invalidation
    on the application-scoped one — because the throwaway service's cache is
    not the live one. That split is P0-5's root cause and the activation
    protocol replaces it wholesale; this only covers the field added here.
    """
    from app.config import OnDetectorFailure
    from app.db.models import Policy
    from app.services.policy_service import PolicyService

    client, _key, session_factory = guard_client

    session = session_factory()
    policy_id = session.query(Policy).filter_by(is_default=True).first().id
    session.close()

    policy_svc = client.app.state.policy_service
    # Warm the cache with the default.
    assert policy_svc.get_engine(policy_id, "input").on_detector_failure is OnDetectorFailure.REPORT

    session = session_factory()
    try:
        PolicyService(session).update_policy(policy_id, on_detector_failure="block")
    finally:
        session.close()

    # The write alone does not reach the live cache — this is the defect.
    assert policy_svc.get_engine(policy_id, "input").on_detector_failure is OnDetectorFailure.REPORT

    policy_svc.invalidate_engines(policy_id)

    assert policy_svc.get_engine(policy_id, "input").on_detector_failure is OnDetectorFailure.BLOCK


def test_degraded_report_does_not_claim_a_clean_scan(guard_client):
    """The interim configuration must not lie.

    With on_detector_failure=report (the shipped default until the preflight
    exists) a failed detector does not block. The response must still say so:
    "No threats detected." is false when part of the scan did not run, and it
    was the exact string the original P0-2 finding quoted.
    """
    client, key, session_factory = guard_client
    det = _FailingBlocker({"action": "block"})
    det.action = "block"
    _install(client, session_factory, [det], on_detector_failure="report")

    body = _post(client, key).json()

    assert body["result"]["blocked"] is False  # report mode
    assert body["result"]["degraded"] is True
    assert body["result"]["failed_detectors"] == ["malicious_prompt"]
    assert "No threats detected" not in body["summary"]


def test_clean_scan_is_not_marked_degraded(guard_client):
    client, key, session_factory = guard_client
    _install(client, session_factory, [])

    body = _post(client, key, content="hello there").json()

    assert body["result"]["degraded"] is False
    assert body["result"]["failed_detectors"] == []
    assert body["summary"] == "No threats detected."
