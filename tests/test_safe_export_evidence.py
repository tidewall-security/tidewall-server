"""Exports must not carry the content the product exists to protect (P0-6 step 2).

`ScanResult.detectors` was passed straight into every export format, and
detector payloads carry the matched value (`custom_entity`), the unmodified URL
including credentials (`malicious_entity`), and offsets. So the audit record
left for a SIEM carrying exactly what it was created to keep out of downstream
systems — before anyone looked at `/v1/logs` at all.

These tests plant a canary in each detector payload shape and assert it is
absent from every export format.
"""

from __future__ import annotations

import json

import pytest

from app.services.safe_export_evidence import EVIDENCE_SCHEMA_VERSION, project_detectors

CANARY = "CANARY-4f81-secret"

# The real shapes, taken from the detectors that produce them.
RAW_DETECTORS = {
    "custom_entity": {
        "detected": True,
        "status": "ok",
        "data": {
            "entities": [
                {"type": "CUSTOM", "value": CANARY, "action": "redacted:replaced", "start_pos": 12},
                {"type": "CUSTOM", "value": f"{CANARY}-2", "action": "redacted:replaced", "start_pos": 40},
            ]
        },
    },
    "malicious_entity": {
        "detected": True,
        "status": "ok",
        "data": {
            "entities": [
                {"type": "URL", "value": f"hxxps://evil.test/{CANARY}", "raw": f"https://evil.test/{CANARY}"},
            ]
        },
    },
    "confidential_and_pii_entity": {
        "detected": True,
        "status": "ok",
        "data": {"entities": [{"type": "EMAIL_ADDRESS", "value": "[REDACTED_EMAIL_1]"}]},
    },
    "malicious_prompt": {
        "detected": False,
        "status": "failed",
        "degraded": True,
        "components": {"generic_injection": {"status": "failed", "failure_code": "model_load_failed"}},
    },
}


def _flatten(obj) -> str:
    return json.dumps(obj, default=str)


def test_no_canary_survives_projection():
    """The headline property."""
    assert CANARY not in _flatten(project_detectors(RAW_DETECTORS))


def test_offsets_do_not_survive_projection():
    """start_pos plus a value is a reconstruction aid for anyone downstream."""
    assert "start_pos" not in _flatten(project_detectors(RAW_DETECTORS))


def test_the_raw_url_does_not_survive_even_though_it_is_defanged_elsewhere():
    """Defanging stops a click; it does not protect credentials, query tokens
    or internal hostnames, and `raw` is not defanged at all."""
    projected = _flatten(project_detectors(RAW_DETECTORS))
    assert "evil.test" not in projected
    assert "hxxps" not in projected


def test_types_and_counts_do_survive():
    """The record still has to be worth reading."""
    projected = project_detectors(RAW_DETECTORS)

    custom = projected["detectors"]["custom_entity"]
    assert custom["detected"] is True
    assert custom["entities"] == [{"type": "CUSTOM", "count": 2}]


def test_diagnostic_status_survives():
    """A degraded verdict without its component detail is not actionable."""
    projected = project_detectors(RAW_DETECTORS)["detectors"]["malicious_prompt"]

    assert projected["status"] == "failed"
    assert projected["degraded"] is True
    assert projected["components"]["generic_injection"]["failure_code"] == "model_load_failed"


def test_an_unknown_field_is_dropped_rather_than_passed_through():
    """The reason this is an allowlist.

    A denylist is a promise about every field anyone adds later. The first
    detector to introduce a differently-named value field would ship it, and
    nothing would fail.
    """
    projected = project_detectors(
        {"future_detector": {"detected": True, "status": "ok", "leaked_field": CANARY, "data": {"raw_text": CANARY}}}
    )

    assert CANARY not in _flatten(projected)
    assert projected["detectors"]["future_detector"]["detected"] is True


@pytest.mark.parametrize("garbage", [None, "string", 42, [], {"d": "not-a-dict"}])
def test_malformed_input_does_not_raise(garbage):
    """This runs inside a fire-and-forget export path; raising here would turn
    a logging concern into a request failure."""
    result = project_detectors(garbage)
    assert result["schema_version"] == EVIDENCE_SCHEMA_VERSION


def test_a_hostile_type_label_is_dropped():
    """Labels come from policy configuration and reach a SIEM."""
    projected = project_detectors(
        {"custom_entity": {"detected": True, "data": {"entities": [{"type": f"x{CANARY} <script>"}]}}}
    )
    assert CANARY not in _flatten(projected)


# ---------------------------------------------------------------------------
# End to end: the canary must not reach any export format or the logs
# ---------------------------------------------------------------------------


def test_no_export_format_carries_the_canary():
    """Projection is only useful if every builder receives the projected form.

    Asserted against the real builders rather than the projector alone, because
    the defect was never in the projector — it was that the raw payload was
    handed to them.
    """
    from app.services.export_service import ExportService

    svc = ExportService(session_factory=lambda: None)
    safe = project_detectors(RAW_DETECTORS)
    common = {
        "status": "blocked",
        "request_id": "req-1",
        "timestamp": "2026-08-18T00:00:00Z",
        "summary": "blocked",
        "policy_name": "default",
        "event_type": "input",
        "detectors": safe,
    }

    for fmt in ("ocsf", "aidr_compat", "raw"):
        event = svc._build_event(fmt, **common)
        assert CANARY not in _flatten(event), f"{fmt} carried the canary"


def test_the_raw_payload_would_have_carried_it():
    """Proves the test above is not vacuous.

    If the builders were harmless with raw input, projecting would not be
    closing anything.
    """
    from app.services.export_service import ExportService

    svc = ExportService(session_factory=lambda: None)
    event = svc._build_event(
        "ocsf",
        status="blocked",
        request_id="req-1",
        timestamp="2026-08-18T00:00:00Z",
        summary="blocked",
        policy_name="default",
        event_type="input",
        detectors=RAW_DETECTORS,
    )

    assert CANARY in _flatten(event), "the unprojected payload should leak; if not, this test proves nothing"


def test_a_webhook_error_body_is_not_logged(caplog):
    """A receiver can echo back what we posted, which puts the exported event
    into our own logs by a route nobody would think to audit."""
    import asyncio

    import httpx

    from app.services.export_service import ExportService

    class _Target:
        id = "t1"
        name = "echo"
        type = "webhook"
        format = "raw"
        config = {"url": "https://receiver.test/hook"}
        events = ["blocked"]
        enabled = True

    svc = ExportService(session_factory=lambda: None)
    original = httpx.AsyncClient

    async def _echo(request):
        return httpx.Response(500, text=f"you sent: {CANARY}")

    class _Patched(original):  # type: ignore[misc,valid-type]
        def __init__(self, *a, **kw):
            kw["transport"] = httpx.MockTransport(_echo)
            super().__init__(*a, **kw)

    httpx.AsyncClient = _Patched  # type: ignore[misc]
    try:
        with caplog.at_level("DEBUG"):
            asyncio.run(svc._send_webhook(_Target(), {"event": "test"}))
    finally:
        httpx.AsyncClient = original  # type: ignore[misc]

    assert CANARY not in caplog.text, "the echoed response body reached the logs"
