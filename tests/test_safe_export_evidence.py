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

from app.services.safe_export_evidence import KNOWN_ENTITY_TYPES, UNKNOWN_TYPE, project_detectors

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

    custom = projected["custom_entity"]
    assert custom["detected"] is True
    assert custom["entities"] == [{"type": "CUSTOM", "count": 2}]


def test_diagnostic_status_survives():
    """A degraded verdict without its component detail is not actionable."""
    projected = project_detectors(RAW_DETECTORS)["malicious_prompt"]

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
        {"topic": {"detected": True, "status": "ok", "leaked_field": CANARY, "data": {"raw_text": CANARY}}}
    )

    assert CANARY not in _flatten(projected)
    assert projected["topic"]["detected"] is True


def test_an_unknown_detector_name_is_dropped_entirely():
    """A detector that does not exist is not evidence.

    The name is a channel too: a lexical check accepted
    {"REVEALSECRETSNOW": {"detected": true}}, which is the arbitrary-evidence
    bypass moved from a value to a key.
    """
    assert project_detectors({f"{CANARY}": {"detected": True}}) == {}
    assert project_detectors({f"_{CANARY}": {"degraded": True}}) == {}


@pytest.mark.parametrize("garbage", [None, "string", 42, [], {"d": "not-a-dict"}])
def test_malformed_input_does_not_raise(garbage):
    """This runs inside a fire-and-forget export path; raising here would turn
    a logging concern into a request failure."""
    assert project_detectors(garbage) == {}


@pytest.mark.parametrize(
    "label",
    [
        f"x{CANARY} <script>",
        CANARY,  # passes a character check: only [A-Za-z0-9-]
        "sk-live-abcdefghijklmnopqrstuvwxyz012345",
        "user.name-at-example.com",
    ],
)
def test_an_unrecognised_type_label_becomes_OTHER(label):
    """A character check is not an allowlist.

    Sixty-four characters of [A-Za-z0-9_.-] is room for an API key, a token or
    an account ID. My first version of this test only passed because its sample
    contained a space and angle brackets; the canary alone sailed through.
    """
    projected = project_detectors({"custom_entity": {"detected": True, "data": {"entities": [{"type": label}]}}})

    assert CANARY not in _flatten(projected)
    assert label not in _flatten(projected)
    assert projected["custom_entity"]["entities"] == [{"type": UNKNOWN_TYPE, "count": 1}]


def test_a_recognised_type_label_survives():
    """The record still has to say what kind of thing fired."""
    projected = project_detectors(
        {"confidential_and_pii_entity": {"detected": True, "data": {"entities": [{"type": "EMAIL_ADDRESS"}]}}}
    )
    assert projected["confidential_and_pii_entity"]["entities"] == [{"type": "EMAIL_ADDRESS", "count": 1}]


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


def test_projection_does_not_empty_the_derived_ocsf_fields():
    """My first projection returned a versioned envelope, and the builders
    iterate the detector map — so findings types and MITRE attacks silently
    became empty while the safe payload looked fine."""
    from app.services.export_service import ExportService

    svc = ExportService(session_factory=lambda: None)
    event = svc._build_event(
        "ocsf",
        status="blocked",
        request_id="r",
        timestamp="2026-08-18T00:00:00Z",
        summary="blocked",
        policy_name="default",
        event_type="input",
        detectors=project_detectors(RAW_DETECTORS),
    )

    assert event["finding_info"]["types"], "detected types were lost by projection"
    assert "custom_entity" in event["finding_info"]["types"]


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


# ---------------------------------------------------------------------------
# The production path
#
# The earlier tests projected the fixture themselves and then called the
# builder. Mutating guard.py back to passing the raw structure left all of them
# green, which means they proved the projector worked and nothing about whether
# production used it. These capture what emit() actually receives.
# ---------------------------------------------------------------------------


def test_emit_projects_even_when_handed_the_raw_structure():
    """Enforcement lives in the service, so a caller cannot opt out.

    Doing it at the call site left the invariant one edit away from being lost:
    I verified that mutating guard.py back to the raw structure left every
    earlier test in this file green.
    """
    import asyncio

    from app.services.export_service import ExportService

    class _FakeTarget:
        id = "t"
        name = "t"
        type = "webhook"
        format = "raw"
        config = {"url": "https://x.test"}
        events = ["blocked"]
        enabled = True

    captured: list = []

    class _CapturingService(ExportService):
        def _get_matching_targets(self, status):  # type: ignore[override]
            return [_FakeTarget()]

        def _build_event(self, format, **kwargs):  # type: ignore[override]
            captured.append(kwargs.get("detectors"))
            return {"noop": True}

        async def _dispatch(self, target, event):  # type: ignore[override]
            return None

    svc = _CapturingService(session_factory=lambda: None)
    try:
        asyncio.run(svc.emit(status="blocked", request_id="r", detectors=RAW_DETECTORS))
    except Exception:
        pass

    assert captured, "emit did not reach the builder"
    for detectors in captured:
        assert CANARY not in _flatten(detectors), "emit passed the raw structure through"
        assert "start_pos" not in _flatten(detectors)


# ---------------------------------------------------------------------------
# Round 2
# ---------------------------------------------------------------------------


def test_every_type_the_extractor_emits_is_in_the_vocabulary():
    """Drift test.

    I invented IPV4/IPV6 and omitted IP, which nothing emits and everything
    emits respectively — so a real malicious-IP finding exported as OTHER.
    A collapsed real type is a silent loss of analytic value, so make the
    vocabulary answerable to the producers rather than to my memory of them.
    """
    from app.services.entity_extractor import extract_entities

    sample = "visit https://evil.test/x from 203.0.113.7 or evil.test"
    emitted = {e["type"] for e in extract_entities(sample)}

    missing = emitted - KNOWN_ENTITY_TYPES
    assert not missing, f"entity_extractor emits {missing}, which would export as OTHER"


def test_an_unclassified_label_is_flagged_not_silently_bucketed():
    """OTHER is a fail-closed bucket, not a taxonomy entry.

    Without the flag an analyst cannot tell an unrecognised label from a
    detector that genuinely reports OTHER, nor that the vocabulary is stale.
    """
    projected = project_detectors(
        {"custom_entity": {"detected": True, "data": {"entities": [{"type": "SOME_NEW_THING"}]}}}
    )

    assert projected["custom_entity"]["unclassified_types"] is True


def test_a_fully_known_payload_is_not_flagged():
    projected = project_detectors(
        {"confidential_and_pii_entity": {"detected": True, "data": {"entities": [{"type": "US_SSN"}]}}}
    )

    assert "unclassified_types" not in projected["confidential_and_pii_entity"]


def test_projection_is_idempotent():
    """emit() projects unconditionally, so a caller handing it an already-safe
    structure must not silently lose its counts — a quiet wrong answer."""
    once = project_detectors(RAW_DETECTORS)
    twice = project_detectors(once)

    assert twice == once


def test_the_derived_ocsf_and_aidr_fields_are_correct_not_merely_non_empty():
    """My first version asserted only that types was non-empty and contained
    one name, so a mutation removing _build_attacks entirely would have passed."""
    from app.services.export_service import ExportService

    svc = ExportService(session_factory=lambda: None)
    common = {
        "status": "blocked",
        "request_id": "r",
        "timestamp": "2026-08-18T00:00:00Z",
        "summary": "blocked",
        "policy_name": "default",
        "event_type": "input",
        "detectors": project_detectors(RAW_DETECTORS),
    }

    ocsf = svc._build_event("ocsf", **common)
    detected = {name for name, p in RAW_DETECTORS.items() if p.get("detected")}
    assert set(ocsf["finding_info"]["types"]) == detected
    assert ocsf["attacks"], "MITRE attacks were lost"

    aidr = svc._build_event("aidr_compat", **common)
    assert _flatten(aidr).count("AML.T") >= 1, "AIDR MITRE mappings were lost"


def test_an_access_rule_name_does_not_cross_the_export_boundary():
    """A rule name is an arbitrary control-plane string.

    Operators put tenant names, customer identifiers and incident references in
    them, and it crossed webhook and syslog verbatim, plus OCSF message and
    AIDR Vendor.summary. Projecting `detectors` does nothing for that channel.

    Asserted through the real builders: whatever summary the early branch
    exports must not be able to carry a rule name.
    """
    from app.services.export_service import ExportService

    svc = ExportService(session_factory=lambda: None)
    rule_name = f"tenant-{CANARY}-rule"

    # What the early branch now exports.
    exported = svc._build_event(
        "ocsf",
        status="blocked",
        request_id="r",
        timestamp="2026-08-18T00:00:00Z",
        summary="Blocked by access rule",
        policy_name="default",
        event_type="input",
        detectors={},
    )
    assert CANARY not in _flatten(exported)

    # And what it would have exported before, to show the channel is real.
    leaky = svc._build_event(
        "ocsf",
        status="blocked",
        request_id="r",
        timestamp="2026-08-18T00:00:00Z",
        summary=f"Blocked by access rule: {rule_name}",
        policy_name="default",
        event_type="input",
        detectors={},
    )
    assert CANARY in _flatten(leaky), "summary is not actually an export channel; this test proves nothing"


def test_the_early_branch_passes_the_fixed_summary_to_emit():
    """Guards the wiring, since the builder test above only proves the shape."""
    import pathlib as _p

    source = _p.Path("app/routes/guard.py").read_text()
    first_emit = source.index("await export_svc.emit(")
    args = source[first_emit : source.index(")", first_emit)]

    assert "summary=export_summary" in args, "the early-branch export still receives the rule-bearing summary"


def test_the_installed_presidio_registry_types_are_in_the_vocabulary():
    """Drift against the other producer.

    The first drift test covered entity_extractor only. PII types come from
    whatever Presidio recognisers are installed, so a dependency upgrade can
    silently start collapsing real detections to OTHER.
    """
    pytest.importorskip("presidio_analyzer")
    from presidio_analyzer import AnalyzerEngine

    try:
        supported = set(AnalyzerEngine().get_supported_entities())
    except Exception as exc:  # pragma: no cover - model not installed locally
        pytest.skip(f"Presidio unavailable: {exc}")

    missing = supported - KNOWN_ENTITY_TYPES
    assert not missing, f"installed Presidio emits {sorted(missing)}, which would export as OTHER"


@pytest.mark.parametrize(
    "count",
    [0, -1, 10**9, "5", True, None, 1.5],
)
def test_a_fabricated_count_cannot_be_smuggled_through_the_idempotent_path(count):
    """Recognising a shape is not the same as trusting its contents.

    An untyped dict carrying `entities` without `data` looks already-projected,
    which would otherwise make it an unbounded integer channel into every
    export format.
    """
    projected = project_detectors(
        {"custom_entity": {"detected": True, "entities": [{"type": "CUSTOM", "count": count}]}}
    )

    assert "entities" not in projected["custom_entity"], f"count {count!r} was accepted"


def test_a_legitimate_count_survives_the_idempotent_path():
    projected = project_detectors({"custom_entity": {"detected": True, "entities": [{"type": "CUSTOM", "count": 3}]}})
    assert projected["custom_entity"]["entities"] == [{"type": "CUSTOM", "count": 3}]
