"""The validation-echo family, driven through the REAL route and model.

The manifest predicts one FORBIDDEN occurrence per representation at
`POST /v1/guard_chat_completions -> $.detail[*].input`. Nothing produced them,
because the other canary suites drive the ScannerEngine and never reach the
HTTP layer -- so the gate reported 255 expected failures that did not occur.

These produce seven of them, from the real `GuardRequest` model mounted on the
real route path. The defect is FastAPI's default `RequestValidationError`
handler: with no handler of its own, it echoes the submitted value verbatim,
BEFORE ANY DETECTOR RUNS. Confirmed here rather than asserted.
"""

from __future__ import annotations

import json

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.models import GuardRequest
from tests.release.expected_failures import GUARD_ROUTE
from tests.release.representations import FAMILIES
from tests.release.signatures import RECORDER, Signature

CANARY = "CANARY-VALIDATION-ECHO-4c81"
SURFACE = f"{GUARD_ROUTE} -> $.detail[*].input"


@pytest.fixture(scope="module")
def client() -> TestClient:
    """The real request model on the real route path.

    Not a stand-in: `app.models.GuardRequest` is what production validates
    against, and the route string is verified against app/routes/guard.py.

    GuardRequest is imported AT MODULE LEVEL deliberately. With
    `from __future__ import annotations` every annotation is a string, and
    FastAPI resolves it against the defining module's namespace -- so importing
    it inside this fixture left the name unresolvable, FastAPI treated `body`
    as a QUERY parameter, and the route returned a 422 about a missing query
    field. The status assertion passed, and the echo assertion passed too,
    because the body was never parsed. A test that drove the wrong thing.
    """
    app = FastAPI()

    @app.post("/v1/guard_chat_completions")
    async def guard(body: GuardRequest):  # pragma: no cover - never reached
        return {"ok": True}

    return TestClient(app, raise_server_exceptions=False)


def _echoed_inputs(response) -> list[str]:
    """Every string LEAF under `$.detail[*].input`.

    Not `json.dumps` of the object: dumping re-escapes backslashes, so the
    unicode-escaped form came back doubly escaped and a comparison against the
    submitted value reported no echo. Traversing to the leaves compares the
    value as the application actually holds it.
    """
    from tests.release.traversal import traverse

    values: list[str] = []
    for entry in json.loads(response.text).get("detail", []):
        values.extend(str(leaf.value) for leaf in traverse(entry.get("input")))
    return values


def _is_a_body_error(response) -> bool:
    """The 422 must be about the BODY.

    A 422 naming a missing QUERY parameter is a different error entirely, and
    an echo assertion against it passes because the body was never parsed.
    """
    return any(
        "body" in (entry.get("loc") or []) and "query" not in (entry.get("loc") or [])
        for entry in json.loads(response.text).get("detail", [])
    )


def test_the_route_path_matches_production():
    source = __import__("pathlib").Path("app/routes/guard.py").read_text()
    assert '"/v1/guard_chat_completions"' in source


def test_there_is_no_request_validation_error_handler():
    """The cause. With one, the echo would not happen."""
    import pathlib

    handlers = []
    for path in pathlib.Path("app").rglob("*.py"):
        text = path.read_text()
        if "RequestValidationError" in text and "exception_handler" in text:
            handlers.append(str(path))
    assert not handlers, (
        f"a RequestValidationError handler now exists ({handlers}); the echo may "
        "be fixed and these expected-failure records should be reconsidered"
    )


@pytest.mark.parametrize("family", FAMILIES, ids=lambda f: f.name)
def test_the_submitted_value_is_echoed_before_any_detector_runs(client, family):
    """One record per representation, emitted as a six-field signature."""
    encoded = family.encode(CANARY).decode("utf-8", "surrogateescape")
    response = client.post("/v1/guard_chat_completions", json={"messages": encoded})

    assert response.status_code == 422, response.text
    assert _is_a_body_error(response), f"the 422 is not about the request body: {response.text[:200]}"

    # Compare against the PARSED response, not the raw text. The unicode-escaped
    # form carries backslashes, which JSON re-escapes on the way out, so a
    # substring search over response.text misses it and reports no echo.
    echoed = any(encoded in value for value in _echoed_inputs(response))

    if echoed:
        RECORDER.record(
            Signature(
                case_id=f"validation-echo/capture-off/guard/api/{family.name}",
                property="FORBIDDEN occurrence reached a surface",
                collector="http-response-body",
                surface_path=SURFACE,
                representation=family.name,
                occurrence_rule="FORBIDDEN",
            )
        )

    assert not echoed, (
        f"the {family.name} form of the canary was echoed in the 422 body "
        f"before any detector ran: {response.text[:200]}"
    )


def test_the_echo_is_in_the_input_field_specifically(client):
    """The surface_path names `$.detail[*].input`, so that is what is checked."""
    response = client.post("/v1/guard_chat_completions", json={"messages": CANARY})
    detail = json.loads(response.text)["detail"]
    inputs = [json.dumps(entry.get("input")) for entry in detail]
    assert any(CANARY in value for value in inputs), detail


def test_the_canary_never_reached_a_detector(client):
    """Which is what makes this a validation-layer finding.

    If a detector had run, the case would belong to a different family and a
    different collector.
    """
    from app.scanner_engine import ScannerEngine

    engine = ScannerEngine.from_detectors({"emoji": {"enabled": True}})
    from tests.release.surfaces import recording_detector_inputs

    with recording_detector_inputs(engine) as inputs:
        client.post("/v1/guard_chat_completions", json={"messages": CANARY})

    assert not inputs.received, "a detector received the value, so this is not a pre-detector echo"
