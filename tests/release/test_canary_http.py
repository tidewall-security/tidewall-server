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
import os

import pytest
from fastapi.testclient import TestClient

from tests.release.expected_failures import GUARD_ROUTE
from tests.release.representations import FAMILIES
from tests.release.signatures import RECORDER, Signature

CANARY = "CANARY-VALIDATION-ECHO-4c81"
SURFACE = f"{GUARD_ROUTE} -> $.detail[*].input"


BOOTSTRAP_KEY = "ak_release_gate_bootstrap_only_not_a_real_credential"


@pytest.fixture(scope="module")
def client(tmp_path_factory) -> TestClient:
    """THE PRODUCTION APPLICATION, via `app.main.create_app`.

    An earlier version built its own `FastAPI()` with a local handler that
    merely accepted `GuardRequest`, and connected to production only by a
    substring search for the route path in guard.py. Changes to app
    construction, router mounting, exception handlers, dependencies or route
    behaviour could not have affected it. This mounts the real app, runs its
    real lifespan (which applies migrations), and calls the real route with a
    real key.
    """
    directory = tmp_path_factory.mktemp("release-gate-http")
    os.environ["BOOTSTRAP_KEY"] = BOOTSTRAP_KEY
    os.environ["DB_URL"] = f"sqlite:///{directory}/gate.db"

    from app.main import create_app

    with TestClient(create_app(), raise_server_exceptions=False) as test_client:
        yield test_client


def test_the_route_is_mounted_on_the_production_application(client):
    """Structural, not a substring search over source text."""
    paths = {route.path for route in client.app.routes if hasattr(route, "path")}
    assert "/v1/guard_chat_completions" in paths, sorted(paths)[:8]
    assert GUARD_ROUTE.endswith("/v1/guard_chat_completions")


def test_authentication_runs_before_the_body_is_parsed(client):
    """The auth-before-body boundary, and the control on the echo below.

    Unauthenticated, the canary is NOT echoed -- so the echo is a property of
    the authenticated validation path, not of any 422 the app can produce.
    """
    response = client.post("/v1/guard_chat_completions", json={"messages": CANARY})
    assert response.status_code == 401, response.text
    assert CANARY not in response.text


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


def test_a_request_validation_error_handler_exists():
    """The cause, now removed.

    This asserted there was NO handler, and carried a tripwire: with one, the
    echo would not happen and these records should be reconsidered. The tripwire
    fired. The handler keeps `loc`, `type` and `msg` -- everything a caller needs
    to fix the request -- and drops the value.
    """
    import pathlib

    handlers = [
        str(path)
        for path in pathlib.Path("app").rglob("*.py")
        if "RequestValidationError" in (text := path.read_text()) and "exception_handler" in text
    ]
    assert handlers, "the handler is gone; the echo is back"


@pytest.mark.parametrize("family", FAMILIES, ids=lambda f: f.name)
def test_the_submitted_value_is_echoed_before_any_detector_runs(client, family):
    """One record per representation, emitted as a six-field signature."""
    encoded = family.encode(CANARY).decode("utf-8", "surrogateescape")
    response = client.post(
        "/v1/guard_chat_completions",
        json={"messages": encoded},
        headers={"Authorization": f"Bearer {BOOTSTRAP_KEY}"},
    )

    assert response.status_code == 422, response.text
    assert _is_a_body_error(response), f"the 422 is not about the request body: {response.text[:200]}"

    # Compare against the PARSED response, not the raw text. The unicode-escaped
    # form carries backslashes, which JSON re-escapes on the way out, so a
    # substring search over response.text misses it and reports no echo.
    echoed = any(encoded in value for value in _echoed_inputs(response))

    if echoed:
        # Record AND fail with the signature, so the failure is tied to the
        # occurrence that caused it. Accounting by node id alone excused any
        # failure this test happened to produce, including an unrelated one.
        RECORDER.record_and_fail(
            Signature(
                case_id=f"validation-echo/capture-off/guard/api/{family.name}",
                property="FORBIDDEN occurrence reached a surface",
                collector="http-response-body",
                surface_path=SURFACE,
                representation=family.name,
                occurrence_rule="FORBIDDEN",
            ),
            f"the {family.name} form of the canary was echoed in the 422 body "
            f"before any detector ran: {response.text[:200]}",
        )


def test_no_field_of_the_error_carries_the_submitted_value(client):
    """The surface_path named `$.detail[*].input`. Nothing is there now, and
    nothing is anywhere else in the entry either."""
    response = client.post(
        "/v1/guard_chat_completions",
        json={"messages": CANARY},
        headers={"Authorization": f"Bearer {BOOTSTRAP_KEY}"},
    )
    detail = json.loads(response.text)["detail"]
    # No entry carries the submitted value, under `input` or any other key. The
    # assertion is over the WHOLE entry rather than over `input` alone, so a
    # future pydantic field carrying the value fails here rather than leaking.
    assert CANARY not in json.dumps(detail), detail
    assert detail, "the caller must still be told which field was wrong"
    assert all(set(entry) <= {"type", "loc", "msg"} for entry in detail), detail


def test_the_canary_never_reached_a_detector(client):
    """Which is what makes this a validation-layer finding.

    If a detector had run, the case would belong to a different family and a
    different collector.
    """
    from app.scanner_engine import ScannerEngine

    engine = ScannerEngine.from_detectors({"emoji": {"enabled": True}})
    from tests.release.surfaces import recording_detector_inputs

    with recording_detector_inputs(engine) as inputs:
        client.post(
            "/v1/guard_chat_completions",
            json={"messages": CANARY},
            headers={"Authorization": f"Bearer {BOOTSTRAP_KEY}"},
        )

    assert not inputs.received, "a detector received the value, so this is not a pre-detector echo"
