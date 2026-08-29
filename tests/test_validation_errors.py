"""A rejected request must not be quoted back.

FastAPI's default handler for a validation error puts the offending value in
the response as `input`. For most services that is a convenience; for this one
it inverts the product. The whole purpose is to stop sensitive text reaching
places it should not, and the error path handed it straight back.

The caller supplied the value, so this is not disclosure to a new party. But a
response body travels much further than the request did -- `app/routes/guard.py`
records the same reasoning for its own payload: proxies, APM tools, browser
devtools and the caller's own logging all see a response, and a prompt rejected
for its shape is rather more likely to reach an error tracker than one accepted.

These are the release gate's `validation-echo` records, which were declared
across seven representations of the same value. The fix drops the field rather
than filtering it, so every representation is covered by construction -- but a
few are exercised here anyway, because "covered by construction" is an argument
and a test is evidence.
"""

from __future__ import annotations

import json
import urllib.parse

import pytest
from fastapi.testclient import TestClient

from app.validation_errors import install

from .test_guard_routes import _make_app_and_client

SECRET = "my-ssn-is-123-45-6789"


@pytest.fixture
def client():
    c, _admin, api_key, _viewer, _sf = _make_app_and_client()
    # Through the same call production makes, not a hand-wired handler: the
    # defect was that nothing installed this anywhere, so wiring it by hand here
    # would test the half that was never broken.
    install(c.app)
    return TestClient(c.app, raise_server_exceptions=False), api_key


def test_the_real_application_installs_it():
    """The behaviour tests build a lightweight app. This one proves the handler
    reaches the app the server actually serves."""
    from fastapi.exceptions import RequestValidationError

    from app.main import create_app

    assert RequestValidationError in create_app().exception_handlers


def _post(client, api_key, body):
    return client.post(
        "/v1/guard_chat_completions",
        json=body,
        headers={"Authorization": f"Bearer {api_key}"},
    )


REPRESENTATIONS = {
    "plain": SECRET,
    "percent-encoded": urllib.parse.quote(SECRET),
    "unicode-escaped": SECRET.encode("unicode_escape").decode(),
    "json-escaped": json.dumps(SECRET),
    "nfc": "my-ssn-is-123-45-6789́",
}


@pytest.mark.parametrize("name,value", REPRESENTATIONS.items(), ids=list(REPRESENTATIONS))
def test_a_rejected_body_is_not_echoed(client, name, value):
    c, api_key = client
    response = _post(c, api_key, {"guard_input": value})
    assert response.status_code == 422
    assert value not in response.text, f"{name} was quoted back in the error"


def test_the_error_still_says_what_was_wrong(client):
    """Dropping the value must not cost the caller the ability to fix the call.

    Without this, deleting the whole detail would pass the test above.
    """
    c, api_key = client
    detail = _post(c, api_key, {"guard_input": SECRET}).json()["detail"]
    assert detail, "the caller was told nothing at all"
    assert detail[0]["loc"] == ["body", "guard_input"]
    assert detail[0]["msg"]
    assert detail[0]["type"] == "dict_type"


def test_no_error_carries_a_value_field(client):
    """`ctx` is dropped wholesale, not audited field by field.

    It is a free-form dict whose contents vary by validator, so allowing it
    through would mean vetting every validator pydantic ships and every one it
    adds later. Assert on the whole payload rather than on named keys, so a new
    field arriving in a future version fails here.
    """
    c, api_key = client
    for error in _post(c, api_key, {"guard_input": SECRET}).json()["detail"]:
        assert set(error) <= {"type", "loc", "msg"}, f"unexpected field: {set(error)}"
