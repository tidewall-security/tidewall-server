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
    """The behaviour tests build a lightweight app. This proves the handler
    reaches the app the server actually serves.

    Asserting the key is PRESENT proves nothing: a bare FastAPI already
    registers a RequestValidationError handler, so that assertion passes on any
    application including one that never called install(). The identity is the
    only thing that distinguishes ours from the default.
    """
    from fastapi.exceptions import RequestValidationError

    from app.main import create_app
    from app.validation_errors import validation_error_handler

    assert create_app().exception_handlers[RequestValidationError] is validation_error_handler


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
    # `type` must be present and non-empty; its exact value is pydantic's, not
    # ours. Pinning the string made this fail when guard_input became a model
    # and the code went from "dict_type" to "model_attributes_type" -- a change
    # in nothing the caller cares about.
    assert detail[0]["type"]


# A body whose error actually carries a `ctx`. Not every validation error does:
# a wrong type for `guard_input` produces type/loc/msg/input and no ctx at all,
# so a test using one cannot observe whether ctx is dropped. A rejected
# `Literal` does carry it.
CTX_BEARING = {
    "guard_input": {"messages": [{"role": "user", "content": SECRET}]},
    "event_type": "nope",
}


def test_no_error_carries_a_value_field(client):
    """`ctx` is dropped wholesale, not audited field by field.

    It is a free-form dict whose contents vary by validator, so allowing it
    through would mean vetting every validator pydantic ships and every one it
    adds later. Assert on the whole payload rather than on named keys, so a new
    field arriving in a future version fails here.
    """
    c, api_key = client
    detail = _post(c, api_key, CTX_BEARING).json()["detail"]
    assert detail
    for error in detail:
        assert set(error) <= {"type", "loc", "msg"}, f"unexpected field: {set(error)}"


def test_the_chosen_body_really_produces_a_ctx(client):
    """Guards the test above. If pydantic stops emitting `ctx` for this input,
    the ctx assertion silently stops testing anything -- so prove the default
    handler would have emitted one."""
    from fastapi.exceptions import RequestValidationError

    from app.models import GuardRequest

    try:
        GuardRequest(**CTX_BEARING)
    except Exception as exc:  # pydantic ValidationError
        assert any("ctx" in error for error in exc.errors()), "this input no longer carries a ctx"
    else:
        raise AssertionError("the chosen body is no longer invalid")
    assert RequestValidationError


# --- Malformed shapes refuse, they do not crash -----------------------------
#
# Each of these returned 500 from inside the handler. `guard_input` was a bare
# `dict`, so nothing checked what was in it, and the route discovered the
# problem by failing on it: `" ".join(m.get("content", "") ...)` raises
# AttributeError when `messages` is a string and TypeError when a content is a
# number. An unknown `event_type` was worse -- it ran the entire guard and then
# raised inside the interaction log, so a caller got a 500 *after* their prompt
# had been scanned.


CRASHING_SHAPES = {
    "messages is a string": {"guard_input": {"messages": SECRET}},
    "content is a number": {"guard_input": {"messages": [{"role": "user", "content": 42}]}},
    "content is a list": {"guard_input": {"messages": [{"role": "user", "content": [SECRET]}]}},
    "unknown event_type": {
        "guard_input": {"messages": [{"role": "user", "content": "hi"}]},
        "event_type": "nope",
    },
}


@pytest.mark.parametrize("name,body", CRASHING_SHAPES.items(), ids=list(CRASHING_SHAPES))
def test_a_malformed_shape_is_refused_not_crashed(client, name, body):
    c, api_key = client
    response = _post(c, api_key, body)
    assert response.status_code == 422, f"{name} produced {response.status_code}"
    assert SECRET not in response.text


def test_a_real_message_still_passes(client):
    """The model must not be so strict it rejects what callers legitimately send.

    Without this, refusing everything would satisfy every test above. Real
    OpenAI messages carry fields this product never reads, and they must survive.
    """
    c, api_key = client
    response = _post(
        c,
        api_key,
        {"guard_input": {"messages": [{"role": "user", "content": "hello", "name": "bob", "tool_calls": []}]}},
    )
    assert response.status_code == 200


def test_the_event_type_vocabulary_has_one_definition():
    """It had two, in modules that never referenced each other.

    Adding a sixth type meant finding both copies; missing one would have been
    silent, and the request model now depends on the same set.
    """
    from app.interaction_log import _EVENT_TYPES as logged
    from app.models import EVENT_TYPES
    from app.services.export_service import _EVENT_TYPES as exported

    assert EVENT_TYPES is logged is exported

    # And the request model admits exactly that vocabulary -- pinned against the
    # set rather than restated, so the two cannot drift.
    from app.models import GuardRequest

    annotation = GuardRequest.model_fields["event_type"].annotation
    from typing import get_args

    assert set(get_args(annotation)) == set(EVENT_TYPES)
