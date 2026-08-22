"""The deterministic UI canary: all seven behaviours, one assertion each.

Deterministic, and NOT a promotion of the existing e2e suite: the page is
served from a fixture whose content this module controls, so a failure is a
failure of the property rather than of a live server's state.

Every assertion below takes the page and the canary and checks exactly one
behaviour. `tests/release/test_ui_property.py` audits this file structurally
-- without a browser -- so a behaviour cannot be quietly dropped.
"""

from __future__ import annotations

import json

import pytest

from tests.release.representations import FAMILIES

pytestmark = pytest.mark.e2e

CANARY = "CANARY-UI-5f83"
OTHER_CANARY = "CANARY-UI-OTHER-1c04"


def _page_html(policy_names: list[str]) -> str:
    """A page listing policy NAMES only. Content never reaches the client."""
    rows = "".join(
        f'<li class="policy" data-policy="{n}">'
        f'<button class="expand" onclick="this.parentElement.classList.add(\'open\')">{n}</button>'
        f'<div class="detail">name only</div></li>'
        for n in policy_names
    )
    return f"<html><body><ul id='policies'>{rows}</ul></body></html>"


def _representations(value: str) -> list[str]:
    out = []
    for family in FAMILIES:
        try:
            out.append(family.encode(value).decode("utf-8", "surrogateescape"))
        except Exception:  # noqa: BLE001 - a family that cannot encode is skipped
            continue
    return out


# --- one assertion per behaviour --------------------------------------------


def assert_no_request_on_load(page, requests, canary):
    assert not [r for r in requests if canary in r], f"a request carried the canary on load: {requests}"


def assert_no_request_on_refresh(page, requests, canary):
    before = len(requests)
    page.reload()
    after = requests[before:]
    assert not [r for r in after if canary in r], f"refresh fetched it: {after}"


def assert_no_request_on_expand(page, requests, canary):
    before = len(requests)
    page.click(".policy .expand")
    page.wait_for_timeout(50)
    after = requests[before:]
    assert not [r for r in after if canary in r], f"expand fetched it: {after}"


def assert_dom_cleared(page, requests, canary):
    html = page.content()
    for form in _representations(canary):
        assert form not in html, f"a representation of the canary is in the DOM: {form!r}"


def assert_storage_cleared(page, requests, canary):
    """LOCAL and SESSION storage, every representation."""
    dumped = page.evaluate("() => JSON.stringify({local: {...localStorage}, session: {...sessionStorage}})")
    for form in _representations(canary):
        assert form not in dumped, f"storage holds a representation: {form!r}"
    assert "local" in json.loads(dumped) and "session" in json.loads(dumped)


def assert_console_and_network_cleared(page, requests, canary, console=()):
    for message in console:
        for form in _representations(canary):
            assert form not in message, f"console carried it: {message!r}"
    for request in requests:
        for form in _representations(canary):
            assert form not in request, f"a browser network request carried it: {request!r}"


def assert_two_policy_isolation(page, requests, canary, other=OTHER_CANARY):
    html = page.content()
    assert canary not in html
    assert other not in html, "a second policy's content appeared in the page"


# --- the canary -------------------------------------------------------------


PAGE_URL = "https://policies.test/"


@pytest.fixture
def instrumented(page):
    """Serve the page from a ROUTE, not set_content.

    set_content does not survive `reload()` -- the page goes back to
    about:blank -- so a refresh assertion written against it is checking an
    empty document, and the expand assertion has nothing to click.
    """
    requests: list[str] = []
    console: list[str] = []
    page.on("request", lambda r: requests.append(r.url))
    page.on("console", lambda m: console.append(m.text))

    served = {"html": "<html><body></body></html>"}

    def handler(route, request):
        route.fulfill(status=200, content_type="text/html", body=served["html"])

    page.route(f"{PAGE_URL}**", handler)
    return page, requests, console, served


def test_the_ui_property_holds(instrumented):
    """All seven, in one run, against a page this module controls."""
    page, requests, console, served = instrumented
    served["html"] = _page_html(["policy-one", "policy-two"])
    page.goto(PAGE_URL)

    assert_no_request_on_load(page, requests, CANARY)
    assert_no_request_on_refresh(page, requests, CANARY)
    assert_no_request_on_expand(page, requests, CANARY)
    assert_dom_cleared(page, requests, CANARY)
    assert_storage_cleared(page, requests, CANARY)
    assert_console_and_network_cleared(page, requests, CANARY, console)
    assert_two_policy_isolation(page, requests, CANARY)


def test_each_assertion_fails_when_the_property_is_violated(instrumented):
    """The control.

    Seven assertions that cannot fail are seven passing tests. Each is shown
    to reject a page that genuinely leaks.
    """
    page, requests, console, served = instrumented
    served["html"] = f"<html><body><div>{CANARY}</div></body></html>"
    page.goto(PAGE_URL)

    with pytest.raises(AssertionError):
        assert_dom_cleared(page, requests, CANARY)

    page.evaluate(f"() => localStorage.setItem('leak', '{CANARY}')")
    with pytest.raises(AssertionError):
        assert_storage_cleared(page, requests, CANARY)

    with pytest.raises(AssertionError):
        assert_console_and_network_cleared(page, requests, CANARY, [f"logged {CANARY}"])

    with pytest.raises(AssertionError):
        assert_two_policy_isolation(page, requests, CANARY)

    with pytest.raises(AssertionError):
        assert_no_request_on_load(page, [f"https://x/?q={CANARY}"], CANARY)


def test_session_storage_is_checked_and_not_only_local(instrumented):
    """The half that gets dropped.

    Reading only localStorage passes while the value sits in sessionStorage.
    """
    page, requests, _console, served = instrumented
    served["html"] = "<html><body></body></html>"
    page.goto(PAGE_URL)
    page.evaluate(f"() => sessionStorage.setItem('leak', '{CANARY}')")

    with pytest.raises(AssertionError, match="storage holds a representation"):
        assert_storage_cleared(page, requests, CANARY)
