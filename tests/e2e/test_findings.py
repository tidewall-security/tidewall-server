"""E2E tests for findings page."""
import pytest

pytestmark = pytest.mark.e2e


def test_findings_shows_events(authed_page, server_url):
    # Seed events
    authed_page.goto(server_url + "/ui/sandbox")
    authed_page.click("button:has-text('Send PII')")
    authed_page.wait_for_selector("text=TRANSFORMED", timeout=15000)

    authed_page.goto(server_url + "/ui/findings")
    authed_page.wait_for_selector("#eventsBody tr", timeout=10000)
    rows = authed_page.query_selector_all("#eventsBody tr")
    assert len(rows) >= 1
