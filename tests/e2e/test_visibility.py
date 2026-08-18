"""E2E tests for visibility page."""

import pytest

pytestmark = pytest.mark.e2e


def _seed_events(authed_page, server_url):
    authed_page.goto(server_url + "/ui/sandbox")
    authed_page.click("button:has-text('Send PII')")
    authed_page.wait_for_selector("text=TRANSFORMED", timeout=15000)
    authed_page.click("button:has-text('Clean Request')")
    authed_page.wait_for_selector("text=ALLOWED", timeout=15000)


def test_visibility_shows_nonzero_stats(authed_page, server_url):
    _seed_events(authed_page, server_url)
    authed_page.goto(server_url + "/ui/visibility")
    authed_page.wait_for_selector(".stat-card", timeout=10000)
    # Find the Total Events stat value
    stat_numbers = authed_page.query_selector_all(".stat-number")
    assert len(stat_numbers) > 0
    total_text = stat_numbers[0].text_content().strip().strip('"')
    assert int(total_text) > 0
