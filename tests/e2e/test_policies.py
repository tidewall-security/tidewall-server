"""E2E tests for policies page."""
import pytest

pytestmark = pytest.mark.e2e


def test_policies_page_loads(authed_page, server_url):
    authed_page.goto(server_url + "/ui/policies")
    authed_page.wait_for_selector("h1", timeout=10000)
    assert authed_page.text_content("h1").strip() == "Policies"
    content = authed_page.text_content("main")
    assert "default" in content.lower() or "policy" in content.lower()
