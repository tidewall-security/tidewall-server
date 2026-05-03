"""E2E tests for sandbox page."""
import pytest

pytestmark = pytest.mark.e2e


def test_sandbox_pii_transformed(authed_page, server_url, console_errors):
    authed_page.goto(server_url + "/ui/sandbox")
    authed_page.click("button:has-text('Send PII')")
    authed_page.wait_for_selector("text=TRANSFORMED", timeout=15000)
    content = authed_page.text_content("main")
    assert "TRANSFORMED" in content
    assert "REDACTED" in content or "redacted" in content.lower()

    js_errors = [e for e in console_errors if "favicon" not in e]
    assert len(js_errors) == 0, f"Console errors: {js_errors}"


def test_sandbox_injection_blocked(authed_page, server_url, console_errors):
    authed_page.goto(server_url + "/ui/sandbox")
    authed_page.click("button:has-text('Prompt Injection')")
    authed_page.wait_for_selector("text=BLOCKED", timeout=15000)
    assert authed_page.is_visible("text=BLOCKED")

    js_errors = [e for e in console_errors if "favicon" not in e]
    assert len(js_errors) == 0, f"Console errors: {js_errors}"


def test_sandbox_clean_allowed(authed_page, server_url, console_errors):
    authed_page.goto(server_url + "/ui/sandbox")
    authed_page.click("button:has-text('Clean Request')")
    authed_page.wait_for_selector("text=ALLOWED", timeout=15000)
    assert authed_page.is_visible("text=ALLOWED")

    js_errors = [e for e in console_errors if "favicon" not in e]
    assert len(js_errors) == 0, f"Console errors: {js_errors}"


def test_sandbox_aws_key_blocked(authed_page, server_url, console_errors):
    authed_page.goto(server_url + "/ui/sandbox")
    authed_page.click("button:has-text('Leak AWS Key')")
    authed_page.wait_for_selector("text=BLOCKED", timeout=15000)
    assert authed_page.is_visible("text=BLOCKED")

    js_errors = [e for e in console_errors if "favicon" not in e]
    assert len(js_errors) == 0, f"Console errors: {js_errors}"
