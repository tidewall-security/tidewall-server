"""E2E tests for auth flow."""
import pytest

pytestmark = pytest.mark.e2e


def test_auth_overlay_appears_without_key(page, server_url):
    """No stored key → auth overlay must appear."""
    page.goto(server_url + "/ui/visibility")
    page.evaluate("() => localStorage.removeItem('tidewall_api_key')")
    page.reload()
    page.wait_for_selector("#auth-overlay", timeout=5000)
    assert page.is_visible("#auth-overlay")


def test_auth_overlay_has_input_and_button(page, server_url):
    """Auth overlay has a key input and submit button."""
    page.goto(server_url + "/ui/visibility")
    page.evaluate("() => localStorage.removeItem('tidewall_api_key')")
    page.reload()
    page.wait_for_selector("#auth-key-input", timeout=5000)
    assert page.is_visible("#auth-key-input")
    assert page.is_visible("#auth-key-submit")


def test_auth_no_console_errors_before_key_entered(page, server_url, console_errors):
    """Before key is entered, no JS errors should fire (no premature API calls)."""
    page.goto(server_url + "/ui/visibility")
    page.evaluate("() => localStorage.removeItem('tidewall_api_key')")
    page.reload()
    page.wait_for_selector("#auth-overlay", timeout=5000)
    page.wait_for_timeout(2000)  # Wait for any async errors to surface

    # Filter out expected 401s (auth check + favicon) and resource loading errors
    js_errors = [e for e in console_errors
                 if "favicon" not in e
                 and "Failed to load resource" not in e]
    assert len(js_errors) == 0, f"Unexpected console errors before auth: {js_errors}"


def test_auth_full_flow_enter_key_then_data_loads(page, server_url, admin_key, console_errors):
    """Full flow: no key → overlay → type key → submit → data loads without errors."""
    page.goto(server_url + "/ui/visibility")
    page.evaluate("() => localStorage.removeItem('tidewall_api_key')")
    page.reload()

    # Overlay should appear
    page.wait_for_selector("#auth-key-input", timeout=5000)

    # Enter key and submit
    page.fill("#auth-key-input", admin_key)
    page.click("#auth-key-submit")

    # Wait for the overlay to go, not for h1.
    #
    # The page shell is public now, so its h1 is already in the DOM behind the
    # overlay before authentication happens. Waiting for h1 therefore returns
    # immediately and the overlay assertion races the submit handler. The
    # overlay disappearing is the actual signal that authentication succeeded.
    page.wait_for_selector("#auth-overlay", state="detached", timeout=10000)
    assert page.text_content("h1").strip() == "Visibility"

    # No unexpected JS errors (401 resource loads are expected during auth check)
    js_errors = [e for e in console_errors
                 if "favicon" not in e
                 and "Failed to load resource" not in e]
    assert len(js_errors) == 0, f"Console errors after auth: {js_errors}"


def test_auth_pre_stored_key_no_overlay(authed_page, server_url, console_errors):
    """Pre-stored valid key → page loads directly, no overlay, no errors."""
    authed_page.goto(server_url + "/ui/visibility")
    authed_page.wait_for_selector("h1", timeout=5000)
    assert not authed_page.is_visible("#auth-overlay")
    assert authed_page.text_content("h1").strip() == "Visibility"

    js_errors = [e for e in console_errors if "favicon" not in e]
    assert len(js_errors) == 0, f"Console errors with pre-stored key: {js_errors}"
