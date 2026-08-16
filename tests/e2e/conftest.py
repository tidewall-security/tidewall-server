"""E2E test fixtures."""
import os
import pathlib
import subprocess
import time

import pytest
import requests

_PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[2]
_DB_PATH = _PROJECT_ROOT / "data" / "e2e-test.db"
_BOOTSTRAP_KEY = "ak_e2e_bootstrap_key_for_tests_only"
_DB_URL = f"sqlite:///{_DB_PATH}"
_LOG_PATH = _PROJECT_ROOT / "data" / "e2e-server.log"


@pytest.fixture(scope="session")
def server_url():
    url = os.environ.get("TEST_SERVER_URL")
    if url:
        yield url
        return

    env = os.environ.copy()
    env["AUTH_ENABLED"] = "true"
    env["DB_URL"] = _DB_URL
    # Startup now refuses a clean authenticated database with no API keys
    # rather than generating a credential it would have to log to deliver, so
    # the key must exist before the server starts — the fixture previously
    # created one only after waiting for /health, which it could never reach.
    env["BOOTSTRAP_KEY"] = _BOOTSTRAP_KEY

    # Clean up any previous test DB
    _DB_PATH.unlink(missing_ok=True)
    _DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    log_file = open(_LOG_PATH, "w")
    proc = subprocess.Popen(
        [".venv/bin/uvicorn", "app.main:app", "--port", "8090"],
        stdout=log_file,
        stderr=log_file,
        env=env,
        cwd=str(_PROJECT_ROOT),
    )

    for _ in range(30):
        try:
            resp = requests.get("http://localhost:8090/health", timeout=1)
            if resp.ok:
                break
        except requests.ConnectionError:
            pass
        time.sleep(1)
    else:
        proc.terminate()
        log_file.close()
        raise RuntimeError("Server failed to start")

    yield "http://localhost:8090"
    proc.terminate()
    proc.wait(timeout=5)
    log_file.close()
    _DB_PATH.unlink(missing_ok=True)


@pytest.fixture(scope="session")
def admin_key(server_url):
    key = os.environ.get("TEST_ADMIN_KEY")
    if key:
        return key

    # The server installed this as the bootstrap admin key at startup, so
    # there is no need to insert one afterwards — and inserting one afterwards
    # was impossible anyway, since startup refuses to come up without it.
    return _BOOTSTRAP_KEY


@pytest.fixture
def authed_page(page, server_url, admin_key):
    """Pre-set the API key then reload so onReady fires correctly."""
    page.goto(server_url + "/ui/visibility")
    page.evaluate(f"() => localStorage.setItem('tidewall_api_key', '{admin_key}')")
    page.reload()
    page.wait_for_selector("h1", timeout=10000)
    return page


@pytest.fixture
def console_errors(page):
    """Collect JS console errors during a test. Assert empty after test."""
    errors = []
    page.on("console", lambda msg: errors.append(msg.text) if msg.type == "error" else None)
    yield errors
