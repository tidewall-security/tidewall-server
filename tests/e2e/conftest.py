"""E2E test fixtures."""

import os
import pathlib
import subprocess
import sys
import time

import pytest

# `requests` lives in the opt-in `e2e` group. Importing it at module scope
# would make the default (marker-deselected) run fail at collection purely to
# skip these tests.

_PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[2]
_DB_PATH = _PROJECT_ROOT / "data" / "e2e-test.db"
_BOOTSTRAP_KEY = "ak_e2e_bootstrap_key_for_tests_only"
_DB_URL = f"sqlite:///{_DB_PATH}"
_LOG_PATH = _PROJECT_ROOT / "data" / "e2e-server.log"
# Cold start downloads and loads several transformer models.
_STARTUP_TIMEOUT = int(os.environ.get("E2E_STARTUP_TIMEOUT", "180"))


def _tail_log(lines: int = 40) -> str:
    """Last few lines of the server log, for diagnostics on failure."""
    try:
        return "\n".join(_LOG_PATH.read_text().splitlines()[-lines:])
    except OSError:
        return "(no log)"


@pytest.fixture(scope="session")
def server_url():
    url = os.environ.get("TEST_SERVER_URL")
    if url:
        yield url
        return

    env = os.environ.copy()
    env["DB_URL"] = _DB_URL
    env["HOST"] = "127.0.0.1"
    env["PORT"] = "8090"
    # Startup now refuses a clean authenticated database with no API keys
    # rather than generating a credential it would have to log to deliver, so
    # the key must exist before the server starts — the fixture previously
    # created one only after waiting for /health, which it could never reach.
    env["BOOTSTRAP_KEY"] = _BOOTSTRAP_KEY

    # Clean up any previous test DB
    _DB_PATH.unlink(missing_ok=True)
    _DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    import requests

    log_file = open(_LOG_PATH, "w")
    proc = subprocess.Popen(
        # The package entry point, so the fixture exercises the launcher the
        # product documents rather than a path of its own. sys.executable
        # rather than a hard-coded .venv path, so `uv run` and non-standard
        # virtualenvs launch the interpreter that actually has the app synced.
        [sys.executable, "-m", "app"],
        stdout=log_file,
        stderr=log_file,
        env=env,
        cwd=str(_PROJECT_ROOT),
    )

    # Cold start loads several transformer models, which on a clean machine
    # includes downloading them. 30s was optimistic and produced a misleading
    # "Server failed to start" for what was really a slow first boot.
    deadline = time.monotonic() + _STARTUP_TIMEOUT
    while time.monotonic() < deadline:
        # A dead process will never answer, so waiting the full timeout for it
        # tells us nothing. Check liveness first and surface the reason.
        if proc.poll() is not None:
            log_file.close()
            raise RuntimeError(
                f"Server exited during startup with code {proc.returncode}.\n"
                f"--- {_LOG_PATH} (tail) ---\n{_tail_log()}"
            )
        try:
            if requests.get("http://localhost:8090/health", timeout=1).ok:
                break
        except requests.ConnectionError:
            pass
        time.sleep(1)
    else:
        proc.terminate()
        log_file.close()
        raise RuntimeError(
            f"Server did not become healthy within {_STARTUP_TIMEOUT}s.\n" f"--- {_LOG_PATH} (tail) ---\n{_tail_log()}"
        )

    yield "http://localhost:8090"

    # A server that died mid-suite is the real explanation for a cascade of
    # connection errors in later tests, so say so rather than leaving every
    # one of them to report a bare refusal.
    if proc.poll() is not None:
        log_file.close()
        raise RuntimeError(
            f"Server exited during the test run with code {proc.returncode}.\n"
            f"--- {_LOG_PATH} (tail) ---\n{_tail_log()}"
        )
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


_E2E_DIR = pathlib.Path(__file__).resolve().parent


def pytest_collection_modifyitems(items):
    """Mark everything in this package `e2e`.

    Applied at the package level rather than per test, so a new browser test
    cannot be added without the marker and silently rejoin the default run.

    The path check matters: pytest hands a subdirectory conftest *every*
    collected item, not just its own, so an unguarded loop marks the entire
    suite e2e and deselects all of it.
    """
    for item in items:
        if _E2E_DIR in pathlib.Path(str(item.fspath)).parents:
            item.add_marker(pytest.mark.e2e)
