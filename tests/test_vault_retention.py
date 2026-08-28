"""Deleting the mapping, and declining to collect one we cannot delete.

A vault holds the placeholder-to-original mapping that makes redaction
reversible, which is to say it holds exactly the values the product exists to
protect. Two things about that are tested here, and they are the same promise
seen from either end.

**Expired rows leave the table.** Refusing to serve one bounds what the API
discloses and bounds nothing on disk, so a key compromise would expose every
row ever written under that key rather than the hour the TTL advertises. The
sweep is what makes the hour true, and it is tested *through the scheduler*:
calling the purge directly proves the purge works and says nothing at all about
whether anything ever runs it -- which is the failure a deployment cannot see,
because the table simply grows.

**A deployment that cannot sweep does not collect.** The lifespan catches a
scheduler that fails to start, logs it, and serves anyway with a green
``/health``. Hanging vault deletion off that as it stands would let such a
deployment write PII rows forever while looking healthy -- the TTL quietly
false again, in a different way. So the keyring reaches the vault manager only
after the scheduler has started: no key means no row, redaction stands and is
irreversible, and the caller is told so by the absence of a token rather than
by a promise nothing can keep.

That gate is why this file also drives the whole feature end to end. Task 3 is
what turns real PII persistence on -- before it, the lifespan built the manager
with no keyring at all and every save declined -- so the test that the wiring
works and the test that it can be withheld are two halves of one change.
"""

from __future__ import annotations

import asyncio
import base64
import logging
import os
import time
from contextlib import ExitStack, contextmanager
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

import app.services.scheduler as scheduler_module
from app.config import Settings
from app.db.engine import get_engine, get_session_factory
from app.db.models import Base, RuleSet
from app.main import create_app
from app.services.scheduler import Scheduler, vault_retention_job
from app.vault_crypto import Keyring
from app.vault_manager import VaultManager

from .test_guard_failure_enforcement import _install
from .test_guard_vault_writeback import CONTENT, _detector, _redacted_text, _VaultRedactor
from .test_vault_manager import SECRET, _ago, _material, _populated, _ring, _rows

#: Long enough to be a credential and fixed so the request can present it.
BOOTSTRAP = "test-bootstrap-key-0123456789"


@pytest.fixture
def session_factory(tmp_path):
    """A file database, not ``:memory:``, and the difference is load bearing.

    An in-memory SQLite engine uses ``StaticPool``, so every session in the
    process shares one connection -- including the sweep's, which runs in a
    worker thread. A reader on that same connection sees the sweep's
    uncommitted DELETE, so a purge that never commits still looks like it
    worked. Separate connections make the commit real, and production is a file
    anyway.
    """
    engine = get_engine(f"sqlite:///{tmp_path / 'vaults.db'}")
    Base.metadata.create_all(engine)
    return get_session_factory(engine)


# ---------------------------------------------------------------------------
# The sweep, driven by the scheduler rather than by hand
# ---------------------------------------------------------------------------


def _sweep(session_factory, *, until=None, timeout: float = 5.0) -> None:
    """Start the scheduler the way the lifespan does, and let its job run.

    Deliberately not ``await job.run()``. The job running when a test calls it
    is not the property under test; the property is that starting the scheduler
    is enough.
    """

    async def _main() -> None:
        scheduler = Scheduler()
        scheduler.start([vault_retention_job(session_factory, interval_seconds=0.01, scheduler=scheduler)])
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            await asyncio.sleep(0.02)
            if until is None or until():
                break
        await scheduler.stop()

    asyncio.run(_main())


def test_the_real_scheduler_deletes_an_expired_vault_row(session_factory):
    """Absence from the table, reached by starting the scheduler and nothing else."""
    manager = VaultManager(session_factory, keyring=_ring())
    expired, _ = _populated(manager, expires_at=_ago(hours=1))
    assert _rows(session_factory) == [expired], "the test did not write the row it means to sweep"

    _sweep(session_factory, until=lambda: _rows(session_factory) == [])

    assert _rows(session_factory) == [], "an expired mapping survived a scheduler that was running"


def test_a_live_vault_row_is_not_swept(session_factory):
    """The sweep is a deletion by expiry, not a truncation.

    Both rows are written and the wait is on the expired one, so the sweep is
    known to have run rather than assumed to have: a test that waits a moment
    and then asserts the live row survives passes just as well against a job
    that never ran at all.
    """
    manager = VaultManager(session_factory, keyring=_ring())
    expired, _ = _populated(manager, "gone@example.com", expires_at=_ago(hours=1))
    live, _ = _populated(manager, "kept@example.com")

    _sweep(session_factory, until=lambda: expired not in _rows(session_factory))

    assert _rows(session_factory) == [live], "the sweep took a row that had not expired"


# ---------------------------------------------------------------------------
# The gate: the real application, started through the real lifespan
# ---------------------------------------------------------------------------


def _declaration() -> str:
    return f"k1:{_material()}"


def _keyring(declaration: str) -> Keyring:
    ring = Keyring.from_settings(Settings(VAULT_ENCRYPTION_KEYS=declaration, VAULT_ENCRYPTION_CURRENT="k1"))
    assert ring is not None
    return ring


def _wait_until(predicate, *, timeout: float = 5.0) -> bool:
    """Poll from the test thread while the server's own loop runs in its own."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.02)
    return predicate()


def _env(tmp_path, name: str, declaration: str) -> dict[str, str]:
    return {
        "DB_URL": f"sqlite:///{tmp_path / f'{name}.db'}",
        "BOOTSTRAP_KEY": BOOTSTRAP,
        "VAULT_ENCRYPTION_KEYS": declaration,
        "VAULT_ENCRYPTION_CURRENT": "k1",
    }


def _unstartable(*_args, **_kwargs):
    raise RuntimeError("scheduler unavailable")


@contextmanager
def _recorded_errors():
    """Every ``logger.error`` call made while this is open.

    Captured at the call rather than at a handler, because Alembic runs
    ``fileConfig`` during the startup migrations and that replaces the root
    handlers -- so ``caplog``, and anything attached beforehand, sees nothing.
    """
    records: list[str] = []
    real_error = logging.Logger.error

    def _record(self, msg, *args, **kwargs):
        records.append(str(msg))
        return real_error(self, msg, *args, **kwargs)

    with patch.object(logging.Logger, "error", _record):
        yield records


def _install_the_redactor(app, client) -> None:
    """Leave the live engine holding one detector, which redacts into the vault.

    The seeded default policy names transformer models, and building its engine
    would load them. Nothing here is about what a detector detects; it is about
    what the lifespan wired behind one.
    """
    factory = app.state.session_factory
    with factory() as session:
        for rule_set in session.query(RuleSet).all():
            rule_set.detectors = {}
        session.commit()
    app.state.policy_service._engine_cache.clear()
    _install(client, factory, [_detector(_VaultRedactor, "redact")])


@contextmanager
def _running_server(tmp_path, name: str, declaration: str, *, break_the_scheduler: bool = False):
    """The real app, through the real lifespan, with a keyring configured.

    ``TestClient`` as a context manager is what runs the lifespan, which is the
    point: the wiring under test is startup's, and a hand-built app would test
    the test's wiring instead.
    """
    with ExitStack() as stack:
        stack.enter_context(patch.dict(os.environ, _env(tmp_path, name, declaration), clear=False))
        if break_the_scheduler:
            stack.enter_context(patch.object(scheduler_module, "Scheduler", _unstartable))
        app = create_app()
        client = stack.enter_context(TestClient(app))
        _install_the_redactor(app, client)
        yield app, client


def _post(client):
    return client.post(
        "/v1/guard_chat_completions",
        headers={"Authorization": f"Bearer {BOOTSTRAP}"},
        json={"guard_input": {"messages": [{"role": "user", "content": CONTENT}]}, "event_type": "input"},
    )


def test_a_lifespan_whose_scheduler_fails_to_start_redacts_irreversibly(tmp_path):
    """No sweep, no collection -- and the caller is told by the missing token.

    A key is configured, so every other part of the system is willing to store
    the mapping. What withholds it is that nothing would ever delete it.
    """
    with _recorded_errors() as errors:
        with _running_server(tmp_path, "no-sweep", _declaration(), break_the_scheduler=True) as (app, client):
            assert app.state.scheduler is None, "the test did not actually stop the scheduler starting"

            body = _post(client).json()

            assert body["result"]["transformed"] is True, "the request was not redacted at all"
            assert SECRET not in _redacted_text(body), "the original survived into the response"
            assert body["result"]["fpe_context"] is None, "a reversal was promised by a deployment that cannot delete"
            assert _rows(app.state.session_factory) == [], "PII was written where nothing would ever sweep it"

    # A feature switching itself off is the operator's business. This log line
    # is the only place the deployment says so: /health stays green, the
    # requests keep succeeding, and the missing token is visible only to a
    # caller who was looking for one.
    assert any(
        "reversible redaction is DISABLED" in message for message in errors
    ), f"reversible redaction switched itself off without saying so; errors were {errors}"


def test_a_started_scheduler_stores_a_row_a_cold_reader_opens(tmp_path):
    """The other half of the same wiring, end to end.

    A genuinely separate engine on the same file, and a manager with an empty
    cache: as close as a test gets to the process that did not do the
    redacting, which is the reader this whole feature exists for.
    """
    declaration = _declaration()
    with _running_server(tmp_path, "swept", declaration) as (app, client):
        assert app.state.scheduler is not None, "the scheduler did not start, so this proves nothing"

        body = _post(client).json()
        token = body["result"]["fpe_context"]

        assert token, "a redaction was returned with no way to reverse it"
        assert _rows(app.state.session_factory) != [], "the token names a vault that was never written"

        cold = VaultManager(get_session_factory(get_engine(os.environ["DB_URL"])), keyring=_keyring(declaration))
        recovered = cold.get_vault(cold.decode_fpe_context(token))

        assert recovered is not None, "the row is there and a cold reader could not open it"
        assert recovered.unredact(_redacted_text(body)) == CONTENT


def test_a_scheduler_that_raises_partway_through_start_also_disables_reversibility(tmp_path):
    """``scheduler is not None`` is a different question, and a comment saying so
    is not a test.

    The reference is deliberately kept after a partial start, so shutdown can
    stop the tasks that were already created. What startup cannot know is how
    far ``start()` got -- which jobs exist and which do not -- so an exception
    from it leaves the sweep's status unknown, and unknown is not good enough
    to begin collecting the mapping.
    """
    real_start = scheduler_module.Scheduler.start

    def _start_then_fail(self, jobs):
        real_start(self, jobs)  # the tasks now exist
        raise RuntimeError("reporting blew up after the tasks were created")

    with patch.object(scheduler_module.Scheduler, "start", _start_then_fail):
        with _running_server(tmp_path, "partial", _declaration()) as (app, client):
            assert app.state.scheduler is not None, "the test did not produce a partial start"

            body = _post(client).json()

            assert body["result"]["transformed"] is True, "the request was not redacted at all"
            assert body["result"]["fpe_context"] is None, "a reversal was promised on an unknown schedule"
            assert _rows(app.state.session_factory) == [], "PII was written on an unknown schedule"


def test_startup_schedules_the_vault_sweep(tmp_path):
    """Whether the lifespan asks for the sweep, which nothing else here would notice.

    The sweep tests above build the job themselves and the gate tests turn on
    whether the scheduler started at all, so a startup that simply omitted this
    job would pass every one of them -- and would collect the mapping and never
    reclaim it, which is the failure the gate exists to prevent, reached from
    the other side.

    Two boots, because the job runs the moment the scheduler starts: the first
    creates the schema, the row is written between them, and the second must
    find it gone. The reader is a separate engine on the same file, so nothing
    is being answered out of the server's own cache.
    """
    declaration = _declaration()
    with _running_server(tmp_path, "scheduled", declaration):
        pass

    factory = get_session_factory(get_engine(f"sqlite:///{tmp_path / 'scheduled.db'}"))
    expired, _ = _populated(VaultManager(factory, keyring=_keyring(declaration)), expires_at=_ago(hours=1))
    assert _rows(factory) == [expired], "the test did not write the row it means to sweep"

    with _running_server(tmp_path, "scheduled", declaration):
        _wait_until(lambda: _rows(factory) == [])

    assert _rows(factory) == [], "startup never scheduled the vault sweep"


def test_the_withheld_case_does_not_claim_no_key_is_configured(tmp_path):
    """The per-request decline must name the real reason.

    In the degraded state a key IS configured; it was withheld because retention
    could not be scheduled. Saying "no vault encryption key is configured" sends
    an operator to check a configuration that turns out to be fine -- and the
    startup line one screen earlier says the opposite, so the two contradict
    each other in the same boot.
    """
    from app.vault import TidewallVault
    from app.vault_manager import VaultManager

    engine = get_engine(f"sqlite:///{tmp_path}/withheld.db")
    Base.metadata.create_all(engine)
    reason = "a vault encryption key is configured but was withheld, because vault retention could not be scheduled"
    manager = VaultManager(get_session_factory(engine), keyring=None, no_keyring_reason=reason)

    vault = TidewallVault()
    vault.store("EMAIL", "ada@example.com")

    errors: list[str] = []
    with patch.object(
        logging.getLogger("app.vault_manager"), "error", side_effect=lambda msg, *a, **k: errors.append(msg % a)
    ):
        assert manager.save("v1", vault, None) is False

    assert errors, "the decline was silent"
    assert reason in errors[0]
    assert "no vault encryption key is configured" not in errors[0]


def test_an_unusable_keyring_declaration_stops_startup(monkeypatch):
    """A CURRENT naming a key nobody declared must not boot quietly.

    Before this branch it did: the server started, reversible redaction was
    silently off, and the only symptom was a per-request log line. The point of
    raising is to stop in front of the operator who wrote the mistake.
    """
    from app.vault_crypto import Keyring

    monkeypatch.setenv("VAULT_ENCRYPTION_KEYS", f"k1:{base64.b64encode(os.urandom(32)).decode()}")
    monkeypatch.setenv("VAULT_ENCRYPTION_CURRENT", "k9-never-declared")

    with pytest.raises(ValueError):
        Keyring.from_settings(Settings.from_env())
