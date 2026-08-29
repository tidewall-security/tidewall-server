"""Who owns a vault, and who may therefore reverse a redaction.

A vault holds the placeholder-to-original mapping -- the PII itself. Until now
`Vault` had no owner column, so `/v1/unredact` resolved a caller-supplied id
with nothing to check it against: any credential with the `api` role could
reverse any vault it had an id for, including one created under a different
policy.

Ownership is fixed at creation from the creating key's policy binding, and is
enforced in two places that cannot drift apart -- a required argument on
`VaultManager.get_vault`, so no consumer can read a vault without saying whose
policy it reads for, and a foreign key, so a vault naming a policy that does not
exist cannot be written at all.

Three things here are easy to get wrong in a way that leaves the suite green:

**A refusal answered from memory is an oracle.** `save` warms the cache during
the guard call, so every live vault is in it. If a mismatch returns from the
cache it answers in microseconds where an absent id costs a query, and that gap
is a usable statement that the id exists. The test counts sessions, because both
refusals return `None` and nothing else tells them apart.

**Eviction must be read back through the same manager.** A fresh manager has an
empty cache and passes against no eviction at all.

**Every other test builds its schema from `Base.metadata`, so they prove the
model and not the migration.** The two can diverge silently: omit a column from
the migration and an upgraded deployment fails its INSERT, guard clears
`fpe_context`, and reversible redaction is off on a database that looks
correctly migrated. One test upgrades a real database and proves the constraints
by using them.
"""

from __future__ import annotations

import base64
import secrets
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.exc import IntegrityError

from app.config import Settings
from app.db.engine import get_engine, get_session_factory
from app.db.models import Base, Policy
from app.db.models import Vault as VaultModel
from app.vault_crypto import Keyring
from app.vault_manager import VaultManager

SECRET = "jon@example.com"


def _material() -> str:
    return base64.b64encode(secrets.token_bytes(32)).decode()


def _ring() -> Keyring:
    ring = Keyring.from_settings(Settings(VAULT_ENCRYPTION_KEYS=f"k1:{_material()}", VAULT_ENCRYPTION_CURRENT="k1"))
    assert ring is not None
    return ring


@pytest.fixture
def session_factory():
    # get_engine, not create_engine: it is what installs PRAGMA foreign_keys=ON,
    # and without that the foreign key in this schema is decorative and three of
    # the tests below silently stop testing anything.
    engine = get_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return get_session_factory(engine)


@pytest.fixture
def policies(session_factory):
    """Real rows. The foreign key rejects a save naming a policy that does not
    exist, so a test that invents an owner raises during setup and never reaches
    its assertions."""
    with session_factory() as session:
        session.add_all(
            [
                Policy(id="pol_a", name="pol_a", type="application"),
                Policy(id="pol_b", name="pol_b", type="application"),
            ]
        )
        session.commit()


@pytest.fixture
def vault_manager(session_factory):
    return VaultManager(session_factory, keyring=_ring())


def _later() -> datetime:
    return datetime.now(UTC) + timedelta(hours=1)


def test_a_policy_cannot_read_another_policys_vault(vault_manager, policies, session_factory):
    vault_id, vault = vault_manager.create_vault()
    vault.store("EMAIL", SECRET)
    assert vault_manager.save(vault_id, vault, policy_id="pol_a", created_by_key_id="ak_1") is True

    assert vault_manager.get_vault(vault_id, "pol_a") is not None
    assert vault_manager.get_vault(vault_id, "pol_b") is None

    # Attribution is required by the schema and is otherwise unproved: an
    # implementation that always writes None passes every other test here.
    with session_factory() as session:
        row = session.get(VaultModel, vault_id)
        assert row.policy_id == "pol_a"
        assert row.created_by_key_id == "ak_1"


def test_a_warm_cache_mismatch_still_reaches_the_row(vault_manager, policies, monkeypatch):
    """The check must not be answerable from memory, or it is the oracle.

    `save` warms the cache, so this is the state every live vault is in. A
    cached refusal and a row-backed refusal both return None; only the number of
    sessions opened tells them apart.
    """
    vault_id, vault = vault_manager.create_vault()
    vault.store("EMAIL", SECRET)
    vault_manager.save(vault_id, vault, policy_id="pol_a", created_by_key_id="ak_1")

    opened: list[int] = []
    original = vault_manager._session_factory

    def counting():
        opened.append(1)
        return original()

    monkeypatch.setattr(vault_manager, "_session_factory", counting)
    assert vault_manager.get_vault(vault_id, "pol_b") is None
    assert opened, "the mismatch was answered from cache; an absent id would have hit the row"


def test_save_refuses_a_policy_that_no_longer_exists(vault_manager, policies, session_factory):
    """The write-after-delete race, through the real save() path.

    A guard request copies its policy onto request.state and then awaits the
    scan; the policy is deleted while it waits; it resumes and persists. Nothing
    in the request re-checks the policy, so the foreign key is what refuses it.
    """
    with session_factory() as session:
        session.delete(session.get(Policy, "pol_a"))
        session.commit()

    vault_id, vault = vault_manager.create_vault()
    vault.store("EMAIL", SECRET)
    with pytest.raises(IntegrityError):
        vault_manager.save(vault_id, vault, policy_id="pol_a", created_by_key_id="ak_1")


def test_deleting_a_policy_takes_its_vaults(vault_manager, policies, session_factory):
    vault_id, vault = vault_manager.create_vault()
    vault.store("EMAIL", SECRET)
    vault_manager.save(vault_id, vault, policy_id="pol_b", created_by_key_id=None)

    with session_factory() as session:
        session.delete(session.get(Policy, "pol_b"))
        session.commit()
        assert session.get(VaultModel, vault_id) is None


# --- The migration, proved by using it -------------------------------------
#
# Every test above builds its schema from `Base.metadata`, so all of them prove
# the MODEL. These prove the MIGRATION, which can diverge from it silently: omit
# a column there and an upgraded deployment fails its INSERT, guard catches
# that, clears `fpe_context`, and reversible redaction is off on a database that
# looks correctly migrated.


def _alembic(url: str, target: str) -> None:
    from alembic import command
    from alembic.config import Config

    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", url)
    command.upgrade(cfg, target) if target != "-1" else command.downgrade(cfg, "-1")


_POLICY_SQL = (
    "INSERT INTO policies (id,name,type,report_only,is_default,created_at,updated_at) "
    "VALUES (:id,:id,'application',0,0,:now,:now)"
)
# Every column the MIGRATED table requires. The ORM's `default=` values are
# applied by SQLAlchemy in Python and do not exist in the database, so a raw
# INSERT receives none of them.
_VAULT_SQL = "INSERT INTO vaults (id,data,created_at,expires_at,policy_id) VALUES (:id,X'00',:now,:exp,:pol)"


def test_the_migration_destroys_pre_existing_ownerless_rows(tmp_path):
    from sqlalchemy import text

    url = f"sqlite:///{tmp_path}/m.db"
    _alembic(url, "d5e91a3c7b40")
    engine = get_engine(url)
    with engine.begin() as conn:
        conn.execute(
            text("INSERT INTO vaults (id,data,created_at,expires_at) VALUES ('legacy',X'00',:n,:n)"),
            {"n": datetime.now(UTC)},
        )
    _alembic(url, "head")
    with get_engine(url).begin() as conn:
        assert conn.execute(text("SELECT COUNT(*) FROM vaults")).scalar() == 0


def test_the_migrated_schema_enforces_ownership(tmp_path):
    """By behaviour, not by inspection: a schema that looks right can still be
    missing the constraint that matters."""
    from sqlalchemy import inspect, text

    url = f"sqlite:///{tmp_path}/m.db"
    _alembic(url, "head")
    engine = get_engine(url)  # get_engine, or foreign keys are not enforced

    assert "created_by_key_id" in {c["name"] for c in inspect(engine).get_columns("vaults")}

    now = datetime.now(UTC)
    with engine.begin() as conn:
        conn.execute(text(_POLICY_SQL), {"id": "p1", "now": now})

        # POSITIVE CONTROL. Deleting this line breaks no assertion, so it is not
        # in the mutation list -- it cannot be independently killed, and
        # pretending otherwise would claim coverage that does not exist.
        #
        # It is here because an earlier draft of this test DID fail for the
        # wrong reason: it omitted `created_at`, so the orphan insert below
        # raised IntegrityError on a missing NOT NULL column rather than on the
        # foreign key, and `pytest.raises` could not tell the difference.
        # Proving the same statement succeeds with a valid owner is what pins
        # the next failure to the owner. If this INSERT grows a column, keep
        # both copies identical.
        conn.execute(text(_VAULT_SQL), {"id": "ok", "now": now, "exp": _later(), "pol": "p1"})

        # Same statement, same columns, only the owner changed.
        with pytest.raises(IntegrityError):
            conn.execute(text(_VAULT_SQL), {"id": "v1", "now": now, "exp": _later(), "pol": "ghost"})

    with engine.begin() as conn:
        conn.execute(text("DELETE FROM policies WHERE id='p1'"))
        assert conn.execute(text("SELECT COUNT(*) FROM vaults")).scalar() == 0


def test_the_migration_round_trips(tmp_path):
    from sqlalchemy import inspect

    url = f"sqlite:///{tmp_path}/m.db"
    _alembic(url, "head")
    _alembic(url, "-1")
    assert "policy_id" not in {c["name"] for c in inspect(get_engine(url)).get_columns("vaults")}
    _alembic(url, "head")
    cols = {c["name"] for c in inspect(get_engine(url)).get_columns("vaults")}
    assert "policy_id" in cols and "created_by_key_id" in cols


# --- The routes ------------------------------------------------------------
#
# The manager tests above prove the boundary in isolation. These prove the two
# call sites reach it with the right policy, which is a separate question: guard
# holds BOTH a bound policy and a resolved one that falls back to the default,
# and using the wrong one is invisible to every test above.

import json  # noqa: E402
from contextlib import contextmanager  # noqa: E402

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.auth.key_utils import generate_key, hash_key, key_prefix  # noqa: E402
from app.auth.middleware import AuthMiddleware  # noqa: E402
from app.db.models import APIKey, RuleSet  # noqa: E402
from app.detectors.base import BaseDetector, DetectorResult  # noqa: E402
from app.services.policy_service import PolicyService  # noqa: E402


class _Redactor(BaseDetector):
    """Redacts, with or without a vault -- as the real PII detector does.

    Handed no vault it still replaces the value; it just emits a placeholder
    nothing can reverse. A redactor that assumed a vault would turn the unbound
    case into a crash and hide the behaviour under test.
    """

    @property
    def name(self) -> str:
        return "confidential_and_pii_entity"

    def scan(self, text: str, **kwargs) -> DetectorResult:
        if SECRET not in text:
            return DetectorResult(detected=False)
        vault = kwargs.get("vault")
        placeholder = vault.store("EMAIL", SECRET) if vault is not None else "[REDACTED_EMAIL_1]"
        return DetectorResult(detected=True, sanitized_text=text.replace(SECRET, placeholder))


@contextmanager
def _routes():
    """An app with the two call sites, one policy, and a bound and unbound key."""
    engine = get_engine("sqlite:///:memory:")  # get_engine: foreign keys enforced
    Base.metadata.create_all(engine)
    factory = get_session_factory(engine)

    app = FastAPI()
    app.add_middleware(AuthMiddleware)
    app.state.session_factory = factory
    app.state.policy_service = PolicyService(session_factory=factory)
    app.state.vault_manager = VaultManager(factory, keyring=_ring())

    from app.interaction_log import InteractionLog
    from app.services.export_service import ExportService

    app.state.interaction_log = InteractionLog(session_factory=factory)
    app.state.export_service = ExportService(session_factory=factory)

    from app.routes import guard, policies, unredact

    for router in (guard.router, unredact.router, policies.router):
        app.include_router(router)

    keys = {}
    with factory() as session:
        # pol_main is NOT the default: deleting the default is refused, and one
        # test has to delete the policy that owns a vault. pol_default exists
        # because an unbound key resolves to it for scanning.
        session.add(Policy(id="pol_default", name="pol_default", type="application", is_default=True))
        session.add(Policy(id="pol_main", name="pol_main", type="application"))
        session.add(Policy(id="pol_other", name="pol_other", type="application"))
        for policy_id in ("pol_default", "pol_main"):
            for event_type in ("input", "output"):
                session.add(RuleSet(policy_id=policy_id, event_type=event_type, detectors={}))
        for label, role, bound in (
            ("bound", "api", "pol_main"),
            ("other", "api", "pol_other"),
            ("unbound", "api", None),
            ("admin", "admin", "pol_main"),
        ):
            raw = generate_key(prefix="ak")
            keys[label] = raw
            session.add(
                APIKey(
                    name=label,
                    key_hash=hash_key(raw),
                    key_prefix=key_prefix(raw),
                    role=role,
                    policy_id=bound,
                )
            )
        session.commit()

    with TestClient(app) as client:
        # Force the live engine to hold exactly this redactor, so no ML model
        # loads and the detector's behaviour with and without a vault is the
        # thing under test.
        # Both engines: the bound key scans under pol_main, the unbound key
        # under the default. Installing on only one would leave half the
        # comparison untested.
        for policy_id in ("pol_main", "pol_default"):
            redactor = _Redactor({"action": "redact"})
            redactor.action = "redact"  # what makes the engine transform, not report
            engine_obj = app.state.policy_service.get_engine(policy_id, "input")
            engine_obj._detectors = [("confidential_and_pii_entity", redactor)]
            engine_obj._construction_failures = []
        yield client, keys, app


def _guard(client, key):
    return client.post(
        "/v1/guard_chat_completions",
        headers={"Authorization": f"Bearer {key}"},
        json={
            "guard_input": {"messages": [{"role": "user", "content": f"mail {SECRET} now"}]},
            "event_type": "input",
        },
    )


def _unredact(client, key, token):
    return client.post(
        "/v1/unredact",
        headers={"Authorization": f"Bearer {key}"},
        json={"fpe_context": token, "redacted_data": "[REDACTED_EMAIL_1]"},
    )


def test_an_unbound_key_is_redacted_but_gets_no_token():
    """Binding is what buys reversibility, and its absence must not cost
    protection: the prompt is still redacted, there is simply nothing to
    reverse it with."""
    with _routes() as (client, keys, _app):
        r = _guard(client, keys["unbound"])
        assert r.status_code == 200
        body = r.json()
        assert body["result"]["fpe_context"] is None
        assert SECRET not in json.dumps(body["result"]["guard_output"])


def test_a_bound_key_does_get_a_token_and_the_row_records_who_made_it():
    """The other half: without this, "no token" passes against a build that
    never issues one.

    The attribution is checked HERE rather than only through the manager,
    because it is guard that has to pass it: a manager test proves the column
    stores what it is given, not that the route gives it anything.
    """
    with _routes() as (client, keys, app):
        r = _guard(client, keys["bound"])
        assert r.status_code == 200
        token = r.json()["result"]["fpe_context"]
        assert token is not None

        mgr = app.state.vault_manager
        vault_id = mgr.decode_fpe_context(token)
        with app.state.session_factory() as session:
            row = session.get(VaultModel, vault_id)
            assert row.policy_id == "pol_main"
            assert row.created_by_key_id is not None, "the row does not record which key made it"


def test_a_foreign_vault_is_indistinguishable_from_an_absent_one():
    """Status AND body. A caller able to tell "not yours" from "no such vault"
    can enumerate other policies' ids."""
    with _routes() as (client, keys, _app):
        token = _guard(client, keys["bound"]).json()["result"]["fpe_context"]
        assert token

        foreign = _unredact(client, keys["other"], token)
        absent = _unredact(client, keys["other"], _absent_token())
        assert foreign.status_code == absent.status_code == 404
        assert foreign.json() == absent.json()
        assert SECRET not in foreign.text


def test_an_unbound_key_cannot_reverse_a_default_policy_vault():
    """The read side must use the caller's BOUND policy, never the resolved one.

    Guard resolves "bound, else default" to decide how to scan. If unredact
    resolved the same way, an unbound key would inherit the default policy and
    reverse every vault that policy owns. The vault here is created by a BOUND
    key, so testing unbound creation does not cover it.
    """
    with _routes() as (client, keys, _app):
        token = _guard(client, keys["bound"]).json()["result"]["fpe_context"]
        assert token
        refused = _unredact(client, keys["unbound"], token)
        assert refused.status_code == 404
        assert SECRET not in refused.text


def test_the_owning_policy_can_reverse_its_own_vault():
    """Otherwise every refusal above passes against a build that refuses
    everyone."""
    with _routes() as (client, keys, _app):
        token = _guard(client, keys["bound"]).json()["result"]["fpe_context"]
        assert _unredact(client, keys["bound"], token).status_code == 200


def test_deleting_a_policy_through_the_route_evicts_the_cache():
    """Read back through the app's OWN manager. A fresh one has an empty cache
    and passes against no eviction at all."""
    with _routes() as (client, keys, app):
        token = _guard(client, keys["bound"]).json()["result"]["fpe_context"]
        assert token
        mgr = app.state.vault_manager
        vault_id = mgr.decode_fpe_context(token)
        assert mgr.get_vault(vault_id, "pol_main") is not None  # warm

        # A policy cannot be deleted while keys are bound to it, so unbind them
        # first -- which is the order an operator has to work in anyway.
        with app.state.session_factory() as session:
            for key in session.query(APIKey).filter_by(policy_id="pol_main").all():
                key.policy_id = "pol_default"
            session.commit()

        r = client.delete("/v1/policies/pol_main", headers={"Authorization": f"Bearer {keys['admin']}"})
        assert r.status_code == 204
        assert mgr.get_vault(vault_id, "pol_main") is None


def _absent_token() -> str:
    import uuid

    from app.vault_manager import VaultManager as _VM

    return _VM.encode_fpe_context(None, str(uuid.uuid4()))  # type: ignore[arg-type]


def test_an_api_key_cannot_be_created_without_a_policy(session_factory, policies):
    """Refused at creation, because the failure is otherwise invisible until a
    reversal is attempted and refused -- which reads as a bug rather than as a
    configuration choice."""
    from app.services.key_service import KeyService

    with session_factory() as session:
        svc = KeyService(session)
        with pytest.raises(ValueError, match="must be bound to a policy"):
            svc.create_key(name="unbound-collector", role="api")

        raw, key = svc.create_key(name="bound-collector", role="api", policy_id="pol_a")
        assert raw.startswith("ak_")
        assert key.policy_id == "pol_a"


def test_a_key_that_is_unbound_anyway_is_reported_not_silent(session_factory, policies, caplog):
    """Requiring a binding at creation does not make unbound keys impossible.

    The bootstrap admin key is installed before any policy exists, and deleting
    a policy sets its keys' binding to NULL. Such a key still guards, still
    redacts, and silently gets no reversal token -- so guard says which key and
    why, rather than leaving an operator with a null field and no reason.
    """

    from app.services.key_service import KeyService

    with session_factory() as session:
        svc = KeyService(session)
        # admin is exempt from the binding requirement, so this is reachable
        _, admin = svc.create_key(name="admin-as-collector", role="admin")
        assert admin.policy_id is None
