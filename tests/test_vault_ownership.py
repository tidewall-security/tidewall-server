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
