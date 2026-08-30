"""The vault manager: what gets written, what may be read back, and when a row dies.

A vault holds the placeholder-to-original mapping that makes redaction
reversible, so these tests are about the handling of the exact values the
product exists to protect. Four things are asserted here that the manager used
to get wrong, and each one was a way for the failure to be invisible:

**A vault written by one manager must open in another.** This is the defect.
``create_vault`` persisted the vault while it was still empty and nothing wrote
it back, so every stored row was ``{"placeholders": {}, "counters": {}}`` and
reversible redaction worked only when the unredacting request happened to land
on the process that created the vault. A single-manager test cannot see that:
it is answered from the in-memory cache and passes either way.

**An expired row leaves the table.** Refusing to serve one bounds what the API
discloses and bounds nothing on disk, so a key compromise would expose every
row ever written under that key rather than an hour of them.

**A cache hit is not exempt from expiry**, or a vault outlives the row it came
from.

**A wrong key and an altered row are loud.** Collapsing either into "no such
vault" is the benign label on a systemic failure -- a deployment holding the
wrong key would look exactly like one whose data had merely aged out.
"""

from __future__ import annotations

import base64
import secrets
from datetime import UTC, datetime, timedelta

import pytest

from app.config import Settings
from app.db.engine import get_engine, get_session_factory
from app.db.models import Base, Policy
from app.db.models import Vault as VaultModel
from app.vault_crypto import AuthenticationFailed, Keyring, UnknownKey
from app.vault_manager import VaultManager

SECRET = "jon@example.com"

#: Vaults are owned by the policy that created them, and the foreign key
#: rejects a save naming one that does not exist. These tests are about the
#: manager rather than about ownership, so they all live under one policy.
POLICY = "pol_test"


@pytest.fixture
def session_factory():
    engine = get_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = get_session_factory(engine)
    with factory() as session:
        session.add(Policy(id=POLICY, name=POLICY, type="application"))
        session.commit()
    return factory


def _material() -> str:
    """Fresh 256-bit key material, base64 encoded as an operator supplies it."""
    return base64.b64encode(secrets.token_bytes(32)).decode()


def _ring(keys: dict[str, str] | None = None, current: str = "k1") -> Keyring:
    """A keyring built the way a deployment builds one -- through the settings."""
    keys = keys if keys is not None else {"k1": _material()}
    declaration = ",".join(f"{key_id}:{material}" for key_id, material in keys.items())
    ring = Keyring.from_settings(Settings(VAULT_ENCRYPTION_KEYS=declaration, VAULT_ENCRYPTION_CURRENT=current))
    assert ring is not None
    return ring


def _manager(session_factory, keyring: Keyring | None = None) -> VaultManager:
    return VaultManager(session_factory, keyring=keyring if keyring is not None else _ring())


def _ensure_policy(mgr: VaultManager) -> str:
    """Give the manager's database the policy these helpers save under.

    Shared with the retention tests, which boot a real server and so get a
    schema this module's fixture never touched. The foreign key means a save
    naming an absent policy raises, so the owner has to exist wherever the
    helper is used.
    """
    with mgr._session_factory() as session:
        if session.get(Policy, POLICY) is None:
            session.add(Policy(id=POLICY, name=POLICY, type="application"))
            session.commit()
    return POLICY


def _populated(mgr: VaultManager, original: str = SECRET, **save_kwargs) -> tuple[str, str]:
    """Create, populate and save a vault. Returns its id and its placeholder."""
    _ensure_policy(mgr)
    vault_id, vault = mgr.create_vault()
    placeholder = vault.store("EMAIL", original)
    assert mgr.save(vault_id, vault, POLICY, **save_kwargs) is True
    return vault_id, placeholder


def _ago(**delta) -> datetime:
    return datetime.now(UTC) - timedelta(**delta)


def _rows(session_factory) -> list[str]:
    with session_factory() as session:
        return [row.id for row in session.query(VaultModel).all()]


def _drop_every_row(session_factory) -> None:
    """Leave the cache as the only thing that can answer a read."""
    with session_factory() as session:
        session.query(VaultModel).delete()
        session.commit()


def _alter_the_ciphertext(session_factory, vault_id: str) -> None:
    """Flip the last byte of the GCM tag, which is what someone able to write
    the database file can do without holding any key."""
    with session_factory() as session:
        row = session.get(VaultModel, vault_id)
        row.data = row.data[:-1] + bytes([row.data[-1] ^ 0xFF])
        session.commit()


# ---------------------------------------------------------------------------
# The defect
# ---------------------------------------------------------------------------


def test_a_vault_saved_by_one_manager_is_recoverable_by_another(session_factory):
    """The whole point. A vault populated in one process must open in another.

    Deliberately two managers: one manager answers from its own cache and
    passes whether or not anything was ever written, which is how a table full
    of empty rows went unnoticed.
    """
    ring = _ring()
    writer = _manager(session_factory, ring)
    vault_id, placeholder = _populated(writer)

    reader = _manager(session_factory, ring)

    recovered = reader.get_vault(vault_id, POLICY)
    assert recovered is not None, "the row was never written, so no other process can reverse the redaction"
    assert recovered.unredact(f"mail {placeholder} now") == f"mail {SECRET} now"


def test_creating_a_vault_writes_nothing(session_factory):
    """Only `save` writes. A vault is empty at creation, and a row written then
    is a row that can only ever hold an empty mapping."""
    mgr = _manager(session_factory)

    vault_id, vault = mgr.create_vault()

    assert vault.is_empty
    assert _rows(session_factory) == [], "creation wrote a row that no redaction had populated yet"


def test_an_empty_vault_is_not_written(session_factory):
    """Nothing was redacted into it, so there is nothing to retrieve and no
    reason to keep a row that later looks like data loss."""
    mgr = _manager(session_factory)
    vault_id, vault = mgr.create_vault()

    assert mgr.save(vault_id, vault, POLICY) is False
    assert _rows(session_factory) == []


def test_no_key_configured_writes_nothing(session_factory):
    """Persistence and encryption are one change. Without a key there is
    nowhere safe to put the mapping, so it is not put anywhere."""
    mgr = VaultManager(session_factory)
    vault_id, vault = mgr.create_vault()
    vault.store("EMAIL", SECRET)

    assert mgr.save(vault_id, vault, POLICY) is False
    assert _rows(session_factory) == []


def test_what_reaches_the_database_is_not_the_mapping(session_factory):
    """The `vaults` table is a store of names, emails and card numbers the
    moment persistence works. It must not be a plaintext one."""
    mgr = _manager(session_factory)
    vault_id, _ = _populated(mgr)

    with session_factory() as session:
        stored = session.get(VaultModel, vault_id).data

    assert SECRET.encode() not in stored
    assert b"placeholders" not in stored


# ---------------------------------------------------------------------------
# Expiry
# ---------------------------------------------------------------------------


def test_an_expired_row_is_deleted_by_the_read_that_finds_it(session_factory):
    """Gone from the table, not merely refused.

    Refusal bounds what the API hands out. It bounds nothing on disk, so a
    compromised key would expose every row ever written under it instead of an
    hour of them.
    """
    ring = _ring()
    writer = _manager(session_factory, ring)
    vault_id, _ = _populated(writer, expires_at=_ago(minutes=1))

    reader = _manager(session_factory, ring)

    assert reader.get_vault(vault_id, POLICY) is None
    assert _rows(session_factory) == [], "the expired row was refused and left on disk"


def test_a_cached_vault_past_its_expiry_is_refused(session_factory):
    """A cache hit skipped the expiry check, so a vault outlived its row."""
    mgr = _manager(session_factory)
    vault_id, _ = _populated(mgr, expires_at=_ago(minutes=1))
    assert vault_id in mgr._cache, "the save did not cache, so this says nothing about cache hits"
    assert _rows(session_factory) == [vault_id], "the row must exist, or the deletion below proves nothing"

    assert mgr.get_vault(vault_id, POLICY) is None

    # The expired hit must FALL THROUGH to the row rather than returning early,
    # because falling through is how the row gets deleted. Returning None from
    # the cache branch passes every other assertion here and leaves the row --
    # a sealed PII mapping on disk that nothing will ever reclaim.
    assert _rows(session_factory) == [], "the expired cache hit short-circuited and left the row behind"


def test_a_live_row_is_still_served(session_factory):
    """The positive control for both expiry tests above: without it they pass
    just as well against a manager that refuses everything."""
    mgr = _manager(session_factory)
    vault_id, placeholder = _populated(mgr)

    recovered = mgr.get_vault(vault_id, POLICY)

    assert recovered is not None
    assert recovered.unredact(placeholder) == SECRET


def test_a_missing_vault_is_absent_rather_than_an_error(session_factory):
    assert _manager(session_factory).get_vault("no-such-vault", POLICY) is None


# ---------------------------------------------------------------------------
# The cache
# ---------------------------------------------------------------------------


def test_the_cache_evicts_by_use_not_by_insertion(session_factory, monkeypatch):
    """It was documented as LRU and evicted in insertion order, so a vault
    being read every second was dropped to keep one nobody had touched."""
    import app.vault_manager as vault_manager

    monkeypatch.setattr(vault_manager, "_MAX_CACHE", 3)
    mgr = _manager(session_factory)
    first, _ = _populated(mgr, "a@example.com")
    second, _ = _populated(mgr, "b@example.com")
    third, _ = _populated(mgr, "c@example.com")

    assert mgr.get_vault(first, POLICY) is not None  # touched, so no longer the oldest by use
    fourth, _ = _populated(mgr, "d@example.com")

    # Only memory can answer now, so what survived eviction is observable.
    _drop_every_row(session_factory)

    assert mgr.get_vault(first, POLICY) is not None, "the most recently used vault was evicted"
    assert mgr.get_vault(second, POLICY) is None, "the least recently used vault was kept"
    assert mgr.get_vault(third, POLICY) is not None
    assert mgr.get_vault(fourth, POLICY) is not None


def test_the_read_path_is_bounded(session_factory, monkeypatch):
    """`get_vault` never evicted, so reads grew the cache without limit."""
    import app.vault_manager as vault_manager

    monkeypatch.setattr(vault_manager, "_MAX_CACHE", 3)
    mgr = _manager(session_factory)
    ids = [_populated(mgr, f"{n}@example.com")[0] for n in range(10)]

    mgr._cache.clear()
    for vault_id in ids:
        assert mgr.get_vault(vault_id, POLICY) is not None

    assert len(mgr._cache) == 3


# ---------------------------------------------------------------------------
# Read-path failures. None of these may answer "no such vault".
# ---------------------------------------------------------------------------


def test_a_row_whose_key_left_the_ring_is_loud(session_factory):
    """A key withdrawn while live rows still name it, a database restored from
    an old backup, or an id an attacker stamped on a row. All three are
    anomalies, and answering 404 to any of them hides the other two."""
    retained = _material()
    writer = _manager(session_factory, _ring({"k1": retained}, current="k1"))
    vault_id, _ = _populated(writer)

    withdrawn = _manager(session_factory, _ring({"k2": _material()}, current="k2"))

    with pytest.raises(UnknownKey):
        withdrawn.get_vault(vault_id, POLICY)


def test_a_row_whose_ciphertext_was_altered_is_loud(session_factory):
    ring = _ring()
    writer = _manager(session_factory, ring)
    vault_id, _ = _populated(writer)
    _alter_the_ciphertext(session_factory, vault_id)

    reader = _manager(session_factory, ring)

    with pytest.raises(AuthenticationFailed):
        reader.get_vault(vault_id, POLICY)


def test_neither_failure_is_reported_as_an_expired_row(session_factory):
    """The row is still there afterwards. Deleting it would turn a wrong key
    into data loss, and would make the next read answer 404 -- the quiet
    outcome these two failures exist to avoid."""
    ring = _ring()
    writer = _manager(session_factory, ring)
    vault_id, _ = _populated(writer)
    _alter_the_ciphertext(session_factory, vault_id)

    with pytest.raises(AuthenticationFailed):
        _manager(session_factory, ring).get_vault(vault_id, POLICY)

    assert _rows(session_factory) == [vault_id]


def test_a_legacy_row_is_absent_rather_than_loud(session_factory):
    """Every row written before the sealed format holds an empty mapping,
    because nothing ever wrote a populated one. There is nothing in one to
    recover, so it is absent -- and it is caught by its own type, not by the
    base class the loud failures share."""
    with session_factory() as session:
        session.add(
            VaultModel(
                id="legacy-1",
                data=b'{"placeholders": {}, "counters": {}}',
                created_at=datetime.now(UTC),
                expires_at=datetime.now(UTC) + timedelta(hours=1),
                policy_id=POLICY,
            )
        )
        session.commit()

    assert _manager(session_factory).get_vault("legacy-1", POLICY) is None


# ---------------------------------------------------------------------------
# Rotation, through the database and a cold reader
# ---------------------------------------------------------------------------


def test_a_row_sealed_under_a_retained_key_opens_after_rotation(session_factory):
    """The crypto rotates; this proves the system does. Seal under k1, then
    read through a manager whose ring holds k1 and k2 with k2 current -- which
    is what a deployment looks like for the TTL after a rotation."""
    retained, incoming = _material(), _material()
    writer = _manager(session_factory, _ring({"k1": retained}, current="k1"))
    vault_id, placeholder = _populated(writer)

    rotated = _manager(session_factory, _ring({"k1": retained, "k2": incoming}, current="k2"))

    recovered = rotated.get_vault(vault_id, POLICY)
    assert recovered is not None
    assert recovered.unredact(placeholder) == SECRET


def test_a_rotated_deployment_seals_new_rows_under_the_new_key(session_factory):
    """The other half: rotation is not just "old rows still open"."""
    retained, incoming = _material(), _material()
    rotated = _manager(session_factory, _ring({"k1": retained, "k2": incoming}, current="k2"))
    vault_id, placeholder = _populated(rotated)

    # A ring holding only the new key opens it, which the old key alone cannot.
    reader = _manager(session_factory, _ring({"k2": incoming}, current="k2"))

    recovered = reader.get_vault(vault_id, POLICY)
    assert recovered is not None
    assert recovered.unredact(placeholder) == SECRET


# ---------------------------------------------------------------------------
# The token
# ---------------------------------------------------------------------------


def test_encode_decode_fpe_context(session_factory):
    mgr = _manager(session_factory)
    vault_id, _ = mgr.create_vault()

    assert mgr.decode_fpe_context(mgr.encode_fpe_context(vault_id)) == vault_id


# ---------------------------------------------------------------------------
# What the logs may name
#
# `/v1/activity` is admin-role and globally unfiltered, so the unredact audit
# records the caller and never the vault. Application logs are operator-facing
# rather than caller-facing, but they are shipped and aggregated far more
# widely than the control plane, so the same rule applies to the same values.
#
# The rule is PROVENANCE, not "no vault ids in logs". An id minted by
# `create_vault` for the request doing the logging discloses nothing -- the
# caller has not seen it and no one else can ask about it. An id that ARRIVED
# from a caller is a question being asked, and answering it in a log is the
# existence oracle the 404 refuses to be. `save` logs its id; `get_vault` must
# not log the one it was handed.


_TELLTALE = "vlt_a_caller_supplied_this"


def test_a_missing_keyring_is_reported_without_the_id_it_was_asked_for(session_factory, caplog):
    """The operator learns the deployment cannot open vaults, not which one was asked for."""
    with caplog.at_level("ERROR"):
        assert VaultManager(session_factory, keyring=None).get_vault(_TELLTALE, POLICY) is None

    assert "no vault can be opened" in caplog.text
    assert _TELLTALE not in caplog.text


def test_a_legacy_row_is_reported_without_the_id_that_found_it(session_factory, caplog):
    """The sharper of the two: this fires only when a row EXISTS.

    Logging the id here would separate "exists but is legacy" from "no such
    vault" for anyone reading the logs, which is precisely the distinction the
    uniform absent-vault answer is built to withhold. "This deployment still
    holds legacy rows" is the actionable part, and it survives the omission.
    """
    with session_factory() as session:
        session.add(
            VaultModel(
                id=_TELLTALE,
                data=b'{"placeholders": {}, "counters": {}}',
                created_at=datetime.now(UTC),
                expires_at=datetime.now(UTC) + timedelta(hours=1),
                policy_id=POLICY,
            )
        )
        session.commit()

    with caplog.at_level("INFO"):
        assert _manager(session_factory).get_vault(_TELLTALE, POLICY) is None

    assert "predates the sealed format" in caplog.text
    assert _TELLTALE not in caplog.text


def test_a_failed_save_still_names_its_own_id(session_factory, caplog):
    """The positive control, and the reason the two above are about provenance.

    Without this, both would pass against a manager that had simply stopped
    logging -- or against one that logged nothing at all. This id came from
    `create_vault` microseconds earlier and has never left the process, so
    naming it tells a reader which write failed and tells an attacker nothing.
    """
    mgr = VaultManager(session_factory, keyring=None)
    _ensure_policy(mgr)
    vault_id, vault = mgr.create_vault()
    vault.store("EMAIL", SECRET)

    with caplog.at_level("ERROR"):
        assert mgr.save(vault_id, vault, POLICY) is False

    assert "redaction is irreversible" in caplog.text
    assert vault_id in caplog.text
