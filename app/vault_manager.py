"""Per-request vaults, and the rows they are written to.

A vault holds the placeholder-to-original mapping that makes redaction
reversible, which is to say it holds exactly the values the product exists to
protect. This module decides when one is written, when one may be read back,
and what happens to a row whose time is up. The bytes themselves are sealed by
:mod:`app.vault_crypto`, and there is no path here that writes or reads them
any other way.

Four rules, and each one replaces something this module used to get wrong.

**Only :meth:`VaultManager.save` writes.** :meth:`~VaultManager.create_vault`
used to persist the vault while it was still empty, and nothing ever wrote it
back -- :meth:`~app.vault.TidewallVault.to_bytes` had one production call site,
inside that method. So every stored row was
``{"placeholders": {}, "counters": {}}`` and reversible redaction worked only
when the unredacting request happened to land on the process that had created
the vault. Creation is now purely in memory: it costs no write for the guard
calls that redact nothing, and it leaves exactly one place a mapping can be
written from.

**An empty vault is not written.** No mapping means nothing to retrieve, and a
row written anyway is one that later reads as data loss.

**A read deletes what it finds expired.** Refusing an expired row bounds what
the API discloses and bounds nothing on disk, so a compromised key exposes every
row still present rather than the hour the TTL suggests. A row found past its
expiry is therefore deleted by the read that found it, cache hit included -- the
expired hit falls through to the row rather than short-circuiting, which is the
only reason that deletion happens at all.

**A read alone was never a retention guarantee, so a sweep does the rest.**
The ordinary request redacts and never calls ``/v1/unredact``, so its row is
never read and a read-time deletion never reaches it. :func:`purge_expired_vaults`
is what reclaims those, on a schedule, and reversible redaction refuses to store
a mapping at all unless that schedule is running -- see ``app/main.py``. The
bound it buys is "not readable through the API and not present in the table",
not "erased from the disk": SQLite keeps deleted rows in the write-ahead log
and in free pages until the file is vacuumed.

The unknown-key-is-loud rule does **not** depend on that sweep, though an
earlier draft of this docstring said it did. The expiry gate runs *before* the
key lookup, so a stale row naming a withdrawn key answers as expired rather than
raising -- the ordering does the work, not the retention.

**The cache is by use, and bounded wherever it grows.** It was documented as
LRU while evicting in insertion order, and :meth:`~VaultManager.get_vault`
never evicted at all, so reads grew it without limit. It also answered hits
without checking expiry, which let a cached vault outlive its row.

On the read path, :class:`~app.vault_crypto.LegacyRow` is caught and the other
two are not. A legacy row is one written before the sealed format, and every
one of them is known to hold an empty mapping, so there is nothing in it to
recover and nothing to shout about. :class:`~app.vault_crypto.UnknownKey` and
:class:`~app.vault_crypto.AuthenticationFailed` mean the deployment holds the
wrong key or the bytes on disk are not the bytes that were written, and
reporting either as a missing vault is the benign label on a systemic failure
-- a server started with the wrong key would look exactly like one whose data
had merely aged out. Catching their shared base class would collapse the
distinction :mod:`app.vault_crypto` exists to draw.
"""

from __future__ import annotations

import base64
import json
import logging
import uuid
from collections import OrderedDict
from datetime import UTC, datetime, timedelta
from typing import NamedTuple

from sqlalchemy.orm import Session, sessionmaker

from app.db.models import Vault as VaultModel
from app.utils import as_utc
from app.vault import TidewallVault
from app.vault_crypto import Keyring, LegacyRow

logger = logging.getLogger(__name__)

#: How long a saved vault stays readable. Also the floor on how long a key must
#: stay in the ring after a rotation: shorter, and live rows would name an id
#: nobody configured, which is a loud failure by design.
_TTL = timedelta(hours=1)

#: How many vaults are held in memory. Read at eviction time rather than bound
#: into the class, so a test can shrink it instead of writing five hundred rows
#: to prove the bound exists.
_MAX_CACHE = 500


class _Cached(NamedTuple):
    """A vault held in memory, with the expiry of the row it came from.

    The expiry travels with it because a cache hit has to answer the same
    question the row would have: a vault whose row has died must die with it.
    """

    vault: TidewallVault
    expires_at: datetime


class VaultManager:
    """Creates vaults, writes the populated ones, and reads them back.

    ``keyring`` is ``None`` when there is nowhere safe to put a mapping, and
    that is two conditions rather than one: the deployment configured no key,
    or it configured one and vault retention could not be scheduled, in which
    case startup withholds the ring it built. Either way redaction still works
    and is irreversible, no row is written and no row can be opened.

    Persistence and encryption are one change -- a vault written in the clear
    would turn a broken feature into a disclosure -- and persistence and
    deletion are likewise: collecting a plaintext mapping nothing will ever
    delete is the TTL quietly false.
    """

    def __init__(self, session_factory: sessionmaker[Session], keyring: Keyring | None = None) -> None:
        self._session_factory = session_factory
        self._keyring = keyring
        # Most recently used last, so the eviction end is the front.
        self._cache: OrderedDict[str, _Cached] = OrderedDict()

    def create_vault(self) -> tuple[str, TidewallVault]:
        """A fresh id and an empty in-memory vault. Nothing is written.

        The detectors populate the returned instance during the scan; whether
        it is ever stored is settled later, by the response's disposition.
        """
        return str(uuid.uuid4()), TidewallVault()

    def save(self, vault_id: str, vault: TidewallVault, expires_at: datetime | None = None) -> bool:
        """Seal the mapping and write the row. ``True`` if one was written.

        Declines rather than raising when there is nothing worth writing or
        nowhere safe to write it: an empty vault, or no keyring. A caller that
        has already promised a reversal must treat a decline exactly as it
        treats a failure, because the outcome for the caller is the same.

        Raises whatever the database raises. The expiry is anchored here rather
        than at creation, so the TTL runs from the moment the mapping actually
        existed.
        """
        if vault.is_empty:
            # Nothing was recorded, so there is nothing to recover and no
            # reason for a row that will later look like a lost mapping.
            return False
        if self._keyring is None:
            logger.error(
                "vault %s was not stored: no vault encryption key is configured, so redaction is irreversible",
                vault_id,
            )
            return False

        when = as_utc(expires_at) if expires_at is not None else datetime.now(UTC) + _TTL

        # Sealed before the session opens. The row's own identity is bound as
        # associated data, so this blob cannot be moved to another row or have
        # its expiry extended without the authentication failing.
        blob = self._keyring.seal(vault_id, when, vault.to_bytes())

        with self._session_factory() as session:
            session.add(VaultModel(id=vault_id, data=blob, created_at=datetime.now(UTC), expires_at=when))
            session.commit()

        self._remember(vault_id, vault, when)
        return True

    def get_vault(self, vault_id: str) -> TidewallVault | None:
        """The vault behind ``vault_id``, or ``None`` if there is genuinely none.

        ``None`` means absent, expired, or written before the sealed format.
        Every other failure raises: see the module docstring for why a wrong
        key must not read as a missing vault.
        """
        now = datetime.now(UTC)

        cached = self._cache.get(vault_id)
        if cached is not None:
            if cached.expires_at > now:
                self._cache.move_to_end(vault_id)
                return cached.vault
            # Past its expiry, so it is not answered from memory and the read
            # continues to the row -- which is how the row gets deleted rather
            # than left behind by a cache hit that short-circuited it.
            del self._cache[vault_id]

        if self._keyring is None:
            # Nothing was sealed and nothing can be opened. Not a quiet branch
            # an attacker can select: it turns on the deployment's own
            # configuration, not on any field in the row.
            logger.error(
                "vault %s was requested but no vault encryption key is configured, so no vault can be opened",
                vault_id,
            )
            return None

        with self._session_factory() as session:
            row = session.get(VaultModel, vault_id)
            if row is None:
                return None
            expires_at = as_utc(row.expires_at)
            if expires_at <= now:
                # Deleted, not merely refused. The TTL is a claim about what is
                # on disk as well as what is served.
                session.delete(row)
                session.commit()
                return None
            blob = bytes(row.data)

        try:
            plaintext = self._keyring.open(vault_id, expires_at, blob)
        except LegacyRow:
            # Caught by its own type. UnknownKey and AuthenticationFailed share
            # a base class with this one and must travel on.
            logger.info("vault %s predates the sealed format and holds no mapping", vault_id)
            return None

        # The plaintext authenticated, so anything wrong with it now is
        # something this server wrote. Left to raise: it is a defect here, not
        # a missing vault.
        vault = TidewallVault.from_bytes(plaintext)
        self._remember(vault_id, vault, expires_at)
        return vault

    def _remember(self, vault_id: str, vault: TidewallVault, expires_at: datetime) -> None:
        """Hold a vault in memory as the most recently used, within the bound.

        A vault_id is new every time this is reached -- `save` mints one per
        request and `get_vault` only lands here on a miss -- and a new key goes
        to the end of an OrderedDict on its own. Reordering is the read's job,
        in `get_vault`, where a hit moves the entry it just used.
        """
        self._cache[vault_id] = _Cached(vault, expires_at)
        while len(self._cache) > _MAX_CACHE:
            # The least recently *used*, which is the point: evicting in
            # insertion order dropped a vault being read every second to keep
            # one nobody had touched since it was written.
            self._cache.popitem(last=False)

    def encode_fpe_context(self, vault_id: str) -> str:
        """Encode vault_id as a base64 ``fpe_context`` string."""
        return base64.b64encode(json.dumps({"vault_id": vault_id}).encode()).decode()

    def decode_fpe_context(self, fpe_context: str) -> str | None:
        """Decode an ``fpe_context`` string back to its vault_id, or None."""
        try:
            data = json.loads(base64.b64decode(fpe_context))
            result: str | None = data.get("vault_id")
            return result
        except Exception:
            return None


def purge_expired_vaults(session: Session, *, now: datetime | None = None) -> int:
    """Delete every vault past its expiry. Returns how many rows went.

    The counterpart to the read path's delete-what-it-finds, and the reason the
    TTL means anything on disk: the ordinary request redacts and never calls
    ``/v1/unredact``, so its row is never read and a read-time deletion never
    reaches it. Without this, a sealed mapping written today stays there for the
    life of the database file and a key compromise exposes every row ever
    written under that key rather than the hour the TTL advertises.

    Deletes by predicate rather than by a list read earlier, so it is idempotent
    and two callers racing simply both find less to do.

    SQLite caveat, because the guarantee should not be overstated: deleted rows
    may persist in the write-ahead log and in free pages until the file is
    vacuumed, and in any backup taken before the deletion. The bound is "not
    readable through the API and not present in the table", not "erased from
    the disk".
    """
    moment = now or datetime.now(UTC)
    deleted: int = session.query(VaultModel).filter(VaultModel.expires_at <= moment).delete(synchronize_session=False)
    if deleted:
        session.commit()
    return deleted
