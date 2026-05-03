"""Manages per-request TidewallVault instances with DB persistence.

Vaults are JSON-serialized and stored in the ``vaults`` table so they survive
server restarts. An in-memory LRU cache avoids DB lookups on hot paths.

The current version JSON-encodes a :class:`~app.vault.TidewallVault`.
Rows with an unrecognized format will fail to deserialize and are treated
as expired.
"""

from __future__ import annotations

import base64
import json
import logging
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy.orm import Session, sessionmaker

from app.db.models import Vault as VaultModel
from app.vault import TidewallVault

logger = logging.getLogger(__name__)

_TTL = timedelta(hours=1)
_MAX_CACHE = 500


class VaultManager:
    """DB-backed vault manager with in-memory LRU cache."""

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory
        # vault_id → TidewallVault instance
        self._cache: dict[str, TidewallVault] = {}

    def create_vault(self) -> tuple[str, TidewallVault]:
        """Create a new TidewallVault, persist to DB, return (vault_id, vault)."""
        vault_id = str(uuid.uuid4())
        vault = TidewallVault()
        now = datetime.now(UTC)

        # Persist serialized vault to DB.
        with self._session_factory() as session:
            row = VaultModel(
                id=vault_id,
                data=vault.to_bytes(),
                created_at=now,
                expires_at=now + _TTL,
            )
            session.add(row)
            session.commit()

        # Cache in memory; evict the oldest entry once we exceed the cap.
        self._cache[vault_id] = vault
        if len(self._cache) > _MAX_CACHE:
            oldest_key = next(iter(self._cache))
            del self._cache[oldest_key]

        return vault_id, vault

    def get_vault(self, vault_id: str) -> TidewallVault | None:
        """Retrieve a vault by ID. Returns None if not found, expired, or corrupt."""
        if vault_id in self._cache:
            return self._cache[vault_id]

        with self._session_factory() as session:
            row = session.get(VaultModel, vault_id)
            if row is None:
                return None
            expires = row.expires_at
            if isinstance(expires, datetime) and expires.tzinfo is None:
                # SQLite returns naive datetimes; treat as UTC for comparison.
                expires = expires.replace(tzinfo=UTC)
            if isinstance(expires, datetime) and expires < datetime.now(UTC):
                return None
            try:
                vault = TidewallVault.from_bytes(row.data)
                self._cache[vault_id] = vault
                return vault
            except Exception:
                # Old pickled rows or corrupt JSON land here — treat as missing.
                logger.warning("Failed to deserialize vault %s", vault_id)
                return None

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
