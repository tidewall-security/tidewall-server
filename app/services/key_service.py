"""API key management — CRUD and bootstrap."""

from __future__ import annotations

import logging
from datetime import UTC, datetime

from sqlalchemy.orm import Session

from app.auth.key_utils import generate_key, hash_key, key_prefix
from app.db.models import APIKey

logger = logging.getLogger(__name__)


class KeyService:
    """Manages API key lifecycle."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def create_key(
        self,
        name: str,
        role: str = "api",
        policy_id: str | None = None,
        collector_type: str | None = None,
        expires_at: datetime | None = None,
    ) -> tuple[str, APIKey]:
        """Create a new API key. Returns (raw_key, api_key_record).

        The raw key is returned ONCE and never stored — only its hash is persisted.
        """
        raw_key = generate_key()
        api_key = APIKey(
            name=name,
            key_hash=hash_key(raw_key),
            key_prefix=key_prefix(raw_key),
            role=role,
            policy_id=policy_id,
            collector_type=collector_type,
            expires_at=expires_at,
        )
        # A viewer with no policy sees nothing, because a null binding is
        # never widened to a wildcard on the read side. Refusing the key is the
        # honest failure: the alternative is a credential that authenticates
        # successfully and shows an empty dashboard, which reads as a bug.
        if role == "viewer" and not policy_id:
            raise ValueError("a viewer key must be bound to a policy: an unbound viewer can see nothing")

        self._session.add(api_key)
        self._session.commit()
        logger.info("Created API key '%s' (role=%s, prefix=%s)", name, role, api_key.key_prefix)
        return raw_key, api_key

    def list_keys(self) -> list[APIKey]:
        return self._session.query(APIKey).order_by(APIKey.created_at.desc()).all()

    def delete_key(self, key_id: str) -> None:
        api_key = self._session.get(APIKey, key_id)
        if api_key is None:
            raise ValueError(f"API key {key_id} not found")
        self._session.delete(api_key)
        self._session.commit()
        logger.info("Deleted API key '%s' (id=%s)", api_key.name, key_id)

    def lookup_key(self, raw_key: str) -> APIKey | None:
        """Look up an API key by its raw value. Returns None if not found or expired."""
        hashed = hash_key(raw_key)
        api_key = self._session.query(APIKey).filter_by(key_hash=hashed).first()
        if api_key is None:
            return None
        if api_key.expires_at:
            expires = api_key.expires_at
            if expires.tzinfo is None:
                expires = expires.replace(tzinfo=UTC)
            if expires < datetime.now(UTC):
                return None  # Expired
        return api_key

    def has_any_key(self) -> bool:
        """True if at least one API key exists."""
        return self._session.query(APIKey).first() is not None

    def install_bootstrap_admin_key(self, raw_key: str) -> bool:
        """Install an operator-supplied bootstrap admin key if no keys exist.

        Returns True if installed, False if keys already existed.

        The raw key is never logged or printed. It is supplied by the operator,
        who therefore already holds it, and emitting it here would place a
        permanent administrator bearer token into log storage — the defect this
        replaces. Only the hash is persisted, preserving the same "raw key never
        stored" boundary :meth:`create_key` honours.
        """
        if self.has_any_key():
            return False

        api_key = APIKey(
            name="bootstrap-admin",
            key_hash=hash_key(raw_key),
            key_prefix=key_prefix(raw_key),
            role="admin",
        )
        self._session.add(api_key)
        self._session.commit()
        logger.info(
            "Installed operator-supplied bootstrap admin key (prefix=%s)",
            api_key.key_prefix,
        )
        return True
