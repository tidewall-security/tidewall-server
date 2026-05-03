"""Device management — registration tokens, device check-in, and access tokens."""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy.orm import Session

from app.auth.key_utils import generate_key, hash_key, key_prefix
from app.db.models import AccessToken, Device, RegistrationToken

logger = logging.getLogger(__name__)

_ACCESS_TOKEN_TTL_SECONDS = 3600

# 37 sites with mode "block"
# Site modes keyed by alias (must match extension's SITE_REGISTRY aliases)
_SITES = {
    "chatgpt": "block",
    "claude": "block",
    "gemini": "block",
    "copilot": "block",
    "m365copilot": "block",
    "perplexity": "block",
    "deepseek": "block",
    "grok": "block",
    "meta": "block",
    "mistral": "block",
    "aistudio": "block",
    "poe": "block",
    "you": "block",
    "glean": "block",
    "salesforce": "block",
    "character": "block",
    "notion": "block",
    "iask": "block",
    "dalle": "block",
    "openart": "block",
    "copyai": "block",
    "sigma": "block",
    "joyland": "block",
    "flowgpt": "block",
    "pi": "block",
    "phind": "block",
    "sakura": "block",
    "anonchatgpt": "block",
    "chatgot": "block",
    "gptonline": "block",
    "askanai": "block",
    "kuki": "block",
    "hereforyou": "block",
    "yodayo": "block",
    "charstar": "block",
    "deftgpt": "block",
    "dopple": "block",
}


class DeviceService:
    """Manages device registration tokens, device check-in, and access tokens."""

    def __init__(self, session: Session) -> None:
        self._session = session

    # ------------------------------------------------------------------
    # Registration token CRUD
    # ------------------------------------------------------------------

    def create_registration_token(
        self,
        name: str,
        created_by: str | None = None,
        expires_at: datetime | None = None,
    ) -> tuple[str, RegistrationToken]:
        """Create a new registration token. Returns (raw_token, record).

        The raw token is returned once and never stored — only its hash is persisted.
        """
        raw = generate_key(prefix="rt")
        record = RegistrationToken(
            name=name,
            token_hash=hash_key(raw),
            token_prefix=key_prefix(raw),
            created_by=created_by,
            expires_at=expires_at,
        )
        self._session.add(record)
        self._session.commit()
        logger.info("Created registration token '%s' (prefix=%s)", name, record.token_prefix)
        return raw, record

    def list_registration_tokens(self) -> list[RegistrationToken]:
        return self._session.query(RegistrationToken).order_by(RegistrationToken.created_at.desc()).all()

    def delete_registration_token(self, token_id: str) -> None:
        record = self._session.get(RegistrationToken, token_id)
        if record is None:
            raise ValueError(f"Registration token {token_id} not found")
        self._session.delete(record)
        self._session.commit()
        logger.info("Deleted registration token id=%s", token_id)

    def lookup_registration_token(self, token_hash: str) -> RegistrationToken | None:
        """Look up a registration token by hash. Returns None if not found or expired."""
        record = self._session.query(RegistrationToken).filter_by(token_hash=token_hash).first()
        if record is None:
            return None
        if record.expires_at:
            expires = record.expires_at
            if expires.tzinfo is None:
                expires = expires.replace(tzinfo=UTC)
            if expires < datetime.now(UTC):
                return None
        return record

    # ------------------------------------------------------------------
    # Device check (register or refresh)
    # ------------------------------------------------------------------

    def check_device(
        self,
        rt_token_hash: str,
        fingerprint: str,
        device_name: str,
        user_name: str,
        user_email: str,
        browser: str,
        os: str,
        ext_version: str,
    ) -> dict[str, Any]:
        """Register a new device or refresh an existing one.

        Returns a dict with keys 'status' and 'result'.
        """
        # Validate the registration token
        rt = self.lookup_registration_token(rt_token_hash)
        if rt is None:
            raise ValueError("Invalid registration token")

        device = self._session.query(Device).filter_by(fingerprint=fingerprint).first()

        if device is None:
            # New device — register it
            device = Device(
                fingerprint=fingerprint,
                device_name=device_name,
                user_name=user_name,
                user_email=user_email,
                browser=browser,
                os=os,
                ext_version=ext_version,
                reg_token_id=rt.id,
                status="active",
            )
            self._session.add(device)
            self._session.flush()
            logger.info("Registered new device fingerprint=%s", fingerprint)
        else:
            if device.status != "active":
                return {"status": "InactiveDevice", "result": None}

            # Update mutable fields
            device.device_name = device_name
            device.user_name = user_name
            device.user_email = user_email
            device.browser = browser
            device.os = os
            device.ext_version = ext_version
            device.last_seen = datetime.now(UTC)

            # Delete old access tokens
            self._session.query(AccessToken).filter_by(device_id=device.id).delete()
            self._session.flush()
            logger.info("Refreshing device fingerprint=%s", fingerprint)

        # Issue a new access token
        raw_at, at_record = self._issue_access_token(device.id)
        self._session.commit()

        return {
            "status": "Success",
            "result": {
                "access_token": {
                    "token": raw_at,
                    "expires_in": _ACCESS_TOKEN_TTL_SECONDS,
                },
                "config": {
                    "sites": self._get_site_config(),
                },
            },
        }

    # ------------------------------------------------------------------
    # Access token resolution
    # ------------------------------------------------------------------

    def resolve_access_token(self, token_hash: str) -> Device | None:
        """Resolve an access token hash to its Device. Returns None if expired or inactive."""
        at = self._session.query(AccessToken).filter_by(token_hash=token_hash).first()
        if at is None:
            return None
        expires = at.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=UTC)
        if expires < datetime.now(UTC):
            return None
        device = self._session.get(Device, at.device_id)
        if device is None or device.status != "active":
            return None
        return device

    # ------------------------------------------------------------------
    # Device CRUD
    # ------------------------------------------------------------------

    def list_devices(self) -> list[Device]:
        return self._session.query(Device).order_by(Device.created_at.desc()).all()

    def get_device(self, device_id: str) -> Device | None:
        return self._session.get(Device, device_id)

    def update_device_status(self, device_id: str, status: str) -> Device:
        device = self._session.get(Device, device_id)
        if device is None:
            raise ValueError(f"Device {device_id} not found")
        device.status = status
        if status == "revoked":
            self._session.query(AccessToken).filter_by(device_id=device_id).delete()
        self._session.commit()
        logger.info("Updated device %s status to %s", device_id, status)
        return device

    def delete_device(self, device_id: str) -> None:
        device = self._session.get(Device, device_id)
        if device is None:
            raise ValueError(f"Device {device_id} not found")
        # Cascade delete access tokens first (in case DB doesn't enforce it)
        self._session.query(AccessToken).filter_by(device_id=device_id).delete()
        self._session.delete(device)
        self._session.commit()
        logger.info("Deleted device id=%s", device_id)

    def update_last_seen(self, device_id: str) -> None:
        device = self._session.get(Device, device_id)
        if device is None:
            raise ValueError(f"Device {device_id} not found")
        device.last_seen = datetime.now(UTC)
        self._session.commit()

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _issue_access_token(self, device_id: str) -> tuple[str, AccessToken]:
        """Create and persist a new access token for the given device."""
        raw_at = generate_key(prefix="at")
        expires_at = datetime.now(UTC) + timedelta(seconds=_ACCESS_TOKEN_TTL_SECONDS)
        at_record = AccessToken(
            token_hash=hash_key(raw_at),
            device_id=device_id,
            expires_at=expires_at,
        )
        self._session.add(at_record)
        return raw_at, at_record

    def _get_site_config(self) -> dict[str, str]:
        """Return the full site configuration (all 37 sites with mode 'block')."""
        return dict(_SITES)
