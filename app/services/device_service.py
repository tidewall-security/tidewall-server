"""Device management — registration tokens, device check-in, and access tokens."""

from __future__ import annotations

import logging
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.auth.key_utils import generate_key, hash_key, key_prefix
from app.db.models import AccessToken, Device, Policy, RegistrationToken
from app.utils import as_utc

logger = logging.getLogger(__name__)

_ACCESS_TOKEN_TTL_SECONDS = 3600
# How long a rotated token stays valid after being replaced, so a request
# already in flight when the refresh landed does not fail.
_ROTATION_OVERLAP_SECONDS = 60

# A key valid for longer than a quarter is one nobody will remember issuing.
MAX_REGISTRATION_TOKEN_TTL = timedelta(days=90)

# No I, O, 0 or 1. The code is read off one screen and typed into another, and a
# transcription error is indistinguishable from a failed match.
_CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
_CODE_LENGTH = 8


def _confirmation_code() -> str:
    return "".join(secrets.choice(_CODE_ALPHABET) for _ in range(_CODE_LENGTH))


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
        policy_id: str,
        created_by: str | None = None,
        expires_at: datetime | None = None,
        max_uses: int | None = None,
        pre_authorized: bool = False,
    ) -> tuple[str, RegistrationToken]:
        """Create a new registration token. Returns (raw_token, record).

        The raw token is returned once and never stored — only its hash is persisted.

        ``policy_id`` is required. Every device enrolled with this token
        inherits it as its immutable scope, so a token without one silently
        produces unscoped devices that fall back to the default policy — the
        binding exists in the schema but is never established.
        """
        if self._session.get(Policy, policy_id) is None:
            raise ValueError(f"Policy {policy_id} not found")
        if expires_at is None:
            raise ValueError("Registration tokens require an expiry")
        if as_utc(expires_at) > datetime.now(UTC) + MAX_REGISTRATION_TOKEN_TTL:
            raise ValueError("Registration token expiry may not exceed 90 days")
        if max_uses is not None and max_uses < 1:
            raise ValueError("max_uses must be at least 1")

        raw = generate_key(prefix="rt")
        record = RegistrationToken(
            name=name,
            token_hash=hash_key(raw),
            token_prefix=key_prefix(raw),
            created_by=created_by,
            expires_at=expires_at,
            max_uses=max_uses,
            pre_authorized=pre_authorized,
            policy_id=policy_id,
        )
        self._session.add(record)
        self._session.commit()
        logger.info("Created registration token '%s' (prefix=%s)", name, record.token_prefix)
        return raw, record

    def list_registration_tokens(self) -> list[RegistrationToken]:
        return self._session.query(RegistrationToken).order_by(RegistrationToken.created_at.desc()).all()

    def revoke_registration_token(self, token_id: str, *, cascade: bool) -> dict[str, Any]:
        """Revoke a key, optionally with every device enrolled through it.

        Soft, so the lineage survives: hard deletion nulls reg_token_id on every
        device the key created, which is the attribution needed to find them.

        Expiring or deleting a key only stops FUTURE enrolments. The devices
        already minted from it keep working, and for a pre_authorized key that
        is the entire exposure. Cascade is what makes a detected leak
        containable rather than merely noted.

        One transaction. A partial cascade leaves some of a leaked fleet live
        and reports success, which is worse than refusing outright.
        """
        rt = self._session.get(RegistrationToken, token_id)
        if rt is None:
            raise LookupError(f"Registration token {token_id} not found")

        rt.revoked_at = datetime.now(UTC)
        revoked = 0
        if cascade:
            devices = self._session.query(Device).filter_by(reg_token_id=rt.id).all()
            for device in devices:
                # Pending devices too: a pending device from a leaked key is one
                # admin mistake from being active, and the approval console
                # gives no sign the key behind it was revoked.
                device.status = "revoked"
            device_ids = [d.id for d in devices]
            if device_ids:
                # Credentials go now. Leaving them to lapse leaves a leaked
                # fleet usable for the rest of the access token's hour.
                self._session.query(AccessToken).filter(AccessToken.device_id.in_(device_ids)).delete(
                    synchronize_session=False
                )
            revoked = len(devices)

        self._session.commit()
        logger.info(
            "Revoked registration token %s (prefix=%s, cascade=%s, devices=%d)",
            rt.id,
            rt.token_prefix,
            cascade,
            revoked,
        )
        return {"token_id": rt.id, "devices_revoked": revoked}

    def lookup_registration_token(self, token_hash: str) -> RegistrationToken | None:
        """Look up a registration token by hash. Returns None if not found or expired."""
        record = self._session.query(RegistrationToken).filter_by(token_hash=token_hash).first()
        if record is None:
            return None
        # Before the expiry check: a revoked key is refused whether or not it
        # also happens to have expired.
        if record.revoked_at is not None:
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

    def enrol_device(
        self,
        rt_token_hash: str,
        installation_id: str,
        device_name: str,
        user_name: str,
        user_email: str,
        browser: str,
        os: str,
        ext_version: str,
        fingerprint: str | None = None,
    ) -> dict[str, Any]:
        """Enrol a NEW device against a registration token.

        Enrolment only ever creates. It never selects an existing row, because
        the only values a caller can offer at this point — a shared onboarding
        token and a client-supplied fingerprint — prove nothing about owning
        one. The previous combined flow looked a device up by fingerprint and
        refreshed it, so any holder of any registration token could revoke a
        victim's session and obtain an access token bound to their device and
        policy (P0-11).

        A client that has lost its stored credentials enrols again with a new
        installation ID and becomes a new device. That leaves a stale row for
        an administrator to remove, which is the cost of never letting an
        unauthenticated caller reclaim one.
        """
        rt = self.lookup_registration_token(rt_token_hash)
        if rt is None:
            raise ValueError("Invalid registration token")

        existing = self._session.query(Device).filter_by(installation_id=installation_id).first()
        if existing is not None:
            # The client already holds credentials for this installation and
            # should refresh with its access token. Re-enrolling would be the
            # takeover path again, so it is refused rather than served.
            return {"status": "InstallationIdAlreadyEnrolled", "result": None}

        if rt.max_uses is not None:
            # Conditional DML, not SELECT ... FOR UPDATE: SQLite has no row
            # locks. WAL admits a single writer, so an UPDATE guarded on the
            # current value IS the concurrency control. rowcount == 0 means
            # another enrolment took the last use between the read above and
            # here -- the duplicate check before this is a fast path, this is
            # the guarantee.
            #
            # Claimed before the insert and rolled back with it, so a racing
            # duplicate that fails at flush returns the use rather than burning
            # it. Otherwise anyone who knows an enrolled installation id could
            # exhaust that key by replaying it.
            claimed = (
                self._session.query(RegistrationToken)
                .filter(RegistrationToken.id == rt.id, RegistrationToken.uses < rt.max_uses)
                .update({"uses": RegistrationToken.uses + 1}, synchronize_session=False)
            )
            if claimed == 0:
                self._session.rollback()
                return {"status": "RegistrationTokenExhausted", "result": None}

        device = Device(
            installation_id=installation_id,
            fingerprint=fingerprint,
            device_name=device_name,
            user_name=user_name,
            user_email=user_email,
            browser=browser,
            os=os,
            ext_version=ext_version,
            reg_token_id=rt.id,
            # Snapshot. The FK above is SET NULL on delete, so this is the only
            # attribution that survives someone deleting the key.
            reg_token_prefix=rt.token_prefix,
            # Scope is inherited from the token and is immutable thereafter.
            policy_id=rt.policy_id,
            # Pending unless the key says otherwise. A leaked key then buys an
            # attacker a device that does nothing, and an unexpected row in the
            # admin console.
            status="active" if rt.pre_authorized else "pending",
            confirmation_code=None if rt.pre_authorized else _confirmation_code(),
        )
        self._session.add(device)
        try:
            self._session.flush()
        except IntegrityError:
            # Two enrolments with the same installation ID raced past the check
            # above. The unique constraint keeps one row; the loser must get
            # the documented conflict rather than a 500.
            self._session.rollback()
            return {"status": "InstallationIdAlreadyEnrolled", "result": None}
        logger.info("Enrolled device %s via registration token %s", device.id, rt.id)

        raw_at, _ = self._issue_access_token(device.id)
        self._session.commit()
        return self._success(device, raw_at)

    def refresh_device(
        self,
        device_id: str,
        access_token_hash: str,
        device_name: str | None = None,
        user_name: str | None = None,
        user_email: str | None = None,
        browser: str | None = None,
        os: str | None = None,
        ext_version: str | None = None,
        fingerprint: str | None = None,
    ) -> dict[str, Any]:
        """Refresh an EXISTING device, proving ownership with its access token.

        The presented token must belong to the named device. No registration
        token is accepted here: holding one says nothing about owning a device.
        """
        token = self._session.query(AccessToken).filter_by(token_hash=access_token_hash).first()
        if token is None:
            raise PermissionError("Invalid access token")
        if token.expires_at and as_utc(token.expires_at) < datetime.now(UTC):
            raise PermissionError("Access token expired")
        if token.replaced_by_id is not None:
            # Rotation is one-time. The overlap exists so requests already in
            # flight with this token still succeed; it is not a licence to
            # refresh again. Without this check a client could present the same
            # token repeatedly, minting an unbounded number of live tokens and
            # renewing its own overlap forever, so it would never expire.
            raise PermissionError("Access token has already been rotated")
        if token.device_id != device_id:
            # A valid token for a different device. Distinguished from an
            # invalid token so the caller can tell a bug from a credential
            # problem, without revealing whether the target device exists.
            raise PermissionError("Access token is not valid for this device")

        device = self._session.get(Device, device_id)
        if device is None:
            raise PermissionError("Access token is not valid for this device")
        if device.status != "active":
            return {"status": "InactiveDevice", "result": None}

        for field, value in (
            ("device_name", device_name),
            ("user_name", user_name),
            ("user_email", user_email),
            ("browser", browser),
            ("os", os),
            ("ext_version", ext_version),
            ("fingerprint", fingerprint),
        ):
            if value is not None:
                setattr(device, field, value)
        device.last_seen = datetime.now(UTC)

        raw_at, new_token = self._issue_access_token(device.id)

        # Rotate rather than revoke. Deleting every token for the device, which
        # is what this used to do, breaks any other in-flight request; expiring
        # only the presented one after a short overlap lets a racing retry
        # succeed. Explicit revocation and admin disablement still kill
        # everything immediately, elsewhere.
        #
        # `min` because the overlap may only ever shorten a token's life: taking
        # the new deadline unconditionally would *extend* one already due to
        # expire sooner. The write is conditional on the token still being
        # unrotated so that two concurrent refreshes cannot both mint a
        # successor — the check above is a fast path, this is the guarantee.
        overlap_deadline = datetime.now(UTC) + timedelta(seconds=_ROTATION_OVERLAP_SECONDS)
        current_expiry = as_utc(token.expires_at) if token.expires_at else None
        deadline = min(overlap_deadline, current_expiry) if current_expiry else overlap_deadline

        rotated = (
            self._session.query(AccessToken)
            .filter(AccessToken.id == token.id, AccessToken.replaced_by_id.is_(None))
            .update({"replaced_by_id": new_token.id, "expires_at": deadline}, synchronize_session=False)
        )
        if rotated == 0:
            # A concurrent refresh with the same token won. Discard the token
            # just issued rather than leaving a second live credential behind.
            self._session.rollback()
            raise PermissionError("Access token has already been rotated")

        self._session.commit()
        logger.info("Refreshed device %s", device.id)
        return self._success(device, raw_at)

    def _success(self, device: Device, raw_at: str) -> dict[str, Any]:
        result: dict[str, Any] = {
            "status": "Success",
            "result": {
                "device_id": device.id,
                # The client needs its own disposition to decide whether to
                # call the guard or display a code and wait.
                "device_status": device.status,
                "access_token": {
                    "token": raw_at,
                    "expires_in": _ACCESS_TOKEN_TTL_SECONDS,
                },
                "config": {
                    "sites": self._get_site_config(),
                },
            },
        }
        if device.confirmation_code is not None:
            # Returned to the ENROLLING client only, so it can display the code
            # for an administrator to match. Never included in any listing.
            result["result"]["confirmation_code"] = device.confirmation_code
        return result

    def approve_device(self, device_id: str, confirmation_code: str) -> Device:
        """Activate a pending device, proving the administrator saw the endpoint.

        The code is what makes approval decidable. Every descriptive field on a
        pending row is supplied by the claimant, so approving on the strength of
        them is approving on the attacker's own account of themselves.

        Compared with compare_digest: the code is short, and an admin endpoint
        is still an oracle if the comparison is timing-variable.
        """
        device = self._session.get(Device, device_id)
        if device is None:
            raise LookupError("Device not found")
        if device.status != "pending":
            raise PermissionError("Device is not pending approval")
        if device.confirmation_code is None or not secrets.compare_digest(device.confirmation_code, confirmation_code):
            raise PermissionError("Confirmation code does not match")

        device.status = "active"
        # Single use. Left in place it is a standing credential for reactivating
        # the device after any later revocation.
        device.confirmation_code = None
        self._session.commit()
        logger.info("Approved device %s", device.id)
        return device

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
        # Flush so the row has its primary key. The id comes from a Python-side
        # default applied at flush, so a caller wiring up replaced_by_id would
        # otherwise record None.
        self._session.flush()
        return raw_at, at_record

    def _get_site_config(self) -> dict[str, str]:
        """Return the full site configuration (all 37 sites with mode 'block')."""
        return dict(_SITES)
