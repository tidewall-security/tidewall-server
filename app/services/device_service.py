"""Device management — registration tokens, device check-in, and access tokens."""

from __future__ import annotations

import logging
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.auth.key_utils import generate_key, hash_key, key_prefix
from app.db.models import (
    AccessToken,
    Device,
    DeviceRefreshToken,
    DeviceTombstone,
    Policy,
    RegistrationToken,
)
from app.utils import as_utc

logger = logging.getLogger(__name__)

_ACCESS_TOKEN_TTL_SECONDS = 3600

# Long enough that a laptop shut in a drawer over a holiday still comes back.
REFRESH_TOKEN_TTL = timedelta(days=30)
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
                self._entomb(device, reason="enrolment key revoked")
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
                # And the refresh credentials. Without this a cascade-revoked
                # device keeps a 30-day token that mints fresh access tokens,
                # and the revocation is cosmetic.
                self._session.query(DeviceRefreshToken).filter(DeviceRefreshToken.device_id.in_(device_ids)).delete(
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
        recovery_secret: str | None = None,
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

        tombstone = (
            self._session.query(DeviceTombstone).filter_by(installation_id=installation_id, consumed_at=None).first()
        )
        if tombstone is not None:
            # A wrong secret answers exactly as no secret does. Any other
            # arrangement reports whether recovery has been authorised, which
            # tells the revoked party when to try.
            if (
                recovery_secret is None
                or tombstone.recovery_secret_hash is None
                or not secrets.compare_digest(tombstone.recovery_secret_hash, hash_key(recovery_secret))
            ):
                return {"status": "InstallationTombstoned", "result": None}
            # Consumed by a CONDITIONAL update in this transaction, so two
            # enrolments cannot share one grant. Single-use decides who wins a
            # race; the secret decides who was entitled to be in it.
            claimed = (
                self._session.query(DeviceTombstone)
                .filter(
                    DeviceTombstone.device_id == tombstone.device_id,
                    DeviceTombstone.consumed_at.is_(None),
                )
                .update({"consumed_at": datetime.now(UTC)}, synchronize_session=False)
            )
            if claimed == 0:
                return {"status": "InstallationTombstoned", "result": None}

            # The revoked row still holds this installation_id, and that column
            # is unique, so recovery cannot create its replacement beside it.
            # Removing it is what "recover" means: a new device, same
            # installation, and the tombstone stays as the record that the old
            # one was stopped. Its credentials went at revocation.
            superseded = self._session.query(Device).filter_by(installation_id=installation_id).first()
            if superseded is not None:
                self._session.query(AccessToken).filter_by(device_id=superseded.id).delete()
                self._session.query(DeviceRefreshToken).filter_by(device_id=superseded.id).delete()
                self._session.delete(superseded)
                self._session.flush()

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
        raw_dr, _ = self._issue_refresh_token(device.id)
        self._session.commit()
        return self._success(device, raw_at, raw_dr)

    def refresh_device(
        self,
        device_id: str,
        refresh_token_hash: str,
        device_name: str | None = None,
        user_name: str | None = None,
        user_email: str | None = None,
        browser: str | None = None,
        os: str | None = None,
        ext_version: str | None = None,
        fingerprint: str | None = None,
    ) -> dict[str, Any]:
        """Refresh an EXISTING device, proving ownership with its dr_ token.

        The presented credential must belong to the named device. No
        registration token is accepted here: holding one says nothing about
        owning a device. No access token either -- that was the credential this
        replaces, and accepting both would leave the one-hour lockout in place
        for any client that still used it.

        Nothing rotates. A client that loses the response simply retries with
        the same credential, which is the property the access-token rotation
        could not offer.
        """
        # THE PRECEDENCE IS THE SPECIFICATION. Written once, in order, with the
        # reason each step sits where it does.
        #
        # 1. Device revoked. Dominates everything below: a revoked device told
        #    anything else re-enrols ITSELF, undoing its own revocation without
        #    the attacker doing more than waiting.
        # 2. Credential unknown, or bound to another device. One answer for
        #    both: distinguishing them tells a caller whether a device exists.
        # 3. Credential expired or revoked.
        # 4. Device pending. Below expiry, so a pending device holding a dead
        #    credential is told to re-enrol rather than polling for an approval
        #    it could never use.
        # 5. Otherwise issue.
        #
        # Step 1 resolves a caller-supplied device id before authenticating, so
        # it does reveal whether a given id names a revoked device. Accepted:
        # ids are UUIDs, the caller is normally the device itself, and the
        # alternative -- authenticate first -- cannot answer device_revoked at
        # all once revocation has deleted the credential, which is the bypass
        # this ordering exists to close.
        device = self._session.get(Device, device_id)
        if device is not None and device.status == "revoked":
            return {"status": "device_revoked", "result": None}
        # The tombstone answers for a device whose row is gone. Without it the
        # credentials went with the device, so the client would be told its
        # credential is unknown and would re-enrol -- the recovery path, taken
        # by a device that was told to stop.
        if self._session.get(DeviceTombstone, device_id) is not None:
            return {"status": "device_revoked", "result": None}

        token = self._session.query(DeviceRefreshToken).filter_by(token_hash=refresh_token_hash).first()
        if token is None or token.device_id != device_id:
            return {"status": "credential_unknown", "result": None}

        if token.revoked_at is not None or as_utc(token.expires_at) < datetime.now(UTC):
            return {"status": "credential_expired", "result": None}

        if device is None:
            # The credential names a device that no longer exists. Task 7's
            # tombstones turn this into device_revoked; until then the client is
            # told its credential is unknown and re-enrols.
            return {"status": "credential_unknown", "result": None}

        if device.status == "pending":
            return {"status": "device_pending", "result": None}

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

        raw_at, _ = self._issue_access_token(device.id)
        self._session.commit()
        logger.info("Refreshed device %s", device.id)
        result = self._success(device, raw_at)
        result["status"] = "ok"
        return result

    def _success(self, device: Device, raw_at: str, raw_dr: str | None = None) -> dict[str, Any]:
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
        if raw_dr is not None:
            # Issued at enrolment and at explicit reissue only. A refresh does
            # NOT return a new one: it does not rotate.
            result["result"]["refresh_token"] = {
                "token": raw_dr,
                "expires_in": int(REFRESH_TOKEN_TTL.total_seconds()),
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

    def authorise_recovery(self, device_id: str) -> str:
        """Grant one recovery for a tombstoned device. Returns the secret once.

        Re-enable authorises a CONSUMER, not merely a race. A bare "this
        installation may enrol again" flag is claimable by whoever asks first,
        including the party the revocation was aimed at. The secret is
        delivered out of band and consumed atomically with the new device row.
        """
        tombstone = self._session.get(DeviceTombstone, device_id)
        if tombstone is None:
            raise LookupError(f"No tombstone for device {device_id}")
        if tombstone.consumed_at is not None:
            raise PermissionError("That recovery has already been used")

        raw = generate_key(prefix="rec")
        tombstone.recovery_secret_hash = hash_key(raw)
        self._session.commit()
        logger.info("Authorised recovery for device %s", device_id)
        return raw

    def _entomb(self, device: Device, reason: str) -> None:
        """Record that this device is finished, durably.

        Called from every terminal transition. A path that removes a device
        without one reopens the hole: the credentials go with the device, so a
        client that returns later presents something unknown, is told to
        re-enrol, and does.

        Idempotent -- re-revoking a device must not raise on the primary key.
        """
        if self._session.get(DeviceTombstone, device.id) is not None:
            return
        self._session.add(
            DeviceTombstone(
                device_id=device.id,
                installation_id=device.installation_id,
                reason=reason,
            )
        )

    def update_device_status(self, device_id: str, status: str) -> Device:
        device = self._session.get(Device, device_id)
        if device is None:
            raise ValueError(f"Device {device_id} not found")
        device.status = status
        if status == "revoked":
            self._entomb(device, reason="revoked by administrator")
            self._session.query(AccessToken).filter_by(device_id=device_id).delete()
            # The refresh credential too. It outlives the access token by thirty
            # days, so leaving it means a device that is later re-activated
            # silently regains a credential issued before it was revoked.
            self._session.query(DeviceRefreshToken).filter_by(device_id=device_id).delete()
        self._session.commit()
        logger.info("Updated device %s status to %s", device_id, status)
        return device

    def delete_device(self, device_id: str) -> None:
        device = self._session.get(Device, device_id)
        if device is None:
            raise ValueError(f"Device {device_id} not found")
        self._entomb(device, reason="deleted by administrator")
        # Cascade delete credentials first (in case the DB doesn't enforce it)
        self._session.query(AccessToken).filter_by(device_id=device_id).delete()
        self._session.query(DeviceRefreshToken).filter_by(device_id=device_id).delete()
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

    def _issue_refresh_token(self, device_id: str) -> tuple[str, DeviceRefreshToken]:
        """Create and persist a non-rotating refresh credential."""
        raw_dr = generate_key(prefix="dr")
        record = DeviceRefreshToken(
            token_hash=hash_key(raw_dr),
            device_id=device_id,
            expires_at=datetime.now(UTC) + REFRESH_TOKEN_TTL,
        )
        self._session.add(record)
        self._session.flush()
        return raw_dr, record

    def reissue_refresh_token(self, device_id: str) -> str:
        """Issue a replacement, revoking the previous one in the same transaction.

        Two statements, one commit. "Issue new" that does not revoke the old
        simply leaves two usable credentials, which is the opposite of what an
        administrator reaching for this is trying to achieve.
        """
        if self._session.get(Device, device_id) is None:
            raise LookupError(f"Device {device_id} not found")
        self._session.query(DeviceRefreshToken).filter(
            DeviceRefreshToken.device_id == device_id,
            DeviceRefreshToken.revoked_at.is_(None),
        ).update({"revoked_at": datetime.now(UTC)}, synchronize_session=False)
        raw_dr, _ = self._issue_refresh_token(device_id)
        self._session.commit()
        logger.info("Reissued refresh token for device %s", device_id)
        return raw_dr

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
