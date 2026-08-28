"""The vault keyring and the sealed row format.

A vault holds the placeholder-to-original mapping that makes redaction
reversible, which is to say it holds exactly the values the product exists to
protect. This module is what stands between that mapping and the database file:
AES-256-GCM under a keyring, with the row's own identity authenticated
alongside the ciphertext.

It knows nothing about the database or the request, so every classification it
makes can be driven directly.

Three things decide the shape, and each one was arrived at by getting it wrong
first.

**The key id selects the key, so it is read before authentication.** It sits in
the row header in the clear, in the database an attacker able to tamper is
already writing to. Every branch keyed on it is therefore attacker-chosen, and
a quiet branch is a quiet answer they can select: they read a plausible id out
of any other row, stamp it on a row whose ciphertext they altered, and take
whatever the quiet branch gives them. So there is no quiet branch. In the ring
and authentic is a decrypt; **everything else raises**. `open` never returns a
value that is not a successfully authenticated plaintext.

That is only correct because expired rows are deleted rather than merely
refused. A key stays in the ring for at least the vault TTL and retention
removes rows before it leaves, so a live row naming an id nobody configured is
an anomaly -- a key withdrawn too early, a database restored from an old
backup, or tampering -- and all three deserve to be loud. Retention is what
makes loud key removal correct.

**GCM authenticates the ciphertext, not where it lives.** Without the row's
identity bound as associated data, a valid blob copied from one row onto
another still authenticates, and the server hands back the first vault's
originals under the second vault's id: a decryption oracle for someone who
never held the key. The associated data binds the format version, the key id,
the **vault id** and the **expiry**.

**The header is length-prefixed, not delimiter-separated.** A delimiter makes
the split depend on some character being absent from a value the parser does
not control -- an operator-chosen id at seal time, arbitrary bytes out of the
row at open time -- and moving the split moves which bytes are authenticated.

Stored layout, all of it in the clear::

    version   1 byte    always 0x01
    id_len    1 byte    length of the key id, 1..255
    key_id    id_len    UTF-8, operator-chosen
    nonce     12 bytes  fresh per row; a reused nonce under one key ends GCM
    sealed    rest      ciphertext followed by the 16-byte GCM tag

Authenticated as associated data, and never stored, because both halves come
from the row itself::

    version | id_len | key_id | vault_id_len | vault_id | expires_at

Callers on the read path must handle :class:`LegacyRow` separately from
:class:`UnknownKey` and :class:`AuthenticationFailed`: the first is a row
written before this format existed and is known to hold nothing, while the
other two are the loud ones. Catching :class:`VaultCryptoError` on that path
collapses the distinction this module exists to draw.
"""

from __future__ import annotations

import base64
import os
import re
import struct
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from typing import NamedTuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.config import Settings
from app.utils import as_utc

#: The only format version this code speaks. A blob announcing any other is
#: refused rather than parsed: the length prefix would be read out of a layout
#: this parser does not know.
_VERSION = 1
_VERSION_BYTE = bytes([_VERSION])

#: AES-256.
_KEY_BYTES = 32
#: The standard GCM nonce length.
_NONCE_BYTES = 12
#: The GCM tag, appended to the ciphertext by ``AESGCM.encrypt``.
_TAG_BYTES = 16
#: What one length byte can address.
_MAX_KEY_ID_BYTES = 255

#: A legacy row is unversioned JSON, so it opens with ``{``. 0x7B is not the
#: version byte and never will be, which is what makes the two separable at
#: all. Recognising one is not a favour to an attacker: they can write these
#: bytes over any row, but doing so destroys it rather than forging anything,
#: and deleting the row was already available to them.
_LEGACY_FIRST_BYTE = b"{"

#: Ids are labels, not arbitrary text. Restricting them removes every question
#: about how the declaration below splits. It is not what makes the *header*
#: safe -- there the id arrives from the row, where nothing is restricted, and
#: the length prefix is what makes that parse unambiguous.
_KEY_ID_RE = re.compile(r"\A[A-Za-z0-9._-]{1,64}\Z")

_ENTRY_SEPARATOR = ","
_ID_SEPARATOR = ":"

_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)

#: How much of an id from a row may reach an error message.
_RENDERED_ID_BYTES = 32


class VaultCryptoError(Exception):
    """Base for every refusal this module makes.

    Do not catch this on the read path. :class:`LegacyRow` means an empty row
    from before this format; the other two mean something is wrong with the
    deployment or with the database, and must not read as a missing vault.
    """


class UnknownKey(VaultCryptoError):
    """The row names a key id that is not in the ring.

    Not a quiet miss. The id is attacker-controlled, so answering quietly here
    would let any tampering be disguised as a key that has simply gone away.
    """


class AuthenticationFailed(VaultCryptoError):
    """The row did not authenticate under the key it names.

    Covers wrong key material under a right id, a blob moved to another row, an
    altered expiry, altered ciphertext, and any header this parser cannot make
    sense of. All of them mean the bytes on disk are not the bytes that were
    written, or the key in the configuration is not the key that wrote them.
    """


class LegacyRow(VaultCryptoError):
    """The row predates this format: unversioned, unencrypted JSON.

    Every such row holds an empty mapping, because nothing ever wrote a
    populated one. It carries no plaintext to recover and this module will not
    return its bytes.
    """


def _render_key_id(key_id: bytes) -> str:
    """A key id from a row, made safe to put in front of an operator.

    The id is attacker-controlled bytes on a path whose whole job is to be
    loud, so it reaches a log by construction. ``repr`` escapes the newline
    that would otherwise let it forge a log line of its own, and the slice
    stops it flooding one.
    """
    return repr(key_id[:_RENDERED_ID_BYTES])


def _expiry_seconds(expires_at: datetime) -> int:
    """The expiry as whole seconds since the epoch.

    Whole seconds on purpose. This datetime makes the round trip through a
    database column, and a backend keeping no fractional seconds would
    otherwise hand back a different instant than was sealed and make every row
    it stored unopenable. Sub-second is the only slack in the binding, and a
    fraction of a second of extra life is worth nothing to anyone.

    Floor division on a timedelta, not ``timestamp()``: exact integer
    arithmetic rather than a float that has to be rounded back.
    """
    return (as_utc(expires_at) - _EPOCH) // timedelta(seconds=1)


def _associated_data(key_id: bytes, vault_id: str, expires_at: datetime) -> bytes:
    """What GCM authenticates besides the ciphertext.

    Every field is length-prefixed or fixed-width, so exactly one set of
    values produces any given string of bytes. Without that, a shorter id and
    a longer vault id could add up to the same authenticated bytes, and the
    binding would hold for a pair of rows that were never the same row.

    The version is the constant rather than the byte off the blob because
    :func:`_parse` has already refused anything else -- which is why altering
    that byte is caught there and not here.
    """
    vault = vault_id.encode("utf-8")
    return b"".join(
        (
            _VERSION_BYTE,
            bytes([len(key_id)]),
            key_id,
            struct.pack(">I", len(vault)),
            vault,
            struct.pack(">q", _expiry_seconds(expires_at)),
        )
    )


class _Sealed(NamedTuple):
    """A parsed header. Nothing in it has been authenticated yet."""

    key_id: bytes
    nonce: bytes
    ciphertext: bytes


def _parse(blob: bytes) -> _Sealed:
    """Split a stored row into its header, nonce and ciphertext.

    Every rejection is loud. A row that cannot be parsed is a row whose bytes
    are not the bytes that were written, and the only alternative to raising is
    guessing at a layout.
    """
    if not blob:
        raise AuthenticationFailed("sealed vault: the row is empty")
    if blob[:1] == _LEGACY_FIRST_BYTE:
        raise LegacyRow("vault row predates the sealed format")
    if blob[:1] != _VERSION_BYTE:
        raise AuthenticationFailed(f"sealed vault: unsupported format version {blob[0]:#04x}")
    if len(blob) < 2:
        raise AuthenticationFailed("sealed vault: the header ends before the key id length")

    key_id_len = blob[1]
    if key_id_len == 0:
        raise AuthenticationFailed("sealed vault: the header carries no key id")

    nonce_at = 2 + key_id_len
    if len(blob) < nonce_at + _NONCE_BYTES + _TAG_BYTES:
        raise AuthenticationFailed("sealed vault: the row is shorter than its header claims")

    return _Sealed(
        key_id=blob[2:nonce_at],
        nonce=blob[nonce_at : nonce_at + _NONCE_BYTES],
        ciphertext=blob[nonce_at + _NONCE_BYTES :],
    )


class Keyring:
    """The keys a deployment can seal and open vault rows with.

    More than one, always, even when only one is in use. A single anonymous key
    cannot tell a rotation apart from a misconfiguration: derive an id from the
    material and wrong material looks like a rotation, hold the id constant and
    every rotation looks like wrong material. Operator-chosen ids, plus a
    separately named current one, is the shape that answers both.
    """

    def __init__(self, keys: Mapping[str, bytes], current: str) -> None:
        if not keys:
            raise ValueError("vault encryption keyring holds no keys")
        if current not in keys:
            raise ValueError(f"vault encryption keyring current key {current!r} is not in the ring")

        by_id: dict[bytes, bytes] = {}
        for key_id, material in keys.items():
            encoded = key_id.encode("utf-8")
            if not encoded:
                raise ValueError("vault encryption key id is empty")
            if len(encoded) > _MAX_KEY_ID_BYTES:
                raise ValueError(
                    f"vault encryption key id {key_id!r} encodes to {len(encoded)} bytes; "
                    f"the row header carries at most {_MAX_KEY_ID_BYTES}"
                )
            if len(material) != _KEY_BYTES:
                raise ValueError(
                    f"vault encryption key {key_id!r} material must be {_KEY_BYTES} bytes "
                    f"(AES-256), got {len(material)}"
                )
            by_id[encoded] = material

        # Keyed by the encoded id, so looking one up out of a row is a bytes
        # comparison and nothing decodes attacker-supplied bytes to get there.
        self._keys = by_id
        self._current = current.encode("utf-8")

    @property
    def current(self) -> str:
        """The id new vaults are sealed under."""
        return self._current.decode("utf-8")

    @classmethod
    def from_settings(cls, settings: Settings) -> Keyring | None:
        """Build the ring the deployment declared, or ``None`` if it declared none.

        ``None`` means no key is configured, and reversible redaction has
        nowhere safe to put a mapping. Every other shape of the declaration is
        a startup error: an operator who wrote half of it did not mean for
        redaction to go quietly irreversible.
        """
        declaration = settings.VAULT_ENCRYPTION_KEYS
        current = settings.VAULT_ENCRYPTION_CURRENT

        if not declaration:
            if current:
                raise ValueError(
                    "VAULT_ENCRYPTION_CURRENT is set but VAULT_ENCRYPTION_KEYS is not; "
                    "supply the key material or unset both"
                )
            return None

        keys = _parse_declaration(declaration)

        if not current:
            raise ValueError(
                "VAULT_ENCRYPTION_KEYS is set but VAULT_ENCRYPTION_CURRENT is not; "
                "name the id new vaults are sealed under"
            )
        if current not in keys:
            raise ValueError(
                f"VAULT_ENCRYPTION_CURRENT names {current!r}, which is not one of the ids in " f"VAULT_ENCRYPTION_KEYS"
            )

        try:
            return cls(keys, current)
        except ValueError as exc:
            raise ValueError(f"VAULT_ENCRYPTION_KEYS: {exc}") from exc

    def seal(self, vault_id: str, expires_at: datetime, plaintext: bytes) -> bytes:
        """Encrypt ``plaintext`` for this row, under the current key."""
        key_id = self._current
        nonce = os.urandom(_NONCE_BYTES)
        sealed = AESGCM(self._keys[key_id]).encrypt(nonce, plaintext, _associated_data(key_id, vault_id, expires_at))
        return b"".join((_VERSION_BYTE, bytes([len(key_id)]), key_id, nonce, sealed))

    def open(self, vault_id: str, expires_at: datetime, blob: bytes) -> bytes:
        """Decrypt a row, or raise.

        ``vault_id`` and ``expires_at`` come from the row being read, not from
        the blob, which is what makes them a binding rather than a copy the
        writer could have adjusted to match.

        There is deliberately no return path that is not an authenticated
        plaintext. Raises :class:`LegacyRow` for a row from before this format,
        :class:`UnknownKey` for an id nobody configured, and
        :class:`AuthenticationFailed` for everything else.
        """
        sealed = _parse(blob)

        material = self._keys.get(sealed.key_id)
        if material is None:
            raise UnknownKey(f"sealed vault {vault_id}: no key configured for id {_render_key_id(sealed.key_id)}")

        try:
            return AESGCM(material).decrypt(
                sealed.nonce,
                sealed.ciphertext,
                _associated_data(sealed.key_id, vault_id, expires_at),
            )
        except InvalidTag as exc:
            raise AuthenticationFailed(
                f"sealed vault {vault_id}: authentication failed under key id " f"{_render_key_id(sealed.key_id)}"
            ) from exc


def _parse_declaration(declaration: str) -> dict[str, bytes]:
    """Parse ``VAULT_ENCRYPTION_KEYS`` into ``id -> material``.

    Every rejection is a startup error, for the reason the NAT64 posture gives:
    a value that has to be cleaned up before it parses is a value nobody
    checked, and the declaration in the environment would then differ from the
    ring in force.
    """
    keys: dict[str, bytes] = {}

    for entry in declaration.split(_ENTRY_SEPARATOR):
        if entry != entry.strip():
            raise ValueError(
                f"VAULT_ENCRYPTION_KEYS entry {entry!r} has surrounding whitespace; "
                "write the value with no spaces around its entries"
            )

        key_id, separator, material = entry.partition(_ID_SEPARATOR)
        if not separator:
            raise ValueError(f"VAULT_ENCRYPTION_KEYS entry {entry!r} is not 'id:base64-material'")
        if not _KEY_ID_RE.match(key_id):
            raise ValueError(
                f"VAULT_ENCRYPTION_KEYS key id {key_id!r} is not 1 to 64 characters of "
                "letters, digits, dot, underscore or hyphen"
            )
        if _ID_SEPARATOR in material:
            raise ValueError(
                f"VAULT_ENCRYPTION_KEYS entry {entry!r} has more than one {_ID_SEPARATOR!r}; "
                "an id carrying the separator would move where this splits"
            )
        if key_id in keys:
            raise ValueError(
                f"VAULT_ENCRYPTION_KEYS names {key_id!r} twice; one id has one material, "
                "or rows sealed under the first would stop opening"
            )

        try:
            # `binascii.Error` is a ValueError, so one clause covers a bad
            # alphabet and bad padding alike.
            keys[key_id] = base64.b64decode(material, validate=True)
        except ValueError as exc:
            raise ValueError(f"VAULT_ENCRYPTION_KEYS material for key id {key_id!r} is not valid base64") from exc

    return keys
