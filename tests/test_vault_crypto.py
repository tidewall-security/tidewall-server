"""The vault keyring and the sealed row format.

Everything here is decided before a database or a request is involved, so the
failure modes can be driven directly. The three that matter:

**The key id selects the key, so it is read before authentication.** It lives
in the row header in the clear, in the database an attacker able to tamper is
already writing to. Every branch keyed on it is therefore attacker-chosen, and
a quiet branch is a quiet answer they can select. In the ring and authentic is
a decrypt; everything else raises.

**GCM authenticates the ciphertext, not where it lives.** Without the row's own
identity bound as associated data, a valid blob copied from one row onto
another still authenticates, and the server returns the first vault's originals
under the second vault's id -- a decryption oracle for someone who never had
the key.

**The header is length-prefixed, not delimiter-separated.** A delimiter makes
the split depend on a character being absent from a value the parser does not
control, and shifting the split shifts which bytes are authenticated.
"""

from __future__ import annotations

import base64
import secrets
from datetime import UTC, datetime, timedelta

import pytest

from app.config import Settings
from app.vault_crypto import AuthenticationFailed, Keyring, LegacyRow, UnknownKey

EXPIRY = datetime(2026, 9, 1, 12, 0, 0, tzinfo=UTC)


def _material() -> bytes:
    """Raw 256-bit key material."""
    return secrets.token_bytes(32)


def _key() -> str:
    """Fresh key material, base64 encoded as an operator supplies it."""
    return base64.b64encode(_material()).decode()


def _settings(keys: dict[str, str] | None, current: str | None = None) -> Settings:
    declaration = None if keys is None else ",".join(f"{kid}:{material}" for kid, material in keys.items())
    return Settings(VAULT_ENCRYPTION_KEYS=declaration, VAULT_ENCRYPTION_CURRENT=current)


def _ring(keys: dict[str, str], current: str) -> Keyring:
    """Build a keyring the way a deployment does -- through the settings."""
    ring = Keyring.from_settings(_settings(keys, current=current))
    assert ring is not None
    return ring


def _key_id_of(blob: bytes) -> bytes:
    """The key id out of a sealed header. It is in the clear, which is the
    whole reason the tests below exist."""
    return blob[2 : 2 + blob[1]]


def _with_key_id(blob: bytes, forged: bytes) -> bytes:
    """Restamp a sealed blob with a different key id, leaving the nonce and
    ciphertext untouched. Exactly what someone able to write the database can
    do, using an id read out of any other row."""
    rest = blob[2 + blob[1] :]
    return blob[:1] + bytes([len(forged)]) + forged + rest


# ---------------------------------------------------------------------------
# The round trip and what it binds
# ---------------------------------------------------------------------------


def test_a_sealed_vault_round_trips():
    ring = _ring({"k1": _key()}, current="k1")
    blob = ring.seal("vault-1", EXPIRY, b'{"placeholders": {"a": "b"}}')
    assert ring.open("vault-1", EXPIRY, blob) == b'{"placeholders": {"a": "b"}}'


def test_a_blob_cannot_be_moved_to_another_row():
    """The row-substitution defect. GCM authenticates the ciphertext, not where
    it lives, so the vault id must be bound as associated data -- otherwise
    anyone able to write the database can copy a blob onto another row and have
    the server decrypt it under that row's id."""
    ring = _ring({"k1": _key()}, current="k1")
    blob = ring.seal("vault-1", EXPIRY, b"secret")

    with pytest.raises(AuthenticationFailed):
        ring.open("vault-2", EXPIRY, blob)


def test_the_expiry_is_bound_too():
    ring = _ring({"k1": _key()}, current="k1")
    blob = ring.seal("vault-1", EXPIRY, b"secret")

    with pytest.raises(AuthenticationFailed):
        ring.open("vault-1", EXPIRY + timedelta(days=365), blob)


def test_an_expiry_one_second_out_is_already_a_different_row():
    """The binding is not to the hour or the day. A row whose expiry was
    extended at all no longer opens."""
    ring = _ring({"k1": _key()}, current="k1")
    blob = ring.seal("vault-1", EXPIRY, b"secret")

    with pytest.raises(AuthenticationFailed):
        ring.open("vault-1", EXPIRY + timedelta(seconds=1), blob)


def test_the_expiry_binds_to_whole_seconds_so_a_stored_row_survives_the_round_trip():
    """Deliberate, and the one place the binding is loose on purpose: the
    expiry is authenticated at second granularity because the datetime comes
    back out of a database, and a backend that keeps no fractional seconds
    would otherwise make every row it stored unopenable. Sub-second is the only
    slack, and buying a fraction of a second of extra life is worth nothing."""
    ring = _ring({"k1": _key()}, current="k1")
    blob = ring.seal("vault-1", EXPIRY.replace(microsecond=123456), b"secret")

    assert ring.open("vault-1", EXPIRY, blob) == b"secret"


def test_a_naive_expiry_reads_as_utc():
    """SQLite has no timezone type, so an expiry read back off a row is naive
    even though it was written as UTC. It must bind to the same bytes."""
    ring = _ring({"k1": _key()}, current="k1")
    blob = ring.seal("vault-1", EXPIRY, b"secret")

    assert ring.open("vault-1", EXPIRY.replace(tzinfo=None), blob) == b"secret"


def test_the_sealed_blob_does_not_contain_the_plaintext():
    """The point of the whole task: no plaintext mapping at rest."""
    ring = _ring({"k1": _key()}, current="k1")
    blob = ring.seal("vault-1", EXPIRY, b"jon@example.com")

    assert b"jon@example.com" not in blob
    assert b"example" not in blob


def test_two_seals_of_the_same_plaintext_differ():
    """A reused nonce under one key destroys GCM. Per-row random nonce."""
    ring = _ring({"k1": _key()}, current="k1")
    assert ring.seal("v", EXPIRY, b"x") != ring.seal("v", EXPIRY, b"x")


# ---------------------------------------------------------------------------
# Rotation, misconfiguration, and the difference between them
# ---------------------------------------------------------------------------


def test_a_retained_key_still_opens_rows_written_under_it():
    """Rotation. The previous key stays in the ring for at least the TTL."""
    old, new = _key(), _key()
    blob = _ring({"k1": old}, current="k1").seal("vault-1", EXPIRY, b"secret")

    rotated = _ring({"k1": old, "k2": new}, current="k2")

    assert rotated.open("vault-1", EXPIRY, blob) == b"secret"


def test_new_vaults_are_sealed_under_the_current_key():
    """The other half of rotation: after repointing CURRENT, new rows name the
    new id, so the old key stops accruing rows and can leave after the TTL."""
    ring = _ring({"k1": _key(), "k2": _key()}, current="k2")

    assert _key_id_of(ring.seal("vault-1", EXPIRY, b"secret")) == b"k2"


def test_wrong_material_under_a_known_id_is_an_authentication_failure():
    """NOT an unknown key. The operator kept the id and changed the bytes, which
    is a misconfiguration and must be loud."""
    blob = _ring({"k1": _key()}, current="k1").seal("vault-1", EXPIRY, b"secret")

    with pytest.raises(AuthenticationFailed):
        _ring({"k1": _key()}, current="k1").open("vault-1", EXPIRY, blob)


def test_an_id_not_in_the_ring_is_UnknownKey_and_never_silent():
    blob = _ring({"k1": _key()}, current="k1").seal("vault-1", EXPIRY, b"secret")

    with pytest.raises(UnknownKey):
        _ring({"k2": _key()}, current="k2").open("vault-1", EXPIRY, blob)


def test_tampering_cannot_be_disguised_by_changing_the_key_id():
    """The evasion that survived two design rounds.

    An attacker who can write the database reads a key id out of any row -- it
    is in the header, in the clear -- and stamps it on a row whose ciphertext
    they altered. There must be no id that buys them a quiet answer: every
    outcome that is not a successful decrypt raises.
    """
    # TWO configured keys. With only one in the ring, forging "k2" exercises the
    # UNKNOWN-key branch and the test says nothing about a substituted key that
    # IS configured -- which is the case the design requires to be loud, and the
    # one an attacker reading ids out of other rows would actually reach.
    ring = _ring({"k1": _key(), "k2": _key()}, current="k1")
    blob = bytearray(ring.seal("vault-1", EXPIRY, b"secret"))
    blob[-1] ^= 0xFF  # tamper with the ciphertext

    # k1: the real id. k2: a DIFFERENT CONFIGURED id. k-nope: not in the ring.
    # None of the three may answer quietly.
    for forged, expected in (
        (b"k1", AuthenticationFailed),
        (b"k2", AuthenticationFailed),
        (b"k-nope", UnknownKey),
    ):
        with pytest.raises(expected):
            ring.open("vault-1", EXPIRY, _with_key_id(bytes(blob), forged))


def test_a_substituted_configured_id_is_loud_even_with_the_ciphertext_intact():
    """The same substitution without the tampering, stated on its own so it
    cannot pass because some *other* alteration was caught. A configured id
    that did not seal this row is an authentication failure, not an unknown
    key and not a quiet miss."""
    ring = _ring({"k1": _key(), "k2": _key()}, current="k1")
    blob = ring.seal("vault-1", EXPIRY, b"secret")

    with pytest.raises(AuthenticationFailed):
        ring.open("vault-1", EXPIRY, _with_key_id(blob, b"k2"))


def test_an_unknown_key_id_from_the_row_cannot_forge_a_log_line():
    """The id in the header is attacker-controlled bytes, and it reaches an
    error that an operator's log will carry. It must arrive escaped and
    bounded, not raw."""
    ring = _ring({"k1": _key()}, current="k1")
    blob = ring.seal("vault-1", EXPIRY, b"secret")
    forged = b"\n2026-01-01 ERROR forged line " + b"A" * 300

    with pytest.raises(UnknownKey) as caught:
        ring.open("vault-1", EXPIRY, _with_key_id(blob, forged[:255]))

    message = str(caught.value)
    assert "\n" not in message  # not a line the reader can be made to believe
    assert "\\n" in message  # escaped, so the id is still identifiable
    assert len(message) < 200  # and bounded, so it cannot flood the log


# ---------------------------------------------------------------------------
# The header: what it is, and what a malformed one does
# ---------------------------------------------------------------------------


def test_a_legacy_unversioned_row_is_recognised_not_crashed_on():
    """Every existing row is plaintext JSON with no header."""
    with pytest.raises(LegacyRow) as caught:
        _ring({"k1": _key()}, current="k1").open("vault-1", EXPIRY, b'{"placeholders": {}, "counters": {}}')

    # Recognised, and that is all. The row is not decoded, not returned, and
    # not quoted into an error an operator's log will keep -- these bytes are
    # unauthenticated and whoever wrote them chose every one of them.
    assert "placeholders" not in str(caught.value)


def test_an_altered_version_byte_is_loud():
    """An unrecognised version is a layout this code cannot parse. Guessing at
    it would read the length prefix out of somebody else's format."""
    ring = _ring({"k1": _key()}, current="k1")
    blob = bytearray(ring.seal("vault-1", EXPIRY, b"secret"))
    blob[0] = 0x02

    with pytest.raises(AuthenticationFailed, match="version"):
        ring.open("vault-1", EXPIRY, bytes(blob))


def test_a_key_id_containing_a_delimiter_still_round_trips():
    """The key id is length-prefixed, not delimiter-separated. A delimiter
    makes the split depend on a character being absent from a value the parser
    does not control -- the operator's id at seal time, arbitrary bytes out of
    the row at open time -- and shifting the split shifts which bytes are
    authenticated."""
    for awkward in ("k1|k2", "k1:k2", "k1,k2", "k1\nk2", "k1\x00k2", "k1 k2"):
        ring = Keyring({awkward: _material()}, current=awkward)
        blob = ring.seal("vault-1", EXPIRY, b"secret")
        assert ring.open("vault-1", EXPIRY, blob) == b"secret"


def test_a_key_id_length_that_swallows_the_nonce_is_loud():
    """The length byte is attacker-controlled too. Growing it moves the split
    between the id and the nonce, which is the shift the length prefix exists
    to make explicit rather than accidental."""
    ring = _ring({"k1": _key()}, current="k1")
    blob = bytearray(ring.seal("vault-1", EXPIRY, b"secret"))
    blob[1] = 14  # "k1" plus the whole nonce

    with pytest.raises((UnknownKey, AuthenticationFailed)):
        ring.open("vault-1", EXPIRY, bytes(blob))


def test_an_empty_key_id_is_loud():
    ring = _ring({"k1": _key()}, current="k1")
    blob = ring.seal("vault-1", EXPIRY, b"secret")

    with pytest.raises(AuthenticationFailed):
        ring.open("vault-1", EXPIRY, _with_key_id(blob, b""))


def test_every_truncation_of_a_row_is_loud():
    """Every cut point, not a sample of them.

    An earlier version of this test tried five, and all five happened to land
    where the header was still self-consistent enough to reach GCM and be
    refused there -- so it passed with the length check taken out, and said
    nothing about the cuts in between, which hand GCM a nonce too short to use
    and get a ValueError straight through `open` instead of one of the three
    failures this module promises.
    """
    ring = _ring({"k1": _key()}, current="k1")
    blob = ring.seal("vault-1", EXPIRY, b"secret")

    for cut in range(len(blob)):
        with pytest.raises((UnknownKey, AuthenticationFailed)):
            ring.open("vault-1", EXPIRY, blob[:cut])


def test_an_empty_row_is_loud():
    with pytest.raises(AuthenticationFailed):
        _ring({"k1": _key()}, current="k1").open("vault-1", EXPIRY, b"")


# ---------------------------------------------------------------------------
# The format is a compatibility contract
# ---------------------------------------------------------------------------

# Sealed once, by hand, under GOLDEN_KEY for vault id "vault-1" and the expiry
# below. Rows outlive the process that wrote them, so the header layout and the
# exact bytes it authenticates are a contract with every row already on disk:
# change either and an upgrade makes them all unopenable, quietly, one release
# later. Nothing here may be regenerated to make a test pass -- a deliberate
# format change is a version bump and a second parser.
GOLDEN_KEY = "3q2+796tvu/erb7v3q2+796tvu/erb7v3q2+796tvu8="
GOLDEN_BLOB = bytes.fromhex(
    "01"  # version
    "02"
    "6b31"  # a two-byte key id, "k1", behind its length
    "000102030405060708090a0b"  # the nonce this one was sealed with
    "876f02f23251c1a9d65e9121c5ae1d24954ca1e22ec8"  # ciphertext and GCM tag
)


def test_the_sealed_format_is_pinned():
    ring = _ring({"k1": GOLDEN_KEY}, current="k1")
    assert ring.open("vault-1", EXPIRY, GOLDEN_BLOB) == b"secret"


def test_the_pinned_blob_is_still_bound_to_its_own_row():
    """The pin is a real sealed row, not a byte string that happens to decode:
    it carries the same binding as everything else, so a change that dropped
    the binding but kept the layout could not slip past the test above."""
    ring = _ring({"k1": GOLDEN_KEY}, current="k1")

    with pytest.raises(AuthenticationFailed):
        ring.open("vault-2", EXPIRY, GOLDEN_BLOB)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


def test_no_keys_configured_means_no_keyring():
    assert Keyring.from_settings(_settings(keys=None)) is None


def test_a_current_key_without_any_keys_is_a_startup_error():
    """Not "unconfigured". The operator named a key and supplied none, and
    returning None here would turn that into silently irreversible redaction."""
    with pytest.raises(ValueError, match="VAULT_ENCRYPTION_KEYS"):
        Keyring.from_settings(_settings(keys=None, current="k1"))


def test_keys_without_a_current_is_a_startup_error():
    # Matching the whole phrase, not just the setting name: the operator has to
    # be told this one is *missing*. Fall through to the is-it-in-the-ring check
    # below and they are told VAULT_ENCRYPTION_CURRENT "names None", which is
    # both true and useless.
    with pytest.raises(ValueError, match="VAULT_ENCRYPTION_CURRENT is not"):
        Keyring.from_settings(_settings({"k1": _key()}))


def test_a_current_that_is_not_in_the_ring_is_a_startup_error():
    with pytest.raises(ValueError, match="VAULT_ENCRYPTION_CURRENT"):
        Keyring.from_settings(_settings({"k1": _key()}, current="k2"))


def test_key_material_must_be_256_bits():
    short = base64.b64encode(secrets.token_bytes(16)).decode()
    with pytest.raises(ValueError, match="32 bytes"):
        Keyring.from_settings(_settings({"k1": short}, current="k1"))

    with pytest.raises(ValueError, match="32 bytes"):
        Keyring({"k1": secrets.token_bytes(16)}, current="k1")


def test_a_ring_whose_current_is_absent_is_refused():
    with pytest.raises(ValueError, match="current"):
        Keyring({"k1": _material()}, current="k2")


def test_an_empty_ring_is_refused():
    # Again the phrase, not the type: without its own check this lands on the
    # current-key check and reports a missing current key for a ring that has
    # no keys at all.
    with pytest.raises(ValueError, match="no keys"):
        Keyring({}, current="k1")


#: Well-formed material, so that every case below fails for its own reason and
#: not because the bytes were never valid. An earlier version wrote "AAAA"
#: here, which decodes to three bytes: every case was already invalid, and the
#: whitespace and key-id rules were being asserted by a test that would have
#: passed without them.
_GOOD = base64.b64encode(bytes(range(32))).decode()


@pytest.mark.parametrize(
    "declaration",
    [
        "k1",  # no material
        "k1:",  # empty material
        f":{_GOOD}",  # no id
        f"k1:{_GOOD[:10]}!{_GOOD[10:]}",  # a stray character inside the material
        "k1:a:b",  # an id carrying the separator would shift this parse
        f" k1:{_GOOD}",  # whitespace is an error, not something to strip
        f"k1:{_GOOD} ",
        f"k1:{_GOOD}, k2:{_GOOD}",
        f"k 1:{_GOOD}",  # ids are labels, not arbitrary text
        f"k\n1:{_GOOD}",
    ],
)
def test_a_malformed_keys_declaration_is_a_startup_error(declaration):
    # Anchored: "VAULT_ENCRYPTION_KEYS" on its own also appears in the message
    # for a CURRENT that names nothing in the ring, so an unanchored match
    # passes when a bad declaration is quietly accepted and the failure lands
    # one check later, on a different setting, for a different reason.
    with pytest.raises(ValueError, match=r"\AVAULT_ENCRYPTION_KEYS"):
        Keyring.from_settings(Settings(VAULT_ENCRYPTION_KEYS=declaration, VAULT_ENCRYPTION_CURRENT="k1"))


def test_a_duplicate_key_id_is_a_startup_error():
    """One id, two materials: the later one would silently win and rows sealed
    under the earlier would stop opening."""
    with pytest.raises(ValueError, match="VAULT_ENCRYPTION_KEYS"):
        Keyring.from_settings(
            Settings(
                VAULT_ENCRYPTION_KEYS=f"k1:{_key()},k1:{_key()}",
                VAULT_ENCRYPTION_CURRENT="k1",
            )
        )


def test_a_key_id_longer_than_the_header_can_carry_is_refused():
    with pytest.raises(ValueError, match="255"):
        Keyring({"k" * 256: _material()}, current="k" * 256)


def test_settings_carry_the_declaration_unparsed():
    """The parse belongs to the crypto module, and runs once at startup where a
    malformed declaration stops the server rather than a single request."""
    settings = Settings(VAULT_ENCRYPTION_KEYS="k1:AAAA", VAULT_ENCRYPTION_CURRENT="k1")
    assert settings.VAULT_ENCRYPTION_KEYS == "k1:AAAA"
    assert settings.VAULT_ENCRYPTION_CURRENT == "k1"
    assert Settings().VAULT_ENCRYPTION_KEYS is None
    assert Settings().VAULT_ENCRYPTION_CURRENT is None
