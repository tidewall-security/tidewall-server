"""Each family must be distinguishable, or it is not a family.

The trap this file exists to close: seven declared representations, one probe,
and three of them producing identical bytes -- so a positive control for
`plain` silently passes for `raw-bytes` and `nfc`, and the suite reports seven
covered while testing five.
"""

from __future__ import annotations

import pytest

from tests.release.representations import (
    ASCII_PROBE,
    BY_NAME,
    FAMILIES,
    MINIMUM_FRAGMENT,
    NFC_PROBE,
    NFD_PROBE,
    STORAGE_DISTINGUISHED,
    distinguishing_probe,
    fragments,
    indistinguishable_from,
)


def test_the_seven_declared_families_exist():
    assert [f.name for f in FAMILIES] == [
        "plain",
        "json-escaped",
        "unicode-escaped",
        "raw-bytes",
        "nfc",
        "nfd",
        "percent-encoded",
    ]


@pytest.mark.parametrize("family", [f.name for f in FAMILIES])
def test_every_family_is_distinguishable_by_its_own_probe(family):
    """Except those distinguished by storage rather than encoding.

    `raw-bytes` is byte-identical to `plain` by construction; it is exercised
    by planting a BLOB, not by comparing encodings. Every other family must
    produce bytes no other family produces for its declared probe.
    """
    probe = distinguishing_probe(family)
    clashes = indistinguishable_from(family, probe)

    # Two exemptions, both definitional rather than convenient:
    #
    #   `raw-bytes` encodes exactly as `plain` -- its distinction is the
    #   storage form, so it is exercised by planting a BLOB.
    #
    #   `plain` IS whichever normalisation form its input already occupies, so
    #   it necessarily equals `nfc` for composed text or `nfd` for decomposed.
    #   That is what the word means; it is not a gap.
    permitted = set(STORAGE_DISTINGUISHED)
    if family == "plain":
        permitted |= {"nfc", "nfd"}
    if family in STORAGE_DISTINGUISHED:
        return

    assert clashes <= permitted, f"{family} is indistinguishable from {sorted(clashes - permitted)} for {probe!r}"


def test_nfc_and_nfd_are_not_accidentally_equal():
    """A single probe made these identical, which is the failure this catches.

    For NFC-typed text, `nfc` equals `plain`. For NFD-typed text, `nfd` does.
    Neither is distinguished by the other's probe.
    """
    assert BY_NAME["nfc"].encode(NFD_PROBE) != BY_NAME["plain"].encode(NFD_PROBE)
    assert BY_NAME["nfd"].encode(NFC_PROBE) != BY_NAME["plain"].encode(NFC_PROBE)


@pytest.mark.parametrize("family", [f.name for f in FAMILIES])
def test_every_family_finds_its_own_encoding_and_a_plain_search_does_not(family):
    """The point of having decoders at all.

    A plain-text search finds the plain form. If it also found the escaped and
    percent-encoded forms, the families would be decoration.
    """
    probe = distinguishing_probe(family)
    representation = BY_NAME[family]
    haystack = b"prefix " + representation.encode(probe) + b" suffix"
    assert representation.find(haystack, probe)

    if family not in {"plain", "raw-bytes", "nfc", "nfd"}:
        assert (
            BY_NAME["plain"].encode(probe) not in haystack
        ), f"a plain search already finds the {family} form; the decoder proves nothing"


def test_fragments_cover_partial_disclosure():
    """A truncated leak is still a leak.

    A whole-value search reports nothing when a log truncates a credential or
    an error quotes its first line.
    """
    value = "AKIA" + "X" * 20
    parts = fragments(value)
    assert all(len(p) == MINIMUM_FRAGMENT for p in parts)
    assert value[:MINIMUM_FRAGMENT] in parts
    assert value[-MINIMUM_FRAGMENT:] in parts


def test_a_short_value_yields_itself():
    assert fragments("short", size=MINIMUM_FRAGMENT) == ("short",)


def test_the_ascii_probe_cannot_distinguish_the_normalisation_families():
    """Recorded so nobody 'simplifies' the probes back to one ASCII value.

    An ASCII canary makes plain, raw-bytes, nfc and nfd byte-identical, which
    is exactly how four families come to look covered by one control.
    """
    encodings = {f.name: f.encode(ASCII_PROBE) for f in FAMILIES}
    assert encodings["plain"] == encodings["nfc"] == encodings["nfd"] == encodings["raw-bytes"]
