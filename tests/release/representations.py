"""How one secret can look on the way to a surface.

A canary planted as plain text does not arrive as plain text everywhere. JSON
encoding escapes it, a URL query percent-encodes it, a database column may hold
raw bytes, and Unicode normalisation can rewrite it before storage. A sweep
that searches only for the plain form finds only the plain form, and reports
absence everywhere else.

**Each family needs its own decoder AND its own positive control.** A
plain-text plant proves the searcher works; it proves nothing about the
`\\uXXXX` decoder sitting beside it. That distinction is why every family here
carries an `encode` and is separately exercised at every applicable surface.

**Stated limit.** This is a finite oracle over an infinite space. It does not
detect arbitrary transforms -- HTML entities, Base64, compression, repeated or
mixed encodings, or serializer-specific forms outside this list. The design
records that as a residual and it is not narrowed here.
"""

from __future__ import annotations

import json
import unicodedata
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass

#: Probes, plural, because no single value distinguishes all seven families.
#:
#: Measured: for "café" typed as NFC, `plain`, `raw-bytes` and `nfc` produce
#: byte-identical output -- so a positive control for one passes for the other
#: two, and three families look covered while one thing is tested. For the same
#: text typed as NFD, `plain` and `nfd` coincide instead.
#:
#: This is not a defect in the families; it is a property of the value. A
#: family is only *exercised* by an input for which it differs from the others,
#: so each family declares the probe that distinguishes it, and
#: `distinguishing_probe` is what the positive controls use.
NFC_PROBE = "caf\u00e9"  # é as one composed code point
NFD_PROBE = "cafe\u0301"  # e + combining acute
ASCII_PROBE = "canary-plain-ascii"


def distinguishing_probe(family: str) -> str:
    """A value for which *family* differs from every other family.

    Using one probe everywhere would let a family with no distinguishing input
    pass on another family's evidence.
    """
    if family == "nfc":
        # Only differs from `plain` when the source is decomposed.
        return NFD_PROBE
    if family == "nfd":
        # Only differs from `plain` when the source is composed.
        return NFC_PROBE
    return NFC_PROBE


@dataclass(frozen=True)
class Representation:
    name: str
    encode: Callable[[str], bytes]
    why: str

    def find(self, haystack: bytes, needle: str) -> bool:
        return self.encode(needle) in haystack


def _plain(value: str) -> bytes:
    return value.encode("utf-8")


def _json_escaped(value: str) -> bytes:
    # json.dumps wraps in quotes; the escaped BODY is what appears inside a
    # larger document, so the quotes are stripped.
    return json.dumps(value)[1:-1].encode("utf-8")


def _unicode_escaped(value: str) -> bytes:
    """`\\uXXXX` escapes, with SURROGATE PAIRS for astral codepoints.

    `f"\\u{ord(c):04x}"` emits five hex digits for anything above the BMP --
    U+1F600 became the malformed `\\u1f600` -- so the form was not decodable
    and did not round-trip. Every escape is exactly four hex digits, which is
    what `\\u` means.
    """
    out = []
    for char in value:
        point = ord(char)
        if point > 0xFFFF:
            point -= 0x10000
            out.append(f"\\u{0xD800 + (point >> 10):04x}")
            out.append(f"\\u{0xDC00 + (point & 0x3FF):04x}")
        else:
            out.append(f"\\u{point:04x}")
    return "".join(out).encode("ascii")


def _raw_bytes(value: str) -> bytes:
    return value.encode("utf-8")


def _nfc(value: str) -> bytes:
    return unicodedata.normalize("NFC", value).encode("utf-8")


def _nfd(value: str) -> bytes:
    return unicodedata.normalize("NFD", value).encode("utf-8")


def _percent_encoded(value: str) -> bytes:
    return urllib.parse.quote(value, safe="").encode("ascii")


# --- DECODERS -----------------------------------------------------------
#
# The module docstring has always said each family needs its own decoder. Only
# the encoders existed, so a case declaring a representation was planted with
# escaped bytes and handed straight to a detector -- skipping the decode any
# real boundary performs. The escaped form is not the value; it is the value's
# wire encoding, and a detector that never sees the decode cannot match it.


def _decode_plain(value: str) -> str:
    return value


def _decode_json_escaped(value: str) -> str:
    return json.loads(f'"{value}"')


def _decode_unicode_escaped(value: str) -> str:
    # `unicode_escape` leaves surrogate halves unpaired; json re-joins them.
    return json.loads(f'"{value}"')


def _decode_nfc(value: str) -> str:
    return unicodedata.normalize("NFC", value)


def _decode_nfd(value: str) -> str:
    # Decoding an NFD form yields the canonical composed value, which is what a
    # comparison against the original expects.
    return unicodedata.normalize("NFC", value)


def _decode_percent(value: str) -> str:
    return urllib.parse.unquote(value)


DECODERS: dict[str, Callable[[str], str]] = {
    "plain": _decode_plain,
    "json-escaped": _decode_json_escaped,
    "unicode-escaped": _decode_unicode_escaped,
    "raw-bytes": _decode_plain,
    "nfc": _decode_nfc,
    "nfd": _decode_nfd,
    "percent-encoded": _decode_percent,
}


def decode(representation: str, value: str) -> str:
    """The value a boundary would hand on after decoding this family's form."""
    if representation not in DECODERS:
        raise KeyError(f"no decoder for representation {representation!r}")
    return DECODERS[representation](value)


#: The seven families the design names, in the manifest's declared order.
FAMILIES: tuple[Representation, ...] = (
    Representation("plain", _plain, "as typed"),
    Representation("json-escaped", _json_escaped, "inside a JSON document"),
    Representation("unicode-escaped", _unicode_escaped, "\\uXXXX, as some serialisers emit"),
    # NOTE: byte-identical to `plain`, and deliberately so. What distinguishes
    # this family is the STORAGE FORM -- a BLOB column rather than TEXT -- not
    # the encoding. Its positive control must therefore plant a BLOB and prove
    # the sweep reads it, because an encoding-only control here is just the
    # `plain` control under another name. See `STORAGE_DISTINGUISHED`.
    Representation("raw-bytes", _raw_bytes, "stored as a BLOB rather than TEXT"),
    Representation("nfc", _nfc, "composed normalisation"),
    Representation("nfd", _nfd, "decomposed normalisation"),
    Representation("percent-encoded", _percent_encoded, "in a URL or query string"),
)

BY_NAME: dict[str, Representation] = {family.name: family for family in FAMILIES}

#: Families whose distinction is WHERE the bytes live, not what they are.
#:
#: `raw-bytes` encodes identically to `plain`; a control that only compares
#: encodings tests `plain` twice and reports two families covered. These
#: families are exercised by planting into the storage form they name.
STORAGE_DISTINGUISHED: frozenset[str] = frozenset({"raw-bytes"})


def indistinguishable_from(family: str, probe: str) -> set[str]:
    """Other families producing identical bytes for *probe*.

    Exposed rather than hidden: a positive control for a family with a
    non-empty result here is not evidence about that family alone.
    """
    mine = BY_NAME[family].encode(probe)
    return {other.name for other in FAMILIES if other.name != family and other.encode(probe) == mine}


#: The shortest fragment of a secret whose disclosure still matters.
#:
#: A full-value search misses partial disclosure: a log truncating to 32
#: characters, or an error quoting the first line, leaks the beginning of a
#: credential while a whole-value sweep reports nothing. Minimum fragments are
#: searched wherever partial disclosure is plausible.
MINIMUM_FRAGMENT = 12


def fragments(value: str, size: int = MINIMUM_FRAGMENT) -> tuple[str, ...]:
    """Every contiguous fragment of *size*, for partial-disclosure searching."""
    if len(value) <= size:
        return (value,)
    return tuple(value[i : i + size] for i in range(len(value) - size + 1))
