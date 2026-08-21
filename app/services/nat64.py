"""RFC 6052 NAT64 translation, against the deployment's declared posture.

`validate_destination` refuses destinations that are not public. On a network
running NAT64 with a Network-Specific Prefix, that refusal does not hold on its
own: an NSP is the deploying organisation's own prefix, chosen from space this
runtime classifies as global, so an address inside it passes an address-scope
predicate while the local gateway translates it to an embedded IPv4 address
that may be internal.

No generic address-scope predicate without deployment prefix knowledge can
detect that. This module supplies the prefix knowledge, from a declaration the
operator makes. The declaration is not verified and cannot be: see
`internal/findings/P1-nat64-nsp-sender-bypass.md`.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

#: RFC 6052 section 2.2 admits exactly these prefix lengths.
_PERMITTED_LENGTHS = frozenset({32, 40, 48, 56, 64, 96})

#: Where the embedded IPv4 sits, per prefix length, as (start_bit, bit_count).
#:
#: The octet at bits 64-71 is reserved and MUST be zero. Two lengths extract
#: directly rather than one: /32 finishes at bit 63, BEFORE the reserved octet,
#: and /96 starts at bit 96, after it. The four in between cross it. Getting
#: this wrong for /32 is a silent hole, and the finding that governs closure
#: originally stated it wrongly.
_LAYOUT: dict[int, tuple[tuple[int, int], ...]] = {
    32: ((32, 32),),
    40: ((40, 24), (72, 8)),
    48: ((48, 16), (72, 16)),
    56: ((56, 8), (72, 24)),
    64: ((72, 32),),
    96: ((96, 32),),
}

_U_OCTET_SHIFT = 128 - 64 - 8


@dataclass(frozen=True)
class Pref64Posture:
    """What the deployment says about NAT64 translation on its network.

    Three states, and they are not interchangeable. ``is_unset`` means nobody
    has said, and content export refuses rather than assuming. ``is_none`` is
    an explicit operator assertion that no translation is reachable -- an
    assertion, not a verified fact. Otherwise ``prefixes`` carries the declared
    translation prefixes, already masked to their own lengths.
    """

    is_unset: bool = False
    is_none: bool = False
    prefixes: tuple[ipaddress.IPv6Network, ...] = ()


def _u_octet(value: int) -> int:
    return (value >> _U_OCTET_SHIFT) & 0xFF


def parse_pref64(raw: str | None) -> Pref64Posture:
    """Parse ``PREF64`` into a canonical posture, or raise.

    Every rejection here is a startup error by design: a value that has to be
    cleaned up before it parses is a value nobody checked, and the declaration
    in the environment would then differ from the posture in force.
    """
    if raw is None:
        return Pref64Posture(is_unset=True)

    entries = raw.split(",")
    for entry in entries:
        if entry != entry.strip():
            raise ValueError(
                f"PREF64 entry {entry!r} has surrounding whitespace; "
                "write the value with no spaces around its entries"
            )
        if not entry:
            raise ValueError("PREF64 has an empty entry")

    if any(entry == "none" for entry in entries):
        if len(entries) != 1:
            raise ValueError("PREF64 cannot combine 'none' with translation prefixes")
        return Pref64Posture(is_none=True)

    prefixes: list[ipaddress.IPv6Network] = []
    for entry in entries:
        try:
            # strict=False so that bits below the prefix length are MASKED
            # rather than rejected. Unmasked they sit exactly where the IPv4
            # payload goes for /32 through /56.
            network = ipaddress.IPv6Network(entry, strict=False)
        except ValueError as exc:
            raise ValueError(f"PREF64 entry {entry!r} is not an IPv6 prefix: {exc}") from exc

        if network.prefixlen not in _PERMITTED_LENGTHS:
            raise ValueError(
                f"PREF64 entry {entry!r} has prefix length /{network.prefixlen}; "
                "RFC 6052 permits /32, /40, /48, /56, /64 and /96"
            )

        # For /96 the reserved octet lies inside the configured prefix, so RFC
        # 6052 makes keeping it zero the administrator's responsibility. A
        # non-zero value is a configuration error, not an address to refuse
        # later -- there is no later, the bits are in the prefix itself.
        if network.prefixlen == 96 and _u_octet(int(network.network_address)):
            raise ValueError(
                f"PREF64 entry {entry!r} has a non-zero reserved octet at bits 64-71; "
                "RFC 6052 requires those bits to be zero"
            )

        if network in prefixes:
            raise ValueError(f"PREF64 has a duplicate prefix {network} after masking")
        prefixes.append(network)

    return Pref64Posture(prefixes=tuple(prefixes))


def embedded_ipv4(addr: ipaddress.IPv6Address, prefix: ipaddress.IPv6Network) -> ipaddress.IPv4Address | None:
    """The IPv4 address embedded in *addr* under *prefix*, or None.

    None means "do not treat this as a translated address": either it is not
    inside the prefix, or its reserved octet is non-zero, which makes it not a
    well-formed RFC 6052 address. Guessing what a gateway would do with a
    malformed one is not this module's job.

    A None result is NOT a licence to accept the address. The caller refuses
    it: an address that matches a translation prefix but is malformed is
    exactly the shape an attacker would reach for, and the generic
    address-scope predicate accepts it because it is globally classified.
    """
    if addr not in prefix:
        return None

    value = int(addr)

    # Bits 64-71 are reserved and MUST be zero (RFC 6052 section 2.2). Checked
    # before extraction, so a malformed address never reaches the layout table.
    # For /96 the octet is inside the prefix itself and is validated at parse
    # time instead; checking it here as well is harmless and keeps the rule in
    # one place for every length.
    if _u_octet(value):
        return None

    out = 0
    for start, count in _LAYOUT[prefix.prefixlen]:
        out = (out << count) | ((value >> (128 - start - count)) & ((1 << count) - 1))
    return ipaddress.IPv4Address(out)
