"""RFC 6052 embedded-IPv4 extraction.

Every fixture here is a LITERAL IPv6 address derived independently of the
production layout table. Round-tripping through an encoder that shares that
table proves only that the table is self-consistent: a wrong row round-trips
perfectly.

RFC 6052 section 2.4's own examples are necessary but not sufficient -- all six
encode the SAME address, 192.0.2.33, so a decoder returning a constant passes
the entire specification example set.
"""

import ipaddress

import pytest

from app.services.nat64 import embedded_ipv4


def _n(prefix: str) -> ipaddress.IPv6Network:
    return ipaddress.IPv6Network(prefix)


def _a(addr: str) -> ipaddress.IPv6Address:
    return ipaddress.IPv6Address(addr)


# RFC 6052 section 2.4, verbatim.
_RFC_EXAMPLES = [
    ("2001:db8::/32", "2001:db8:c000:221::", "192.0.2.33"),
    ("2001:db8:100::/40", "2001:db8:1c0:2:21::", "192.0.2.33"),
    ("2001:db8:122::/48", "2001:db8:122:c000:2:2100::", "192.0.2.33"),
    ("2001:db8:122:300::/56", "2001:db8:122:3c0:0:221::", "192.0.2.33"),
    ("2001:db8:122:344::/64", "2001:db8:122:344:c0:2:2100::", "192.0.2.33"),
    ("2001:db8:122:344::/96", "2001:db8:122:344::192.0.2.33", "192.0.2.33"),
]


@pytest.mark.parametrize("prefix,addr,expected", _RFC_EXAMPLES)
def test_the_rfc_examples_decode(prefix, addr, expected):
    assert embedded_ipv4(_a(addr), _n(prefix)) == ipaddress.IPv4Address(expected)


# One exact decoded value per length, from DISTINCT addresses, because the RFC
# set cannot tell a real decoder from a constant.
#
# These literals were derived with an encoder written separately from the RFC
# diagram and anchored by reproducing all six RFC 2.4 examples -- not by
# round-tripping through the production layout table, which would let a wrong
# row validate itself.
_EXACT = [
    ("2001:db8::/32", "2001:db8:a01:203::", "10.1.2.3"),
    ("2001:db8:1200::/40", "2001:db8:12ac:1063:7::", "172.16.99.7"),
    ("2001:db8:122::/48", "2001:db8:122:7f00:0:100::", "127.0.0.1"),
    ("2001:db8:122:300::/56", "2001:db8:122:3a9:fe:101::", "169.254.1.1"),
    ("2001:db8:122:344::/64", "2001:db8:122:344:c0:a801:700:0", "192.168.1.7"),
    ("2001:db8:122:344::/96", "2001:db8:122:344::a63:584d", "10.99.88.77"),
]


@pytest.mark.parametrize("prefix,addr,expected", _EXACT)
def test_each_length_has_an_exact_decoded_value(prefix, addr, expected):
    assert embedded_ipv4(_a(addr), _n(prefix)) == ipaddress.IPv4Address(expected)


# The five NON-native interpretations of one /48 encoding, by exact value.
# Inequality alone admits a wrong-but-distinct decoder.
_CROSS_ADDR = "2001:db8:122:a01:2:300::"
_CROSS = [(32, "1.34.10.1"), (40, "34.10.1.2"), (56, "1.2.3.0"), (64, "2.3.0.0"), (96, "0.0.0.0")]


@pytest.mark.parametrize("length,expected", _CROSS)
def test_the_same_bits_decode_differently_at_every_other_length(length, expected):
    prefix = ipaddress.IPv6Network(f"{_CROSS_ADDR}/{length}", strict=False)
    assert embedded_ipv4(_a(_CROSS_ADDR), prefix) == ipaddress.IPv4Address(expected)


def test_the_48_native_interpretation_of_the_cross_fixture():
    assert embedded_ipv4(_a(_CROSS_ADDR), _n("2001:db8:122::/48")) == ipaddress.IPv4Address("10.1.2.3")


# A non-zero reserved octet is REFUSED, not decoded. Guessing what a gateway
# would do with a malformed translation address is not this module's job.
@pytest.mark.parametrize(
    "prefix,addr",
    [
        ("2001:db8::/32", "2001:db8:a01:203:100::"),
        ("2001:db8:1200::/40", "2001:db8:12ac:1063:ff07::"),
        ("2001:db8:122::/48", "2001:db8:122:7f00:0100:1::"),
        ("2001:db8:122:300::/56", "2001:db8:122:3a9:2a00:fea9:0101::"),
        ("2001:db8:122:344::/64", "2001:db8:122:344:9900:808:808::"),
    ],
)
def test_a_non_zero_reserved_octet_is_refused(prefix, addr):
    assert embedded_ipv4(_a(addr), _n(prefix)) is None


def test_an_address_outside_the_prefix_is_not_translated():
    assert embedded_ipv4(_a("2600:1f00::1"), _n("2001:db8::/32")) is None
