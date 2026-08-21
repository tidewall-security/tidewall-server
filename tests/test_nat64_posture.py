"""The declared NAT64 posture, parsed once at startup.

`PREF64` is a deployment declaration, not a verified fact. Unset refuses to
export at all; `none` is an operator assertion that no NAT64 translation is
reachable. Both are recorded in
`internal/findings/P1-nat64-nsp-sender-bypass.md`, which governs closure.
"""

import ipaddress

import pytest

from app.services.nat64 import Pref64Posture, parse_pref64


def test_unset_is_unset():
    posture = parse_pref64(None)
    assert posture.is_unset
    assert not posture.is_none
    assert posture.prefixes == ()


def test_none_is_the_operator_assertion():
    posture = parse_pref64("none")
    assert posture.is_none
    assert not posture.is_unset
    assert posture.prefixes == ()


def test_one_prefix():
    posture = parse_pref64("2001:db8::/32")
    assert posture.prefixes == (ipaddress.ip_network("2001:db8::/32"),)
    assert not posture.is_unset and not posture.is_none


def test_several_prefixes_keep_their_order():
    posture = parse_pref64("2001:db8::/32,2600:1f00:a00:1::/96,2001:db8:122::/48")
    assert posture.prefixes == (
        ipaddress.ip_network("2001:db8::/32"),
        ipaddress.ip_network("2600:1f00:a00:1::/96"),
        ipaddress.ip_network("2001:db8:122::/48"),
    )


# Whitespace is an ERROR, not something to strip. A configured value that has
# to be cleaned up before it parses is a value nobody checked; silently
# accepting it means the declaration in the environment and the posture in
# force are different strings.
@pytest.mark.parametrize("raw", [" 2001:db8::/32", "2001:db8::/32 ", "2001:db8::/32, 2001:db8:1::/48"])
def test_surrounding_whitespace_is_a_startup_error(raw):
    with pytest.raises(ValueError, match="whitespace"):
        parse_pref64(raw)


# Duplicates are detected AFTER canonical masking, so two spellings of one
# network cannot evade the check.
@pytest.mark.parametrize(
    "raw",
    [
        "2001:db8::/32,2001:db8::/32",
        "2001:db8::/32,2001:db8:ffff::/32",  # same network after masking
    ],
)
def test_duplicate_prefixes_are_a_startup_error(raw):
    with pytest.raises(ValueError, match="duplicate"):
        parse_pref64(raw)


@pytest.mark.parametrize("raw", ["none,2001:db8::/32", "2001:db8::/32,none"])
def test_none_mixed_with_prefixes_is_a_startup_error(raw):
    with pytest.raises(ValueError, match="none"):
        parse_pref64(raw)


# RFC 6052 section 2.2 admits exactly six lengths.
@pytest.mark.parametrize("length", [0, 24, 31, 33, 44, 60, 80, 97, 128])
def test_a_length_outside_the_six_is_a_startup_error(length):
    with pytest.raises(ValueError, match="prefix length"):
        parse_pref64(f"2001:db8::/{length}")


@pytest.mark.parametrize("raw", ["192.0.2.0/24", "not-an-address/32", "2001:db8::", "/32"])
def test_a_non_ipv6_prefix_is_a_startup_error(raw):
    with pytest.raises(ValueError):
        parse_pref64(raw)


# For /96 the reserved octet at bits 64-71 lies INSIDE the configured prefix,
# so RFC 6052 makes it the administrator's responsibility and a non-zero value
# is a configuration error rather than an address to refuse later.
def test_a_96_prefix_with_a_non_zero_u_octet_is_a_startup_error():
    with pytest.raises(ValueError, match="reserved"):
        parse_pref64("2001:db8:122:344:100::/96")


def test_a_96_prefix_with_a_zero_u_octet_parses():
    posture = parse_pref64("2001:db8:122:344::/96")
    assert posture.prefixes == (ipaddress.ip_network("2001:db8:122:344::/96"),)


# Bits below the prefix length are MASKED, not rejected: a configured
# 2001:db8:122:344::/32 means 2001:db8::/32. Unmasked, those bits sit exactly
# where the IPv4 payload goes for /32 through /56.
def test_bits_below_the_prefix_length_are_masked():
    posture = parse_pref64("2001:db8:122:344::/32")
    assert posture.prefixes == (ipaddress.ip_network("2001:db8::/32"),)


def test_masking_is_bound_at_every_length():
    raw = ",".join(
        [
            "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff/32",
            "2001:db8:12ff:ffff:ffff:ffff:ffff:ffff/40",
            "2001:db8:122:ffff:ffff:ffff:ffff:ffff/48",
            "2001:db8:122:3ff:ffff:ffff:ffff:ffff/56",
            "2001:db8:122:344:0:ffff:ffff:ffff/64",
            "2001:db8:122:344:0:0:ffff:ffff/96",
        ]
    )
    posture = parse_pref64(raw)
    assert posture.prefixes == (
        ipaddress.ip_network("2001:db8::/32"),
        ipaddress.ip_network("2001:db8:1200::/40"),
        ipaddress.ip_network("2001:db8:122::/48"),
        ipaddress.ip_network("2001:db8:122:300::/56"),
        ipaddress.ip_network("2001:db8:122:344::/64"),
        ipaddress.ip_network("2001:db8:122:344::/96"),
    )


def test_an_empty_entry_is_a_startup_error():
    with pytest.raises(ValueError):
        parse_pref64("2001:db8::/32,,2001:db8:1::/48")


def test_the_posture_is_immutable():
    posture = parse_pref64("2001:db8::/32")
    assert isinstance(posture, Pref64Posture)
    with pytest.raises((AttributeError, TypeError)):
        posture.prefixes = ()  # type: ignore[misc]


# --- The posture must reach the application through REAL startup ------------
#
# A correct but unused parser satisfies every test above. These bind the wiring:
# a malformed PREF64 has to stop `Settings.from_env()`, which is what runs at
# startup, not just `parse_pref64` called directly by a test.


def test_settings_from_env_parses_the_posture(monkeypatch):
    from app.config import Settings

    monkeypatch.setenv("PREF64", "2001:db8::/32,2001:db8:122::/48")
    settings = Settings.from_env()
    assert settings.pref64_posture.prefixes == (
        ipaddress.ip_network("2001:db8::/32"),
        ipaddress.ip_network("2001:db8:122::/48"),
    )


def test_settings_from_env_defaults_to_unset(monkeypatch):
    from app.config import Settings

    monkeypatch.delenv("PREF64", raising=False)
    assert Settings.from_env().pref64_posture.is_unset


@pytest.mark.parametrize(
    "raw",
    [
        "bogus",
        "2001:db8::/33",
        "none,2001:db8::/32",
        "2001:db8:122:344:100::/96",
        " 2001:db8::/32",
        "2001:db8::/32,2001:db8:ffff::/32",
    ],
)
def test_a_malformed_pref64_stops_startup(monkeypatch, raw):
    """Eagerly, on construction -- not on first use.

    Parsed lazily, a malformed declaration survives startup and fails on the
    first export instead, which is the opposite of the point.
    """
    from pydantic import ValidationError

    from app.config import Settings

    monkeypatch.setenv("PREF64", raw)
    with pytest.raises((ValidationError, ValueError)):
        Settings.from_env()


def test_a_malformed_pref64_stops_real_lifespan_before_any_service(monkeypatch, tmp_path):
    """Through `app.main.lifespan`, not `Settings.from_env` alone.

    The unit tests above prove the parser rejects the value. They do not prove
    the ORDER: that startup fails before the process lock, the database, or any
    service is constructed. `Settings.from_env()` is the first statement in
    lifespan, so a malformed value must stop it there -- and that ordering is
    what this binds, by spying on the next stateful boundary and asserting it
    is never reached.
    """
    import asyncio

    from fastapi import FastAPI
    from pydantic import ValidationError

    import app.main as main

    # Spy on something startup ACTUALLY calls. The first version patched
    # `acquire_process_lock`, which `app.main` does not define -- with
    # raising=False the patch silently created it, nothing ever called it, and
    # the assertion that it was not reached was true for the wrong reason.
    # `ProcessLock` is the real first stateful boundary after Settings.from_env.
    # Patched at its SOURCE module: lifespan imports ProcessLock inside the
    # function, so it is not an attribute of app.main. The hasattr assertion
    # below is what caught that -- it is the check on the spy itself, and it
    # has now caught two wrong targets.
    import app.services.process_lock as lock_module

    assert hasattr(lock_module, "ProcessLock"), "the spied symbol must exist, or this proves nothing"
    reached = []
    real_lock = lock_module.ProcessLock

    class _SpyLock(real_lock):  # type: ignore[misc, valid-type]
        def __init__(self, *a, **k):
            reached.append("ProcessLock")
            super().__init__(*a, **k)

    monkeypatch.setattr(lock_module, "ProcessLock", _SpyLock)
    monkeypatch.setenv("PREF64", "not-a-prefix/32")
    monkeypatch.setenv("DB_URL", f"sqlite:///{tmp_path / 'x.db'}")

    async def _enter():
        async with main.lifespan(FastAPI()):
            pass

    with pytest.raises((ValidationError, ValueError)):
        asyncio.run(_enter())

    assert reached == [], "startup constructed ProcessLock before rejecting PREF64"
    assert not (tmp_path / "x.db").exists(), "a rejected configuration left a database behind"
