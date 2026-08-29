"""Per-path plants, and the controls that stop a plant from proving nothing."""

from __future__ import annotations

import pytest

from tests.release.representations import FAMILIES, indistinguishable_from
from tests.release.traversal import (
    SecurityFailure,
    Sweep,
    delete_at,
    registered_collectors,
    set_at,
    traverse,
)

SECRET = "CANARY-TRAVERSE-7d15"


def _exchange() -> dict:
    """An HTTP exchange: status, EVERY header, and body."""
    return {
        "status": 200,
        "headers": {
            "Content-Type": "application/json",
            "Content-Disposition": 'attachment; filename="export.json"',
        },
        "body": {
            "policy": {"name": "default", "rules": [{"id": 1, "note": "ok"}]},
            "meta": {"count": 1},
        },
    }


# --- traversal is total -----------------------------------------------------


def test_traversal_emits_a_path_for_every_leaf():
    paths = {leaf.path for leaf in traverse(_exchange())}
    assert "status" in paths
    assert "headers.Content-Type" in paths
    assert "headers.Content-Disposition" in paths
    assert "body.policy.name" in paths
    assert "body.policy.rules[0].note" in paths
    assert "body.meta.count" in paths


def test_traversal_descends_into_list_elements():
    """A container that yields its own repr hides every path inside it."""
    paths = {leaf.path for leaf in traverse({"a": [{"b": 1}, {"b": 2}]})}
    assert paths == {"a[0].b", "a[1].b"}


def test_a_header_path_is_emitted_not_only_the_body():
    """Content-Disposition is where policy.name currently appears.

    A body-derived inventory passes all its own controls while never looking
    at the header the value is in.
    """
    paths = {leaf.path for leaf in traverse(_exchange())}
    assert any(p.startswith("headers.") for p in paths)


# --- per-path plants, each with its removal control -------------------------


@pytest.mark.parametrize(
    "path",
    [leaf.path for leaf in traverse(_exchange())],
)
def test_every_path_is_planted_and_removed(path: str):
    """The generated per-path plant, paired with its control.

    Plant: the canary at this path is found.
    Control: with the path REMOVED, it is not. Without the second half, a
    sweep that searched the whole serialised blob and never traversed would
    pass every plant.
    """
    planted = _exchange()
    set_at(planted, path, SECRET)
    sweep = Sweep()

    found = sweep.findings(planted, SECRET)
    assert found, f"the canary planted at {path} was not found"
    assert any(f.path == path for f in found), (
        f"found at {[f.path for f in found]}, none of which is {path} -- the "
        "sweep matched bytes without attributing them to the planted path"
    )

    # The control must PLANT and then REMOVE. An earlier version removed the
    # path from a fresh, UNPLANTED exchange, so the assertion held whether or
    # not the removal did anything -- a control that could not fail, and a
    # mutation making delete_at a no-op survived it.
    removed = _exchange()
    set_at(removed, path, SECRET)
    assert sweep.findings(removed, SECRET), "the control's own plant did not take"
    delete_at(removed, path)
    assert sweep.findings(removed, SECRET) == [], f"removing {path} did not clear the finding"


def test_an_unplanted_exchange_yields_nothing():
    """The sweep must be able to report clean, or its reports mean nothing."""
    assert Sweep().findings(_exchange(), SECRET) == []


# --- per-collector control (design section 7) -------------------------------


def test_disabling_a_collector_removes_only_its_findings():
    planted = _exchange()
    set_at(planted, "body.policy.name", SECRET)

    everything = Sweep().findings(planted, SECRET)
    by_collector = {f.collector for f in everything}
    assert by_collector == registered_collectors(), f"not every collector found the plant: {by_collector}"

    without = Sweep(disabled=frozenset({"structure"})).findings(planted, SECRET)
    assert {f.collector for f in without} == registered_collectors() - {"structure"}
    assert without, "disabling one collector silenced all of them"


def test_disabling_every_collector_finds_nothing():
    """The control's own control: the disable switch works."""
    planted = _exchange()
    set_at(planted, "body.policy.name", SECRET)
    assert Sweep(disabled=registered_collectors()).findings(planted, SECRET) == []


def test_the_serialised_collector_sees_what_the_structural_one_does_not():
    """Two collectors that would be redundant if they saw the same thing.

    The distinguishing case must be one where JSON encoding differs from
    Python's own repr. A newline does NOT qualify: `str({"n": "a\nb"})`
    escapes it to `a\\nb` exactly as JSON does, so a mutation replacing
    json.dumps with the raw object passed every test.

    `ensure_ascii=True` escapes non-ASCII to \\uXXXX; repr does not. So the
    escaped form of a non-ASCII value exists only after encoding.
    """
    # A RAW string: the canary is the literal characters c a f \\ u 0 0 e 9,
    # which is what JSON's ensure_ascii produces and what repr never does.
    secret = r"caf\u00e9-CANARY"
    planted = {"body": {"note": "café-CANARY"}}

    assert secret not in str(planted), (
        "premise changed: repr now produces the escaped form too, so this no " "longer separates the two collectors"
    )

    structural = Sweep(disabled=frozenset({"serialised"})).findings(planted, secret)
    serialised = Sweep(disabled=frozenset({"structure"})).findings(planted, secret)

    assert not structural, "the escaped form should not exist before encoding"
    assert serialised, "the serialised collector missed the JSON-escaped form"


# --- per-representation control ---------------------------------------------


@pytest.mark.parametrize("family", [f.name for f in FAMILIES])
def test_each_representation_family_is_detected_at_a_real_path(family: str):
    """A plain-text plant does not prove the \\uXXXX decoder runs.

    Each family is planted in its own encoding, at a real path, and swept
    through the identical top-level sweep.
    """
    representation = next(f for f in FAMILIES if f.name == family)
    planted = _exchange()
    encoded = representation.encode(SECRET)
    set_at(planted, "body.policy.name", encoded.decode("utf-8", "surrogateescape"))

    found = Sweep().findings(planted, SECRET)
    families_found = {f.family for f in found}

    assert family in families_found or families_found & indistinguishable_from(
        family, SECRET
    ), f"{family} plant was matched only as {families_found}"


def test_a_minimum_length_fragment_is_detected():
    """Partial disclosure. A truncated secret is still a disclosed secret."""
    from tests.release.representations import MINIMUM_FRAGMENT, fragments

    piece = fragments(SECRET)[0]
    assert len(piece) == MINIMUM_FRAGMENT

    planted = _exchange()
    set_at(planted, "body.policy.name", piece)
    assert Sweep().findings(planted, piece), "a minimum-length fragment was missed"


# --- the single security-failure conversion ---------------------------------


def test_a_finding_becomes_a_security_failure():
    planted = _exchange()
    set_at(planted, "headers.Content-Disposition", f'attachment; filename="{SECRET}.json"')
    with pytest.raises(SecurityFailure, match="headers.Content-Disposition"):
        Sweep().check(planted, SECRET)


def test_a_clean_object_raises_nothing():
    Sweep().check(_exchange(), SECRET)


def test_the_failure_names_every_occurrence():
    planted = _exchange()
    set_at(planted, "body.policy.name", SECRET)
    set_at(planted, "headers.Content-Type", SECRET)
    with pytest.raises(SecurityFailure) as exc:
        Sweep().check(planted, SECRET)
    assert "body.policy.name" in str(exc.value)
    assert "headers.Content-Type" in str(exc.value)
