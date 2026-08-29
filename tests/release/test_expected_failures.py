"""The manifest is exact, expanded, and honest about what is blocked."""

from __future__ import annotations

import collections
import pathlib
import tomllib

import pytest

from tests.release.expected_failures import (
    GUARD_ROUTE,
    OWNER_UNASSIGNED,
    Record,
    generate,
    render,
)
from tests.release.gate_report import SIGNATURE_FIELDS
from tests.release.manifest import load_cases

MANIFEST = pathlib.Path(__file__).resolve().parent / "expected_failures.toml"
REPO = pathlib.Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def checked_in() -> list[dict]:
    # `.get`, not `[...]`. An empty manifest has no `expected_failure` key at
    # all, and empty is the goal state -- every record is an ACCEPTED defect, so
    # none of them is what "nothing left to accept" looks like. Indexing made the
    # file unloadable in exactly the condition the gate exists to reach.
    return tomllib.loads(MANIFEST.read_text()).get("expected_failure", [])


@pytest.fixture(scope="module")
def generated() -> list[Record]:
    return generate(load_cases())


# --- the artifact matches its generator -------------------------------------


def test_the_checked_in_file_is_byte_identical_to_the_generator_output(generated):
    """Reviewed output, not a described process.

    A generator whose output is not checked in cannot be reviewed, and a
    checked-in file that drifts from its generator is two sources of truth.
    """
    assert MANIFEST.read_text() == render(generated)


def test_every_record_carries_all_six_signature_fields(checked_in):
    for record in checked_in:
        missing = [f for f in SIGNATURE_FIELDS if f not in record]
        assert not missing, (record, missing)


def test_signatures_are_unique(checked_in):
    counts = collections.Counter(tuple(r[f] for f in SIGNATURE_FIELDS) for r in checked_in)
    duplicates = [sig for sig, n in counts.items() if n > 1]
    assert not duplicates, duplicates[:3]


# --- expansion, not defect classes ------------------------------------------


def test_the_guard_route_exists_in_the_source():
    """`POST /v1/guard` was written once and does not exist.

    surface_path is compared exactly, so a stale route means the baseline
    multiset could never reconcile -- before any product defect.
    """
    source = (REPO / "app" / "routes" / "guard.py").read_text()
    assert '"/v1/guard_chat_completions"' in source
    assert GUARD_ROUTE.endswith("/v1/guard_chat_completions")


def test_no_record_names_a_route_that_does_not_exist(checked_in):
    routes = set()
    for path in (REPO / "app" / "routes").glob("*.py"):
        source = path.read_text()
        for line in source.splitlines():
            if '"/v1/' in line:
                routes.add(line.split('"')[1])

    for record in checked_in:
        if "-> " in record["surface_path"] and record["surface_path"].startswith("POST "):
            route = record["surface_path"].split(" -> ")[0].removeprefix("POST ")
            assert route in routes, (route, sorted(routes)[:6])


# --- MCP is an execution-manifest matter, not an expected failure -----------


def test_mcp_description_and_parameters_are_not_expected_failures(checked_in):
    """Read literally, an earlier draft contradicted Task 2.

    They ARE execution-manifest entries -- Task 2 requires every leaf and
    placement -- and those carry "not evaluated by this component".
    """
    offenders = [r for r in checked_in if "mcp-description" in r["case_id"] or "mcp-parameters" in r["case_id"]]
    assert not offenders, offenders[:3]


def test_the_execution_manifest_does_carry_them():
    leaves = {c.leaf for c in load_cases()}
    assert "mcp-description" in leaves
    assert "mcp-parameters" in leaves


# --- owners are blocked, and the manifest says so ---------------------------


def test_every_record_carries_an_owner_field(checked_in):
    for record in checked_in:
        assert "owner" in record, record


def test_the_manifest_is_empty_because_every_declared_defect_is_fixed(checked_in):
    """It held 255 records: three defects multiplied by representation and
    surface.

    The access-rule name reached the guard response and the creation log. The
    validation echo quoted a rejected request back. Detector matches never
    reached the capture column, because a detector named itself by its class
    while the scanner opened its capture batch under the policy's key for it.

    All three are fixed. Three tests describing the shape those records took are
    gone with them; the generators that produced them are kept, unused.
    """
    assert checked_in == []

    from tests.release.expected_failures import generate
    from tests.release.manifest import load_cases

    assert generate(load_cases()) == []


def test_every_record_carries_a_real_owner(checked_in):
    """Owners were a blocked input; they are supplied now.

    This test previously asserted the OPPOSITE -- that every owner was the
    unassigned sentinel -- and carried a note telling whoever supplied names to
    come and update it. That is the point: a deferred input should not be able
    to quietly become satisfied, or quietly stay unsatisfied, without someone
    editing the oracle on purpose.
    """
    from tests.release.expected_failures import OWNER, OWNER_UNASSIGNED

    still_unassigned = [r for r in checked_in if r["owner"] == OWNER_UNASSIGNED]
    assert not still_unassigned, still_unassigned[:2]

    # A SUBSET, so this holds while the manifest is empty and bites the moment a
    # record returns. Equality asserted the manifest was non-empty as a side
    # effect -- a different claim, made deliberately by the emptiness test above.
    # Two tests must not both depend on the count.
    owners = {r["owner"] for r in checked_in}
    assert owners <= {OWNER}, sorted(owners)


def test_the_owner_is_reachable(checked_in):
    """A name nobody can contact is not accountability.

    Only a shape check -- whether the address is monitored is not something a
    test can establish, and pretending otherwise would be the defect this
    programme removes.
    """
    from tests.release.expected_failures import OWNER

    assert "@" in OWNER and OWNER.endswith("tidewall.ai"), OWNER
    assert not OWNER.startswith("<"), "still a placeholder"


def test_the_manifest_header_no_longer_claims_owners_are_blocked(checked_in):
    header = MANIFEST.read_text().split("[[expected_failure]]")[0]
    assert "BLOCKED" not in header.upper()
    assert "accountable owner" in header


def test_the_owner_sentinel_is_not_mistakable_for_a_name():
    assert OWNER_UNASSIGNED.startswith("<") and "blocked" in OWNER_UNASSIGNED


# --- xfail is used nowhere ---------------------------------------------------


def test_the_manifest_mechanism_does_not_use_xfail():
    """A manifested failure still FAILS; it is reconciled by the aggregator.

    xfail would make the failure invisible to the JUnit XML and to the counts,
    and the gate refuses non-zero xfailed for that reason.
    """
    source = (pathlib.Path(__file__).resolve().parent / "expected_failures.py").read_text()
    assert "xfail" not in source
