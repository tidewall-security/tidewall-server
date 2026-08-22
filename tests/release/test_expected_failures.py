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
    return tomllib.loads(MANIFEST.read_text())["expected_failure"]


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


def test_matches_json_expands_per_case_and_representation(checked_in):
    """Not one shared entry.

    A single record cannot be multiset-compared against a run that fails once
    per case, and it hides how much is missing.
    """
    from tests.release.representations import FAMILIES

    records = [r for r in checked_in if r["surface_path"] == "interactions.matches_json"]
    assert records, "no matches_json records at all"

    by_case = collections.defaultdict(set)
    for record in records:
        by_case[record["case_id"]].add(record["representation"])

    assert len(by_case) > 1, "matches_json collapsed to a single case"
    for case_id, representations in by_case.items():
        assert representations == {f.name for f in FAMILIES}, (case_id, representations)


def test_the_422_echo_is_present_per_representation(checked_in):
    """Omitted entirely from an earlier draft."""
    from tests.release.representations import FAMILIES

    records = [r for r in checked_in if "$.detail[*].input" in r["surface_path"]]
    assert {r["representation"] for r in records} == {f.name for f in FAMILIES}


def test_all_three_access_rule_surfaces_are_present(checked_in):
    """The third was missed once, and it is a distinct surface."""
    paths = {r["surface_path"] for r in checked_in}
    assert "app.services.access_rule_service:logger.info/created" in paths
    assert f"{GUARD_ROUTE} -> $.summary" in paths
    assert f"{GUARD_ROUTE} -> $.result.access_rules[*] (key)" in paths


# --- the route is verified, not assumed -------------------------------------


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

    assert {r["owner"] for r in checked_in} == {OWNER}, sorted({r["owner"] for r in checked_in})


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
