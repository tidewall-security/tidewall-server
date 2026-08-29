"""The resolver's mechanics, and the mutations that show it decides.

Runtime enforcement -- that every occurrence the collectors emit is routed
through `resolve`, and that every REQUIRED row was actually emitted -- belongs
to Task 6, where a real consumer exists. Scheduling it here would have been
untestable: no collector, witness or suite exists yet.
"""

from __future__ import annotations

import pytest

from tests.release.occurrences import (
    EXCLUDED_FROM_HTTP_DOMAIN,
    ROWS,
    Ambiguous,
    NoRule,
    OutOfDomain,
    Row,
    Rule,
    resolve,
)

BASE = dict(
    leaf="random-canary",
    placement="message-content",
    branch="allow",
    detector="malicious_prompt",
    event="input",
    capture="capture-off",
    operation="guard",
    grant="api",
    representation="plain",
)


def test_an_unmatched_occurrence_hits_the_checked_in_catch_all():
    """FORBIDDEN comes from a real row, not from the resolver inventing one."""
    row = resolve(**BASE, path="db:interactions.some_column")
    assert row.rule is Rule.FORBIDDEN
    assert row in ROWS, "the default must be a checked-in row"


def test_capture_on_input_json_is_required():
    row = resolve(**{**BASE, "capture": "capture-on"}, path="db:interaction_contents.input_json")
    assert row.rule is Rule.REQUIRED


def test_a_sibling_column_is_still_forbidden_under_capture_on():
    """ALLOWED-BOUNDED is bounded.

    input_json being legitimate says nothing about the column beside it, which
    is the distinction a coarse `surface=database` key could not express.
    """
    row = resolve(**{**BASE, "capture": "capture-on"}, path="db:interactions.input_json")
    assert row.rule is Rule.FORBIDDEN


def test_the_content_disposition_header_is_allowed_for_a_policy_name():
    """A body-only collector would never see this path at all."""
    row = resolve(
        **{**BASE, "placement": "policy-name"},
        path="GET /v1/policies/p-123/export -> header:Content-Disposition",
    )
    assert row.rule is Rule.ALLOWED_BOUNDED


def test_a_path_template_matches_its_instantiation():
    row = resolve(
        **{**BASE, "leaf": "access-rule-name"},
        path="POST /v1/policies/p-9/rule-sets/input/access-rules -> $.name",
    )
    assert row.rule is Rule.ALLOWED_BOUNDED, row


def test_the_access_rule_create_response_is_legitimate():
    """The case the plan says could not otherwise reconcile.

    `_rule_to_dict` returns the name on create, so a planted access-rule name
    legitimately comes back. Without this row a FORBIDDEN default reports
    intended control-plane output as a security violation.
    """
    row = resolve(
        **{**BASE, "leaf": "access-rule-name", "placement": "access-rule-name"},
        path="POST /v1/policies/p-1/rule-sets/input/access-rules -> $.name",
    )
    assert row.rule is Rule.ALLOWED_BOUNDED


def test_unredact_is_out_of_domain_and_names_its_owner():
    """Declared and tested, not silently omitted.

    A silent omission and an intentional exclusion are observationally
    identical; this makes the difference observable.
    """
    with pytest.raises(OutOfDomain) as caught:
        resolve(**BASE, path="POST /v1/unredact -> $.data")
    assert "reverses redaction by design" in str(caught.value)
    assert "POST /v1/unredact" in EXCLUDED_FROM_HTTP_DOMAIN


def test_specificity_decides_between_overlapping_rows():
    """Most non-wildcard axes wins, and the winner is the specific row."""
    specific = Row(
        "random-canary",
        "message-content",
        "allow",
        "malicious_prompt",
        "input",
        "capture-off",
        "guard",
        "api",
        "plain",
        "db:x.y",
        Rule.ALLOWED_BOUNDED,
        "specific",
    )
    general = Row(
        "*",
        "*",
        "*",
        "*",
        "*",
        "*",
        "*",
        "*",
        "*",
        "db:x.y",
        Rule.FORBIDDEN,
        "general",
    )
    assert resolve(**BASE, path="db:x.y", rows=(specific, general)) is specific


def test_zero_matching_rows_raises_rather_than_reporting_success():
    """The cardinality contract, in the direction that was missing.

    Synthesising a FORBIDDEN answer meant an occurrence matching no checked-in
    policy reported success -- the resolver deciding instead of the matrix. The
    catch-all is a real row, so reaching this state means the matrix is
    incomplete, which is a defect rather than a default.
    """
    with pytest.raises(NoRule):
        resolve(**BASE, path="db:x.y", rows=())


def test_an_unrelated_canary_in_a_control_plane_column_is_forbidden():
    """Exceptions scoped to the ingress that makes them legitimate.

    Wildcarding every axis on the rule_sets.detectors row turned any canary
    accidentally copied into that column into an allowed occurrence, whatever
    supplied it.
    """
    assert resolve(**BASE, path="db:rule_sets.detectors").rule is Rule.FORBIDDEN
    supplied_as_config = resolve(
        **{
            **BASE,
            "leaf": "competitor-phrase",
            "placement": "rule-set-detector-config",
            "detector": "competitors",
            "operation": "policy-admin",
            "grant": "admin",
        },
        path="db:rule_sets.detectors",
    )
    assert supplied_as_config.rule is Rule.ALLOWED_BOUNDED


@pytest.mark.parametrize(
    "path",
    [
        "GET /v1/settings/prompt-lists -> $[0].pattern",
        "GET /v1/policies/p1/rule-sets/input/access-rules -> $[0].name",
        "GET /v1/settings/model-intent -> $[0].statement",
        "GET /v1/settings/threat-intel -> $.local_blocklists.urls[0]",
    ],
)
def test_real_list_shaped_paths_resolve_to_their_allow_rows(path):
    """`[*]` is an index wildcard, not a literal.

    Treating it literally made every real list occurrence FORBIDDEN despite an
    explicit allow row, so the matrix classified intended output as a
    violation.
    """
    leaf, placement = {
        "prompt-lists": ("unrecognised-confidential-sentence", "prompt-list-pattern"),
        "access-rules": ("access-rule-name", "access-rule-name"),
        "model-intent": ("random-canary", "model-intent-statement"),
        "threat-intel": ("query-url", "threat-intelligence-config"),
    }[next(k for k in ("prompt-lists", "access-rules", "model-intent", "threat-intel") if k in path)]
    row = resolve(
        **{**BASE, "leaf": leaf, "placement": placement, "operation": "settings-admin", "grant": "admin"},
        path=path,
    )
    assert row.rule is Rule.ALLOWED_BOUNDED, row


def test_matches_json_is_required_only_for_exact_value_detectors():
    """A classifier reports no exact value; requiring it manufactures a failure."""
    pii = resolve(
        **{**BASE, "detector": "confidential_and_pii_entity", "capture": "capture-on"},
        path="db:interaction_contents.matches_json",
    )
    assert pii.rule is Rule.REQUIRED
    classifier = resolve(
        **{**BASE, "detector": "language", "capture": "capture-on"}, path="db:interaction_contents.matches_json"
    )
    assert classifier.rule is Rule.ALLOWED_BOUNDED


def test_a_tie_is_an_error_not_a_silent_choice():
    """'Exactly one' is not implementable without this.

    Two rows of equal specificity disagreeing is a policy defect. Picking one
    silently would make the matrix's answer depend on declaration order.
    """
    rows = ROWS + (
        Row("*", "*", "*", "*", "*", "*", "*", "*", "*", "db:tie.col", Rule.ALLOWED_BOUNDED, "a"),
        Row("*", "*", "*", "*", "*", "*", "*", "*", "*", "db:tie.col", Rule.FORBIDDEN, "b"),
    )
    with pytest.raises(Ambiguous):
        resolve(**BASE, path="db:tie.col", rows=rows)


def test_every_row_resolves_to_exactly_one_rule():
    """No row in the shipped matrix is unreachable or ambiguous.

    A row that can never win is dead policy; a tie is undefined policy. Both
    are caught here, before any finder consumes them.
    """
    for row in ROWS:
        given = {
            "leaf": row.leaf if row.leaf != "*" else "random-canary",
            "placement": row.placement if row.placement != "*" else "message-content",
            "branch": row.branch if row.branch != "*" else "allow",
            "detector": row.detector if row.detector != "*" else "malicious_prompt",
            "event": row.event if row.event != "*" else "input",
            "capture": row.capture if row.capture != "*" else "capture-off",
            "operation": row.operation if row.operation != "*" else "guard",
            "grant": row.grant if row.grant != "*" else "api",
            "representation": row.representation if row.representation != "*" else "plain",
            "path": row.path,
        }
        try:
            resolved = resolve(**given)
        except Ambiguous as exc:  # pragma: no cover - the message is the point
            pytest.fail(f"{row.path} is ambiguous: {exc}")
        except OutOfDomain:
            pytest.fail(f"{row.path} is both a declared row and out of domain")
        # Strict identity. An `or resolved.rule is row.rule` arm was the
        # loophole: a row shadowed everywhere by a more-specific row sharing
        # its rule passed as reachable, which is dead policy.
        assert resolved is row, f"{row.path} resolves to {resolved.why!r}, not to itself: dead policy"


def test_forbidden_by_default_is_scoped_to_enumerated_surfaces():
    """The narrowed claim, stated in a test.

    An unmatched path on a surface the sweep already enumerates is FORBIDDEN.
    That is not a claim about a surface nobody declared -- the resolver never
    sees one, which is exactly why section 10 keeps it as a residual.
    """
    row = resolve(**BASE, path="db:interactions.undeclared_column")
    assert row.rule is Rule.FORBIDDEN
    assert row in ROWS


@pytest.mark.parametrize(
    "path",
    [
        "GET /v1/policies/p1/rule-sets/input -> " "$.detectors.malicious_entity.intel.local_blocklists.urls[0]",
        "PATCH /v1/policies/p1/rule-sets/input -> " "$.detectors.malicious_entity.intel.local_blocklists.urls[0]",
        "GET /v1/policies/p1/export -> body:detectors",
        "PUT /v1/settings/threat-intel -> $.intel.local_blocklists.urls[0]",
        "db:rule_sets.detectors",
    ],
)
def test_threat_intelligence_config_is_allowed_on_every_surface_that_returns_it(path):
    """The regression evidence, checked in this time.

    These paths were verified by hand and the tests were reported as added
    without being added -- so nothing would have caught the rows regressing.
    Threat-intelligence configuration is stored inside `rule_sets.detectors`,
    which means it comes back from the rule-set endpoints and the YAML export
    exactly as the competitor literals do.
    """
    row = resolve(
        **{
            **BASE,
            "leaf": "query-url",
            "placement": "threat-intelligence-config",
            "detector": "malicious_entity",
            "event": "output",
            "operation": "settings-admin",
            "grant": "admin",
        },
        path=path,
    )
    assert row.rule is Rule.ALLOWED_BOUNDED, row
    # The row's identity, not merely its verdict: the catch-all is FORBIDDEN,
    # so a rule check alone cannot distinguish "the threat-intelligence row
    # won" from "some unrelated allow row won".
    assert row in ROWS
    assert row.placement == "threat-intelligence-config", row
