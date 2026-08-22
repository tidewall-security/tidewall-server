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
    OutOfDomain,
    Row,
    Rule,
    resolve,
)

BASE = dict(
    leaf="random-canary",
    placement="message-content",
    branch="allow",
    capture="capture-off",
    operation="guard",
    grant="api",
    representation="plain",
)


def test_an_unmatched_occurrence_is_forbidden_by_default():
    row = resolve(**BASE, path="db:interactions.some_column")
    assert row.rule is Rule.FORBIDDEN
    assert "no rule matched" in row.why


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
    assert "P0-9" in str(caught.value)
    assert "POST /v1/unredact" in EXCLUDED_FROM_HTTP_DOMAIN


def test_specificity_decides_between_overlapping_rows():
    rows = ROWS + (
        Row(
            "random-canary",
            "message-content",
            "allow",
            "capture-off",
            "guard",
            "api",
            "plain",
            "db:x.y",
            Rule.ALLOWED_BOUNDED,
            "most specific",
        ),
        Row("*", "*", "*", "*", "*", "*", "*", "db:x.y", Rule.FORBIDDEN, "general"),
    )
    assert resolve(**BASE, path="db:x.y", rows=rows).rule is Rule.ALLOWED_BOUNDED


def test_a_tie_is_an_error_not_a_silent_choice():
    """'Exactly one' is not implementable without this.

    Two rows of equal specificity disagreeing is a policy defect. Picking one
    silently would make the matrix's answer depend on declaration order.
    """
    rows = ROWS + (
        Row("*", "*", "*", "*", "*", "*", "*", "db:tie.col", Rule.ALLOWED_BOUNDED, "a"),
        Row("*", "*", "*", "*", "*", "*", "*", "db:tie.col", Rule.FORBIDDEN, "b"),
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
            "capture": row.capture if row.capture != "*" else "capture-off",
            "operation": row.operation if row.operation != "*" else "guard",
            "grant": row.grant if row.grant != "*" else "api",
            "representation": row.representation if row.representation != "*" else "plain",
            "path": row.path,
        }
        try:
            resolve(**given)
        except Ambiguous as exc:  # pragma: no cover - the failure message is the point
            pytest.fail(f"{row.path} is ambiguous: {exc}")
        except OutOfDomain:
            pytest.fail(f"{row.path} is both a declared row and out of domain")


def test_forbidden_by_default_is_scoped_to_enumerated_surfaces():
    """The narrowed claim, stated in a test.

    An unmatched path on a surface the sweep already enumerates is FORBIDDEN.
    That is not a claim about a surface nobody declared -- the resolver never
    sees one, which is exactly why section 10 keeps it as a residual.
    """
    row = resolve(**BASE, path="db:interactions.undeclared_column")
    assert row.rule is Rule.FORBIDDEN
    assert row.why.startswith("no rule matched")
