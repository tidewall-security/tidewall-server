"""The occurrence matrix: where a canary value may legitimately appear.

These rows **are the security policy**, not implementation mechanics. They are
checked in as data so a reviewer can read what the gate will treat as a
violation, before any finder exists to enforce it.

**Forbidden by default, over enumerated surfaces only.** An occurrence at a
path with no matching rule is a violation — but that operates *after* the sweep
has discovered a surface. It does **not** fail closed for a surface nobody
declared, which is §10's residual and is not narrowed by anything here.

**Why `ALLOWED-BOUNDED` is not `REQUIRED`.** `REQUIRED` means the value must be
there; `ALLOWED-BOUNDED` means it may be, and only at the enumerated paths. The
collector returns *every* occurrence path, so an unexpected sibling still
fails. Defining it as "present with an exact expected field" would just be
`REQUIRED` under another name.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum

WILDCARD = "*"


class Rule(str, Enum):
    REQUIRED = "REQUIRED"
    FORBIDDEN = "FORBIDDEN"
    ALLOWED_BOUNDED = "ALLOWED-BOUNDED"


@dataclass(frozen=True)
class Row:
    """One resolved rule.

    Any axis may be `*`. Precedence is by **specificity**: the row with the
    most non-wildcard axes wins, and a tie is an error rather than a silent
    choice -- "exactly one" is not implementable without that stated.
    """

    leaf: str
    placement: str
    branch: str
    capture: str
    operation: str
    grant: str
    representation: str
    path: str
    rule: Rule
    why: str = ""

    @property
    def specificity(self) -> int:
        return sum(
            1
            for axis in (
                self.leaf,
                self.placement,
                self.branch,
                self.capture,
                self.operation,
                self.grant,
                self.representation,
                self.path,
            )
            if axis != WILDCARD
        )


class Ambiguous(Exception):
    """Two rows match at the same specificity. A tie must never be resolved silently."""


class OutOfDomain(Exception):
    """The occurrence is at a surface this matrix deliberately does not govern."""


#: Endpoints excluded from the "every HTTP response" domain, with their owner.
#:
#: `/v1/unredact` returns exact PII to a base `api` caller through the
#: in-process VaultManager cache. That is assigned to P0-9 and is not step 10's
#: to fix -- but a silent omission and an intentional exclusion are
#: observationally identical, so it is declared and tested rather than left out.
EXCLUDED_FROM_HTTP_DOMAIN: dict[str, str] = {
    "POST /v1/unredact": "P0-9: exact-content exception via VaultManager._cache",
}


def _p(prefix: str, suffix: str = "") -> str:
    return f"{prefix}{suffix}"


#: The control-plane rows, every path verified against source.
#:
#: Each of these is a place the product legitimately puts an operator-supplied
#: value. Without them a FORBIDDEN default reports intended output as a
#: security violation, and the baseline can never reconcile.
ROWS: tuple[Row, ...] = (
    # -- prompt list patterns ------------------------------------------------
    Row(
        "*",
        "prompt-list-pattern",
        "*",
        "*",
        "*",
        "*",
        "*",
        "db:global_prompt_lists.pattern",
        Rule.ALLOWED_BOUNDED,
        "the configured pattern is the rule itself",
    ),
    Row(
        "*",
        "prompt-list-pattern",
        "*",
        "*",
        "*",
        "*",
        "*",
        "GET /v1/settings/prompt-lists -> $[*].pattern",
        Rule.ALLOWED_BOUNDED,
        "admin reads back what an admin configured",
    ),
    # -- export target configuration ----------------------------------------
    Row(
        "*",
        "export-target-config",
        "*",
        "*",
        "*",
        "*",
        "*",
        "db:export_targets.config",
        Rule.ALLOWED_BOUNDED,
        "the destination config is operator-supplied",
    ),
    Row(
        "*",
        "export-target-config",
        "*",
        "*",
        "*",
        "*",
        "*",
        "GET /v1/settings/export-targets -> $[*].config",
        Rule.ALLOWED_BOUNDED,
        "admin reads back what an admin configured",
    ),
    # -- model intent --------------------------------------------------------
    Row(
        "*",
        "model-intent-statement",
        "*",
        "*",
        "*",
        "*",
        "*",
        "db:model_intent.statement",
        Rule.ALLOWED_BOUNDED,
        "operator-supplied",
    ),
    Row(
        "*",
        "model-intent-statement",
        "*",
        "*",
        "*",
        "*",
        "*",
        "GET /v1/settings/model-intent -> $.statement",
        Rule.ALLOWED_BOUNDED,
        "admin reads back what an admin configured",
    ),
    # -- policy name ---------------------------------------------------------
    Row("*", "policy-name", "*", "*", "*", "*", "*", "db:policies.name", Rule.ALLOWED_BOUNDED, "the policy's own name"),
    Row(
        "*",
        "policy-name",
        "*",
        "*",
        "*",
        "*",
        "*",
        "GET /v1/policies/{policy_id}/export -> body",
        Rule.ALLOWED_BOUNDED,
        "the exported YAML names its policy",
    ),
    Row(
        "*",
        "policy-name",
        "*",
        "*",
        "*",
        "*",
        "*",
        "GET /v1/policies/{policy_id}/export -> header:Content-Disposition",
        Rule.ALLOWED_BOUNDED,
        "the filename is built from the policy name -- a body-only collector misses this",
    ),
    # -- competitor / custom-entity literals --------------------------------
    Row(
        "*",
        "*",
        "*",
        "*",
        "*",
        "*",
        "*",
        "db:rule_sets.detectors",
        Rule.ALLOWED_BOUNDED,
        "detector configuration holds the literal it matches",
    ),
    Row(
        "*",
        "*",
        "*",
        "*",
        "*",
        "*",
        "*",
        "GET /v1/policies/{policy_id}/rule-sets/{event_type} -> $.detectors",
        Rule.ALLOWED_BOUNDED,
        "admin reads back detector configuration",
    ),
    Row(
        "*",
        "*",
        "*",
        "*",
        "*",
        "*",
        "*",
        "GET /v1/policies/{policy_id}/export -> body:detectors",
        Rule.ALLOWED_BOUNDED,
        "the YAML export carries the rule set's detectors",
    ),
    # -- access rule names ---------------------------------------------------
    Row(
        "access-rule-name",
        "*",
        "*",
        "*",
        "*",
        "*",
        "*",
        "db:access_rules.name",
        Rule.ALLOWED_BOUNDED,
        "the rule's own name, needed to exercise it",
    ),
    Row(
        "access-rule-name",
        "*",
        "*",
        "*",
        "*",
        "*",
        "*",
        "GET /v1/policies/{policy_id}/rule-sets/{event_type}/access-rules -> $[*].name",
        Rule.ALLOWED_BOUNDED,
        "_rule_to_dict returns the name on list",
    ),
    Row(
        "access-rule-name",
        "*",
        "*",
        "*",
        "*",
        "*",
        "*",
        "POST /v1/policies/{policy_id}/rule-sets/{event_type}/access-rules -> $.name",
        Rule.ALLOWED_BOUNDED,
        "_rule_to_dict returns the name on create",
    ),
    Row(
        "access-rule-name",
        "*",
        "*",
        "*",
        "*",
        "*",
        "*",
        "PATCH /v1/policies/{policy_id}/rule-sets/{event_type}/access-rules/{rule_id} -> $.name",
        Rule.ALLOWED_BOUNDED,
        "_rule_to_dict returns the name on update",
    ),
    # -- threat intelligence -------------------------------------------------
    Row(
        "*",
        "*",
        "*",
        "*",
        "*",
        "*",
        "*",
        "GET /v1/settings/threat-intelligence -> $.urls",
        Rule.ALLOWED_BOUNDED,
        "operator-supplied local threat intelligence",
    ),
    # -- capture-on: where content legitimately lives ------------------------
    Row(
        "*",
        "message-content",
        "*",
        "capture-on",
        "*",
        "*",
        "*",
        "db:interaction_contents.input_json",
        Rule.REQUIRED,
        "capture-on stores the full input here and nowhere else",
    ),
    Row(
        "*",
        "message-content",
        "*",
        "capture-on",
        "*",
        "*",
        "*",
        "db:interaction_contents.output_json",
        Rule.ALLOWED_BOUNDED,
        "derived output only",
    ),
    Row(
        "*",
        "message-content",
        "*",
        "capture-on",
        "*",
        "*",
        "*",
        "db:interaction_contents.matches_json",
        Rule.REQUIRED,
        "source-bound exact values, for detectors that report them",
    ),
    # -- protected reads and the explicit export -----------------------------
    Row(
        "*",
        "message-content",
        "*",
        "capture-on",
        "read-full",
        "content:read-full",
        "*",
        "GET /v1/logs/{id}/content -> $.input",
        Rule.ALLOWED_BOUNDED,
        "the stronger grant is what this projection requires",
    ),
    Row(
        "*",
        "message-content",
        "*",
        "capture-on",
        "read-matches",
        "content:read-matches",
        "*",
        "GET /v1/logs/{id}/content?view=matches -> $.matches",
        Rule.ALLOWED_BOUNDED,
        "matches omit surrounding content",
    ),
    Row(
        "*",
        "message-content",
        "*",
        "capture-on",
        "content-export",
        "content:export",
        "*",
        "transport:content-export -> body",
        Rule.ALLOWED_BOUNDED,
        "the one expected external occurrence",
    ),
)


def resolve(
    *,
    leaf: str,
    placement: str,
    branch: str,
    capture: str,
    operation: str,
    grant: str,
    representation: str,
    path: str,
    rows: tuple[Row, ...] = ROWS,
) -> Row:
    """Exactly one rule, or an exception. Never a silent default choice."""
    if _http_endpoint(path) in EXCLUDED_FROM_HTTP_DOMAIN:
        raise OutOfDomain(f"{_http_endpoint(path)} is excluded: " f"{EXCLUDED_FROM_HTTP_DOMAIN[_http_endpoint(path)]}")

    given = {
        "leaf": leaf,
        "placement": placement,
        "branch": branch,
        "capture": capture,
        "operation": operation,
        "grant": grant,
        "representation": representation,
        "path": path,
    }
    matches = [row for row in rows if _matches(row, given)]
    if not matches:
        # FORBIDDEN by default -- on an enumerated surface. This says nothing
        # about a surface nobody declared.
        return Row(
            leaf,
            placement,
            branch,
            capture,
            operation,
            grant,
            representation,
            path,
            Rule.FORBIDDEN,
            "no rule matched; forbidden by default",
        )

    best = max(row.specificity for row in matches)
    winners = [row for row in matches if row.specificity == best]
    if len(winners) > 1:
        raise Ambiguous(
            f"{len(winners)} rows match {path!r} at specificity {best}: "
            + "; ".join(f"{w.rule.value}@{w.path}" for w in winners)
        )
    return winners[0]


_ENDPOINT = re.compile(r"^([A-Z]+ [^ ]+)")


def _http_endpoint(path: str) -> str:
    match = _ENDPOINT.match(path)
    return match.group(1) if match else ""


def _matches(row: Row, given: dict[str, str]) -> bool:
    for axis, value in given.items():
        declared = getattr(row, axis)
        if declared == WILDCARD:
            continue
        if axis == "path":
            if not _path_matches(declared, value):
                return False
        elif declared != value:
            return False
    return True


def _path_matches(declared: str, actual: str) -> bool:
    """Path templates match their instantiations.

    `GET /v1/policies/{policy_id}/export -> body` must match the same path with
    a real id substituted, or every row would have to enumerate ids.
    """
    if declared == actual:
        return True
    pattern = re.escape(declared).replace(r"\{", "{").replace(r"\}", "}")
    pattern = re.sub(r"\{[a-z_]+\}", "[^/]+", pattern)
    return re.fullmatch(pattern, actual) is not None
