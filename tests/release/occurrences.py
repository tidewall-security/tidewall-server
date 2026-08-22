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
    detector: str
    event: str
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
                self.detector,
                self.event,
                self.capture,
                self.operation,
                self.grant,
                self.representation,
                self.path,
            )
            if axis != WILDCARD
        )


def _r(leaf, placement, branch, detector, event, capture, operation, grant, representation, path, rule, why=""):
    """Positional constructor, so a row reads as a row rather than a wall of keywords."""
    return Row(leaf, placement, branch, detector, event, capture, operation, grant, representation, path, rule, why)


class Ambiguous(Exception):
    """Two rows match at the same specificity. A tie must never be resolved silently."""


class NoRule(Exception):
    """No checked-in row matched. The matrix is incomplete, and that is a defect."""


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
    # The catch-all. An explicit checked-in row, not a value the resolver
    # invents: a zero-match occurrence must fail, and it cannot fail if the
    # resolver silently manufactures a FORBIDDEN answer for it.
    _r(
        "*",
        "*",
        "*",
        "*",
        "*",
        "*",
        "*",
        "*",
        "*",
        "*",
        Rule.FORBIDDEN,
        "forbidden by default, on surfaces the sweep enumerates",
    ),
    # -- prompt list patterns, scoped to the ingress that makes them legal ---
    _r(
        "*",
        "prompt-list-pattern",
        "*",
        "*",
        "*",
        "*",
        "*",
        "*",
        "*",
        "db:global_prompt_lists.pattern",
        Rule.ALLOWED_BOUNDED,
        "the configured pattern is the rule itself",
    ),
    _r(
        "*",
        "prompt-list-pattern",
        "*",
        "*",
        "*",
        "*",
        "*",
        "*",
        "*",
        "GET /v1/settings/prompt-lists -> $[*].pattern",
        Rule.ALLOWED_BOUNDED,
        "admin reads back what an admin configured",
    ),
    _r(
        "*",
        "prompt-list-pattern",
        "*",
        "*",
        "*",
        "*",
        "*",
        "*",
        "*",
        "POST /v1/settings/prompt-lists -> $.pattern",
        Rule.ALLOWED_BOUNDED,
        "create returns the stored entry",
    ),
    _r(
        "*",
        "prompt-list-pattern",
        "*",
        "*",
        "*",
        "*",
        "*",
        "*",
        "*",
        "PUT /v1/settings/prompt-lists/{entry_id} -> $.pattern",
        Rule.ALLOWED_BOUNDED,
        "update returns the stored entry",
    ),
    # -- export target configuration ----------------------------------------
    _r(
        "*",
        "export-target-config",
        "*",
        "*",
        "*",
        "*",
        "*",
        "*",
        "*",
        "db:export_targets.config",
        Rule.ALLOWED_BOUNDED,
        "operator-supplied destination",
    ),
    _r(
        "*",
        "export-target-config",
        "*",
        "*",
        "*",
        "*",
        "*",
        "*",
        "*",
        "GET /v1/settings/export-targets -> $[*].config",
        Rule.ALLOWED_BOUNDED,
        "admin reads back configuration",
    ),
    _r(
        "*",
        "export-target-config",
        "*",
        "*",
        "*",
        "*",
        "*",
        "*",
        "*",
        "POST /v1/settings/export-targets -> $.config",
        Rule.ALLOWED_BOUNDED,
        "create returns it",
    ),
    _r(
        "*",
        "export-target-config",
        "*",
        "*",
        "*",
        "*",
        "*",
        "*",
        "*",
        "PATCH /v1/settings/export-targets/{target_id} -> $.config",
        Rule.ALLOWED_BOUNDED,
        "update returns it",
    ),
    # -- model intent (the route returns a LIST) ----------------------------
    _r(
        "*",
        "model-intent-statement",
        "*",
        "*",
        "*",
        "*",
        "*",
        "*",
        "*",
        "db:model_intent.statement",
        Rule.ALLOWED_BOUNDED,
        "operator-supplied",
    ),
    _r(
        "*",
        "model-intent-statement",
        "*",
        "*",
        "*",
        "*",
        "*",
        "*",
        "*",
        "GET /v1/settings/model-intent -> $[*].statement",
        Rule.ALLOWED_BOUNDED,
        "a list, not an object -- the earlier $.statement row never matched",
    ),
    # -- policy name ---------------------------------------------------------
    _r(
        "*",
        "policy-name",
        "*",
        "*",
        "*",
        "*",
        "*",
        "*",
        "*",
        "db:policies.name",
        Rule.ALLOWED_BOUNDED,
        "the policy's own name",
    ),
    _r(
        "*",
        "policy-name",
        "*",
        "*",
        "*",
        "*",
        "*",
        "*",
        "*",
        "GET /v1/policies/{policy_id}/export -> body",
        Rule.ALLOWED_BOUNDED,
        "the exported YAML names its policy",
    ),
    _r(
        "*",
        "policy-name",
        "*",
        "*",
        "*",
        "*",
        "*",
        "*",
        "*",
        "GET /v1/policies/{policy_id}/export -> header:Content-Disposition",
        Rule.ALLOWED_BOUNDED,
        "the filename is built from the name; a body-only collector misses it",
    ),
    _r(
        "*",
        "policy-name",
        "*",
        "*",
        "*",
        "*",
        "*",
        "*",
        "*",
        "GET /v1/policies -> $[*].name",
        Rule.ALLOWED_BOUNDED,
        "list returns names",
    ),
    _r(
        "*",
        "policy-name",
        "*",
        "*",
        "*",
        "*",
        "*",
        "*",
        "*",
        "POST /v1/policies -> $.name",
        Rule.ALLOWED_BOUNDED,
        "create returns it",
    ),
    _r(
        "*",
        "policy-name",
        "*",
        "*",
        "*",
        "*",
        "*",
        "*",
        "*",
        "GET /v1/policies/{policy_id} -> $.name",
        Rule.ALLOWED_BOUNDED,
        "get returns it",
    ),
    _r(
        "*",
        "policy-name",
        "*",
        "*",
        "*",
        "*",
        "*",
        "*",
        "*",
        "PATCH /v1/policies/{policy_id} -> $.name",
        Rule.ALLOWED_BOUNDED,
        "update returns it",
    ),
    # -- competitor / custom-entity literals, SCOPED to their ingress --------
    #
    # Wildcarding every axis made any unrelated canary copied into this column
    # an allowed occurrence. The legitimate home is tied to the placement that
    # makes it legitimate.
    _r(
        "*",
        "rule-set-detector-config",
        "*",
        "*",
        "*",
        "*",
        "*",
        "*",
        "*",
        "db:rule_sets.detectors",
        Rule.ALLOWED_BOUNDED,
        "detector config holds its literal",
    ),
    _r(
        "*",
        "rule-set-detector-config",
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
    _r(
        "*",
        "rule-set-detector-config",
        "*",
        "*",
        "*",
        "*",
        "*",
        "*",
        "*",
        "PATCH /v1/policies/{policy_id}/rule-sets/{event_type} -> $.detectors",
        Rule.ALLOWED_BOUNDED,
        "update returns them",
    ),
    _r(
        "*",
        "rule-set-detector-config",
        "*",
        "*",
        "*",
        "*",
        "*",
        "*",
        "*",
        "GET /v1/policies/{policy_id}/export -> body:detectors",
        Rule.ALLOWED_BOUNDED,
        "the YAML export carries them",
    ),
    # -- access rule names ---------------------------------------------------
    _r(
        "access-rule-name",
        "*",
        "*",
        "*",
        "*",
        "*",
        "*",
        "*",
        "*",
        "db:access_rules.name",
        Rule.ALLOWED_BOUNDED,
        "the rule's own name",
    ),
    _r(
        "access-rule-name",
        "*",
        "*",
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
    _r(
        "access-rule-name",
        "*",
        "*",
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
    _r(
        "access-rule-name",
        "*",
        "*",
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
    # -- threat intelligence (real endpoint and nested shape) ---------------
    _r(
        "*",
        "threat-intelligence-config",
        "*",
        "*",
        "*",
        "*",
        "*",
        "*",
        "*",
        "GET /v1/settings/threat-intel -> $.local_blocklists.urls[*]",
        Rule.ALLOWED_BOUNDED,
        "the endpoint is /threat-intel and the shape is nested",
    ),
    # Threat-intelligence configuration is stored INSIDE rule_sets.detectors,
    # so it comes back from the rule-set endpoints and the YAML export exactly
    # as the competitor and custom-entity literals do. The allow rows for those
    # three surfaces were scoped to rule-set-detector-config only, so a
    # threat-intelligence canary hit the catch-all on all three.
    _r(
        "*",
        "threat-intelligence-config",
        "*",
        "*",
        "*",
        "*",
        "*",
        "*",
        "*",
        "GET /v1/policies/{policy_id}/rule-sets/{event_type} -> "
        "$.detectors.malicious_entity.intel.local_blocklists.urls[*]",
        Rule.ALLOWED_BOUNDED,
        "the rule set returns its own detector configuration",
    ),
    _r(
        "*",
        "threat-intelligence-config",
        "*",
        "*",
        "*",
        "*",
        "*",
        "*",
        "*",
        "PATCH /v1/policies/{policy_id}/rule-sets/{event_type} -> "
        "$.detectors.malicious_entity.intel.local_blocklists.urls[*]",
        Rule.ALLOWED_BOUNDED,
        "update returns it too",
    ),
    _r(
        "*",
        "threat-intelligence-config",
        "*",
        "*",
        "*",
        "*",
        "*",
        "*",
        "*",
        "GET /v1/policies/{policy_id}/export -> body:detectors",
        Rule.ALLOWED_BOUNDED,
        "the YAML export carries the whole detector block",
    ),
    # -- capture-on: where content legitimately lives ------------------------
    _r(
        "*",
        "message-content",
        "*",
        "*",
        "*",
        "capture-on",
        "*",
        "*",
        "*",
        "db:interaction_contents.input_json",
        Rule.REQUIRED,
        "capture-on stores the full input here",
    ),
    _r(
        "*",
        "message-content",
        "*",
        "*",
        "*",
        "capture-on",
        "*",
        "*",
        "*",
        "db:interaction_contents.output_json",
        Rule.ALLOWED_BOUNDED,
        "derived output only",
    ),
    # matches_json is REQUIRED only for detectors that report exact values.
    # A classifier's DetectorResult has no source/value field, so requiring it
    # there manufactures a failure for correct behaviour.
    _r(
        "*",
        "message-content",
        "*",
        "confidential_and_pii_entity",
        "*",
        "capture-on",
        "*",
        "*",
        "*",
        "db:interaction_contents.matches_json",
        Rule.REQUIRED,
        "PII reports exact values",
    ),
    _r(
        "*",
        "message-content",
        "*",
        "custom_entity",
        "*",
        "capture-on",
        "*",
        "*",
        "*",
        "db:interaction_contents.matches_json",
        Rule.REQUIRED,
        "custom entity reports exact values",
    ),
    _r(
        "*",
        "message-content",
        "*",
        "*",
        "*",
        "capture-on",
        "*",
        "*",
        "*",
        "db:interaction_contents.matches_json",
        Rule.ALLOWED_BOUNDED,
        "other detectors report no exact value, so its absence is correct",
    ),
    # Tools travel WITH the input when any were supplied, because they were
    # scanned -- `content_capture` stores {"messages": ..., "tools": ...}. The
    # input_json row was restricted to message-content, so every MCP capture-on
    # case resolved FORBIDDEN for storing what production deliberately stores.
    _r(
        "*",
        "tool-name",
        "*",
        "*",
        "*",
        "capture-on",
        "*",
        "*",
        "*",
        "db:interaction_contents.input_json",
        Rule.REQUIRED,
        "tools are part of the evaluated input",
    ),
    _r(
        "*",
        "tool-description",
        "*",
        "*",
        "*",
        "capture-on",
        "*",
        "*",
        "*",
        "db:interaction_contents.input_json",
        Rule.REQUIRED,
        "tools are part of the evaluated input",
    ),
    _r(
        "*",
        "tool-parameters",
        "*",
        "*",
        "*",
        "capture-on",
        "*",
        "*",
        "*",
        "db:interaction_contents.input_json",
        Rule.REQUIRED,
        "tools are part of the evaluated input",
    ),
    # Threat intelligence lives in the malicious-entity rule-set config and is
    # returned by PUT as well as GET.
    _r(
        "*",
        "threat-intelligence-config",
        "*",
        "*",
        "*",
        "*",
        "*",
        "*",
        "*",
        "db:rule_sets.detectors",
        Rule.ALLOWED_BOUNDED,
        "the configuration is stored in the rule set",
    ),
    _r(
        "*",
        "threat-intelligence-config",
        "*",
        "*",
        "*",
        "*",
        "*",
        "*",
        "*",
        "PUT /v1/settings/threat-intel -> $.intel.local_blocklists.urls[*]",
        Rule.ALLOWED_BOUNDED,
        "update returns the stored configuration",
    ),
    # Model intent is returned by create and update, not only by GET.
    _r(
        "*",
        "model-intent-statement",
        "*",
        "*",
        "*",
        "*",
        "*",
        "*",
        "*",
        "POST /v1/settings/model-intent -> $.statement",
        Rule.ALLOWED_BOUNDED,
        "create returns the stored statement",
    ),
    _r(
        "*",
        "model-intent-statement",
        "*",
        "*",
        "*",
        "*",
        "*",
        "*",
        "*",
        "PUT /v1/settings/model-intent/{intent_id} -> $.statement",
        Rule.ALLOWED_BOUNDED,
        "update returns the stored statement",
    ),
    # -- protected reads and the explicit export -----------------------------
    _r(
        "*",
        "message-content",
        "*",
        "*",
        "*",
        "capture-on",
        "read-full",
        "content:read-full",
        "*",
        "GET /v1/logs/{id}/content -> $.messages[*].content",
        Rule.ALLOWED_BOUNDED,
        "the projection returns messages, not a coarse $.input",
    ),
    _r(
        "*",
        "message-content",
        "*",
        "*",
        "*",
        "capture-on",
        "read-matches",
        "content:read-matches",
        "*",
        "GET /v1/logs/{id}/content -> $.matches.matches[*].value",
        Rule.ALLOWED_BOUNDED,
        "the matches view is a nested block",
    ),
    _r(
        "*",
        "message-content",
        "*",
        "*",
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
    detector: str,
    event: str,
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
        "detector": detector,
        "event": event,
        "capture": capture,
        "operation": operation,
        "grant": grant,
        "representation": representation,
        "path": path,
    }
    matches = [row for row in rows if _matches(row, given)]
    if not matches:
        # The plan requires a zero-match occurrence to FAIL. Synthesising a
        # FORBIDDEN row here reported success for an occurrence that matched no
        # checked-in policy at all -- the resolver deciding, rather than the
        # matrix. The catch-all below is a real row, so a genuine no-match now
        # means the matrix itself is incomplete.
        raise NoRule(f"no checked-in rule matches {path!r}")

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
    # `[*]` is an INDEX wildcard, not a literal. Treating it literally made
    # every real list occurrence -- `$[0].pattern`, `$[0].name` -- resolve
    # FORBIDDEN despite an explicit allow row, so the matrix classified
    # intended output as a violation.
    pattern = pattern.replace(re.escape("[*]"), r"\[\d+\]")
    return re.fullmatch(pattern, actual) is not None
