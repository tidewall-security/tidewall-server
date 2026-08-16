"""Write-time validation for policy content.

Three security predicates in this codebase used to fail *open* when their
configuration was invalid, and none of them lived inside ``DetectorResult`` so
none was covered by the detector-status work:

- an invalid regex in a custom-entity pattern or a prompt-list entry was
  logged and skipped, so the rule it expressed simply did not apply;
- an unrecognised access-rule operator returned ``False``, which for a
  ``block`` rule means "did not match", so the rule never fired;
- an invalid CIDR in a threat-intel list returned "not malicious".

In each case a typo in an administrator's policy silently removed a control,
and nothing in the system said so.

Validation belongs at write time. A policy that cannot be enforced as written
should be rejected while the administrator is looking at it, rather than
accepted and then quietly not applied — which is indistinguishable from being
applied and finding nothing.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

# Operators understood by :mod:`app.services.rule_evaluator`. Kept here so the
# write path and the evaluator cannot drift apart: an operator accepted at write
# time but unknown to the evaluator would fail open at evaluation, which is the
# defect this module exists to prevent.
VALID_OPERATORS: frozenset[str] = frozenset(
    {
        "==",
        "!=",
        "contains",
        "not contains",
        "in",
        "not in",
    }
)

VALID_ACTIONS: frozenset[str] = frozenset({"block", "redact", "report"})

# An upper bound on pattern length. Not a safety analysis — that is RE2's job —
# but a cheap guard against pathological input reaching the engine at all.
MAX_PATTERN_LENGTH = 1000


class PolicyValidationError(ValueError):
    """Raised when policy content cannot be enforced as written."""


def validate_regex(pattern: str, *, where: str) -> None:
    """Reject a regex that will not compile, or that is implausibly long."""
    if not isinstance(pattern, str):
        raise PolicyValidationError(f"{where}: pattern must be a string, got {type(pattern).__name__}")
    if len(pattern) > MAX_PATTERN_LENGTH:
        raise PolicyValidationError(
            f"{where}: pattern is {len(pattern)} characters, over the {MAX_PATTERN_LENGTH} limit"
        )
    try:
        re.compile(pattern)
    except re.error as exc:
        raise PolicyValidationError(f"{where}: invalid regex ({exc})") from None


def validate_operator(operator: str, *, where: str) -> None:
    """Reject an access-rule operator the evaluator does not implement."""
    if operator not in VALID_OPERATORS:
        known = ", ".join(sorted(VALID_OPERATORS))
        raise PolicyValidationError(f"{where}: unknown operator {operator!r}. Valid operators: {known}")


def validate_cidr(cidr: str, *, where: str) -> None:
    """Reject a CIDR that does not parse."""
    try:
        ipaddress.ip_network(cidr, strict=False)
    except ValueError as exc:
        raise PolicyValidationError(f"{where}: invalid CIDR ({exc})") from None


def validate_action(action: str, *, where: str) -> None:
    if action not in VALID_ACTIONS:
        known = ", ".join(sorted(VALID_ACTIONS))
        raise PolicyValidationError(f"{where}: unknown action {action!r}. Valid actions: {known}")


def validate_detectors(detectors: dict[str, Any]) -> None:
    """Validate a raw detectors mapping from a policy write.

    Raises :class:`PolicyValidationError` on the first problem found, naming the
    detector and field so the administrator can fix it directly.
    """
    from app.scanner_engine import _DETECTOR_REGISTRY

    if not isinstance(detectors, dict):
        raise PolicyValidationError(f"detectors must be a mapping, got {type(detectors).__name__}")

    for name, cfg in detectors.items():
        if not isinstance(cfg, dict):
            raise PolicyValidationError(f"detectors.{name}: configuration must be a mapping")
        if not cfg.get("enabled", True):
            continue

        if name not in _DETECTOR_REGISTRY:
            known = ", ".join(sorted(_DETECTOR_REGISTRY))
            raise PolicyValidationError(f"detectors.{name}: no such detector. Known detectors: {known}")

        action = cfg.get("action", "report")
        validate_action(action, where=f"detectors.{name}.action")

        for i, pattern in enumerate(cfg.get("patterns", []) or []):
            validate_regex(pattern, where=f"detectors.{name}.patterns[{i}]")

        # Nested threat-intel blocklists, validated against the shape
        # ThreatIntelService actually reads: cfg["intel"]["local_blocklists"]["ips"].
        # An earlier version checked keys ("blocked_cidrs", "cidrs", "ip_ranges")
        # that nothing consumes, which is a dead validator wearing the costume
        # of a live one. An invalid CIDR returns "not malicious" at runtime, so
        # it silently removes the blocklist entry it expressed.
        intel = cfg.get("intel") or {}
        blocklists = (intel.get("local_blocklists") or {}) if isinstance(intel, dict) else {}
        for i, entry in enumerate(blocklists.get("ips", []) or []):
            if "/" in str(entry):
                validate_cidr(entry, where=f"detectors.{name}.intel.local_blocklists.ips[{i}]")


def _iter_conditions(conditions: Any) -> list[dict[str, Any]]:
    """Yield condition mappings from either stored shape.

    Access rules store ``conditions`` as a mapping with an ``all``/``any`` key
    in some paths and as a bare list in others. Validating only one shape would
    silently pass the other, which is how the previous version managed to be
    wired and still inert.
    """
    if isinstance(conditions, dict):
        out: list[dict[str, Any]] = []
        for key in ("all", "any", "conditions"):
            value = conditions.get(key)
            if isinstance(value, list):
                out.extend(c for c in value if isinstance(c, dict))
        if not out and "field" in conditions:
            out.append(conditions)
        return out
    if isinstance(conditions, list):
        return [c for c in conditions if isinstance(c, dict)]
    return []


def validate_access_rules(rules: list[dict[str, Any]]) -> None:
    """Validate access rules, rejecting operators the evaluator cannot apply."""
    for i, rule in enumerate(rules or []):
        where_rule = f"access_rules[{i}]"
        for j, condition in enumerate(_iter_conditions(rule.get("conditions"))):
            if not isinstance(condition, dict):
                raise PolicyValidationError(f"{where_rule}.conditions[{j}]: must be a mapping")
            # The evaluator reads "op", not "operator". Its default is "==",
            # so an absent key is valid rather than missing.
            operator = condition.get("op", "==")
            validate_operator(operator, where=f"{where_rule}.conditions[{j}]")


def validate_prompt_list_entry(pattern: str, match_type: str, *, where: str = "prompt_list") -> None:
    """Validate one prompt-list entry before it is stored."""
    if match_type == "regex":
        validate_regex(pattern, where=where)
    elif match_type not in ("substring", "exact"):
        raise PolicyValidationError(f"{where}: unknown match_type {match_type!r}")
