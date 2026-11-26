"""Freeze and evaluate the Tidewall policy subset supported by Claude UserPromptSubmit."""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import asdict, dataclass, field
from typing import Any, Literal

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import AccessRule, Policy, RuleSet
from app.services.policy_validation import VALID_OPERATORS
from app.services.prompt_classifier_client import (
    PROFILE,
    AssessmentReason,
    AssessmentResult,
    AssessmentStatus,
    ModelIdentity,
)
from app.services.prompt_list_service import (
    FrozenPromptEntry,
    PromptListConfigError,
    PromptListService,
    match_prompt_entries,
    preflight_prompt_entries,
)
from app.services.rule_evaluator import evaluate_access_rules

MAX_NATIVE_RULES = 64
Mode = Literal["report", "enforce"]
DetectorAction = Literal["block", "report"]
DecisionAction = Literal["allow", "deny"]
Reason = (
    AssessmentReason
    | Literal[
        "access_rule_block",
        "malicious_list",
        "benign_override",
        "capture_disabled",
        "clean",
        "classifier_positive",
        "prompt_list_failed",
    ]
)
PrecheckReason = Literal[
    "access_rule_block", "malicious_list", "benign_override", "capture_disabled", "prompt_list_failed"
]
_RULE_ACTIONS = {"continue", "report_and_continue", "report_and_stop", "ignore_and_stop", "block_and_stop"}
# The native profile explicitly replaces the guard classifier and its model-specific settings.
_MALICIOUS_SETTINGS = {
    "enabled",
    "action",
    "generic_injection_detection",
    "custom_malicious_detection",
    "custom_benign_detection",
    "intent_conformance",
    "model",
    "tokenizer",
    "revision",
    "threshold",
    "injection_label",
}


class NativePolicyUnsupported(ValueError):
    """The policy cannot be activated or evaluated under the native profile."""


@dataclass(frozen=True)
class NativePolicyConfig:
    enabled: bool = False
    profile: str = PROFILE
    threshold: float = 0.5
    generation: int = 0


@dataclass(frozen=True)
class FrozenAccessRule:
    id: str
    sort_order: int
    name: str = field(repr=False)
    op: str
    value: str | tuple[str, ...] = field(repr=False)
    then_action: str
    else_action: str

    def for_evaluator(self) -> dict[str, Any]:
        # The guard evaluator expects JSON lists for "in"/"not in".
        value = list(self.value) if isinstance(self.value, tuple) else self.value
        return {
            "name": self.name,
            "conditions": {"field": "app_id", "op": self.op, "value": value},
            "then_action": self.then_action,
            "else_action": self.else_action,
        }


@dataclass(frozen=True)
class NativePolicySnapshot:
    policy_id: str
    rule_set_id: str
    revision: str
    mode: Mode
    failure_action: DetectorAction
    detector_action: DetectorAction
    rules: tuple[FrozenAccessRule, ...]
    # None disables a list. An empty tuple enables it with no rows.
    malicious_entries: tuple[FrozenPromptEntry, ...] | None
    benign_entries: tuple[FrozenPromptEntry, ...] | None
    config: NativePolicyConfig


@dataclass(frozen=True)
class Precheck:
    reason: PrecheckReason | None

    @property
    def needs_assessment(self) -> bool:
        return self.reason is None


@dataclass(frozen=True)
class NativeAssessment:
    status: AssessmentStatus | Literal["not_requested"]
    reason: Reason
    profile: str = PROFILE
    model_identity: ModelIdentity | None = None
    unsafe_score: float | None = None
    score_kind: str | None = None
    input_tokens: int | None = None


@dataclass(frozen=True)
class NativeOutcome:
    assessment: NativeAssessment
    evaluated_action: DecisionAction | Literal["unknown"]
    returned_action: DecisionAction
    reason: Reason


def _flag(settings: dict[str, Any], key: str, default: bool) -> bool:
    value = settings.get(key, default)
    if not isinstance(value, bool):
        raise NativePolicyUnsupported(f"{key} must be boolean")
    return value


def _detector_action(value: Any) -> DetectorAction:
    if value == "block":
        return "block"
    if value == "report":
        return "report"
    raise NativePolicyUnsupported("native profile requires block or report")


def _supported_detector(detectors: Any) -> dict[str, Any]:
    if not isinstance(detectors, dict):
        raise NativePolicyUnsupported("input detectors must be a mapping")
    for name, cfg in detectors.items():
        if not isinstance(cfg, dict):
            raise NativePolicyUnsupported("detector settings must be a mapping")
        if _flag(cfg, "enabled", True) and name != "malicious_prompt":
            raise NativePolicyUnsupported("input rule set enables another detector")
    cfg = detectors.get("malicious_prompt")
    if (
        not isinstance(cfg, dict)
        or not _flag(cfg, "enabled", True)
        or not _flag(cfg, "generic_injection_detection", True)
    ):
        raise NativePolicyUnsupported("native profile requires generic malicious-prompt detection")
    if cfg.keys() - _MALICIOUS_SETTINGS:
        raise NativePolicyUnsupported("unsupported malicious-prompt settings")
    intent = cfg.get("intent_conformance", {})
    if not isinstance(intent, dict) or _flag(intent, "enabled", False):
        raise NativePolicyUnsupported("native profile does not support intent conformance")
    return cfg


def _freeze_rules(session: Session, rule_set_id: str) -> tuple[FrozenAccessRule, ...]:
    rows = session.execute(
        select(
            AccessRule.id,
            AccessRule.sort_order,
            AccessRule.name,
            AccessRule.conditions,
            AccessRule.then_action,
            AccessRule.else_action,
        )
        .where(AccessRule.rule_set_id == rule_set_id)
        .order_by(AccessRule.sort_order, AccessRule.id)
        .limit(MAX_NATIVE_RULES + 1)
    ).all()
    if len(rows) > MAX_NATIVE_RULES:
        raise NativePolicyUnsupported("input rule set exceeds native access-rule limit")
    rules = []
    for row in rows:
        if not isinstance(row.id, str) or not isinstance(row.name, str) or type(row.sort_order) is not int:
            raise NativePolicyUnsupported("native access rules require text IDs and names and integer sort orders")
        condition = row.conditions
        if (
            not isinstance(condition, dict)
            or condition.keys() - {"field", "op", "value"}
            or condition.get("field") != "app_id"
            or "value" not in condition
        ):
            raise NativePolicyUnsupported("native access rules require a simple app_id condition")
        op = condition.get("op", "==")
        value = condition["value"]
        if not isinstance(op, str):
            raise NativePolicyUnsupported("invalid access-rule operator shape")
        if op in ("in", "not in") or (op not in VALID_OPERATORS and isinstance(value, list)):
            if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
                raise NativePolicyUnsupported("membership requires a list of app IDs")
            value = tuple(value)
        elif not isinstance(value, str):
            raise NativePolicyUnsupported("native access-rule comparison requires an app ID")
        if row.then_action not in _RULE_ACTIONS or row.else_action not in _RULE_ACTIONS:
            raise NativePolicyUnsupported("unsupported native access-rule action")
        # Preserve the guard's fail-closed runtime result for an unknown operator.
        rules.append(FrozenAccessRule(row.id, row.sort_order, row.name, op, value, row.then_action, row.else_action))
    return tuple(rules)


def _freeze_entries(
    service: PromptListService, settings: dict[str, Any], kind: str
) -> tuple[FrozenPromptEntry, ...] | None:
    if not _flag(settings, f"custom_{kind}_detection", False):
        return None
    try:
        entries = service.frozen_entries(kind, deterministic_ties=True)
        for entry in entries:
            if not isinstance(entry.pattern, str):
                raise NativePolicyUnsupported(f"stored {kind} prompt list requires text patterns")
            if entry.match_type not in ("substring", "exact", "regex"):
                raise NativePolicyUnsupported(f"stored {kind} prompt list has an unsupported match type")
        preflight_prompt_entries(entries, kind)
    except PromptListConfigError:
        raise NativePolicyUnsupported(f"stored {kind} prompt list cannot be enforced") from None
    return entries


def freeze_native_policy(session: Session, policy_id: str, config: NativePolicyConfig) -> NativePolicySnapshot:
    """Read all effective values inside the caller's SQLite BEGIN IMMEDIATE transaction.

    Select scalar columns to reread current database values even in a reused Session.
    The caller owns the reservation, deadline and transaction completion.
    """
    if config.enabled is not True or config.profile != PROFILE:
        raise NativePolicyUnsupported("native policy is disabled or has an unsupported profile")
    threshold = config.threshold
    if type(threshold) not in (int, float) or not 0 <= threshold <= 1 or not math.isfinite(threshold):
        raise NativePolicyUnsupported("native threshold must be finite and in [0,1]")
    if type(config.generation) is not int or config.generation < 0:
        raise NativePolicyUnsupported("invalid native config generation")
    row = session.execute(
        select(
            Policy.report_only,
            Policy.on_detector_failure,
            RuleSet.id,
            RuleSet.report_only.label("rule_report"),
            RuleSet.detectors,
        )
        .join(RuleSet, RuleSet.policy_id == Policy.id)
        .where(Policy.id == policy_id, RuleSet.event_type == "input")
    ).one_or_none()
    if row is None:
        raise NativePolicyUnsupported("native policy requires an input rule set")
    report = row.report_only if row.rule_report is None else row.rule_report
    mode: Mode = "report" if report else "enforce"
    settings = _supported_detector(row.detectors)
    detector_action = _detector_action(settings.get("action", "report"))
    failure_action = _detector_action(row.on_detector_failure)
    rules = _freeze_rules(session, row.id)
    service = PromptListService(session)
    malicious = _freeze_entries(service, settings, "malicious")
    benign = _freeze_entries(service, settings, "benign")
    # Generation is an independent authority check. A -> B -> A restores
    # semantics, never authority. Normalize integral thresholds and negative zero.
    semantic = {
        "policy_id": policy_id,
        "rule_set_id": row.id,
        "mode": mode,
        "detector_action": detector_action,
        "failure_action": failure_action,
        "profile": config.profile,
        "threshold": float(threshold) or 0.0,
        "rules": [asdict(rule) for rule in rules],
        "malicious_entries": None if malicious is None else [asdict(entry) for entry in malicious],
        "benign_entries": None if benign is None else [asdict(entry) for entry in benign],
    }
    revision = hashlib.sha256(json.dumps(semantic, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return NativePolicySnapshot(
        policy_id, row.id, revision, mode, failure_action, detector_action, rules, malicious, benign, config
    )


def evaluate_native_precheck(snapshot: NativePolicySnapshot, text: str | None) -> Precheck:
    """Evaluate admitted metadata and, if present, the exact validated complete prompt."""
    if text is not None and not isinstance(text, str):
        raise TypeError("expected one admitted prompt string or None")
    try:
        result = evaluate_access_rules([rule.for_evaluator() for rule in snapshot.rules], {"app_id": "claude-code"})
    except ValueError:
        return Precheck("access_rule_block")
    if result["blocked"]:
        return Precheck("access_rule_block")
    if text is None:
        return Precheck("capture_disabled")
    try:
        if snapshot.malicious_entries and match_prompt_entries(text, snapshot.malicious_entries):
            return Precheck("malicious_list")
        if snapshot.benign_entries and match_prompt_entries(text, snapshot.benign_entries):
            return Precheck("benign_override")
    except Exception:
        # Matching a frozen, preflighted row can still fail at runtime. Later
        # stages cannot erase this failure or manufacture a complete assessment.
        return Precheck("prompt_list_failed")
    return Precheck(None)


def _incomplete(snapshot: NativePolicySnapshot, detail: NativeAssessment) -> NativeOutcome:
    if snapshot.detector_action == "block" and snapshot.failure_action == "block":
        return NativeOutcome(detail, "deny", "deny", detail.reason)
    return NativeOutcome(detail, "unknown", "allow", detail.reason)


def _finding(snapshot: NativePolicySnapshot, detail: NativeAssessment) -> NativeOutcome:
    if snapshot.detector_action == "block":
        return NativeOutcome(detail, "deny", "allow" if snapshot.mode == "report" else "deny", detail.reason)
    return NativeOutcome(detail, "allow", "allow", detail.reason)


def resolve_native_result(
    snapshot: NativePolicySnapshot, precheck: Precheck, assessment: AssessmentResult | None = None
) -> NativeOutcome:
    """Resolve a precheck and the client result, or an authenticated local input refusal.

    A missing prompt with no assessment represents capture_disabled. For opted-in
    unassessable input pass None text and the corresponding unsupported result.
    """
    reason = precheck.reason
    if reason == "access_rule_block":
        detail = NativeAssessment("not_requested", reason)
        if assessment is not None and assessment.status == "unsupported" and assessment.reason is not None:
            detail = NativeAssessment("unsupported", assessment.reason)
        return NativeOutcome(detail, "deny", "deny", reason)
    if reason == "prompt_list_failed":
        return _incomplete(snapshot, NativeAssessment("failed", reason))
    if reason == "malicious_list":
        return _finding(snapshot, NativeAssessment("not_requested", reason))
    if reason == "benign_override" or (reason == "capture_disabled" and assessment is None):
        return NativeOutcome(NativeAssessment("not_requested", reason), "allow", "allow", reason)
    if assessment is None:
        raise ValueError("complete prompt requires a classifier result")
    if reason == "capture_disabled" and assessment.status != "unsupported":
        raise ValueError("absent prompt may only carry an input refusal")
    if assessment.status != "assessed":
        if assessment.reason is None:
            raise ValueError("a classifier refusal requires a reason")
        return _incomplete(snapshot, NativeAssessment(assessment.status, assessment.reason))
    if assessment.unsafe_score is None:
        raise ValueError("an assessed result requires a score")
    positive = assessment.unsafe_score >= snapshot.config.threshold
    detail = NativeAssessment(
        "assessed",
        "classifier_positive" if positive else "clean",
        assessment.profile,
        assessment.model_identity,
        assessment.unsafe_score,
        assessment.score_kind,
        assessment.input_tokens,
    )
    if positive:
        return _finding(snapshot, detail)
    return NativeOutcome(detail, "allow", "allow", detail.reason)
