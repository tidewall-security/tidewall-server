"""Scanner engine — orchestrates detectors based on policy configuration.

The ScannerEngine is the heart of the detection pipeline.  For each policy
it maintains a list of instantiated detector objects (loaded once) and
runs them in a fixed priority order:

    1. **Blockers** (malicious_prompt, mcp_validation) — checked first.
       If a blocker fires, the pipeline short-circuits and no further
       detectors run.  This minimizes latency for clearly malicious input.
    2. **Redactors** (pii, secrets, custom_entity) — mutate text in-place.
       Each redactor receives the text produced by the previous one, so
       entities are progressively replaced.
    3. **Reporters** (malicious_entity, topic, language, code, competitors,
       emoji) — observe only, never modify text.

Engines are cached by ``PolicyService`` keyed on ``(policy_id, event_type)``
so detector models are loaded once and reused across requests.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from app.config import OnDetectorFailure, PolicyConfig
from app.detectors.base import BaseDetector, DetectorStatus, FailureCode

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Scan result
# ---------------------------------------------------------------------------


@dataclass
class FailedDetector:
    """A detector that could not be constructed, or that failed while running.

    Carrying construction failures as *values* rather than dropping them is the
    point: ``_make_detector`` used to return ``None`` on any error, so a
    detector that failed to build simply vanished from the engine and there was
    nothing left to enforce on. A failed slot keeps it visible.
    """

    name: str
    code: FailureCode
    action: str = "report"

    @property
    def enforcing(self) -> bool:
        """True if this detector was configured to block or redact.

        A failed reporter degrades observability. A failed blocker or redactor
        degrades *protection*, which is what makes a request unsafe to allow.
        """
        return self.action in ("block", "redact")


@dataclass
class ScanResult:
    """Aggregated result from running all enabled detectors."""

    blocked: bool = False
    transformed: bool = False
    guard_output_text: str | None = None
    detectors: dict[str, dict] = field(default_factory=dict)
    summary_parts: list[str] = field(default_factory=list)
    failures: list[FailedDetector] = field(default_factory=list)
    partial: list[str] = field(default_factory=list)

    @property
    def degraded(self) -> bool:
        """True if any detector failed outright or returned an incomplete verdict.

        ``partial`` carries the second case: a composite that found something
        with one sub-detector down produced a real finding from an incomplete
        check. That is not a failure — the detection stands — but it must not
        be reported as a complete result.
        """
        return bool(self.failures) or bool(self.partial)

    @property
    def enforcement_degraded(self) -> bool:
        """True if a *blocking or redacting* detector failed.

        This is the condition that must not be allowed through: the request was
        not actually protected, whatever the other detectors reported.
        """
        return any(f.enforcing for f in self.failures)

    def record_failure(self, name: str, code: FailureCode, action: str = "report") -> None:
        """Record a detector failure and reflect it in the per-detector payload."""
        self.failures.append(FailedDetector(name=name, code=code, action=action))
        self.detectors[name] = {
            "detected": False,
            "data": None,
            "status": DetectorStatus.FAILED.value,
            "failure_code": code.value,
        }


# ---------------------------------------------------------------------------
# Detector ordering
# ---------------------------------------------------------------------------

# 1. Blockers run first (can short-circuit)
# 2. Redactors mutate text
# 3. Reporters only observe
_DETECTOR_ORDER: list[str] = [
    "malicious_prompt",
    "mcp_validation",  # only runs on tool_listing
    "confidential_and_pii_entity",
    "secret_and_key_entity",
    "custom_entity",
    "malicious_entity",
    "topic",
    "language",
    "code",
    "competitors",
    "emoji",
]

# Map policy detector names to (module, class) pairs
_DETECTOR_REGISTRY: dict[str, tuple[str, str]] = {
    "malicious_prompt": ("app.detectors.malicious_prompt", "MaliciousPromptDetector"),
    "mcp_validation": ("app.detectors.mcp_validation", "MCPValidationDetector"),
    "confidential_and_pii_entity": ("app.detectors.pii", "PIIDetector"),
    "secret_and_key_entity": ("app.detectors.secrets", "SecretsDetector"),
    "custom_entity": ("app.detectors.custom_entity", "CustomEntityDetector"),
    "malicious_entity": ("app.detectors.malicious_entity", "MaliciousEntityDetector"),
    "topic": ("app.detectors.topic", "TopicDetector"),
    "language": ("app.detectors.language", "LanguageDetector"),
    "code": ("app.detectors.code", "CodeDetector"),
    "competitors": ("app.detectors.competitors", "CompetitorsDetector"),
    "emoji": ("app.detectors.emoji_detector", "EmojiDetector"),
}


def _detector_applies(name: str, event_type: str) -> bool:
    """True if *name* would run for *event_type*.

    Two detectors are event-scoped. Keeping the rule in one place means the
    construction-failure seeding and the live scan loop cannot disagree about
    whether a detector was expected to run — if they did, a detector could be
    skipped as inapplicable while simultaneously being reported as a failure.
    """
    if name == "malicious_entity":
        return event_type == "output"
    if name == "mcp_validation":
        return event_type == "tool_listing"
    return True


def _make_detector(
    name: str, config: dict[str, Any], **kwargs: Any
) -> tuple[BaseDetector | None, FailureCode | None]:
    """Dynamically instantiate a detector by policy name.

    Returns ``(detector, None)`` on success or ``(None, code)`` on failure.

    This used to return a bare ``None`` for three quite different causes — an
    unknown detector name, an import error, and a constructor raising — and the
    caller treated all of them as "skip this detector". A configured security
    control silently disappeared and the engine reported success. Distinguishing
    the causes is what lets the caller keep a failed slot and enforce on it.
    """
    entry = _DETECTOR_REGISTRY.get(name)
    if entry is None:
        logger.warning("No implementation for detector '%s'", name)
        return None, FailureCode.DETECTOR_UNKNOWN

    module_path, class_name = entry
    try:
        import importlib

        mod = importlib.import_module(module_path)
        cls = getattr(mod, class_name)
    except Exception:
        # Exception detail is logged here and nowhere else — it can carry file
        # paths and configuration values, and must not reach a response or an
        # audit row.
        logger.warning("Failed to import detector '%s'", name, exc_info=True)
        return None, FailureCode.IMPORT_FAILED

    try:
        return cls(config, **kwargs), None
    except Exception:
        logger.warning("Failed to instantiate detector '%s'", name, exc_info=True)
        return None, FailureCode.CONSTRUCT_FAILED


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class ScannerEngine:
    """Orchestrates all enabled detectors according to the policy."""

    def __init__(
        self,
        policy: PolicyConfig,
        session_factory: Any = None,
        use_onnx: bool = False,
    ) -> None:
        self._policy = policy
        self._session_factory = session_factory
        self._use_onnx = use_onnx
        # ALL detectors initialized once at startup
        self._detectors: list[tuple[str, BaseDetector]] = []
        # Detectors the policy enabled but which could not be constructed.
        # These are not dropped: every scan reports them as failures so a
        # missing security control cannot be mistaken for a clean result.
        self._construction_failures: list[FailedDetector] = []

        # Known detectors run in priority order; any *unknown* name the policy
        # enables is visited afterwards so it can be reported as a failure.
        # Iterating only _DETECTOR_ORDER meant a misspelled or unimplemented
        # detector was never looked for at all — a fail-open one level below
        # the one _make_detector was guarding, since nothing ever asked for it.
        unknown_names = [
            name
            for name, cfg in policy.detectors.items()
            if name not in _DETECTOR_ORDER and cfg is not None and cfg.enabled
        ]

        for det_name in [*_DETECTOR_ORDER, *unknown_names]:
            det_cfg = policy.detectors.get(det_name)
            if det_cfg is None or not det_cfg.enabled:
                continue

            cfg_dict = det_cfg.model_dump()
            cfg_dict["use_onnx"] = use_onnx
            if det_name == "malicious_prompt" and self._session_factory:
                detector, code = _make_detector(det_name, cfg_dict, session_factory=self._session_factory)
            else:
                detector, code = _make_detector(det_name, cfg_dict)

            if detector is not None:
                self._detectors.append((det_name, detector))
                logger.info("Loaded detector: %s (action=%s)", det_name, det_cfg.action)
            else:
                assert code is not None  # _make_detector returns one or the other
                self._construction_failures.append(
                    FailedDetector(name=det_name, code=code, action=det_cfg.action)
                )
                logger.error(
                    "Detector '%s' (action=%s) is enabled by policy but could not be "
                    "constructed: %s. Scans will report a degraded verdict.",
                    det_name,
                    det_cfg.action,
                    code.value,
                )

    @property
    def construction_failures(self) -> list[FailedDetector]:
        """Detectors the policy enabled that could not be built.

        The activation protocol's startup preflight reads this to decide whether
        a candidate runtime is servable at all — an engine that silently omits a
        detector is not a successfully built runtime.
        """
        return list(self._construction_failures)

    @property
    def is_enforcement_complete(self) -> bool:
        """True if every enabled blocking/redacting detector was constructed."""
        return not any(f.enforcing for f in self._construction_failures)

    @property
    def on_detector_failure(self) -> OnDetectorFailure:
        """What the policy says to do when an enforcing detector fails."""
        return self._policy.on_detector_failure

    def _seed_construction_failures(
        self,
        result: ScanResult,
        event_type: str | None = None,
        redactors_only: bool = False,
    ) -> None:
        """Report construction failures on every scan, not just at startup.

        A detector that failed to build is missing for the lifetime of the
        engine, so every request it should have covered is degraded — not only
        the first one after boot.

        Two filters keep that from over-reporting:

        ``event_type`` — a detector that would not have run for this event was
        not going to contribute a verdict anyway, so its absence is a skip
        rather than a degradation. Without this a failed ``malicious_entity``
        (output-only) would degrade every input scan.

        ``redactors_only`` — :meth:`scan_single` is a redactor-only pass, so a
        failed blocker or reporter is immaterial to it. Without this, an
        unrelated failed reporter would mark every message reconstruction
        degraded and discard perfectly good redacted output.
        """
        for failure in self._construction_failures:
            if redactors_only and failure.action != "redact":
                continue
            if event_type is not None and not _detector_applies(failure.name, event_type):
                continue
            result.record_failure(failure.name, failure.code, failure.action)

    @classmethod
    def from_detectors(
        cls,
        detectors: dict[str, dict[str, Any]],
        report_only: bool = False,
        session_factory: Any = None,
        use_onnx: bool = False,
        on_detector_failure: OnDetectorFailure = OnDetectorFailure.REPORT,
    ) -> ScannerEngine:
        """Build a ScannerEngine from a raw detectors dict (from DB RuleSet.detectors)."""
        from app.config import DetectorConfig, PolicyConfig

        policy = PolicyConfig(
            name="_from_detectors",
            report_only=report_only,
            on_detector_failure=on_detector_failure,
            detectors={name: DetectorConfig(**cfg) for name, cfg in detectors.items() if isinstance(cfg, dict)},
        )
        return cls(policy, session_factory=session_factory, use_onnx=use_onnx)

    # -----------------------------------------------------------------------
    # Full scan (all messages concatenated)
    # -----------------------------------------------------------------------

    def scan(
        self,
        text: str,
        event_type: str,
        vault_id: str,
        vault: Any,
        tools: list[dict] | None = None,
        messages: list[dict] | None = None,
    ) -> ScanResult:
        """Run all enabled detectors on *text* and return aggregated result."""
        result = ScanResult()
        self._seed_construction_failures(result, event_type=event_type)
        current_text = text

        for det_name, detector in self._detectors:
            if not _detector_applies(det_name, event_type):
                continue

            try:
                if det_name == "mcp_validation" and tools:
                    det_result = detector.scan(current_text, tools=tools)
                elif det_name == "malicious_prompt" and messages:
                    det_result = detector.scan(current_text, messages=messages)
                elif det_name == "confidential_and_pii_entity" and vault is not None:
                    det_result = detector.scan(current_text, vault=vault)
                else:
                    det_result = detector.scan(current_text)
            except Exception:
                logger.error("Detector '%s' raised during scan", det_name, exc_info=True)
                result.record_failure(det_name, FailureCode.SCAN_FAILED, detector.action)
                continue

            # A detector may also report failure by value rather than raising —
            # most know far better than we do why they could not run.
            if det_result.status is DetectorStatus.FAILED:
                assert det_result.failure_code is not None
                logger.error(
                    "Detector '%s' reported failure: %s",
                    det_name,
                    det_result.failure_code.value,
                )
                result.record_failure(det_name, det_result.failure_code, detector.action)
                continue

            if det_result.degraded:
                result.partial.append(det_name)

            result.detectors[det_name] = {
                "detected": det_result.detected,
                "data": det_result.data,
                "status": det_result.status.value,
                # Surfaced on the wire rather than dying at scan(): the
                # per-component detail is the answer to "what did you actually
                # check", which is exactly what an audit needs after a
                # degraded verdict.
                **({"degraded": True} if det_result.degraded else {}),
                **(
                    {"components": {k: v.status.value for k, v in det_result.components.items()}}
                    if det_result.components
                    else {}
                ),
            }

            if not det_result.detected:
                continue

            # --- blocking ---
            if detector.can_block:
                result.blocked = True
                action_label = "blocked" if not self._policy.report_only else "reported"
                result.summary_parts.append(f"{det_name}: {action_label}")
                if not self._policy.report_only:
                    break  # short-circuit

            # --- redacting ---
            elif detector.can_redact and det_result.sanitized_text:
                result.transformed = True
                current_text = det_result.sanitized_text
                result.guard_output_text = current_text
                result.summary_parts.append(f"{det_name}: redacted")

            # --- reporting ---
            else:
                result.summary_parts.append(f"{det_name}: detected")

        return result

    # -----------------------------------------------------------------------
    # Per-message scan (for rebuilding individual messages)
    # -----------------------------------------------------------------------

    def scan_single(
        self,
        text: str,
        vault_id: str,
        vault: Any,
    ) -> ScanResult:
        """Scan a single message through redacting detectors only.

        Used to rebuild individual messages with PII/secrets redacted while
        reusing the same vault (so unredact works across all messages).
        """
        result = ScanResult()
        self._seed_construction_failures(result, redactors_only=True)
        current_text = text

        for det_name, detector in self._detectors:
            if not detector.can_redact:
                continue

            failure_code: FailureCode | None = None
            try:
                if det_name == "confidential_and_pii_entity" and vault is not None:
                    det_result = detector.scan(current_text, vault=vault)
                else:
                    det_result = detector.scan(current_text)
                if det_result.status is DetectorStatus.FAILED:
                    failure_code = det_result.failure_code
            except Exception:
                logger.error("Redactor '%s' raised", det_name, exc_info=True)
                failure_code = FailureCode.REDACTION_FAILED

            if failure_code is not None:
                # A redactor failed. Everything redacted so far is discarded:
                # the remaining redactors never ran, so `current_text` may still
                # contain exactly the PII or secrets a later one would have
                # removed. Returning it — even partially cleaned — is the
                # disclosure this path exists to prevent.
                result.record_failure(det_name, failure_code, detector.action)
                result.transformed = False
                result.guard_output_text = None
                return result

            if det_result.detected and det_result.sanitized_text:
                result.transformed = True
                current_text = det_result.sanitized_text
                result.guard_output_text = current_text

        if not result.transformed:
            result.guard_output_text = text

        return result
