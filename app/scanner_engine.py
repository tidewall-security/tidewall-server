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

from app.config import PolicyConfig
from app.detectors.base import BaseDetector

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Scan result
# ---------------------------------------------------------------------------


@dataclass
class ScanResult:
    """Aggregated result from running all enabled detectors."""

    blocked: bool = False
    transformed: bool = False
    guard_output_text: str | None = None
    detectors: dict[str, dict] = field(default_factory=dict)
    summary_parts: list[str] = field(default_factory=list)


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


def _make_detector(name: str, config: dict[str, Any], **kwargs: Any) -> BaseDetector | None:
    """Dynamically instantiate a detector by policy name."""
    entry = _DETECTOR_REGISTRY.get(name)
    if entry is None:
        logger.debug("No implementation for detector '%s' — skipping", name)
        return None

    module_path, class_name = entry
    try:
        import importlib

        mod = importlib.import_module(module_path)
        cls = getattr(mod, class_name)
        return cls(config, **kwargs)  # type: ignore[no-any-return]
    except Exception as exc:
        logger.warning("Failed to instantiate detector '%s': %s", name, exc)
        return None


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

        for det_name in _DETECTOR_ORDER:
            det_cfg = policy.detectors.get(det_name)
            if det_cfg is None or not det_cfg.enabled:
                continue

            cfg_dict = det_cfg.model_dump()
            cfg_dict["use_onnx"] = use_onnx
            if det_name == "malicious_prompt" and self._session_factory:
                detector = _make_detector(det_name, cfg_dict, session_factory=self._session_factory)
            else:
                detector = _make_detector(det_name, cfg_dict)
            if detector is not None:
                self._detectors.append((det_name, detector))
                logger.info("Loaded detector: %s (action=%s)", det_name, det_cfg.action)

    @classmethod
    def from_detectors(
        cls,
        detectors: dict[str, dict[str, Any]],
        report_only: bool = False,
        session_factory: Any = None,
        use_onnx: bool = False,
    ) -> ScannerEngine:
        """Build a ScannerEngine from a raw detectors dict (from DB RuleSet.detectors)."""
        from app.config import DetectorConfig, PolicyConfig

        policy = PolicyConfig(
            name="_from_detectors",
            report_only=report_only,
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
        current_text = text

        for det_name, detector in self._detectors:
            # malicious_entity only runs on output
            if det_name == "malicious_entity" and event_type != "output":
                continue

            if det_name == "mcp_validation" and event_type != "tool_listing":
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
            except Exception as exc:
                logger.error("Detector '%s' raised: %s", det_name, exc)
                result.detectors[det_name] = {"detected": False, "data": None}
                continue

            result.detectors[det_name] = {
                "detected": det_result.detected,
                "data": det_result.data,
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
        current_text = text

        for det_name, detector in self._detectors:
            if not detector.can_redact:
                continue

            try:
                if det_name == "confidential_and_pii_entity" and vault is not None:
                    det_result = detector.scan(current_text, vault=vault)
                else:
                    det_result = detector.scan(current_text)
            except Exception as exc:
                logger.error("Detector '%s' raised: %s", det_name, exc)
                continue

            if det_result.detected and det_result.sanitized_text:
                result.transformed = True
                current_text = det_result.sanitized_text
                result.guard_output_text = current_text

        if not result.transformed:
            result.guard_output_text = text

        return result
