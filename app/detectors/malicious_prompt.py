"""Composite Malicious Prompt Detector.

Matches an industry structure with independent sub-detectors:
1. Custom Malicious List (override → detected)
2. Custom Benign List (override → not detected)
3. Generic Injection/Jailbreak (HF text-classification model)
4. Intent Conformance (sentence-transformer cosine similarity)

Evaluation order: malicious list → benign list → ML → intent
"""

from __future__ import annotations

import logging
from typing import Any

from app.model_registry import INJECTION as _INJECTION_REF
from app.services.prompt_list_service import PromptListConfigError

from .base import BaseDetector, ComponentStatus, DetectorResult, DetectorStatus, FailureCode, SkipReason

logger = logging.getLogger(__name__)


def _resolve_injection_label(configured: Any, model: Any) -> str | None:
    """Resolve a configured injection label to the model's own label string.

    ``policy.yaml`` shipped ``injection_label: 1`` — an int — against a
    text-classification pipeline that returns ``{"label": "LABEL_1", ...}``.
    The comparison was ``r["label"] == 1``, which is never true, so the
    flagship blocking detector scored every prompt at 0.0 and detected nothing
    on every clean install. That is P0-3.

    Both sides are canonicalised to the model's own vocabulary here rather than
    compared as written, so ``1``, ``"1"``, ``"LABEL_1"`` and ``"INJECTION"``
    all resolve identically. Returns ``None`` if the configured label does not
    exist in the model at all, which is a configuration error rather than a
    detector that finds nothing.
    """
    config = getattr(model, "config", None)
    raw_id2label = dict(getattr(config, "id2label", None) or {})
    raw_label2id = dict(getattr(config, "label2id", None) or {})

    # Normalise: config.json stores id2label keys as strings ("0", "1") and
    # transformers converts them to ints on load, so both shapes occur
    # depending on whether this sees a loaded config or a raw one. Derive
    # either map from the other so a model publishing only one still resolves.
    id2label: dict[int, str] = {}
    for key, value in raw_id2label.items():
        try:
            id2label[int(key)] = str(value)
        except (TypeError, ValueError):
            continue
    label2id: dict[str, int] = {str(k): v for k, v in raw_label2id.items()}
    if not label2id:
        label2id = {v: k for k, v in id2label.items()}
    if not id2label:
        for label, label_id in label2id.items():
            try:
                id2label[int(label_id)] = str(label)
            except (TypeError, ValueError):
                continue

    if configured is None:
        return None

    # Already the model's exact label.
    if configured in label2id:
        return str(configured)

    # An index, given as int or as a numeric string.
    idx: int | None
    try:
        idx = int(configured)
    except (TypeError, ValueError):
        idx = None
    if idx is not None and idx in id2label:
        return str(id2label[idx])

    # Case-insensitive match against the model's labels.
    wanted = str(configured).strip().lower()
    for label in label2id:
        if str(label).strip().lower() == wanted:
            return str(label)

    return None


class MaliciousPromptDetector(BaseDetector):
    """Composite prompt injection detector with sub-toggles.

    Supports four independent detection paths, configured via policy YAML:

    1. **Custom malicious/benign lists** — exact/substring/regex matching
       against admin-curated prompt lists stored in the DB.  These act as
       hard overrides: a malicious match short-circuits to "detected",
       a benign match short-circuits to "not detected".

    2. **ML-based injection detection** — a text-classification model that
       scores prompts for injection/jailbreak probability.  Requires both
       ``model`` and ``tokenizer`` keys in the policy YAML.

    3. **Intent conformance** — checks whether the user prompt aligns with
       declared model/app intent statements stored in the DB.  Uses
       sentence-transformer cosine similarity.
    """

    def __init__(self, config: dict[str, Any], session_factory: Any = None) -> None:
        """Initialize all sub-detectors based on policy config.

        The ML model is loaded once here and reused across requests.
        This is the most expensive part of startup (~2-5s per model).
        """
        super().__init__(config)

        # Sub-detector toggles — each can be independently enabled in policy YAML
        self._generic_injection_enabled = config.get("generic_injection_detection", True)
        self._custom_malicious_enabled = config.get("custom_malicious_detection", False)
        self._custom_benign_enabled = config.get("custom_benign_detection", False)

        # ML model state — direct HuggingFace pipeline only.
        # Configure the model with both ``model`` and ``tokenizer`` keys in
        # policy YAML so the loader has everything it needs.
        # Per-sub-detector construction failures. A sub-detector the operator
        # enabled but which could not be built used to vanish silently, so the
        # composite reported a confident verdict from a pipeline that was never
        # there. Recorded here and surfaced on every scan instead.
        self._load_failures: dict[str, FailureCode] = {}

        self._pipeline = None
        self._injection_label = config.get("injection_label")  # label to treat as "injection" (e.g. 1, "LABEL_1")
        self._threshold = config.get("threshold", 0.9)  # score above this = injection
        if self._generic_injection_enabled:
            model_path = config.get("model")
            # The selected model ships its own tokenizer, so `tokenizer` is
            # optional and defaults to the model. Requiring both was what let a
            # ModernBERT tokenizer be paired with a different model.
            tokenizer_path = config.get("tokenizer") or model_path
            if model_path:
                try:
                    from transformers import (
                        AutoModelForSequenceClassification,
                        AutoTokenizer,
                        pipeline,
                    )

                    # Pin the artifact so it cannot change under us. An
                    # explicit policy revision wins; otherwise fall back to the
                    # registry, which knows the SHA for the shipped default.
                    # Without that fallback the policy file and the registry
                    # are two sources of truth for the same pin, and only one
                    # of them is verified by the model-reference tests.
                    revision = config.get("revision") or _INJECTION_REF.revision_for(model_path)
                    tokenizer = AutoTokenizer.from_pretrained(tokenizer_path, revision=revision)
                    model = AutoModelForSequenceClassification.from_pretrained(model_path, revision=revision)
                    self._pipeline = pipeline(
                        "text-classification",
                        model=model,
                        tokenizer=tokenizer,
                        truncation=True,
                        max_length=512,
                        device="cpu",
                    )
                    resolved = _resolve_injection_label(self._injection_label, model)
                    if resolved is None:
                        known = list(getattr(getattr(model, "config", None), "label2id", None) or {})
                        logger.error(
                            "injection_label %r does not exist in model %s (labels: %s); "
                            "the detector cannot classify anything",
                            self._injection_label,
                            model_path,
                            known,
                        )
                        self._load_failures["generic_injection"] = FailureCode.CONFIG_INVALID
                        self._pipeline = None
                    else:
                        if str(resolved) != str(self._injection_label):
                            logger.info(
                                "Resolved injection_label %r to model label %r",
                                self._injection_label,
                                resolved,
                            )
                        self._injection_label = resolved
                    logger.info("Loaded direct HF pipeline: model=%s tokenizer=%s", model_path, tokenizer_path)
                except Exception:
                    logger.warning("Failed to load direct HF pipeline for %s", model_path, exc_info=True)
                    self._load_failures["generic_injection"] = FailureCode.MODEL_LOAD_FAILED
            else:
                # Generic injection was switched on but cannot run: this is a
                # policy that asks for protection it has not configured, which
                # is a misconfiguration rather than an opt-out.
                logger.error(
                    "malicious_prompt.generic_injection_detection is enabled but no "
                    "model+tokenizer pair is configured; ML detection cannot run"
                )
                self._load_failures["generic_injection"] = FailureCode.CONFIG_INVALID

        self._prompt_list_svc = None
        if self._custom_malicious_enabled or self._custom_benign_enabled:
            if not session_factory:
                # Previously skipped without even entering the try, so a
                # configured list check silently never ran.
                logger.error("malicious_prompt custom lists are enabled but no session factory was provided")
                self._load_failures["custom_lists"] = FailureCode.CONSTRUCT_FAILED
            else:
                try:
                    from app.services.prompt_list_service import PromptListService

                    self._prompt_list_svc = PromptListService(session_factory())

                    # Compile the stored rows now, not on whichever request
                    # first scans this list. Without this, an unenforceable row
                    # is invisible to activation preflight: the engine reports
                    # no construction failure, activation declares the policy
                    # servable, and the problem surfaces only once some caller's
                    # text happens to exercise that list.
                    for list_type, enabled in (
                        ("malicious", self._custom_malicious_enabled),
                        ("benign", self._custom_benign_enabled),
                    ):
                        if not enabled:
                            continue
                        try:
                            self._prompt_list_svc.preflight(list_type)
                        except PromptListConfigError:
                            logger.error("Stored %s prompt list cannot be enforced as written", list_type)
                            self._load_failures[f"custom_{list_type}"] = FailureCode.CONFIG_INVALID
                except Exception:
                    logger.warning("Failed to initialize PromptListService", exc_info=True)
                    self._load_failures["custom_lists"] = FailureCode.CONSTRUCT_FAILED

        intent_config = config.get("intent_conformance", {})
        if isinstance(intent_config, dict):
            self._intent_enabled = intent_config.get("enabled", False)
            self._check_model_intent = intent_config.get("check_model_intent", True)
            self._check_app_intent = intent_config.get("check_app_intent", True)
            self._intent_threshold = intent_config.get("threshold", 0.3)
        else:
            self._intent_enabled = False
            self._check_model_intent = False
            self._check_app_intent = False
            self._intent_threshold = 0.3

        self._intent_svc = None
        if self._intent_enabled:
            if not session_factory:
                logger.error("malicious_prompt intent conformance is enabled but no session factory was provided")
                self._load_failures["intent_conformance"] = FailureCode.CONSTRUCT_FAILED
            else:
                try:
                    from app.services.intent_conformance_service import IntentConformanceService

                    self._intent_svc = IntentConformanceService(
                        session_factory(),
                        model_intent_threshold=self._intent_threshold,
                        app_intent_threshold=self._intent_threshold,
                    )
                except Exception:
                    logger.warning("Failed to initialize IntentConformanceService", exc_info=True)
                    self._load_failures["intent_conformance"] = FailureCode.CONSTRUCT_FAILED

    @property
    def name(self) -> str:
        return "malicious_prompt"

    def scan(self, text: str, **kwargs: Any) -> DetectorResult:
        """Evaluate text through the 4-step detection pipeline.

        Returns as soon as any step produces a definitive result (short-circuit).
        Steps 1-2 (custom lists) are O(n) string matching — fast.
        Step 3 (ML model) is the expensive inference call.
        Step 4 (intent conformance) uses sentence-transformer similarity.
        """
        analyzer_responses: list[dict[str, Any]] = []
        components: dict[str, ComponentStatus] = {
            name: ComponentStatus(status=DetectorStatus.FAILED, failure_code=code)
            for name, code in self._load_failures.items()
        }

        def _detected(reason_components: dict[str, ComponentStatus]) -> DetectorResult:
            """Build a positive result.

            A detection stands on its own: it is real regardless of what
            happens to the request next. When a component also failed the
            finding is *incomplete* rather than untrustworthy, so it is kept
            and marked ``degraded``. Discarding it would delete a true positive
            and report "nothing found", which is the defect this work closes.
            """
            failed = [c for c in reason_components.values() if c.status is DetectorStatus.FAILED]
            action = "blocked" if self.can_block else "reported"
            return DetectorResult(
                detected=True,
                degraded=bool(failed),
                data={"action": action, "analyzer_responses": analyzer_responses},
                components=reason_components,
            )

        def _mark_remaining_skipped(after: str) -> None:
            """Record deliberate short-circuits so they are not read as failures.

            Later components are *overwritten*, not defaulted. A construction
            failure preloaded for a stage the override then prevented from
            running is not a degradation — that stage was never going to
            contribute. Using setdefault left it FAILED, which made a benign
            override return status=OK and degraded=False while its own
            component payload said a component had failed: a response
            contradicting itself.

            Failures from stages that actually ran before the override are
            untouched, because those did matter.
            """
            order = ["custom_malicious", "custom_benign", "generic_injection", "intent_conformance"]
            for later in order[order.index(after) + 1 :]:
                components[later] = ComponentStatus(
                    status=DetectorStatus.SKIPPED, skip_reason=SkipReason.SHORT_CIRCUITED
                )

        # 1. Custom malicious list — override to detected
        if self._custom_malicious_enabled and self._prompt_list_svc:
            try:
                matched = self._prompt_list_svc.check_match(text, "malicious")
                components["custom_malicious"] = ComponentStatus()
            except PromptListConfigError:
                # Configuration that cannot be enforced as written, not an
                # operational failure. The distinction matters to whoever has to
                # fix it: retrying will never help, the row must be corrected.
                logger.error("Custom malicious list has unenforceable configuration", exc_info=True)
                components["custom_malicious"] = ComponentStatus(
                    status=DetectorStatus.FAILED, failure_code=FailureCode.CONFIG_INVALID
                )
                matched = False
            except Exception:
                logger.warning("Custom malicious list check failed", exc_info=True)
                components["custom_malicious"] = ComponentStatus(
                    status=DetectorStatus.FAILED, failure_code=FailureCode.SCAN_FAILED
                )
                matched = False
            if matched:
                analyzer_responses.append({"analyzer": "CustomMaliciousList", "confidence": 1.0})
                _mark_remaining_skipped("custom_malicious")
                return _detected(components)

        # 2. Custom benign list — override to not detected
        if self._custom_benign_enabled and self._prompt_list_svc:
            try:
                matched = self._prompt_list_svc.check_match(text, "benign")
                components["custom_benign"] = ComponentStatus()
            except PromptListConfigError:
                # Configuration that cannot be enforced as written, not an
                # operational failure. The distinction matters to whoever has to
                # fix it: retrying will never help, the row must be corrected.
                logger.error("Custom benign list has unenforceable configuration", exc_info=True)
                components["custom_benign"] = ComponentStatus(
                    status=DetectorStatus.FAILED, failure_code=FailureCode.CONFIG_INVALID
                )
                matched = False
            except Exception:
                logger.warning("Custom benign list check failed", exc_info=True)
                components["custom_benign"] = ComponentStatus(
                    status=DetectorStatus.FAILED, failure_code=FailureCode.SCAN_FAILED
                )
                matched = False
            if matched:
                # A benign match is a deliberate policy decision that the
                # remaining stages need not run, so it is an OK negative rather
                # than a degraded one — the operator asked for exactly this.
                #
                # But it only excuses stages that come *after* it. The malicious
                # list runs first and short-circuits to a block; if that check
                # failed we do not know whether it would have matched, and a
                # benign override cannot stand in for an answer we never got.
                _mark_remaining_skipped("custom_benign")
                earlier_failed = [
                    c
                    for name, c in components.items()
                    if name in ("custom_lists", "custom_malicious") and c.status is DetectorStatus.FAILED
                ]
                if earlier_failed:
                    return DetectorResult(
                        detected=False,
                        status=DetectorStatus.FAILED,
                        failure_code=earlier_failed[0].failure_code,
                        components=components,
                    )
                return DetectorResult(detected=False, components=components)

        # 3. Generic injection ML model — direct HF pipeline only.
        if self._generic_injection_enabled and self._pipeline:
            try:
                results = self._pipeline(text)
                injection_score = 0.0
                for r in results:
                    if r["label"] == self._injection_label:
                        injection_score = r["score"]
                        break
                components["generic_injection"] = ComponentStatus()
            except Exception:
                # Covers both inference and malformed output: indexing r["label"]
                # or r["score"] on an unexpected response shape lands here rather
                # than bubbling to the engine-wide catch, so the failure is
                # attributed to this sub-detector.
                logger.warning("Generic injection classifier failed", exc_info=True)
                components["generic_injection"] = ComponentStatus(
                    status=DetectorStatus.FAILED, failure_code=FailureCode.OUTPUT_INVALID
                )
                injection_score = 0.0
            else:
                is_valid = injection_score < self._threshold
                analyzer_name = self.config.get("model", "direct-hf-pipeline")
                analyzer_responses.append(
                    {
                        "analyzer": analyzer_name,
                        "confidence": max(0.0, min(1.0, injection_score)),
                    }
                )
                if not is_valid:
                    _mark_remaining_skipped("generic_injection")
                    return _detected(components)

        # 4. Intent conformance
        if self._intent_enabled and self._intent_svc:
            # The service records why it cannot run rather than raising into
            # this detector's constructor and vanishing. An unavailable service
            # means the configured check never happened, which is a failure,
            # not a pass.
            if not self._intent_svc.available:
                components["intent_conformance"] = ComponentStatus(
                    status=DetectorStatus.FAILED,
                    failure_code=FailureCode(self._intent_svc.failure_code or "construct_failed"),
                )
            else:
                try:
                    if self._check_model_intent:
                        violation = self._intent_svc.check_model_intent(text)
                        if violation:
                            analyzer_responses.append(violation)
                    if self._check_app_intent:
                        messages = kwargs.get("messages", [])
                        app_intent = None
                        for msg in messages:
                            if isinstance(msg, dict) and msg.get("role") == "system":
                                app_intent = msg.get("content", "")
                                break
                        if app_intent:
                            violation = self._intent_svc.check_app_intent(text, app_intent)
                            if violation:
                                analyzer_responses.append(violation)
                    components["intent_conformance"] = ComponentStatus()
                except Exception:
                    logger.warning("Intent conformance check failed", exc_info=True)
                    components["intent_conformance"] = ComponentStatus(
                        status=DetectorStatus.FAILED, failure_code=FailureCode.SCAN_FAILED
                    )

        # Check if intent conformance found violations (steps 1-3 didn't trigger)
        if analyzer_responses and any("IntentConformance" in r.get("analyzer", "") for r in analyzer_responses):
            return _detected(components)

        # Nothing detected. Any sub-detector that failed is now load-bearing:
        # it is precisely the one that might have caught something, and there
        # is no positive verdict to make its absence immaterial. Reporting
        # "clean" here is the fail-open P0-2 describes.
        failed = [c for c in components.values() if c.status is DetectorStatus.FAILED]
        if failed:
            return DetectorResult(
                detected=False,
                status=DetectorStatus.FAILED,
                failure_code=failed[0].failure_code,
                components=components,
            )

        # Not detected
        return DetectorResult(
            detected=False,
            data={"action": "reported", "analyzer_responses": analyzer_responses} if analyzer_responses else None,
            components=components,
        )
