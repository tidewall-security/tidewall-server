"""Topic + toxicity detector — combines two independent HF pipelines.

- **BanTopics** — ``MoritzLaurer/roberta-base-zeroshot-v2.0-c`` as a
  ``zero-shot-classification`` pipeline. The configured ``topics`` list
  is passed in as candidate labels; if the top label's score exceeds
  ``threshold``, we flag the topic.

- **Toxicity** — ``unitary/unbiased-toxic-roberta`` as a multi-label
  ``text-classification`` pipeline. It emits 16 labels, of which only seven
  describe harm (toxicity, severe_toxicity, obscene, identity_attack, insult,
  threat, sexual_explicit). The remaining nine are identity-PRESENCE
  attributes that score highly when a group is merely mentioned, so the score
  is the max over the harm labels only — see ``_TOXICITY_HARM_LABELS``. This
  docstring previously listed the Jigsaw label set, which this model does not
  emit, and the code took the max over all 16.

Both sub-detectors are independent — either may be configured without
the other.
"""

from __future__ import annotations

import logging
from typing import Any

from app.model_registry import TOPICS as _TOPICS_REF
from app.model_registry import TOXICITY as _TOXICITY_REF
from app.services.safe_logging import describe

from .base import BaseDetector, ComponentStatus, DetectorResult, DetectorStatus, FailureCode, SkipReason

logger = logging.getLogger(__name__)


_DEFAULT_TOPICS_MODEL = _TOPICS_REF.repo_id
_DEFAULT_TOXICITY_MODEL = _TOXICITY_REF.repo_id

# `unitary/unbiased-toxic-roberta` emits 16 labels, and only these seven
# describe harm. The other nine are identity-PRESENCE attributes — male,
# female, homosexual_gay_or_lesbian, christian, jewish, muslim, black, white,
# psychiatric_or_mental_illness — which the model scores highly when a group is
# merely *mentioned*.
#
# Taking the maximum across all 16, which is what this did, therefore reported
# "toxicity" for saying someone is Muslim, or Black, or has a mental illness.
# In a guard that flags user content, that is discriminatory behaviour rather
# than a tuning problem, so the harm axes are named explicitly and anything
# outside this set is ignored.
# Two vocabularies appear in practice and both are accepted: the original
# Jigsaw names (toxic, severe_toxic, identity_hate), which this module's
# docstring was written against, and the `unbiased-toxic-roberta` names
# (toxicity, severe_toxicity, identity_attack), which the configured model
# actually emits. The two had drifted apart unnoticed.
_TOXICITY_HARM_LABELS = frozenset(
    {
        # unitary/unbiased-toxic-roberta
        "toxicity",
        "severe_toxicity",
        "identity_attack",
        "sexual_explicit",
        # unitary/toxic-bert (Jigsaw)
        "toxic",
        "severe_toxic",
        "identity_hate",
        # common to both
        "obscene",
        "insult",
        "threat",
    }
)


class TopicDetector(BaseDetector):
    """Detects banned topics + general toxicity via two HF pipelines."""

    def __init__(self, config: dict[str, Any]) -> None:
        super().__init__(config)
        self._topics_pipeline = None
        self._toxicity_pipeline = None
        self._topics: list[str] = config.get("topics", []) or []
        self._topic_threshold = config.get("threshold", 0.75)
        self._toxicity_threshold = config.get("toxicity_threshold", 0.5)
        self._device = config.get("device", "cpu")
        # Per-sub-detector load failures. Recorded individually rather than
        # marking the whole detector unavailable, because one pipeline can load
        # while the other does not — and a sub-detector the operator configured
        # but which never loaded must still be reported on every scan, not
        # silently absent.
        self._load_failures: dict[str, FailureCode] = {}

        try:
            from transformers import pipeline
        except ImportError:
            logger.warning("transformers not installed — TopicDetector unavailable")
            self.mark_unavailable(FailureCode.DEPENDENCY_MISSING)
            return

        if self._topics:
            topics_model = config.get("topics_model") or _DEFAULT_TOPICS_MODEL
            try:
                self._topics_pipeline = pipeline(
                    "zero-shot-classification",
                    model=topics_model,
                    device=self._device,
                    revision=_TOPICS_REF.revision_for(topics_model),
                )
                logger.info("Loaded topics classifier: %s", topics_model)
            except Exception:
                logger.warning("Failed to load topics model %s", topics_model, exc_info=True)
                self._load_failures["topics"] = FailureCode.MODEL_LOAD_FAILED

        toxicity_model = config.get("toxicity_model") or _DEFAULT_TOXICITY_MODEL
        try:
            self._toxicity_pipeline = pipeline(
                "text-classification",
                model=toxicity_model,
                revision=_TOXICITY_REF.revision_for(toxicity_model),
                top_k=None,  # return all labels with scores (multi-label)
                truncation=True,
                max_length=512,
                device=self._device,
            )
            logger.info("Loaded toxicity classifier: %s", toxicity_model)
        except Exception:
            logger.warning("Failed to load toxicity model %s", toxicity_model, exc_info=True)
            self._load_failures["toxicity"] = FailureCode.MODEL_LOAD_FAILED

        if self._load_failures and self._topics_pipeline is None and self._toxicity_pipeline is None:
            self.mark_unavailable(FailureCode.MODEL_LOAD_FAILED)

    @property
    def name(self) -> str:
        return "topic"

    def scan(self, text: str, **kwargs: Any) -> DetectorResult:
        # release:component topic/both_pipelines_unavailable -- neither loaded; speaks to neither property
        if self._topics_pipeline is None and self._toxicity_pipeline is None:
            return self.unavailable_result()

        topics_found: list[dict[str, Any]] = []
        detected = False
        # This detector is a composite (toxicity + banned topics), so one
        # sub-detector failing does not automatically invalidate the verdict.
        # See the aggregation rule below.
        components: dict[str, ComponentStatus] = {}

        # Toxicity: max across the HARM labels only — see _TOXICITY_HARM_LABELS.
        # release:component topic/toxicity_pipeline -- independent of topics; either can run alone
        if self._toxicity_pipeline is not None:
            try:
                results = self._toxicity_pipeline(text)
                # top_k=None returns [[{label, score}, ...]] for a single input.
                scores = (
                    results[0] if isinstance(results, list) and results and isinstance(results[0], list) else results
                )
                harm_scores = [
                    float(r["score"]) for r in scores if str(r.get("label", "")).lower() in _TOXICITY_HARM_LABELS
                ]
                if not harm_scores:
                    # The configured model publishes none of the expected harm
                    # labels, so this cannot produce a toxicity verdict at all.
                    # Reporting 0.0 would be a confident "not toxic" from a
                    # check that never ran.
                    logger.error(
                        "Toxicity model emitted no recognised harm labels (got %s); " "it cannot be scored against %s",
                        sorted({str(r.get("label", "")) for r in scores}),
                        sorted(_TOXICITY_HARM_LABELS),
                    )
                    raise ValueError("no recognised toxicity harm labels")
                tox_score = max(harm_scores, default=0.0)
                if tox_score >= self._toxicity_threshold:
                    detected = True
                    topics_found.append({"topic": "toxicity", "confidence": max(0.0, min(1.0, tox_score))})
                components["toxicity"] = ComponentStatus()
            except Exception as exc:
                logger.warning("Toxicity classifier inference failed: %s", describe(exc))
                components["toxicity"] = ComponentStatus(
                    status=DetectorStatus.FAILED, failure_code=FailureCode.SCAN_FAILED
                )
        elif "toxicity" in self._load_failures:
            components["toxicity"] = ComponentStatus(
                status=DetectorStatus.FAILED, failure_code=self._load_failures["toxicity"]
            )
        else:
            components["toxicity"] = ComponentStatus(status=DetectorStatus.SKIPPED, skip_reason=SkipReason.NOT_ENABLED)

        # Banned topics: zero-shot classification against the candidate list.
        # release:component topic/topics_pipeline -- zero-shot over the configured topic list
        if self._topics_pipeline is not None and self._topics:
            try:
                zsl = self._topics_pipeline(text, candidate_labels=self._topics, multi_label=True)
                # Returns {labels: [...], scores: [...]} sorted by score desc.
                top_label = zsl["labels"][0] if zsl.get("labels") else None
                top_score = float(zsl["scores"][0]) if zsl.get("scores") else 0.0
                if top_label and top_score >= self._topic_threshold:
                    detected = True
                    topics_found.append({"topic": top_label, "confidence": max(0.0, min(1.0, top_score))})
                components["topics"] = ComponentStatus()
            except Exception as exc:
                logger.warning("Topics classifier inference failed: %s", describe(exc))
                components["topics"] = ComponentStatus(
                    status=DetectorStatus.FAILED, failure_code=FailureCode.SCAN_FAILED
                )
        elif "topics" in self._load_failures:
            components["topics"] = ComponentStatus(
                status=DetectorStatus.FAILED, failure_code=self._load_failures["topics"]
            )
        else:
            components["topics"] = ComponentStatus(status=DetectorStatus.SKIPPED, skip_reason=SkipReason.NOT_ENABLED)

        failed = [c for c in components.values() if c.status is DetectorStatus.FAILED]

        # Composite aggregation. A failed sub-detector is absorbed only when the
        # composite verdict is *provably* unchanged by it: another sub-detector
        # has already produced detected=True, and detected cannot become more
        # true. The payload may lose an entry, but the verdict — and so the
        # enforcement decision — is invariant.
        #
        # When nothing was detected the opposite holds: the sub-detector that
        # failed is precisely the one that might have found something, so
        # reporting "clean" would be the fail-open this exists to close.
        if failed and not detected:
            return DetectorResult(
                detected=False,
                status=DetectorStatus.FAILED,
                failure_code=failed[0].failure_code,
                components=components,
            )

        if not detected:
            return DetectorResult(detected=False, components=components)

        # Aggregation does not depend on the action. A detection is real
        # regardless of what happens next, so it is kept and marked `degraded`
        # when a sibling failed; the caller gets both the finding and the fact
        # that the check was incomplete. Earlier revisions tried to decide this
        # from can_block/can_redact and were wrong in both directions — once
        # `degraded` exists there is nothing left for the action to decide.
        # A detection stands on its own. If a sub-detector also failed the
        # finding is *incomplete*, not *untrustworthy* — discarding it would
        # throw away a real positive the system actually obtained and report
        # "nothing found", which is the very defect this work exists to close.
        action = "blocked" if self.can_block else "reported"
        return DetectorResult(
            detected=True,
            degraded=bool(failed),
            data={
                "action": action,
                "topics": topics_found,
            },
            components=components,
        )
