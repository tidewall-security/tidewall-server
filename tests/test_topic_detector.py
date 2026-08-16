"""Tests for TopicDetector — banned-topics zero-shot + toxicity classifiers."""

from unittest.mock import patch

# Prime transformers _LazyModule so patch("transformers.pipeline", ...) works.
import transformers as _transformers

_transformers.pipeline  # noqa: B018

from app.detectors.topic import TopicDetector  # noqa: E402  (priming order matters)


def _make(topics=None, threshold=0.75, toxicity_threshold=0.5, action="report"):
    return TopicDetector(
        {
            "enabled": True,
            "action": action,
            "topics": topics or [],
            "threshold": threshold,
            "toxicity_threshold": toxicity_threshold,
        }
    )


def test_both_pipelines_none_when_load_fails():
    """If both pipelines fail to load, scan() returns undetected."""

    def _bad(*args, **kwargs):
        raise RuntimeError("simulated load failure")

    with patch("transformers.pipeline", side_effect=_bad):
        d = TopicDetector({"enabled": True, "action": "report", "topics": ["violence"]})
    assert d._topics_pipeline is None
    assert d._toxicity_pipeline is None
    r = d.scan("anything")
    assert r.detected is False
    assert r.data is None


def test_toxicity_above_threshold_is_detected():
    d = _make(toxicity_threshold=0.5)
    # Stub: top_k=None returns [[{label, score}, ...]]
    d._toxicity_pipeline = lambda text: [
        [
            {"label": "toxic", "score": 0.9},
            {"label": "obscene", "score": 0.3},
        ]
    ]
    r = d.scan("offensive text")
    assert r.detected is True
    assert r.data["topics"] == [{"topic": "toxicity", "confidence": 0.9}]
    assert r.data["action"] == "reported"


def test_toxicity_below_threshold_is_not_detected():
    d = _make(toxicity_threshold=0.9)
    d._toxicity_pipeline = lambda text: [[{"label": "toxic", "score": 0.4}]]
    r = d.scan("benign text")
    assert r.detected is False
    assert r.data is None


def test_banned_topic_above_threshold_is_detected():
    d = _make(topics=["violence", "drugs"], threshold=0.7)
    d._topics_pipeline = lambda text, candidate_labels, multi_label: {
        "labels": ["violence", "drugs"],
        "scores": [0.85, 0.2],
    }
    r = d.scan("text about hurting people")
    assert r.detected is True
    assert r.data["topics"] == [{"topic": "violence", "confidence": 0.85}]


def test_banned_topic_below_threshold_is_not_detected():
    d = _make(topics=["violence"], threshold=0.9)
    d._topics_pipeline = lambda text, candidate_labels, multi_label: {
        "labels": ["violence"],
        "scores": [0.5],
    }
    r = d.scan("text")
    assert r.detected is False
    assert r.data is None


def test_both_signals_detected_combine_in_topics_list():
    d = _make(topics=["violence"], threshold=0.5, toxicity_threshold=0.5)
    d._toxicity_pipeline = lambda text: [[{"label": "toxic", "score": 0.7}]]
    d._topics_pipeline = lambda text, candidate_labels, multi_label: {
        "labels": ["violence"],
        "scores": [0.8],
    }
    r = d.scan("violent toxic text")
    assert r.detected is True
    # Toxicity is appended first, then the banned topic.
    assert {"topic": "toxicity", "confidence": 0.7} in r.data["topics"]
    assert {"topic": "violence", "confidence": 0.8} in r.data["topics"]
    assert len(r.data["topics"]) == 2


def test_inference_exception_in_toxicity_is_reported_not_absorbed():
    d = _make(topics=["violence"], threshold=0.5, toxicity_threshold=0.5)

    def _explode(text):
        raise RuntimeError("simulated toxicity failure")

    d._toxicity_pipeline = _explode
    d._topics_pipeline = lambda text, candidate_labels, multi_label: {
        "labels": ["violence"],
        "scores": [0.9],
    }
    r = d.scan("text")
    # Toxicity blew up. Under a report action the detection is not terminal —
    # the payload is what the operator sees, and it is now missing whatever
    # toxicity would have contributed — so the composite reports the failure
    # rather than presenting a partial result as complete.
    from app.detectors.base import DetectorStatus

    assert r.status is DetectorStatus.FAILED
    assert r.components["toxicity"].status is DetectorStatus.FAILED


def test_inference_exception_in_topics_is_reported_not_absorbed():
    d = _make(topics=["violence"], threshold=0.5, toxicity_threshold=0.5)
    d._toxicity_pipeline = lambda text: [[{"label": "toxic", "score": 0.9}]]

    def _explode(text, candidate_labels, multi_label):
        raise RuntimeError("simulated topics failure")

    d._topics_pipeline = _explode
    r = d.scan("text")
    from app.detectors.base import DetectorStatus

    assert r.status is DetectorStatus.FAILED
    assert r.components["topics"].status is DetectorStatus.FAILED


def test_blocking_action_when_can_block():
    d = _make(toxicity_threshold=0.5, action="block")
    d._toxicity_pipeline = lambda text: [[{"label": "toxic", "score": 0.9}]]
    r = d.scan("offensive")
    assert r.detected is True
    assert r.data["action"] == "blocked"


def test_no_topics_configured_skips_topics_pipeline():
    """If `topics` is empty, the topics pipeline is never loaded."""
    d = _make(topics=[])
    assert d._topics_pipeline is None
    # Toxicity still loads (it has no per-item config requirement).


def test_blocking_action_absorbs_a_failure_because_the_outcome_is_terminal():
    """Absorption is only sound when the request is already blocked.

    With action=block a positive detection ends the matter: whatever the failed
    sub-detector would have added cannot change what happens to the request.
    Under report the payload is the product, so a missing contribution matters.
    """
    from app.detectors.base import DetectorStatus

    d = _make(toxicity_threshold=0.5, action="block")
    d._toxicity_pipeline = lambda text: [[{"label": "toxic", "score": 0.9}]]

    def _explode(text, candidate_labels, multi_label):
        raise RuntimeError("simulated topics failure")

    d._topics_pipeline = _explode
    d._topics = ["violence"]

    r = d.scan("offensive")

    assert r.detected is True
    assert r.status is DetectorStatus.OK
    assert r.components["topics"].status is DetectorStatus.FAILED
