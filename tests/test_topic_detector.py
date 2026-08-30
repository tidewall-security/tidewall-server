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


def test_detection_survives_a_failed_sibling_and_is_marked_degraded():
    d = _make(topics=["violence"], threshold=0.5, toxicity_threshold=0.5)

    def _explode(text):
        raise RuntimeError("simulated toxicity failure")

    d._toxicity_pipeline = _explode
    d._topics_pipeline = lambda text, candidate_labels, multi_label: {
        "labels": ["violence"],
        "scores": [0.9],
    }
    from app.detectors.base import DetectorStatus

    r = d.scan("text")
    # Toxicity blew up but topics found something. The detection is real and is
    # kept; it is also incomplete, and says so. Discarding it would delete a
    # true positive and report "nothing found" — the fail-open exactly.
    assert r.detected is True
    assert r.degraded is True
    assert r.data["topics"] == [{"topic": "violence", "confidence": 0.9}]
    assert r.components["toxicity"].status is DetectorStatus.FAILED


def test_detection_survives_a_failed_topics_pipeline_and_is_marked_degraded():
    d = _make(topics=["violence"], threshold=0.5, toxicity_threshold=0.5)
    d._toxicity_pipeline = lambda text: [[{"label": "toxic", "score": 0.9}]]

    def _explode(text, candidate_labels, multi_label):
        raise RuntimeError("simulated topics failure")

    d._topics_pipeline = _explode
    from app.detectors.base import DetectorStatus

    r = d.scan("text")
    assert r.detected is True
    assert r.degraded is True
    assert r.data["topics"] == [{"topic": "toxicity", "confidence": 0.9}]
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


def test_no_detection_plus_a_failure_is_still_failed():
    """Without a detection there is nothing to stand on.

    The sub-detector that failed is precisely the one that might have found
    something, and there is no positive result to make its absence immaterial.
    """
    from app.detectors.base import DetectorStatus

    d = _make(topics=["violence"], threshold=0.5, toxicity_threshold=0.5)
    d._toxicity_pipeline = lambda text: [[{"label": "toxic", "score": 0.1}]]

    def _explode(text, candidate_labels, multi_label):
        raise RuntimeError("simulated topics failure")

    d._topics_pipeline = _explode

    r = d.scan("ordinary text")

    assert r.detected is False
    assert r.status is DetectorStatus.FAILED


def test_identity_labels_are_not_scored_as_toxicity():
    """The fairness bug: identity mentions were reported as toxic.

    unitary/unbiased-toxic-roberta emits 16 labels, nine of which are
    identity-PRESENCE attributes that score highly when a group is merely
    mentioned. Taking the max across all of them meant "my colleague is
    Muslim" scored 0.97 on the `muslim` output and was reported as toxicity.
    """
    d = _make(toxicity_threshold=0.5)
    d._topics_pipeline = None
    d._topics = []
    # A benign sentence: high identity signal, no harm signal.
    d._toxicity_pipeline = lambda text: [
        [
            {"label": "toxicity", "score": 0.02},
            {"label": "severe_toxicity", "score": 0.00},
            {"label": "obscene", "score": 0.01},
            {"label": "identity_attack", "score": 0.03},
            {"label": "insult", "score": 0.01},
            {"label": "threat", "score": 0.00},
            {"label": "sexual_explicit", "score": 0.00},
            {"label": "muslim", "score": 0.97},
            {"label": "black", "score": 0.88},
            {"label": "female", "score": 0.71},
        ]
    ]

    r = d.scan("My colleague is Muslim and she is Black.")

    assert r.detected is False, "identity mentions must not be scored as toxicity"


def test_genuine_harm_is_still_detected():
    """The narrowing must not stop real toxicity being caught."""
    d = _make(toxicity_threshold=0.5)
    d._topics_pipeline = None
    d._topics = []
    d._toxicity_pipeline = lambda text: [
        [
            {"label": "toxicity", "score": 0.94},
            {"label": "insult", "score": 0.91},
            {"label": "muslim", "score": 0.02},
        ]
    ]

    r = d.scan("something genuinely abusive")

    assert r.detected is True
    assert r.data["topics"][0]["topic"] == "toxicity"
    assert abs(r.data["topics"][0]["confidence"] - 0.94) < 1e-6


def test_unrecognised_label_set_fails_rather_than_reporting_clean():
    """A model with no harm labels cannot produce a verdict."""
    from app.detectors.base import DetectorStatus

    d = _make(toxicity_threshold=0.5)
    d._topics_pipeline = None
    d._topics = []
    d._toxicity_pipeline = lambda text: [[{"label": "LABEL_0", "score": 0.9}]]

    r = d.scan("anything")

    assert r.status is DetectorStatus.FAILED
