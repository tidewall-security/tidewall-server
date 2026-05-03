"""Tests for CodeDetector — programming-language classifier."""

from unittest.mock import patch

import transformers as _transformers

# transformers uses a _LazyModule with internal caching.  Accessing the
# `pipeline` attribute now primes that cache so that patch("transformers.pipeline")
# works correctly and doesn't leak a stale mock reference to other tests.
_transformers.pipeline  # noqa: B018

from app.detectors.code import CodeDetector  # noqa: E402  (priming order matters)


def _make(languages=None, threshold=0.5, action="report"):
    return CodeDetector(
        {
            "enabled": True,
            "action": action,
            "languages": languages or ["Python"],
            "threshold": threshold,
        }
    )


def test_pipeline_is_none_when_load_fails():
    """If transformers fails to load, scan() returns undetected without crashing."""
    # transformers uses a _LazyModule; patch the top-level attribute after the
    # module-level cache-primer above has primed it, so patch() both intercepts
    # the call and restores cleanly without leaking to other tests.
    with patch("transformers.pipeline", side_effect=RuntimeError("simulated model load failure")):
        d = CodeDetector({"enabled": True, "action": "report", "languages": ["Python"]})
    assert d._pipeline is None
    r = d.scan("def foo(): pass")
    assert r.detected is False
    assert r.data is None


def test_top_label_in_allow_list_above_threshold_is_detected():
    d = _make(languages=["Python"])
    # Stub pipeline to return a confident Python prediction
    d._pipeline = lambda text: [{"label": "Python", "score": 0.95}]
    r = d.scan("def fibonacci(n): pass")
    assert r.detected is True
    assert r.data == {"action": "reported", "language": "Python"}


def test_top_label_outside_allow_list_is_not_detected():
    d = _make(languages=["Python"])
    d._pipeline = lambda text: [{"label": "Markdown", "score": 0.95}]
    r = d.scan("# Heading\n\nSome text")
    assert r.detected is False
    assert r.data is None  # no language leakage on non-detection


def test_below_threshold_is_not_detected():
    d = _make(languages=["Python"], threshold=0.9)
    d._pipeline = lambda text: [{"label": "Python", "score": 0.5}]
    r = d.scan("def foo(): pass")
    assert r.detected is False
    assert r.data is None


def test_inference_exception_is_caught_and_returns_undetected():
    """If pipeline inference raises, scan() must not crash the request."""
    d = _make()

    def _explode(text):
        raise RuntimeError("simulated inference failure")

    d._pipeline = _explode
    r = d.scan("def foo(): pass")
    assert r.detected is False
    assert r.data is None


def test_blocking_action_when_can_block():
    d = _make(action="block")
    d._pipeline = lambda text: [{"label": "Python", "score": 0.95}]
    r = d.scan("def foo(): pass")
    assert r.detected is True
    assert r.data["action"] == "blocked"
