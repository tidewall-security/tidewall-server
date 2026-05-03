"""Tests for LanguageDetector — multilingual text classifier."""

from unittest.mock import patch

# Prime transformers _LazyModule so patch("transformers.pipeline", ...) works.
import transformers as _transformers

_transformers.pipeline  # noqa: B018  — touch lazy attribute to materialize it

from app.detectors.language import LanguageDetector  # noqa: E402  (priming order matters)


def _make(valid_languages=None, action="report"):
    return LanguageDetector(
        {
            "enabled": True,
            "action": action,
            "valid_languages": valid_languages or ["en"],
        }
    )


def test_pipeline_is_none_when_load_fails():
    """If transformers.pipeline raises, the detector is disabled gracefully."""

    def _bad(*args, **kwargs):
        raise RuntimeError("simulated model load failure")

    with patch("transformers.pipeline", side_effect=_bad):
        d = LanguageDetector({"enabled": True, "action": "report", "valid_languages": ["en"]})
    assert d._pipeline is None
    r = d.scan("hello")
    assert r.detected is False
    assert r.data is None


def test_predicted_in_allow_list_is_not_detected():
    d = _make(valid_languages=["en"])
    d._pipeline = lambda text: [{"label": "en", "score": 0.99}]
    r = d.scan("hello world")
    assert r.detected is False
    assert r.data is None


def test_predicted_outside_allow_list_is_detected():
    d = _make(valid_languages=["en"])
    d._pipeline = lambda text: [{"label": "de", "score": 0.95}]
    r = d.scan("Guten Tag")
    assert r.detected is True
    assert r.data["action"] == "reported"
    assert r.data["predicted"] == "de"
    assert r.data["languages"] == [{"language": "en", "confidence": 0.95}]


def test_inference_exception_is_caught_and_returns_undetected():
    d = _make()

    def _explode(text):
        raise RuntimeError("simulated inference failure")

    d._pipeline = _explode
    r = d.scan("hello")
    assert r.detected is False
    assert r.data is None


def test_blocking_action_when_can_block():
    d = _make(valid_languages=["en"], action="block")
    d._pipeline = lambda text: [{"label": "fr", "score": 0.9}]
    r = d.scan("Bonjour")
    assert r.detected is True
    assert r.data["action"] == "blocked"


def test_multiple_valid_languages_allow_any():
    d = _make(valid_languages=["en", "es", "fr"])
    d._pipeline = lambda text: [{"label": "es", "score": 0.85}]
    r = d.scan("Hola")
    assert r.detected is False
    assert r.data is None


def test_confidence_is_clamped_to_unit_interval():
    """Some HF models return scores slightly outside [0,1] due to rounding."""
    d = _make(valid_languages=["en"])
    # Score exactly 1.0 is valid, but the clamp guards weird models.
    d._pipeline = lambda text: [{"label": "de", "score": 1.5}]
    r = d.scan("Hallo")
    assert r.detected is True
    assert r.data["languages"][0]["confidence"] == 1.0
