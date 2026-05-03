"""Tests for CompetitorsDetector — Presidio-based competitor matching."""

from unittest.mock import MagicMock

from app.detectors.competitors import CompetitorsDetector


def _make(competitors=None, action="report"):
    return CompetitorsDetector(
        {
            "enabled": True,
            "action": action,
            "competitors": competitors or ["Acme", "Globex"],
        }
    )


def _stub_analyzer(d, results):
    """Replace the detector's _analyzer with a stub returning fixed results."""
    fake = MagicMock()
    fake.analyze = MagicMock(return_value=results)
    d._analyzer = fake


def _ner_result(entity_type, start, end):
    """Build a fake RecognizerResult-shaped object with start/end/entity_type."""
    r = MagicMock()
    r.entity_type = entity_type
    r.start = start
    r.end = end
    return r


def test_no_competitors_configured_returns_undetected():
    d = CompetitorsDetector({"enabled": True, "action": "report", "competitors": []})
    assert d._analyzer is None
    r = d.scan("Acme is great")
    assert r.detected is False
    assert r.data is None


def test_presidio_load_failure_returns_undetected(monkeypatch):
    """If presidio-analyzer is not installed, detector is disabled gracefully."""
    import sys

    # Hide presidio_analyzer from imports for this test
    saved = sys.modules.get("presidio_analyzer")
    sys.modules["presidio_analyzer"] = None  # makes import raise ImportError
    try:
        d = CompetitorsDetector({"enabled": True, "action": "report", "competitors": ["Acme"]})
    finally:
        if saved is not None:
            sys.modules["presidio_analyzer"] = saved
        else:
            sys.modules.pop("presidio_analyzer", None)
    assert d._analyzer is None
    r = d.scan("Acme is great")
    assert r.detected is False
    assert r.data is None


def test_competitor_pattern_match_is_detected():
    d = _make(competitors=["Acme", "Globex"])
    text = "We should switch from Acme to a better vendor"
    # Presidio matches "Acme" via the COMPETITOR recognizer (deny-list).
    _stub_analyzer(d, [_ner_result("COMPETITOR", 22, 26)])
    r = d.scan(text)
    assert r.detected is True
    assert r.data["entities"] == ["Acme"]
    assert r.data["action"] == "reported"


def test_organization_span_matching_competitor_is_detected():
    d = _make(competitors=["Globex"])
    text = "Globex announced a new product"
    # NER spotted Globex as an ORGANIZATION; its span text matches a competitor.
    _stub_analyzer(d, [_ner_result("ORGANIZATION", 0, 6)])
    r = d.scan(text)
    assert r.detected is True
    assert r.data["entities"] == ["Globex"]


def test_organization_span_not_matching_competitor_is_ignored():
    """An ORGANIZATION span that isn't on the competitor list shouldn't fire."""
    d = _make(competitors=["Globex"])
    text = "Microsoft announced a new product"
    _stub_analyzer(d, [_ner_result("ORGANIZATION", 0, 9)])  # "Microsoft"
    r = d.scan(text)
    assert r.detected is False
    assert r.data is None


def test_duplicate_matches_are_deduped_in_order():
    d = _make(competitors=["Acme"])
    text = "Acme is bad. Acme is worse. Acme is the worst."
    _stub_analyzer(
        d,
        [
            _ner_result("COMPETITOR", 0, 4),
            _ner_result("COMPETITOR", 13, 17),
            _ner_result("COMPETITOR", 28, 32),
        ],
    )
    r = d.scan(text)
    assert r.detected is True
    assert r.data["entities"] == ["Acme"]  # de-duplicated


def test_inference_exception_returns_undetected():
    d = _make()
    fake = MagicMock()
    fake.analyze = MagicMock(side_effect=RuntimeError("simulated analyze failure"))
    d._analyzer = fake
    r = d.scan("Acme")
    assert r.detected is False
    assert r.data is None


def test_blocking_action_when_can_block():
    d = _make(competitors=["Acme"], action="block")
    _stub_analyzer(d, [_ner_result("COMPETITOR", 0, 4)])
    r = d.scan("Acme")
    assert r.detected is True
    assert r.data["action"] == "blocked"


def test_no_matches_returns_undetected():
    d = _make(competitors=["Acme"])
    _stub_analyzer(d, [])
    r = d.scan("just some text")
    assert r.detected is False
    assert r.data is None


def test_organization_match_is_case_insensitive():
    """Lowercase ACME in input should still match competitor 'Acme' (case-insensitive)."""
    d = _make(competitors=["Acme"])
    text = "acme is here"
    _stub_analyzer(d, [_ner_result("ORGANIZATION", 0, 4)])
    r = d.scan(text)
    assert r.detected is True
    assert r.data["entities"] == ["acme"]
