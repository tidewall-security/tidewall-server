"""Tests for ScannerEngine with dict-based construction."""


def test_engine_from_detectors_dict():
    from app.scanner_engine import ScannerEngine

    detectors = {"emoji": {"enabled": True, "action": "report"}}
    engine = ScannerEngine.from_detectors(detectors, report_only=False)
    assert engine is not None


def test_engine_from_detectors_dict_empty():
    from app.scanner_engine import ScannerEngine

    engine = ScannerEngine.from_detectors({}, report_only=False)
    assert engine is not None


def test_engine_scan_with_from_detectors():
    from app.scanner_engine import ScannerEngine

    detectors = {"emoji": {"enabled": True, "action": "report"}}
    engine = ScannerEngine.from_detectors(detectors, report_only=False)
    result = engine.scan("Hello world", "input", "vault-id", None)
    assert result.blocked is False
