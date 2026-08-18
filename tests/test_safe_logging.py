"""Scan-time exceptions must not put the prompt in the operator's log.

`exc_info=True` writes a traceback, and a traceback carries the arguments of
every frame in it. At scan time those arguments are the text being scanned, so
a tokenizer or model raising on a malformed input writes that input to the log
— a copy of the content the product exists to contain, in a place nobody treats
as a content store, by a path that only opens once something has gone wrong.

Third-party libraries make it worse: their messages routinely quote the
offending value, so the message alone can carry it with no traceback at all.
"""

from __future__ import annotations

import logging

import pytest

from app.services.safe_logging import describe

CANARY = "CANARY-log-7c1f-secret"


def test_describe_drops_the_message():
    """Distinguishing a safe library message from one quoting the input is not
    a judgement this can make per exception."""
    assert CANARY not in describe(ValueError(f"bad token in {CANARY}"))
    assert describe(ValueError("x")) == "ValueError"


def test_a_detector_raising_with_the_prompt_in_its_message_does_not_log_it(caplog):
    """The real path: a detector blows up on the text it was given."""
    from app.detectors.base import BaseDetector, DetectorResult
    from app.scanner_engine import ScannerEngine

    class _Exploding(BaseDetector):
        action = "report"

        @property
        def name(self) -> str:
            return "exploding"

        def scan(self, text: str, **kwargs) -> DetectorResult:
            raise RuntimeError(f"tokenizer failed on input: {text}")

    engine = ScannerEngine.__new__(ScannerEngine)
    engine._detectors = [("exploding", _Exploding({"enabled": True}))]
    engine._construction_failures = []
    engine._policy = None
    engine._session_factory = None

    with caplog.at_level(logging.DEBUG):
        try:
            engine.scan(f"my secret is {CANARY}")
        except Exception:
            pass

    assert CANARY not in caplog.text, "the scanned text reached the log through the exception"


@pytest.mark.parametrize(
    "module,line_fragment",
    [
        ("app/detectors/code.py", "Code classifier inference failed"),
        ("app/detectors/language.py", "Language classifier inference failed"),
        ("app/detectors/topic.py", "Toxicity classifier inference failed"),
        ("app/detectors/competitors.py", "Competitors analyzer inference failed"),
        ("app/scanner_engine.py", "raised during scan"),
    ],
)
def test_scan_time_sites_do_not_use_exc_info(module, line_fragment):
    """A regression here is one word, so assert the word.

    Load-time failures deliberately keep exc_info: those exceptions carry a
    model path and no request content, and the traceback is the most useful
    thing in the log when a model will not load.
    """
    import pathlib

    for line in pathlib.Path(module).read_text().split("\n"):
        if line_fragment in line:
            assert "exc_info" not in line, f"{module}: {line.strip()}"


@pytest.mark.parametrize(
    "module,fragment",
    [
        ("app/routes/guard.py", "Access rule evaluation failed"),
        ("app/routes/guard.py", "econstruct"),
        ("app/detectors/pii.py", "Presidio analysis failed"),
        ("app/detectors/malicious_entity.py", "ML URL classifier failed"),
        ("app/detectors/malicious_prompt.py", "list check failed"),
        ("app/detectors/malicious_prompt.py", "Intent conformance check failed"),
    ],
)
def test_no_scan_path_site_retains_a_traceback(module, fragment):
    """The first pass converted seven sites and I called it complete.

    It missed ten, including PII and malicious_prompt — the two primary
    content scanners — where the exception is raised inside scan(text) and the
    library message routinely quotes the offending value.
    """
    import pathlib

    for line in pathlib.Path(module).read_text().split("\n"):
        if fragment in line and "logger." in line:
            assert "exc_info" not in line, f"{module}: {line.strip()}"


def test_construction_time_sites_deliberately_keep_their_traceback():
    """Not everything should be stripped.

    A model that will not load raises with a path and no request content, and
    the traceback is the most useful thing in the log. Removing it there would
    be cargo-culting the rule rather than applying it.
    """
    import pathlib

    source = pathlib.Path("app/detectors/pii.py").read_text()
    load_line = next(ln for ln in source.split("\n") if "Failed to initialize Presidio" in ln)

    assert "exc_info=True" in load_line
