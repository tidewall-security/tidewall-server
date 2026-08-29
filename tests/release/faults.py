"""Produce the failure STATE a case declares.

Some cases declare a state no input can reach: an analyzer that never built,
an analyzer that raises. Shaping the planted value differently cannot produce
either, so a driver that only varies input leaves those cases observing a
success state while declaring a failure one.

Injecting the fault is what makes the case executable. The alternative -- and
what was there before -- is a case that never runs its declared state and
reports a pass.

Each injector is REVERSIBLE and asserts it changed something, because an
injector that silently did nothing produces the success state and looks
exactly like a case that was driven correctly.
"""

from __future__ import annotations

from contextlib import contextmanager


class FaultNotInjected(Exception):
    """The injector did not change the detector's state."""


class NoInjectorForState(Exception):
    """A declared failure state with no way to produce it."""


def _raises(*_args, **_kwargs):
    raise RuntimeError("injected analyzer failure")


@contextmanager
def injected(detector, sub_path: str):
    """Put `detector` into the state named by `sub_path`, then restore it."""
    if sub_path == "analyzer_unavailable":
        original = detector._analyzer
        if original is None:
            raise FaultNotInjected(
                "the analyzer was already None, so this run does not demonstrate "
                "the unavailable state being produced"
            )
        detector._analyzer = None
        try:
            yield
        finally:
            detector._analyzer = original
        return

    if sub_path == "analysis_failure":
        analyzer = detector._analyzer
        if analyzer is None:
            raise FaultNotInjected(
                "there is no analyzer to make raise; the case would reach " "analyzer_unavailable instead"
            )
        original = analyzer.analyze
        analyzer.analyze = _raises
        if analyzer.analyze is original:
            raise FaultNotInjected("the analyze method was not replaced")
        try:
            yield
        finally:
            analyzer.analyze = original
        return

    raise NoInjectorForState(f"no injector for declared state {sub_path!r}")


#: States that require injection rather than input shaping.
INJECTED_STATES: frozenset[str] = frozenset({"analyzer_unavailable", "analysis_failure"})
