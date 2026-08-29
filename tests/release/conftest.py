"""Write per-suite selection counts that JUnit XML cannot carry.

Measured: running a suite with `--junitxml` while cases are deselected prints
`12 deselected` on the terminal and writes `tests="0"`, `skipped="0"`,
`failures="0"`, `errors="0"` and NO DESELECTION VALUE AT ALL to the XML. A
gate that reads only the XML therefore cannot tell a clean run from one where
every case was deselected -- both look like nothing failed.

`selected == declared` is not a substitute. It catches deselection of a
DECLARED case, but cannot distinguish a clean partition from an extra
collected test being silently deselected while every declared test still ran,
which is why both facts are required.

The output file is chosen by `--release-counts`, so the two suites write
separate files and neither can be mistaken for the other.
"""

from __future__ import annotations

import json
import pathlib

import pytest


def pytest_addoption(parser):
    parser.addoption(
        "--release-counts",
        action="store",
        default=None,
        help="write {selected, deselected, skipped, xfailed} to this path",
    )
    parser.addoption(
        "--release-signatures",
        action="store",
        default=None,
        help="write observed six-field failure signatures to this path",
    )


def pytest_configure(config):
    config._release_counts = {"selected": 0, "deselected": 0, "skipped": 0, "xfailed": 0}


@pytest.hookimpl(trylast=True)
def pytest_collection_modifyitems(config, items):
    """`trylast`, or the count is taken BEFORE deselection.

    Without it this hook runs ahead of the mark plugin, records the full
    collected list as `selected`, and a suite whose cases were all deselected
    still reports `selected == declared` -- the exact false green this file
    exists to prevent. Measured: 2 selected, 1 deselected, 1 actually run.
    """
    config._release_counts["selected"] = len(items)


def pytest_deselected(items):
    # Module-level access: the hook does not receive config.
    _DESELECTED.extend(items)


_DESELECTED: list = []


def pytest_terminal_summary(terminalreporter, exitstatus, config):
    counts = config._release_counts
    counts["deselected"] = len(_DESELECTED)
    counts["skipped"] = len(terminalreporter.stats.get("skipped", []))
    counts["xfailed"] = len(terminalreporter.stats.get("xfailed", []))

    target = config.getoption("--release-counts")
    if target:
        pathlib.Path(target).write_text(json.dumps(counts, indent=2, sort_keys=True))

    signatures = config.getoption("--release-signatures")
    if signatures:
        from tests.release.signatures import RECORDER

        RECORDER.dump(pathlib.Path(signatures))
