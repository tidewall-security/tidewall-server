"""The reporter is tested, or it is one more unverified counter.

Each case runs a real pytest subprocess against a temporary suite, because
the thing under test is a plugin hook: asserting on the functions directly
would not show whether pytest calls them.
"""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys

CONFTEST = pathlib.Path(__file__).resolve().parent / "conftest.py"
REPO = pathlib.Path(__file__).resolve().parents[2]


def _run(tmp_path: pathlib.Path, files: dict[str, str], args: list[str]) -> dict:
    suite = tmp_path / "suite"
    suite.mkdir()
    (suite / "conftest.py").write_text(CONFTEST.read_text())
    for name, body in files.items():
        (suite / name).write_text(body)

    counts = tmp_path / "counts.json"
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            str(suite),
            "-q",
            "-p",
            "no:randomly",
            "-p",
            "no:cacheprovider",
            "-o",
            "addopts=",
            "--release-counts",
            str(counts),
            *args,
        ],
        cwd=REPO,
        capture_output=True,
        text=True,
        env={**os.environ},
    )
    assert counts.exists(), (result.stdout + result.stderr)[-800:]
    return json.loads(counts.read_text())


def test_a_deselected_test_is_counted(tmp_path):
    """The fact JUnit XML cannot carry."""
    counts = _run(
        tmp_path,
        {
            "test_s.py": (
                "import pytest\n" "def test_kept(): pass\n" "@pytest.mark.slow\n" "def test_dropped(): pass\n"
            ),
            "pytest.ini": "[pytest]\nmarkers = slow: marked\n",
        },
        ["-m", "not slow"],
    )
    assert counts["deselected"] == 1, counts
    assert counts["selected"] == 1, counts


def test_a_clean_run_reports_zero_deselected(tmp_path):
    counts = _run(tmp_path, {"test_s.py": "def test_a(): pass\ndef test_b(): pass\n"}, [])
    assert counts == {"deselected": 0, "selected": 2, "skipped": 0, "xfailed": 0}


def test_skips_are_counted_separately_from_deselections(tmp_path):
    counts = _run(
        tmp_path,
        {"test_s.py": "import pytest\n@pytest.mark.skip\ndef test_a(): pass\ndef test_b(): pass\n"},
        [],
    )
    assert counts["skipped"] == 1, counts
    assert counts["deselected"] == 0, counts
    assert counts["selected"] == 2, counts


def test_xfails_are_counted(tmp_path):
    """The gate refuses any xfail. It has to be able to see one."""
    counts = _run(
        tmp_path,
        {"test_s.py": "import pytest\n@pytest.mark.xfail\ndef test_a(): assert False\n"},
        [],
    )
    assert counts["xfailed"] == 1, counts


def test_the_junit_xml_does_not_carry_the_deselection(tmp_path):
    """The measurement behind this whole file.

    Same run, both outputs: the counts file records the deselection and the
    XML records nothing that could reveal it.
    """
    suite = tmp_path / "suite"
    suite.mkdir()
    (suite / "conftest.py").write_text(CONFTEST.read_text())
    (suite / "pytest.ini").write_text("[pytest]\nmarkers = slow: marked\n")
    (suite / "test_s.py").write_text("import pytest\n@pytest.mark.slow\ndef test_dropped(): pass\n")
    counts, xml = tmp_path / "c.json", tmp_path / "r.xml"
    subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            str(suite),
            "-q",
            "-p",
            "no:randomly",
            "-p",
            "no:cacheprovider",
            "-o",
            "addopts=",
            "-m",
            "not slow",
            "--release-counts",
            str(counts),
            "--junitxml",
            str(xml),
        ],
        cwd=REPO,
        capture_output=True,
        text=True,
    )

    assert json.loads(counts.read_text())["deselected"] == 1
    body = xml.read_text()
    assert 'tests="0"' in body, body[:400]
    assert "deselect" not in body.lower(), (
        "premise changed: the XML now carries a deselection value, and the " "counts file may no longer be necessary"
    )
