"""The job as checked in, not as described.

A workflow that reads correctly and selects zero tests is the same defect as
a check that never runs: Playwright sits in the opt-in `e2e` group, Chromium
needs a separate install, and the default addopts select `not e2e`.
"""

from __future__ import annotations

import pathlib

import pytest
import yaml

WORKFLOW = pathlib.Path(__file__).resolve().parents[2] / ".github" / "workflows" / "ci.yml"


@pytest.fixture(scope="module")
def gate() -> dict:
    jobs = yaml.safe_load(WORKFLOW.read_text())["jobs"]
    assert "release-gate" in jobs, sorted(jobs)
    return jobs["release-gate"]


def _runs(gate: dict) -> list[str]:
    return [s["run"] for s in gate["steps"] if "run" in s]


def test_the_e2e_group_is_installed():
    """Without it, the browser step errors rather than running."""
    jobs = yaml.safe_load(WORKFLOW.read_text())["jobs"]
    assert any("--group e2e" in r for r in _runs(jobs["release-gate"]))


def test_chromium_is_installed_separately(gate):
    """`uv sync` does not fetch the browser binary."""
    assert any("playwright install" in r and "chromium" in r for r in _runs(gate))


def test_both_suites_always_run(gate):
    """Neither may be used as control flow for the other."""
    steps = {s.get("id"): s for s in gate["steps"] if s.get("id")}
    assert set(steps) == {"release_suite", "browser_canary"}, sorted(steps)
    for step in steps.values():
        assert step.get("continue-on-error") is True, step


def test_the_browser_subtree_is_ignored_by_the_release_suite(gate):
    """Load-bearing.

    `pytest tests/release` collects the browser subtree and then deselects it
    under the default -m 'not e2e', which contradicts the deselected == 0 rule
    and makes the gate permanently un-greenable.
    """
    release = next(s for s in gate["steps"] if s.get("id") == "release_suite")
    assert "--ignore=tests/release/browser" in release["run"]


def test_the_browser_step_overrides_the_default_addopts(gate):
    """Otherwise `-m 'not e2e'` selects nothing and the canary silently
    contributes zero tests."""
    browser = next(s for s in gate["steps"] if s.get("id") == "browser_canary")
    assert "-o addopts=''" in browser["run"]
    assert "-m e2e" in browser["run"]


def test_each_suite_writes_its_own_counts_file(gate):
    """Sharing one file lets a clean suite excuse a deselected one."""
    release = next(s for s in gate["steps"] if s.get("id") == "release_suite")
    browser = next(s for s in gate["steps"] if s.get("id") == "browser_canary")
    assert "--release-counts=release-counts.json" in release["run"]
    assert "--release-counts=browser-counts.json" in browser["run"]
    assert "release-counts.json" not in browser["run"]


def test_each_suite_writes_its_own_junit_file(gate):
    release = next(s for s in gate["steps"] if s.get("id") == "release_suite")
    browser = next(s for s in gate["steps"] if s.get("id") == "browser_canary")
    assert "--junitxml=release.xml" in release["run"]
    assert "--junitxml=browser.xml" in browser["run"]


def test_the_last_step_is_the_only_one_that_decides(gate):
    """It must not be continue-on-error, or nothing fails the job."""
    last = gate["steps"][-1]
    assert "gate_report.py" in last["run"]
    assert last.get("continue-on-error") is not True


def test_the_decider_receives_both_suites_counts_and_results(gate):
    last = gate["steps"][-1]["run"]
    for expected in (
        "release.xml",
        "release-counts.json",
        "browser.xml",
        "browser-counts.json",
    ):
        assert expected in last, expected


def test_the_two_commands_partition_the_release_tree():
    """Measured against the real tree, not asserted about it.

    Every test under tests/release is selected by exactly one of the two
    commands.
    """
    import subprocess
    import sys

    repo = WORKFLOW.parents[2]

    def collected(args: list[str]) -> set[str]:
        result = subprocess.run(
            [sys.executable, "-m", "pytest", "-q", "--co", "-p", "no:randomly", *args],
            cwd=repo,
            capture_output=True,
            text=True,
        )
        return {line.split("[")[0] for line in result.stdout.splitlines() if "::" in line}

    release = collected(["tests/release", "--ignore=tests/release/browser"])
    browser = collected(["tests/release/browser", "-m", "e2e", "-o", "addopts="])
    everything = collected(["tests/release", "-o", "addopts="])

    assert release and browser, (len(release), len(browser))
    assert not (release & browser), sorted(release & browser)[:5]
    assert release | browser == everything, {
        "collected by neither": sorted(everything - (release | browser))[:5],
    }


def test_the_release_suite_deselects_nothing():
    """The assertion the gate makes, checked here against the real tree."""
    import subprocess
    import sys

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "tests/release",
            "--ignore=tests/release/browser",
            "-q",
            "--co",
            "-p",
            "no:randomly",
        ],
        cwd=WORKFLOW.parents[2],
        capture_output=True,
        text=True,
    )
    # Match the SUMMARY LINE, not the substring: `--co` prints every test id,
    # and this test's own name contains "deselects", so a bare substring check
    # failed on itself.
    import re

    summary = re.search(r"(\d+) deselected", result.stdout)
    assert summary is None, f"{summary.group(0)}: {result.stdout[-300:]}"


# ---------------------------------------------------------------------------
# Teardown must not be able to fail a job whose work succeeded
#
# `setup-uv` prunes ~/.cache/uv at teardown. That prune has failed -- `uv failed
# with exit code 2` -- AFTER every real step passed, twice: once in this
# repository's contract job, and once in the extension's mirror of it, which was
# red on every run from creation until it was found.
#
# The runner is ephemeral, so the prune saves nothing that outlives the job. It
# is disabled everywhere rather than only where a failure has been observed:
# both observed failures were two-checkout jobs running uv from a subdirectory,
# which is a plausible but unproven cause, and a rule applied by a theory nobody
# can evaluate is how four blocks came to sit silently outside it.


def _workflow_files():
    root = pathlib.Path(__file__).resolve().parents[2] / ".github" / "workflows"
    files = sorted(root.glob("*.yml"))
    assert files, f"no workflows found under {root}"
    return files


def _setup_uv_steps():
    """Every setup-uv step in every workflow, as (file, job, step) triples."""
    found = []
    for path in _workflow_files():
        jobs = yaml.safe_load(path.read_text())["jobs"]
        for job_name, job in jobs.items():
            for step in job.get("steps", []):
                if "astral-sh/setup-uv" in str(step.get("uses", "")):
                    found.append((path.name, job_name, step))
    return found


def test_the_scan_finds_the_setup_uv_steps_at_all():
    """Without this the assertion below passes vacuously on a parsing change.

    The steps are read through the YAML rather than by grepping the text, so a
    restructure that this scan cannot follow would silently find nothing and
    report every workflow compliant.
    """
    steps = _setup_uv_steps()
    assert len(steps) >= 8, [(f, j) for f, j, _ in steps]


def test_no_job_prunes_the_uv_cache_at_teardown():
    """Uniform, across every workflow -- not only the ones that use actions/cache.

    Scoped to observed failures, this rule had four silent exceptions and
    nothing recording whether that was a decision or an omission. It was an
    omission: the extension's nightly had the same gap and had never once been
    green.
    """
    offenders = [
        f"{file}:{job}"
        for file, job, step in _setup_uv_steps()
        if (step.get("with") or {}).get("prune-cache") is not False
    ]

    assert not offenders, (
        f"setup-uv prunes the cache at teardown in: {offenders}. "
        "Set `prune-cache: false` -- the runner is ephemeral, so the prune "
        "saves nothing, and its failure fails the job after every real step "
        "has passed."
    )
