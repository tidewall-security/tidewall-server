"""The standalone step, and the claim it deliberately does not make."""

from __future__ import annotations

import pathlib

import yaml

from tests.release.manifest_empty import BLOCKED_ON_OWNER, main, manifest_records

WORKFLOW = pathlib.Path(__file__).resolve().parents[2] / ".github" / "workflows" / "ci.yml"


def test_the_step_exists_as_its_own_required_job():
    jobs = yaml.safe_load(WORKFLOW.read_text())["jobs"]
    assert "manifest-empty" in jobs, sorted(jobs)
    runs = [s["run"] for s in jobs["manifest-empty"]["steps"] if "run" in s]
    assert any("manifest_empty.py" in r for r in runs)


def test_the_step_is_not_continue_on_error():
    jobs = yaml.safe_load(WORKFLOW.read_text())["jobs"]
    for step in jobs["manifest-empty"]["steps"]:
        assert step.get("continue-on-error") is not True


def test_it_fails_while_the_manifest_is_non_empty(capsys):
    assert main(["manifest_empty.py"]) == 1
    assert "MANIFEST NOT EMPTY" in capsys.readouterr().out


def test_it_passes_on_an_empty_manifest(tmp_path, capsys):
    empty = tmp_path / "e.toml"
    empty.write_text("")
    assert main(["manifest_empty.py", str(empty)]) == 0
    assert "MANIFEST EMPTY" in capsys.readouterr().out


def test_a_missing_file_reads_as_empty_rather_than_erroring(tmp_path):
    assert manifest_records(tmp_path / "absent.toml") == []


def test_no_publish_job_needs_the_release_gate_yet():
    """The blocked half, asserted rather than assumed.

    If a publish job is added later, this test fails and whoever adds it must
    update the claim below deliberately.
    """
    jobs = yaml.safe_load(WORKFLOW.read_text())["jobs"]
    gated = [name for name, job in jobs.items() if "release-gate" in str(job.get("needs", ""))]
    assert not gated, gated


def test_the_repository_does_not_claim_that_failures_block_release():
    """The one thing this programme exists to stop is a claim outrunning its
    evidence. A workflow that asserts emptiness is not one that gates
    publication."""
    assert "does NOT claim" in BLOCKED_ON_OWNER
    assert "deferred owner decision" in BLOCKED_ON_OWNER

    workflow = WORKFLOW.read_text()
    assert "is NOT the same as" in workflow
