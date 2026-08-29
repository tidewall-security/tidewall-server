"""The standalone step, and the claim it deliberately does not make."""

from __future__ import annotations

import pathlib

import yaml

from tests.release.manifest_empty import PUBLISH_TOPOLOGY, main, manifest_records

WORKFLOW = pathlib.Path(__file__).resolve().parents[2] / ".github" / "workflows" / "ci.yml"
RELEASE_WORKFLOW = pathlib.Path(__file__).resolve().parents[2] / ".github" / "workflows" / "release.yml"


def test_the_step_exists_as_its_own_required_job():
    jobs = yaml.safe_load(WORKFLOW.read_text())["jobs"]
    assert "manifest-empty" in jobs, sorted(jobs)
    runs = [s["run"] for s in jobs["manifest-empty"]["steps"] if "run" in s]
    assert any("manifest_empty.py" in r for r in runs)


def test_the_step_is_not_continue_on_error():
    jobs = yaml.safe_load(WORKFLOW.read_text())["jobs"]
    for step in jobs["manifest-empty"]["steps"]:
        assert step.get("continue-on-error") is not True


def test_it_fails_on_a_non_empty_manifest(tmp_path, capsys):
    """The checker's behaviour, against a fixture rather than the real file.

    This used to call `main([])` and assert 1 -- reading the REAL manifest and
    depending on it being non-empty. That conflated two claims: what the checker
    does with records, and whether this project currently has any. The first is
    a property of the checker and must hold forever; the second is a fact about
    today, asserted separately below.
    """
    populated = tmp_path / "p.toml"
    populated.write_text('[[expected_failure]]\ncase_id = "x"\nowner = "someone"\n')
    assert main(["manifest_empty.py", str(populated)]) == 1
    assert "MANIFEST NOT EMPTY" in capsys.readouterr().out


def test_this_projects_manifest_is_empty(capsys):
    """The fact about today: nothing is accepted, so the gate can be green.

    All three declared defects -- the access-rule name reaching the guard
    response and the creation log, the validation echo, and detector matches
    never reaching the capture column -- are fixed.
    """
    assert main(["manifest_empty.py"]) == 0
    assert "MANIFEST EMPTY" in capsys.readouterr().out


def test_it_passes_on_an_empty_manifest(tmp_path, capsys):
    empty = tmp_path / "e.toml"
    empty.write_text("")
    assert main(["manifest_empty.py", str(empty)]) == 0
    assert "MANIFEST EMPTY" in capsys.readouterr().out


def test_a_missing_file_reads_as_empty_rather_than_erroring(tmp_path):
    assert manifest_records(tmp_path / "absent.toml") == []


def test_a_publish_job_needs_the_release_gate():
    """The blocked half, answered on 2026-08-23: PyPI.

    This test previously asserted the OPPOSITE -- that NO job depended on the
    gate -- so that adding one would fail it and force whoever added it to
    update the claim deliberately rather than inherit it. That is what
    happened.
    """
    jobs = yaml.safe_load(RELEASE_WORKFLOW.read_text())["jobs"]
    assert "publish" in jobs, sorted(jobs)
    assert jobs["publish"]["needs"] == "release-gate", jobs["publish"].get("needs")


def test_the_publish_job_also_asserts_the_manifest_itself():
    """`needs:` is evidence about ANOTHER job.

    A gate that passed elsewhere is a fact about elsewhere. The publishing job
    re-asserts emptiness in its own steps, so a change to the job graph cannot
    silently detach the check from the act it guards.
    """
    jobs = yaml.safe_load(RELEASE_WORKFLOW.read_text())["jobs"]
    runs = [s.get("run", "") for s in jobs["publish"]["steps"]]
    assert any("manifest_empty.py" in r for r in runs), runs


def test_the_release_workflow_runs_the_gate_itself():
    """`needs:` cannot reach across workflows.

    Inferring "CI passed on this SHA" from an API call is a check that can be
    wrong in a way nobody sees, so the gate is duplicated into the release
    workflow rather than assumed from CI.
    """
    jobs = yaml.safe_load(RELEASE_WORKFLOW.read_text())["jobs"]
    assert "release-gate" in jobs
    runs = [s.get("run", "") for s in jobs["release-gate"]["steps"]]
    assert any("gate_report.py" in r for r in runs)


def test_publication_is_triggered_by_a_tag_not_a_branch():
    """A workflow that publishes on every merge eventually publishes something
    nobody decided to release."""
    workflow = yaml.safe_load(RELEASE_WORKFLOW.read_text())
    trigger = workflow[True] if True in workflow else workflow["on"]
    assert set(trigger) == {"push"}, trigger
    assert "tags" in trigger["push"], trigger["push"]
    assert "branches" not in trigger["push"], trigger["push"]


def test_publishing_uses_oidc_and_no_long_lived_token():
    """No API token to leak, be committed, or outlive its creator."""
    jobs = yaml.safe_load(RELEASE_WORKFLOW.read_text())["jobs"]
    publish = jobs["publish"]
    # BOTH, not just id-token. Asserting exact equality with {"id-token":
    # "write"} cemented a real bug: overriding permissions sets every unlisted
    # scope to `none`, so checkout could not read the repository at all. The
    # test agreed with the workflow and both were wrong.
    assert publish["permissions"] == {"contents": "read", "id-token": "write"}, publish["permissions"]

    body = RELEASE_WORKFLOW.read_text()
    for secret in ("PYPI_API_TOKEN", "TWINE_PASSWORD", "password:"):
        assert secret not in body, secret


def test_the_gate_step_is_the_only_one_that_can_fail_the_release_gate_job():
    jobs = yaml.safe_load(RELEASE_WORKFLOW.read_text())["jobs"]
    steps = jobs["release-gate"]["steps"]
    decider = steps[-1]
    assert "gate_report.py" in decider["run"]
    assert decider.get("continue-on-error") is not True
    for step in steps:
        if step.get("id") in {"release_suite", "browser_canary"}:
            assert step.get("continue-on-error") is True, step["id"]


def test_the_claim_that_failures_block_release_is_now_earned():
    """It was deliberately NOT claimed until both halves existed.

    A workflow that merely asserts emptiness is not one that gates
    publication. Both now exist: a publish job that `needs: release-gate` and
    an in-job assertion of the manifest.
    """
    jobs = yaml.safe_load(RELEASE_WORKFLOW.read_text())["jobs"]
    publish = jobs["publish"]

    gated = publish.get("needs") == "release-gate"
    asserts_manifest = any("manifest_empty.py" in s.get("run", "") for s in publish["steps"])
    assert gated and asserts_manifest, {
        "needs release-gate": gated,
        "asserts the manifest": asserts_manifest,
    }


def test_the_publish_job_declares_no_oidc_environment():
    """The OIDC claim includes the environment name.

    PyPI's Trusted Publisher for this project was registered with the
    environment field blank, so declaring one here makes the claims disagree
    and publication fails at the last hop -- after the gate has passed.

    Changing this means changing BOTH sides together: the PyPI publisher entry,
    the workflow, and a GitHub environment of that name. This test exists so
    the workflow cannot drift away from the publisher entry silently.
    """
    publish = yaml.safe_load(RELEASE_WORKFLOW.read_text())["jobs"]["publish"]
    assert "environment" not in publish, (
        "the publish job declares an OIDC environment; the PyPI publisher entry "
        f"must declare the same one or the claims will not match: {publish.get('environment')}"
    )


def test_the_recorded_topology_matches_the_workflow():
    """The prose and the YAML must not drift.

    A comment describing a workflow is not the workflow; this asserts the
    recorded description is true of the file it describes.
    """
    workflow = yaml.safe_load(RELEASE_WORKFLOW.read_text())
    body = RELEASE_WORKFLOW.read_text()

    assert "PyPI" in PUBLISH_TOPOLOGY
    assert "pypi-publish" in body, "the recorded topology says PyPI"

    assert "OIDC" in PUBLISH_TOPOLOGY
    assert workflow["jobs"]["publish"]["permissions"]["id-token"] == "write"

    assert "v* tag" in PUBLISH_TOPOLOGY
    trigger = workflow[True] if True in workflow else workflow["on"]
    assert trigger["push"]["tags"] == ["v*"], trigger

    assert "DO block release" in PUBLISH_TOPOLOGY
    assert workflow["jobs"]["publish"]["needs"] == "release-gate"


def test_every_job_that_checks_out_can_read_the_repository():
    """Overriding `permissions` sets unlisted scopes to `none`.

    A job that overrides permissions and then runs actions/checkout without
    `contents: read` fails at its first step. In the publish job that happens
    AFTER the gate has passed -- the worst place to find out.
    """
    for workflow in (WORKFLOW, RELEASE_WORKFLOW):
        jobs = yaml.safe_load(workflow.read_text())["jobs"]
        for name, job in jobs.items():
            checks_out = any("actions/checkout" in str(step.get("uses", "")) for step in job["steps"])
            permissions = job.get("permissions")
            if checks_out and permissions is not None:
                assert permissions.get("contents") == "read", (
                    f"{workflow.name}:{name} overrides permissions and checks out, "
                    f"but has no contents: read -- {permissions}"
                )
