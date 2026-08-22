"""The aggregator decides the job, so its decisions are tested."""

from __future__ import annotations

import json
import pathlib

import pytest

from tests.release.gate_report import (
    SIGNATURE_FIELDS,
    SuiteResult,
    check_counts,
    decide,
    load_manifest,
    main,
    parse_junit,
    signature,
)

CLEAN_COUNTS = {"selected": 5, "deselected": 0, "skipped": 0, "xfailed": 0}


def _suite(name="release", **kw) -> SuiteResult:
    s = SuiteResult(name=name, counts=dict(CLEAN_COUNTS), declared=5)
    for k, v in kw.items():
        setattr(s, k, v)
    return s


def _xml(tmp_path, body: str, name="r.xml") -> pathlib.Path:
    p = tmp_path / name
    p.write_text(f'<testsuites><testsuite name="pytest">{body}</testsuite></testsuites>')
    return p


# --- what fails the gate ----------------------------------------------------


def test_a_clean_pair_with_an_empty_manifest_is_green():
    code, reasons = decide([_suite(), _suite("browser")], manifest=[])
    assert code == 0, reasons


def test_a_non_empty_manifest_fails_the_gate():
    code, reasons = decide([_suite()], manifest=[{"case_id": "x"}])
    assert code == 1
    assert any("manifest holds 1 record" in r for r in reasons)


def test_a_harness_error_fails_and_is_named_as_never_manifestable():
    """A manifest entry records a known product defect. A collection error
    records that the gate did not run."""
    code, reasons = decide([_suite(errors=["t::collect"])], manifest=[])
    assert code == 1
    assert any("never manifestable" in r for r in reasons)


def test_a_security_failure_fails_the_gate():
    code, reasons = decide([_suite(failures=["t::leak"])], manifest=[])
    assert code == 1
    assert any("failure(s)" in r for r in reasons)


def test_a_browser_suite_failure_fails_the_gate_too():
    """Both suites decide the job, not only the first."""
    code, reasons = decide([_suite(), _suite("browser", failures=["t::ui"])], manifest=[])
    assert code == 1
    assert any(r.startswith("browser:") for r in reasons)


# --- the counts, per suite --------------------------------------------------


def test_a_deselected_case_fails_the_gate():
    """The fact the XML cannot carry."""
    s = _suite()
    s.counts["deselected"] = 1
    assert any("deselected == 1" in r for r in check_counts(s))


@pytest.mark.parametrize("key", ["skipped", "xfailed"])
def test_a_skipped_or_xfailed_case_fails_the_gate(key: str):
    s = _suite()
    s.counts[key] = 1
    assert any(f"{key} == 1" in r for r in check_counts(s))


def test_selected_must_equal_declared():
    s = _suite()
    s.counts["selected"] = 4
    assert any("selected 4 != declared 5" in r for r in check_counts(s))


def test_each_suite_is_checked_against_its_own_counts_file():
    """Sharing one counts file lets a clean suite excuse a deselected one."""
    good = _suite("release")
    bad = _suite("browser")
    bad.counts["deselected"] = 3

    code, reasons = decide([good, bad], manifest=[])
    assert code == 1
    assert any(r.startswith("browser: deselected") for r in reasons)
    assert not any(r.startswith("release:") for r in reasons)


# --- parsing ----------------------------------------------------------------


def test_errors_and_failures_are_distinguished(tmp_path):
    path = _xml(
        tmp_path,
        '<testcase classname="a" name="err"><error message="boom"/></testcase>'
        '<testcase classname="a" name="fail"><failure message="leak"/></testcase>'
        '<testcase classname="a" name="ok"/>',
    )
    result = parse_junit(path, "release")
    assert result.errors == ["a::err"]
    assert result.failures == ["a::fail"]


def test_a_passing_suite_parses_to_nothing(tmp_path):
    result = parse_junit(_xml(tmp_path, '<testcase classname="a" name="ok"/>'), "release")
    assert not result.errors and not result.failures


# --- the manifest signature -------------------------------------------------


def test_the_signature_is_exactly_six_fields():
    assert len(SIGNATURE_FIELDS) == 6
    assert SIGNATURE_FIELDS == (
        "case_id",
        "property",
        "collector",
        "surface_path",
        "representation",
        "occurrence_rule",
    )


def test_a_signature_is_order_stable_for_multiset_comparison():
    record = dict.fromkeys(SIGNATURE_FIELDS, "v")
    assert signature(record) == tuple("v" for _ in SIGNATURE_FIELDS)


def test_a_record_missing_a_field_is_an_error_not_a_default():
    with pytest.raises(KeyError):
        signature({"case_id": "x"})


def test_xfail_is_not_used_anywhere_in_the_release_suite():
    """The gate refuses non-zero xfailed counts, so using xfail would make
    that rule unreachable by construction -- a manifested failure must still
    FAIL and be reconciled by the aggregator.

    Detects USAGE, not the word. An earlier version matched the substring and
    flagged a file that merely explains why xfail is not used: a string match
    wearing the name of a usage check.
    """
    import ast

    root = pathlib.Path(__file__).resolve().parent
    offenders = []
    for path in root.rglob("*.py"):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            # @pytest.mark.xfail / @mark.xfail, bare or called
            target = node.func if isinstance(node, ast.Call) else node
            if isinstance(target, ast.Attribute) and target.attr == "xfail":
                offenders.append(f"{path.name}:{node.lineno}")
            # pytest.xfail("...") imperative form
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "xfail":
                offenders.append(f"{path.name}:{node.lineno}")

    assert not offenders, offenders


def test_the_xfail_detector_finds_a_real_xfail(tmp_path):
    """The control. A detector that finds nothing anywhere proves nothing."""
    import ast

    module = tmp_path / "t.py"
    module.write_text("import pytest\n@pytest.mark.xfail\ndef test_a(): pass\n")

    found = [
        node
        for node in ast.walk(ast.parse(module.read_text()))
        if isinstance(node, ast.Attribute) and node.attr == "xfail"
    ]
    assert found, "the detector would not notice a real xfail"


# --- end to end -------------------------------------------------------------


def test_main_returns_nonzero_while_the_manifest_is_non_empty(tmp_path, monkeypatch):
    release_xml = _xml(tmp_path, '<testcase classname="a" name="ok"/>', "release.xml")
    browser_xml = _xml(tmp_path, '<testcase classname="b" name="ok"/>', "browser.xml")
    rc = tmp_path / "rc.json"
    bc = tmp_path / "bc.json"
    rc.write_text(json.dumps({"selected": 1, "deselected": 0, "skipped": 0, "xfailed": 0}))
    bc.write_text(json.dumps({"selected": 1, "deselected": 0, "skipped": 0, "xfailed": 0}))

    manifest = tmp_path / "expected_failures.toml"
    manifest.write_text(
        '[[expected_failure]]\ncase_id = "x"\nproperty = "p"\ncollector = "c"\n'
        'surface_path = "s"\nrepresentation = "plain"\noccurrence_rule = "FORBIDDEN"\n'
        'owner = "unassigned"\n'
    )
    monkeypatch.setattr("tests.release.gate_report.MANIFEST", manifest)

    code = main(["gate_report.py", str(release_xml), str(rc), str(browser_xml), str(bc), "1", "1"])
    assert code == 1


def test_main_is_green_when_everything_holds(tmp_path, monkeypatch):
    release_xml = _xml(tmp_path, '<testcase classname="a" name="ok"/>', "release.xml")
    browser_xml = _xml(tmp_path, '<testcase classname="b" name="ok"/>', "browser.xml")
    rc = tmp_path / "rc.json"
    bc = tmp_path / "bc.json"
    for p in (rc, bc):
        p.write_text(json.dumps({"selected": 1, "deselected": 0, "skipped": 0, "xfailed": 0}))

    empty = tmp_path / "empty.toml"
    empty.write_text("")
    monkeypatch.setattr("tests.release.gate_report.MANIFEST", empty)

    assert load_manifest(empty) == []
    code = main(["gate_report.py", str(release_xml), str(rc), str(browser_xml), str(bc), "1", "1"])
    assert code == 0
