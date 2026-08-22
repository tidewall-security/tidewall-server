"""The seven behaviours are asserted, and none was quietly dropped.

This runs WITHOUT a browser, so the coverage claim does not depend on the e2e
group being installed. The canary itself is marked `e2e`; the default run
deselects it, and a deselected test asserts nothing at all.
"""

from __future__ import annotations

import pathlib

import pytest

from tests.release.ui_property import (
    BEHAVIOURS,
    BehaviourNotAsserted,
    assertion_name,
    audit,
)

CANARY_MODULE = pathlib.Path(__file__).resolve().parent / "test_ui_canary.py"


def test_there_are_exactly_seven_behaviours():
    """The design names seven. Six is a dropped one; eight is a renamed one."""
    assert len(BEHAVIOURS) == 7, [b.key for b in BEHAVIOURS]
    assert len({b.key for b in BEHAVIOURS}) == 7


def test_the_canary_asserts_every_behaviour():
    audit(CANARY_MODULE)


@pytest.mark.parametrize("behaviour", BEHAVIOURS, ids=lambda b: b.key)
def test_each_behaviour_has_a_named_assertion_in_the_canary(behaviour):
    source = CANARY_MODULE.read_text()
    assert f"def {assertion_name(behaviour)}(" in source, f"{behaviour.key} has no assertion: {behaviour.why}"


def test_an_assertion_that_is_defined_but_never_called_is_refused(tmp_path):
    """The exact shape this oracle exists for.

    The function exists, a reader counts seven, and the test body invokes six.
    """
    module = tmp_path / "canary.py"
    body = "\n".join(f"def {assertion_name(b)}(page): pass" for b in BEHAVIOURS)
    calls = "\n".join(f"    {assertion_name(b)}(page)" for b in BEHAVIOURS if b.key != "storage_cleared")
    module.write_text(f"{body}\n\ndef test_it(page):\n{calls}\n")

    with pytest.raises(BehaviourNotAsserted, match="never called for: \\['storage_cleared'\\]"):
        audit(module)


def test_a_missing_assertion_is_refused(tmp_path):
    module = tmp_path / "canary.py"
    module.write_text("def test_it(page): pass\n")
    with pytest.raises(BehaviourNotAsserted, match="no assertion defined"):
        audit(module)


def test_a_complete_canary_passes_the_audit(tmp_path):
    """The oracle must be able to pass, or its failures mean nothing."""
    module = tmp_path / "canary.py"
    body = "\n".join(f"def {assertion_name(b)}(page): pass" for b in BEHAVIOURS)
    calls = "\n".join(f"    {assertion_name(b)}(page)" for b in BEHAVIOURS)
    module.write_text(f"{body}\n\ndef test_it(page):\n{calls}\n")
    audit(module)


def test_the_canary_is_marked_e2e_and_therefore_deselected_by_default():
    """Stated so it is not mistaken for coverage in the default run.

    `addopts = "-m 'not e2e'"` deselects it, and pytest's JUnit XML does not
    record deselections -- so a report can show a green run in which this
    canary never executed.
    """
    source = CANARY_MODULE.read_text()
    assert "pytestmark = pytest.mark.e2e" in source

    import tomllib

    config = tomllib.loads((pathlib.Path(__file__).resolve().parents[2] / "pyproject.toml").read_text())
    assert config["tool"]["pytest"]["ini_options"]["addopts"] == "-m 'not e2e'"


def test_the_canary_checks_both_storage_kinds():
    """Reading only localStorage passes while the value sits in sessionStorage."""
    source = CANARY_MODULE.read_text()
    assert "localStorage" in source
    assert "sessionStorage" in source


def test_the_canary_checks_every_representation_family():
    from tests.release.representations import FAMILIES

    source = CANARY_MODULE.read_text()
    assert "_representations(" in source
    assert "FAMILIES" in source
    assert len(FAMILIES) >= 7
