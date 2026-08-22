"""The only step that decides the release gate.

Both suites always run, and both are allowed to fail their own step: the
capture-off suite is deliberately red while the expected-failure manifest is
non-empty, and using a failing step as control flow would remove the browser
canary from the gate for exactly as long as the gate is red.

So each suite's step is `continue-on-error` and this script makes the decision,
from four inputs per suite:

  * the JUnit XML -- which tests ran and which failed;
  * that suite's own counts file -- selected, deselected, skipped, xfailed,
    because JUNIT XML CANNOT CARRY A DESELECTION COUNT and a fully deselected
    run is indistinguishable in the XML from a clean one;
  * the declared case count for that suite;
  * the expected-failure manifest.

The gate fails if either suite had a HARNESS ERROR or a SECURITY FAILURE, if
any suite's counts do not match exactly, or if the manifest is non-empty.

A HARNESS ERROR IS NEVER MANIFESTABLE. A manifest entry records a known
product defect; a collection error, an import failure or a fixture crash
records that the gate did not run, and letting one be excused would let a
broken gate report success forever.
"""

from __future__ import annotations

import json
import pathlib
import sys
import tomllib
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

MANIFEST = pathlib.Path(__file__).resolve().parent / "expected_failures.toml"

#: The six fields compared exactly, as a multiset.
SIGNATURE_FIELDS = (
    "case_id",
    "property",
    "collector",
    "surface_path",
    "representation",
    "occurrence_rule",
)


@dataclass
class SuiteResult:
    name: str
    failures: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)
    declared: int = 0


def parse_junit(path: pathlib.Path, name: str) -> SuiteResult:
    result = SuiteResult(name=name)
    root = ET.parse(path).getroot()
    for case in root.iter("testcase"):
        ident = f"{case.get('classname', '')}::{case.get('name', '')}"
        if case.find("error") is not None:
            result.errors.append(ident)
        elif case.find("failure") is not None:
            result.failures.append(ident)
    return result


def load_manifest(path: pathlib.Path | None = None) -> list[dict]:
    # Resolved at CALL time. A default argument binds the module constant when
    # the function is defined, so pointing MANIFEST elsewhere -- in a test, or
    # in a caller that ships its own file -- had no effect and the real
    # manifest was read regardless.
    path = MANIFEST if path is None else path
    if not path.exists():
        return []
    data = tomllib.loads(path.read_text())
    return list(data.get("expected_failure", []))


def signature(record: dict) -> tuple:
    return tuple(record[f] for f in SIGNATURE_FIELDS)


def check_counts(result: SuiteResult) -> list[str]:
    """Every count exact, per suite, from that suite's own file."""
    problems = []
    counts = result.counts
    if counts.get("selected") != result.declared:
        problems.append(f"{result.name}: selected {counts.get('selected')} != declared {result.declared}")
    for key in ("deselected", "skipped", "xfailed"):
        if counts.get(key):
            problems.append(f"{result.name}: {key} == {counts[key]}, must be 0")
    return problems


def decide(results: list[SuiteResult], manifest: list[dict]) -> tuple[int, list[str]]:
    reasons: list[str] = []

    for result in results:
        if result.errors:
            reasons.append(
                f"{result.name}: {len(result.errors)} harness error(s), which are "
                f"never manifestable: {result.errors[:3]}"
            )
        if result.failures:
            reasons.append(f"{result.name}: {len(result.failures)} failure(s): {result.failures[:3]}")
        reasons.extend(check_counts(result))

    if manifest:
        reasons.append(
            f"the expected-failure manifest holds {len(manifest)} record(s); " "the gate is red until it is empty"
        )

    return (1 if reasons else 0), reasons


def main(argv: list[str]) -> int:
    if len(argv) < 5:
        print(
            "usage: gate_report.py <release.xml> <release-counts.json> "
            "<browser.xml> <browser-counts.json> [declared_release] [declared_browser]",
            file=sys.stderr,
        )
        return 2

    release = parse_junit(pathlib.Path(argv[1]), "release")
    release.counts = json.loads(pathlib.Path(argv[2]).read_text())
    browser = parse_junit(pathlib.Path(argv[3]), "browser")
    browser.counts = json.loads(pathlib.Path(argv[4]).read_text())

    release.declared = int(argv[5]) if len(argv) > 5 else release.counts.get("selected", 0)
    browser.declared = int(argv[6]) if len(argv) > 6 else browser.counts.get("selected", 0)

    code, reasons = decide([release, browser], load_manifest())
    for reason in reasons:
        print(f"RELEASE GATE: {reason}")
    if code == 0:
        print("RELEASE GATE: green")
    return code


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
