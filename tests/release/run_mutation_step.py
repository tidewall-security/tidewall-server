"""Execute the out-of-tree mutation step. This is the RUNNER, not the checkers.

`mutation_step.py` holds the comparison rules; before this file existed they
had no caller outside their own unit tests, so the "out-of-tree mutation step"
was a set of well-tested helpers that never ran against anything.

WHAT THIS DOES, in order:
  1. run the release suite UNMUTATED and extract its real signature multiset;
  2. check that multiset equals the recorded baseline exactly -- not a
     superset, or a later delta cannot be attributed to the mutant;
  3. apply the named edit and PROVE the source changed;
  4. run the suite again, extract the mutant multiset and the harness-error
     count;
  5. require the delta to be exactly one predeclared novel signature, with no
     harness error standing in for it;
  6. restore the source, whatever happened.

It never reads an exit code. While the baseline is red every run exits
non-zero, so an exit code carries no information at all.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from collections import Counter

from tests.release.mutation_step import (
    Mutation,
    check_baseline,
    check_delta,
    verify_applied,
)
from tests.release.signatures import FIELDS

REPO = pathlib.Path(__file__).resolve().parents[2]

#: The mutation this step exercises. Its delta must fall OUTSIDE the baseline,
#: or the new signature is indistinguishable from a record already there.
#:
#: Chosen for that reason: neutering the emoji detector makes cases declaring
#: `emoji/reported` observe `emoji/pattern_match`, which no baseline record
#: covers -- the baseline is about matches_json and forbidden echoes.
DEFAULT_MUTATION = Mutation(
    name="emoji-detector-never-detects",
    path="app/detectors/emoji_detector.py",
    old="        if not emojis:\n            return DetectorResult(detected=False)",
    new="        if True:\n            return DetectorResult(detected=False)",
    expected_signature=("component-mismatch", "emoji/reported"),
    # Measured: 14 manifest cases declare emoji/reported and none of them
    # reaches it once the detector stops detecting.
    expected_count=14,
)


def run_suite(signatures: pathlib.Path, junit: pathlib.Path) -> tuple[Counter, int]:
    """Run the release suite; return its signature multiset and UNACCOUNTED failures.

    Every JUnit outcome is classified. An `<error>` is a harness error. A
    `<failure>` is ACCOUNTED FOR only if that same test emitted a signature or
    is a recognised component mismatch; anything else -- an unrelated assertion
    failure, a fixture problem, a typo in a test -- is counted as unaccounted.

    Counting only `<error>` meant an unrelated assertion failure could exist in
    BOTH runs while the runner still reported the expected delta and succeeded.
    The release suite is deliberately red, so an exit code cannot make this
    distinction and something must.
    """
    subprocess.run(
        [
            "uv",
            "run",
            "pytest",
            "tests/release",
            "--ignore=tests/release/browser",
            "-q",
            "-p",
            "no:randomly",
            f"--junitxml={junit}",
            f"--release-signatures={signatures}",
        ],
        cwd=REPO,
        capture_output=True,
        text=True,
    )

    from tests.release.signatures import accounted_nodeids

    observed: Counter = Counter()
    accounted = accounted_nodeids(signatures)
    if signatures.exists():
        payload = json.loads(signatures.read_text())
        rows = payload["signatures"] if isinstance(payload, dict) else payload
        for row in rows:
            observed[tuple(row[f] for f in FIELDS)] += 1

    unaccounted = 0
    if junit.exists():
        root = ET.parse(junit).getroot()
        for case in root.iter("testcase"):
            nodeid = f"{(case.get('classname') or '').replace('.', '/')}.py::{case.get('name')}"
            simple = f"{case.get('classname')}::{case.get('name')}"
            if case.find("error") is not None:
                unaccounted += 1
                continue
            failure = case.find("failure")
            if failure is None:
                continue

            message = failure.get("message") or ""
            mismatch = _component_mismatch(message)
            if mismatch:
                observed[("component-mismatch", mismatch)] += 1
                continue

            if any(a.startswith(nodeid) or a.startswith(simple) for a in accounted):
                continue
            if any(nodeid.split("::")[-1] in a for a in accounted):
                continue

            unaccounted += 1

    return observed, unaccounted


def _component_mismatch(message: str) -> str | None:
    """The declared component a mismatch names, whatever it is.

    Two component names were hard-coded here, so a mismatch on any other
    component was silently ignored.
    """
    if "ComponentMismatch" not in message:
        return None
    match = re.search(r"declares '([^']+)'", message)
    return match.group(1) if match else None


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline", type=pathlib.Path, default=None)
    parser.add_argument("--write-baseline", action="store_true")
    args = parser.parse_args(argv[1:])

    mutation = DEFAULT_MUTATION
    source = REPO / mutation.path
    original = source.read_text()

    with tempfile.TemporaryDirectory() as tmp:
        tmpdir = pathlib.Path(tmp)

        unmutated, unmutated_errors = run_suite(tmpdir / "base.json", tmpdir / "base.xml")
        if unmutated_errors:
            print(
                f"MUTATION STEP: {unmutated_errors} unaccounted failure(s) in the "
                "unmutated run; every failure must either emit a signature or be a "
                "recognised component mismatch"
            )
            return 1

        if args.write_baseline:
            path = args.baseline or (REPO / "tests" / "release" / "mutation_baseline.json")
            path.write_text(json.dumps(sorted([list(k), v] for k, v in unmutated.items()), indent=2) + "\n")
            print(f"MUTATION STEP: baseline written to {path} ({sum(unmutated.values())} signatures)")
            return 0

        baseline_path = args.baseline or (REPO / "tests" / "release" / "mutation_baseline.json")
        baseline = Counter({tuple(key): count for key, count in json.loads(baseline_path.read_text())})

        try:
            check_baseline(unmutated, baseline)
        except Exception as exc:  # noqa: BLE001 - reported, not swallowed
            print(f"MUTATION STEP: {exc}")
            return 1

        try:
            source.write_text(mutation.apply(original))
            verify_applied(mutation, original, source.read_text())
            mutant, mutant_errors = run_suite(tmpdir / "mut.json", tmpdir / "mut.xml")
        finally:
            source.write_text(original)

        try:
            check_delta(mutation, baseline, mutant, mutant_errors)
        except Exception as exc:  # noqa: BLE001
            print(f"MUTATION STEP: {exc}")
            return 1

    print(f"MUTATION STEP: {mutation.name} produced exactly its predeclared delta")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
