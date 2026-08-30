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
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from collections import Counter

from tests.release.mutation_step import (
    Mutation,
    UnexpectedDelta,
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
    # MEASURED, then declared. Neutering the emoji detector also breaks eight
    # tests that observe emoji behaviour directly. Each is a legitimate
    # consequence -- and naming them is what stops an unrelated mutant-only
    # failure being excused while the runner reports an exact result.
    expected_unaccounted=frozenset(
        {
            "tests/release/test_canary_capture_off.py::test_an_evaluated_case_IS_sensitive_to_its_planted_value",
            "tests/release/test_component_mapping.py::"
            "test_a_case_reaches_the_component_it_declares"
            "[report-emoji-hello \\U0001f600 \\U0001f4a9]",
            "tests/release/test_component_mapping.py::test_the_mechanism_discriminates_a_taken_branch_from_an_untaken_one",
            "tests/release/test_leaves.py::test_a_reported_case_reaches_both_which_is_correct",
            "tests/release/test_observation.py::test_a_marker_on_a_branch_test_is_narrowed_to_the_branch_body",
            "tests/release/test_observation.py::test_observing_a_real_scan_reports_the_components_it_actually_reached",
            "tests/release/test_states.py::test_a_surface_comparison_that_looks_at_nothing_finds_no_difference",
            "tests/release/test_states.py::test_emoji_reported_is_behaviour_changing",
        }
    ),
)


def run_suite(signatures: pathlib.Path, junit: pathlib.Path, counts: pathlib.Path) -> tuple[Counter, int, set[str]]:
    """Run the release suite; return its signature multiset and UNACCOUNTED failures.

    Every JUnit outcome is classified. An `<error>` is a harness error. A
    `<skipped>` is unaccounted -- a skip is not a pass, and a mutation that
    DISABLES a test rather than breaking it must not slip through. A `<failure>`
    is ACCOUNTED FOR only if that same test emitted a signature or is a
    recognised component mismatch; anything else -- an unrelated assertion
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
            f"--release-counts={counts}",
        ],
        cwd=REPO,
        capture_output=True,
        text=True,
    )

    # HOW MANY TESTS RAN. Nothing here used to ask.
    #
    # The unmutated run was checked only against the recorded baseline, and while
    # that baseline held 255 signature-producing cases it was incidentally
    # evidence that the suite had run: you cannot emit 255 signatures without
    # running the cases that emit them. That is not a property of the check, it
    # is a property of the number being large -- and it disappears the moment the
    # baseline is empty, which is what a gate with nothing left to accept looks
    # like. A run of ZERO tests then satisfies `check_baseline(empty, empty)`.
    #
    # The release gate already solved this: `--release-counts` records how many
    # tests were SELECTED after deselection, and `gate_report.check_counts`
    # compares that against `declared_counts.json` and refuses any deselection,
    # skip or xfail. The mutation runner simply never asked for it. Calling that
    # same function rather than restating the rule keeps one definition of "the
    # whole suite ran".
    from tests.release.gate_report import DECLARED_COUNTS, SuiteResult, check_counts

    if not counts.exists():
        raise SystemExit(f"the run produced no counts file at {counts}; the suite did not start")
    declared = json.loads(DECLARED_COUNTS.read_text())["release"]
    problems = check_counts(SuiteResult(name="release", counts=json.loads(counts.read_text()), declared=declared))
    if problems:
        raise SystemExit(
            "the release suite did not run in full, so a delta cannot be attributed " f"to the mutation: {problems}"
        )

    from tests.release.signatures import (
        recorded_mismatches,
        signatures_by_node,
        signatures_in,
    )

    observed: Counter = Counter()
    by_node = signatures_by_node(signatures)
    mismatches = recorded_mismatches(signatures)
    if signatures.exists():
        payload = json.loads(signatures.read_text())
        rows = payload["signatures"] if isinstance(payload, dict) else payload
        for row in rows:
            observed[tuple(row[f] for f in FIELDS)] += 1

    errors = 0
    unaccounted: set[str] = set()
    if junit.exists():
        root = ET.parse(junit).getroot()
        for case in root.iter("testcase"):
            nodeid = f"{(case.get('classname') or '').replace('.', '/')}.py::{case.get('name')}"
            if case.find("error") is not None:
                errors += 1
                continue

            # A SKIP IS NOT A PASS, and it is neither an error nor a failure --
            # so a mutation that turns a test into a skip escaped every check
            # here and was silently accepted. The release gate already refuses
            # any skip (`skipped == 0` per suite); the mutation step must see
            # them too, or a mutant can disable a test rather than break it.
            if case.find("skipped") is not None:
                unaccounted.add(nodeid)
                continue
            failure = case.find("failure")
            if failure is None:
                continue

            message = failure.get("message") or ""

            # RECORDED, not parsed. Trusting any failure whose text contained
            # "ComponentMismatch" and "declares '<x>'" let fourteen fabricated
            # assertion failures be accepted as the mutation's exact delta.
            recorded = mismatches.get(nodeid, [])
            if recorded:
                for declared in recorded:
                    observed[("component-mismatch", declared)] += 1
                continue

            # ACCOUNTED means the failure CARRIES a signature this test
            # emitted -- not merely that the test emitted one. Matching on node
            # id alone excused any failure a signature-emitting test happened to
            # produce, so a mutation could make such a test fail for an
            # unrelated reason and still be accepted.
            carried = signatures_in(message)
            if carried and carried <= by_node.get(nodeid, set()):
                continue

            unaccounted.add(nodeid)

    return observed, errors, unaccounted


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

        unmutated, base_errors, base_unaccounted = run_suite(
            tmpdir / "base.json", tmpdir / "base.xml", tmpdir / "base-counts.json"
        )
        # THE UNMUTATED RUN MUST BE CLEAN IN BOTH SENSES. A harness error means
        # the gate did not run; an unaccounted failure means something is
        # broken for a reason nobody has attributed, and a later delta cannot
        # be blamed on the mutation.
        if base_errors:
            print(f"MUTATION STEP: {base_errors} harness error(s) in the unmutated run")
            return 1
        # `--write-baseline` runs BEFORE the unaccounted gate, deliberately.
        # Its whole purpose is to record what the suite currently emits, and
        # the drift oracles legitimately fail while the baseline is stale --
        # so gating the writer on them makes the baseline unwritable exactly
        # when it needs rewriting. Harness errors still block: those mean the
        # run did not happen, and a baseline from a broken run is worthless.
        if args.write_baseline:
            path = args.baseline or (REPO / "tests" / "release" / "mutation_baseline.json")
            path.write_text(json.dumps(sorted([list(k), v] for k, v in unmutated.items()), indent=2) + "\n")
            print(f"MUTATION STEP: baseline written to {path} ({sum(unmutated.values())} signatures)")
            return 0

        if base_unaccounted:
            print(
                f"MUTATION STEP: {len(base_unaccounted)} unaccounted failure(s) in the "
                "unmutated run; every failure must emit a signature or be a "
                f"recognised component mismatch: {sorted(base_unaccounted)[:3]}"
            )
            return 1

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
            # In the MUTANT run, unaccounted failures are the mutation's own
            # effect -- neutering a detector breaks tests that observe it -- and
            # are expected. A harness error is not, and must never stand in for
            # the predeclared delta.
            # The mutant's unaccounted failures are its own effect -- neutering
            # a detector breaks tests that observe it -- but "its own effect" is
            # KNOWABLE AND DECLARED, not waved through. Discarding this set let
            # any number of unrelated failures introduced only in the mutant run
            # be excused while the message still claimed an exact delta.
            mutant, mutant_errors, mutant_unaccounted = run_suite(
                tmpdir / "mut.json", tmpdir / "mut.xml", tmpdir / "mut-counts.json"
            )
        finally:
            source.write_text(original)

        try:
            check_delta(mutation, baseline, mutant, mutant_errors)
            unexpected = mutant_unaccounted - mutation.expected_unaccounted
            absent = mutation.expected_unaccounted - mutant_unaccounted
            if unexpected or absent:
                raise UnexpectedDelta(
                    f"{mutation.name}: mutant-only failures do not match the "
                    f"predeclared set; unexpected={sorted(unexpected)[:3]} "
                    f"absent={sorted(absent)[:3]}"
                )
        except Exception as exc:  # noqa: BLE001
            print(f"MUTATION STEP: {exc}")
            return 1

    print(f"MUTATION STEP: {mutation.name} produced exactly its predeclared delta")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
