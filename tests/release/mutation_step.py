"""The out-of-tree mutation step: compare to the BASELINE, never to an exit code.

A non-zero exit proves a mutant broke something. It does not prove the mutant
broke THE THING THE GATE IS FOR, and while the baseline is red every run exits
non-zero anyway -- so "the suite failed" carries no information at all.

So the step compares SIGNATURE MULTISETS:

  1. the unmutated run must produce EXACTLY the baseline multiset -- not a
     superset, not "the baseline plus some noise", because a run that already
     fails in an unrecorded way cannot attribute a later delta to the mutant;
  2. the mutation must be PROVEN APPLIED -- an edit that silently failed to
     match produces an identical multiset, which reads as a surviving mutant;
  3. the mutant run must add EXACTLY ONE predeclared novel signature;
  4. NO HARNESS ERROR MAY SUBSTITUTE. A collection failure changes the
     multiset too, and counting it as the expected delta means the mutation
     was never actually exercised.

While the baseline is red, the mutation is chosen so its delta falls OUTSIDE
the baseline -- otherwise the new signature is indistinguishable from a
record that was already there.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass


class MutationNotApplied(Exception):
    """The edit did not match, so nothing was mutated."""


class BaselineMismatch(Exception):
    """The unmutated run did not reproduce the baseline multiset."""


class UnexpectedDelta(Exception):
    """The mutant's delta was not exactly the predeclared signature."""


class HarnessErrorSubstituted(Exception):
    """A harness error stood in for the expected delta."""


@dataclass(frozen=True)
class Mutation:
    """One named edit, with the signature it is predicted to add."""

    name: str
    path: str
    old: str
    new: str
    expected_signature: tuple

    def apply(self, source: str) -> str:
        if self.old not in source:
            raise MutationNotApplied(f"{self.name}: anchor not found in {self.path}")
        if source.count(self.old) != 1:
            raise MutationNotApplied(f"{self.name}: anchor matches {source.count(self.old)} times in {self.path}")
        return source.replace(self.old, self.new, 1)


def verify_applied(mutation: Mutation, before: str, after: str) -> None:
    """An edit that silently failed reads exactly like a surviving mutant."""
    if before == after:
        raise MutationNotApplied(f"{mutation.name}: source unchanged after applying")


def check_baseline(observed: Counter, baseline: Counter) -> None:
    if observed != baseline:
        extra = observed - baseline
        missing = baseline - observed
        raise BaselineMismatch(
            f"unmutated run does not reproduce the baseline; "
            f"extra={sorted(extra)[:3]} missing={sorted(missing)[:3]}"
        )


def check_delta(
    mutation: Mutation,
    baseline: Counter,
    mutant: Counter,
    harness_errors: int,
) -> None:
    """Exactly one predeclared novel signature, and nothing standing in for it."""
    if harness_errors:
        raise HarnessErrorSubstituted(
            f"{mutation.name}: {harness_errors} harness error(s) in the mutant run; " "the mutation was not exercised"
        )

    delta = mutant - baseline
    if delta != Counter({mutation.expected_signature: 1}):
        raise UnexpectedDelta(
            f"{mutation.name}: expected exactly {mutation.expected_signature}, " f"got {sorted(delta.items())[:3]}"
        )

    lost = baseline - mutant
    if lost:
        raise UnexpectedDelta(
            f"{mutation.name}: the mutant also REMOVED {sorted(lost)[:3]}; "
            "a delta that both adds and removes is not one novel signature"
        )


def delta_is_outside_baseline(mutation: Mutation, baseline: Counter) -> bool:
    """While the baseline is red, the delta must not already be in it."""
    return mutation.expected_signature not in baseline
