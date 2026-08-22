"""Witnesses: proof that a case reached what it claims, before absence counts.

AN ABSENCE ASSERTION IS ONLY WORTH WHAT ITS WITNESS IS WORTH. "The canary is
not in the store" is equally true when the request was rejected at the router,
when the detector never ran, and when the collector was never invoked. Each of
those is a passing test measuring nothing.

So absence assertions are GATED. They run only when, FOR THIS CHAIN'S CALL ID:

  * `ingress` holds -- the value was received;
  * `outcome` holds -- the component ran and produced a result;
  * `collector_visited` holds -- the collector actually looked.

The call id is what makes those three about the same call. Matching an outcome
to an ingress by anything else lets a result from a different call satisfy the
gate, and the chain reads complete.

TWO BOUNDARY CLASSES, because they cannot share one gate. A path that ends
before any component is invoked -- malformed JSON, auth before body, role
denial, grant denial, unknown route, unknown method, unhandled failure -- has
no component, no call id and no detector outcome. Applying the chain gate to
it forces an implementer to fabricate a call id, skip the gate, or drop the
case. It takes a `BoundaryWitness` instead.

MODEL VALIDATION IS NOT IN THAT CLASS. A duplicate JSON key makes the raw body
and the effective value differ, which is the entire reason the 422 case
exists, so it carries the PARSER-SELECTED value and the validation location.
"""

from __future__ import annotations

from dataclasses import dataclass, field

#: A collector that reported nothing must say WHICH nothing.
EXAMINED = "examined"
EXAMINED_ZERO = "examined_zero"
NEVER_INVOKED = "never_invoked"

#: Paths that genuinely end before any component is invoked. Design section 6
#: requires role and grant denial here; a rewrite into two classes dropped
#: them once already.
UNPARSED_BOUNDARY_KINDS: frozenset[str] = frozenset(
    {
        "malformed-json",
        "auth-before-body",
        "role-denial",
        "grant-denial",
        "unknown-route",
        "unknown-method",
        "unhandled-failure",
    }
)


class WitnessMissing(Exception):
    """The gate refused: absence cannot be asserted for this case."""


@dataclass(frozen=True)
class Ingress:
    """The value as received at the boundary, for one call."""

    call_id: str
    value: str


@dataclass(frozen=True)
class Outcome:
    """The component's result, for one call."""

    call_id: str
    component: str
    result: str


@dataclass(frozen=True)
class CollectorResult:
    """What a collector saw, for one call, and whether it ran at all."""

    call_id: str
    collector: str
    status: str
    objects: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.status not in (EXAMINED, EXAMINED_ZERO, NEVER_INVOKED):
            raise ValueError(f"unknown collector status {self.status!r}")


@dataclass(frozen=True)
class WitnessChain:
    """A case that reached a component, with every field tied to one call id."""

    case_id: str
    effective_parsed_path: str
    effective_parsed_value: str
    component: str
    sub_path: str
    call_id: str
    consumed_field: str
    result: str
    response_consumer: str


@dataclass(frozen=True)
class BoundaryWitness:
    """A case that ended before any component ran.

    No component call id and no detector outcome, because there was neither.
    """

    case_id: str
    kind: str
    raw_asgi_request: bytes
    status: int
    exchange_id: str

    def __post_init__(self) -> None:
        if self.kind not in UNPARSED_BOUNDARY_KINDS:
            raise ValueError(
                f"{self.kind!r} is not an unparsed boundary kind; " f"known: {sorted(UNPARSED_BOUNDARY_KINDS)}"
            )


@dataclass(frozen=True)
class ValidationWitness:
    """Model validation: the PARSER-SELECTED value, not the raw body.

    A duplicate JSON key makes the two differ. Asserting on the raw body here
    checks a string the application never evaluated.
    """

    case_id: str
    parsed_value: str
    validation_location: str
    status: int
    exchange_id: str


@dataclass
class AbsenceEvaluator:
    """Instrumented, so a mutation that runs it when it should not is visible.

    Asserting only that a case fails cannot kill a gate mutation: a case with
    an absent witness already fails. What distinguishes correct code from the
    mutant is whether this was CALLED at all.
    """

    calls: list[str] = field(default_factory=list)

    def evaluate(self, case_id: str, found: bool) -> None:
        self.calls.append(case_id)
        if found:
            raise AssertionError(f"{case_id}: canary present where absence was asserted")

    def called_for(self, case_id: str) -> bool:
        return case_id in self.calls


def gate(
    chain: WitnessChain,
    *,
    ingress: Ingress | None,
    outcome: Outcome | None,
    collector: CollectorResult | None,
    declared_object_count: int,
) -> None:
    """Refuse unless all three witnesses hold FOR THIS CHAIN'S CALL ID."""
    if ingress is None:
        raise WitnessMissing(f"{chain.case_id}: no ingress witness")
    if outcome is None:
        raise WitnessMissing(f"{chain.case_id}: no outcome witness")
    if collector is None:
        raise WitnessMissing(f"{chain.case_id}: no collector witness")

    for name, witness_call_id in (
        ("ingress", ingress.call_id),
        ("outcome", outcome.call_id),
        ("collector", collector.call_id),
    ):
        if witness_call_id != chain.call_id:
            raise WitnessMissing(
                f"{chain.case_id}: {name} witness belongs to call " f"{witness_call_id!r}, chain is {chain.call_id!r}"
            )

    if outcome.component != chain.component:
        raise WitnessMissing(
            f"{chain.case_id}: outcome came from {outcome.component!r}, " f"chain declares {chain.component!r}"
        )

    if collector.status == NEVER_INVOKED:
        raise WitnessMissing(f"{chain.case_id}: collector never invoked")

    if collector.status == EXAMINED_ZERO and declared_object_count != 0:
        raise WitnessMissing(
            f"{chain.case_id}: collector examined zero objects but the declared "
            f"object set says {declared_object_count}"
        )


def assert_absent(
    chain: WitnessChain,
    *,
    ingress: Ingress | None,
    outcome: Outcome | None,
    collector: CollectorResult | None,
    declared_object_count: int,
    found: bool,
    evaluator: AbsenceEvaluator,
) -> None:
    """Gate first, then evaluate. Never the other way round."""
    gate(
        chain,
        ingress=ingress,
        outcome=outcome,
        collector=collector,
        declared_object_count=declared_object_count,
    )
    evaluator.evaluate(chain.case_id, found)
