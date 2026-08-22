"""Generate the expected-failure manifest, fully expanded.

"At minimum" is incompatible with an exact baseline multiset: a baseline that
lists a defect CLASS cannot be compared against a run that produces concrete
signatures. So every record here is a full six-field signature plus an owner,
and the generator's exact output is checked in and reviewed.

The six fields are compared as a MULTISET. Two records differing only in
representation are two records, and a run producing one of them has not
reconciled.

OWNERS ARE A BLOCKED INPUT. An owner cannot be derived from source and must
not be invented by the implementer, so every record ships with the field
present and set to the sentinel below. The manifest is NOT claimed complete
until the project owner supplies names.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass

from tests.release.representations import FAMILIES

#: Not a name. A record carrying this is incomplete by construction, and the
#: oracle in test_expected_failures.py refuses to call the manifest complete
#: while any remain.
OWNER_UNASSIGNED = "<unassigned: blocked on project owner>"

#: Verified against source, not assumed. `POST /v1/guard` does not exist;
#: app/routes/guard.py:106-107 declares `/v1/guard_chat_completions`.
GUARD_ROUTE = "POST /v1/guard_chat_completions"


@dataclass(frozen=True)
class Record:
    case_id: str
    property: str
    collector: str
    surface_path: str
    representation: str
    occurrence_rule: str
    owner: str = OWNER_UNASSIGNED

    def signature(self) -> tuple:
        return (
            self.case_id,
            self.property,
            self.collector,
            self.surface_path,
            self.representation,
            self.occurrence_rule,
        )


FORBIDDEN_REACHED = "FORBIDDEN occurrence reached a surface"
REQUIRED_MISSING = "REQUIRED occurrence was never emitted"


def access_rule_records() -> list[Record]:
    """Three surfaces, not two.

    The creation log, the guard response `summary`, AND `result.access_rules`
    -- the third was missed once, and it is a distinct surface with a distinct
    collector path.
    """
    return [
        Record(
            case_id="access-rule-name/capture-off/create/admin/plain",
            property=FORBIDDEN_REACHED,
            collector="app-log",
            surface_path="app.services.access_rule_service:logger.info/created",
            representation="plain",
            occurrence_rule="FORBIDDEN",
        ),
        Record(
            case_id="access-rule-name/capture-off/guard/admin/plain",
            property=FORBIDDEN_REACHED,
            collector="http-response-body",
            surface_path=f"{GUARD_ROUTE} -> $.summary",
            representation="plain",
            occurrence_rule="FORBIDDEN",
        ),
        Record(
            case_id="access-rule-name/capture-off/guard/admin/plain#rules",
            property=FORBIDDEN_REACHED,
            collector="http-response-body",
            surface_path=f"{GUARD_ROUTE} -> $.result.access_rules[*] (key)",
            representation="plain",
            occurrence_rule="FORBIDDEN",
        ),
    ]


def matches_json_records(cases) -> list[Record]:
    """ONE RECORD PER APPLICABLE CASE, DETECTOR, PATH AND REPRESENTATION.

    Not one shared entry. A single record cannot be multiset-compared against
    a run that fails once per case, and it hides how much is missing.
    """
    from tests.release.manifest import EXACT_MATCH_DETECTORS, NOT_EVALUATED

    records = []
    for case in cases:
        if case.capture.value != "capture-on":
            continue
        # Only two detectors call `report_match`. A classifier's DetectorResult
        # carries no source/value field, so a matches_json REQUIRED record for
        # a classifier case MANUFACTURES A FAILURE FOR CORRECT BEHAVIOUR --
        # 2450 of them, in the first version of this generator.
        if case.detector not in EXACT_MATCH_DETECTORS:
            continue
        # A leaf this component never evaluates cannot have a required
        # occurrence of it. These are execution-manifest entries carrying
        # "not evaluated by this component", not expected failures.
        if (case.leaf, case.component, case.sub_path) in NOT_EVALUATED:
            continue
        for family in FAMILIES:
            records.append(
                Record(
                    case_id=f"{case.identity}#matches_json",
                    property=REQUIRED_MISSING,
                    collector="database",
                    surface_path="interactions.matches_json",
                    representation=family.name,
                    occurrence_rule="REQUIRED",
                )
            )
    return records


def validation_echo_records() -> list[Record]:
    """The 422 `detail[*].input` echo, per applicable representation.

    `app/models.py` declares the request models and there is no
    `RequestValidationError` handler, so FastAPI's default handler echoes the
    submitted value verbatim -- before any detector runs. Omitted entirely
    from an earlier draft.
    """
    return [
        Record(
            case_id=f"validation-echo/capture-off/guard/api/{family.name}",
            property=FORBIDDEN_REACHED,
            collector="http-response-body",
            surface_path=f"{GUARD_ROUTE} -> $.detail[*].input",
            representation=family.name,
            occurrence_rule="FORBIDDEN",
        )
        for family in FAMILIES
    ]


def generate(cases) -> list[Record]:
    records = access_rule_records() + matches_json_records(cases) + validation_echo_records()
    return sorted(records, key=lambda r: r.signature())


def render(records: list[Record]) -> str:
    lines = [
        "# GENERATED by tests/release/expected_failures.py -- checked in and reviewed.",
        "#",
        "# Each record is a full six-field signature plus an owner. Compared as a",
        "# MULTISET: two records differing only in representation are two records.",
        "#",
        "# OWNERS ARE BLOCKED on the project owner. Every record below carries the",
        "# unassigned sentinel, and the manifest is not claimed complete until they",
        "# are supplied.",
        "",
    ]
    for record in records:
        lines.append("[[expected_failure]]")
        for key, value in asdict(record).items():
            lines.append(f'{key:15s} = "{value}"')
        lines.append("")
    return "\n".join(lines)
