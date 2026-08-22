"""The execution manifest: what the release suite must exercise.

Declared here, independently of the code that runs it. Two oracles compare it
against reality, and they are separate on purpose:

1. **Components** — every `# release:component` marker in `app/` must appear
   here, and every component here must exist in the source. Deleting an
   arbitrary case cannot be caught by this one, because many cases share a
   component; deleting the *last* case for a component can.
2. **Leaf/placement product** — the canonical domain of canary leaves and
   ingress placements, declared here as its own data. Without a domain that
   exists independently of the case list, collapsing a slash-group leaf
   collapses the manifest and its selector together and nothing fails.

The grouped kinds in the spec (`bearer/password`, `SSN/card`,
`MCP name/description/parameters`) are enumerated as **separate leaves**. A
singular `Canary(kind, ...)` exercising one member of a slash group looks
complete and is not.
"""

from __future__ import annotations

import pathlib
import tomllib
from dataclasses import dataclass
from enum import Enum


class CaptureMode(str, Enum):
    OFF = "capture-off"
    ON = "capture-on"


#: Every canary leaf. Slash groups in the spec are separate entries here.
LEAVES: tuple[str, ...] = (
    "random-canary",
    "aws-key",
    "bearer",  # bearer/password is two leaves
    "password",
    "email",
    "ssn",  # SSN/card is two leaves
    "card",
    "credential-url",
    "query-url",
    "custom-match",
    "competitor-phrase",
    "mcp-name",  # MCP name/description/parameters is three leaves
    "mcp-description",
    "mcp-parameters",
    "malicious-metadata",
    "access-rule-name",
    "unrecognised-confidential-sentence",
)

#: Where a leaf can enter. Declared independently of the cases, so a case list
#: that quietly stops covering a placement fails the product oracle.
PLACEMENTS: tuple[str, ...] = (
    "message-content",
    "tool-name",
    "tool-description",
    "tool-parameters",
    "caller-metadata",
    "access-rule-name",
    "prompt-list-pattern",
    "export-target-config",
    "model-intent-statement",
    "policy-name",
    "rule-set-detector-config",
    "threat-intelligence-config",
)

#: Every branch the suite must reach. Named here rather than emerging from the
#: cases, or a suite can omit one entirely and still equal a leaf x surface
#: product.
BRANCHES: tuple[str, ...] = (
    "allow",
    "report",
    "alert",
    "detector-block",
    "transform",
    "degraded",
    "failure-block",
    "tool-listing",
    "access-rule-early-block",
)

#: Every detector the engine can run, from ScannerEngine._DETECTOR_REGISTRY.
#: "Every branch" and "every detector" are different claims: BRANCHES lists
#: outcomes, this lists the components that produce them.
DETECTORS: tuple[str, ...] = (
    "malicious_prompt",
    "mcp_validation",
    "confidential_and_pii_entity",
    "secret_and_key_entity",
    "custom_entity",
    "malicious_entity",
    "topic",
    "language",
    "code",
    "competitors",
    "emoji",
)

#: Operations a case can run under, and the grants they require. Both are in
#: Case.identity, and neither had a domain -- an invented operation passed
#: every test.
OPERATIONS: tuple[str, ...] = (
    "guard",
    "access-rule-admin",
    "policy-admin",
    "settings-admin",
    "content-export",
)

GRANTS: tuple[str, ...] = ("api", "admin", "content:export")

#: The events a scan can be performed for.
EVENTS: tuple[str, ...] = ("input", "output", "tool_listing")

#: Which placements each leaf can legitimately occupy. A bare Cartesian
#: product would demand nonsensical pairs like `policy-name@tool-parameters`,
#: so the canonical domain is this relation.
APPLICABLE: dict[str, tuple[str, ...]] = {
    # A random value is legitimate in any control-plane field an operator
    # types into, which is why it is the leaf used to probe them.
    "random-canary": ("message-content", "policy-name", "model-intent-statement"),
    "aws-key": ("message-content",),
    "bearer": ("message-content", "caller-metadata"),
    "password": ("message-content",),
    "email": ("message-content",),
    "ssn": ("message-content",),
    "card": ("message-content",),
    "credential-url": ("message-content", "export-target-config"),
    "query-url": ("message-content", "threat-intelligence-config"),
    "custom-match": ("message-content", "rule-set-detector-config"),
    "competitor-phrase": ("message-content", "rule-set-detector-config"),
    "mcp-name": ("tool-name",),
    "mcp-description": ("tool-description",),
    "mcp-parameters": ("tool-parameters",),
    "malicious-metadata": ("caller-metadata",),
    "access-rule-name": ("access-rule-name",),
    "unrecognised-confidential-sentence": ("message-content", "prompt-list-pattern"),
}

#: Representation families. Each needs its own decoder and its own positive
#: detection at every applicable surface -- a plain-text plant does not prove
#: the \uXXXX decoder works.
REPRESENTATIONS: tuple[str, ...] = (
    "plain",
    "json-escaped",
    "unicode-escaped",
    "raw-bytes",
    "nfc",
    "nfd",
    "percent-encoded",
)

#: Collectors a case can declare. The set is part of a case's identity: a case
#: that silently stops declaring a collector must not look the same.
COLLECTORS: tuple[str, ...] = (
    "database",
    "http-response-body",
    "http-response-headers",
    "http-status",
    "app-log",
    "uvicorn-access-log",
    "uvicorn-error-log",
    "transport-bytes",
    "browser-dom",
    "browser-state",
    "browser-storage",
    "browser-console",
    "browser-network",
    "stderr",
    "artifact-bytes",
)


@dataclass(frozen=True, order=True)
class Case:
    """One row of the execution manifest, over all seven declared axes.

    The third axis is `branch/detector/event` **and** component/sub-path --
    five fields, not two. Without `branch`, `detector` and `event` the manifest
    cannot say "every detector", and cannot distinguish the same component path
    reached under input, output and tool-listing events.
    """

    leaf: str
    placement: str
    branch: str
    detector: str
    event: str
    component: str
    sub_path: str
    capture: CaptureMode
    operation: str
    grant: str
    representation: str
    collectors: tuple[str, ...]

    @property
    def identity(self) -> str:
        """Includes the collector set, which this module says is part of identity.

        Omitting it gave the same identity to two rows differing only because
        one silently stopped declaring `database`, a log selector, transport or
        browser collection -- the drift the manifest exists to expose.
        """
        collectors = "+".join(sorted(self.collectors))
        return (
            f"{self.leaf}@{self.placement}"
            f"/{self.branch}.{self.detector}.{self.event}"
            f"/{self.component}.{self.sub_path}"
            f"/{self.capture.value}/{self.operation}/{self.grant}/{self.representation}"
            f"/[{collectors}]"
        )


#: Components this manifest exercises, as identity strings. Compared with the
#: generated inventory in both directions.
#:
#: MCP description and parameters carry a fact rather than coverage: the
#: detector reads only `function.name`, so nothing evaluates them. Recording
#: that as "not evaluated by this component" is honest; giving them a green
#: case would not be.
#: Keyed by (leaf, component, sub_path), because the fact is about a COMPONENT
#: not reading a leaf. Keyed by leaf alone it would stay true-looking if some
#: other component began evaluating MCP descriptions tomorrow.
NOT_EVALUATED: dict[tuple[str, str, str], str] = {
    ("mcp-description", "mcp_validation", "scan"): "reads only function.name",
    ("mcp-parameters", "mcp_validation", "scan"): "reads only function.name",
}


#: Detectors that can put an exact value in `matches_json`.
#:
#: Measured, not assumed: only these two call `report_match`. A classifier's
#: DetectorResult has no source/value field, so a matches_json REQUIRED rule
#: for a classifier case manufactures a failure for correct behaviour.
EXACT_MATCH_DETECTORS: frozenset[str] = frozenset({"confidential_and_pii_entity", "custom_entity"})


def report_match_callers() -> frozenset[str]:
    """Which detector modules actually call `report_match`, read from source.

    The constant above was a hand-copied measurement, and a test comparing the
    constant to the same hardcoded pair could never notice production changing.
    This reads the tree, so wiring a third detector fails the drift check.
    """
    import pathlib as _p

    root = _p.Path(__file__).resolve().parents[2] / "app" / "detectors"
    module_to_detector = {
        "pii": "confidential_and_pii_entity",
        "custom_entity": "custom_entity",
        "secrets": "secret_and_key_entity",
        "malicious_prompt": "malicious_prompt",
        "malicious_entity": "malicious_entity",
        "competitors": "competitors",
        "topic": "topic",
        "language": "language",
        "code": "code",
        "emoji_detector": "emoji",
        "mcp_validation": "mcp_validation",
    }
    found = set()
    for path in root.glob("*.py"):
        if "report_match" in path.read_text():
            name = module_to_detector.get(path.stem)
            if name:
                found.add(name)
    return frozenset(found)


def registry_detectors() -> tuple[str, ...]:
    """The detector names production can run, read from _DETECTOR_REGISTRY."""
    import pathlib as _p
    import re as _re

    source = (_p.Path(__file__).resolve().parents[2] / "app" / "scanner_engine.py").read_text()
    block = source[source.index("_DETECTOR_REGISTRY") :]
    block = block[: block.index("\n}")]
    return tuple(_re.findall(r'^\s+"([a-z_]+)":', block, _re.M))


def source_event_scoping() -> dict[str, str]:
    """The event-scoped detectors, read from `_detector_applies`."""
    import pathlib as _p
    import re as _re

    source = (_p.Path(__file__).resolve().parents[2] / "app" / "scanner_engine.py").read_text()
    body = source[source.index("def _detector_applies") :]
    body = body[: body.index("\ndef ", 1)]
    return dict(_re.findall(r'if name == "([a-z_]+)":\s*\n\s*return event_type == "([a-z_]+)"', body))


#: Event scoping, from `_detector_applies`. Two detectors are event-scoped and
#: a case that pairs them with the wrong event cannot invoke them at all.
EVENT_SCOPED: dict[str, str] = {
    "malicious_entity": "output",
    "mcp_validation": "tool_listing",
}


def applicable_events(detector: str) -> tuple[str, ...]:
    scoped = EVENT_SCOPED.get(detector)
    return (scoped,) if scoped else EVENTS


#: The manifest is CHECKED-IN DATA, in manifest.cases.toml, not generated here.
#:
#: The previous version generated cases from the same domains the oracles then
#: compared them against, so every comparison was equality by construction:
#: deleting `nfd` from REPRESENTATIONS removed it from the declared set and
#: from every generated case at once, and all seventeen tests passed.
#:
#: It also carried a `REACHES` table that assigned unrelated code to each
#: (branch, detector) pair purely so the coverage oracle would report
#: everything covered -- competitors cases attributed to malicious-prompt's
#: prompt-list branches, PII transforms to model-intent, and 56 rows giving
#: malicious_entity an `input` event it can never run under. That was data
#: written to satisfy a test rather than to describe production.
#:
#: Cases now live in a file no generator writes. A domain change does not move
#: them, so the comparison fails until someone deliberately edits both -- a
#: two-file diff a reviewer sees.
CASES_FILE = pathlib.Path(__file__).resolve().parent / "manifest.cases.toml"


def load_cases() -> tuple[Case, ...]:
    """The checked-in cases. No fallback: an unreadable manifest is a failure."""
    data = tomllib.loads(CASES_FILE.read_text())
    return tuple(
        sorted(
            Case(
                leaf=row["leaf"],
                placement=row["placement"],
                branch=row["branch"],
                detector=row["detector"],
                event=row["event"],
                component=row["component"],
                sub_path=row["sub_path"],
                capture=CaptureMode(row["capture"]),
                operation=row["operation"],
                grant=row["grant"],
                representation=row["representation"],
                collectors=tuple(row["collectors"]),
            )
            for row in data["case"]
        )
    )


CASES: tuple[Case, ...] = load_cases()
