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

#: The events a scan can be performed for.
EVENTS: tuple[str, ...] = ("input", "output", "tool_listing")

#: Which placements each leaf can legitimately occupy. A bare Cartesian
#: product would demand nonsensical pairs like `policy-name@tool-parameters`,
#: so the canonical domain is this relation.
APPLICABLE: dict[str, tuple[str, ...]] = {
    "random-canary": ("message-content",),
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


#: Which component/sub-path each (branch, detector) pair reaches.
#:
#: DECLARED, not derived from the source registry. Deriving it would make the
#: coverage oracle compare the source with a projection of itself and agree
#: unconditionally -- the circularity that made the first version of this
#: module vacuous.
REACHES: dict[tuple[str, str], tuple[str, str]] = {
    ("allow", "malicious_prompt"): ("malicious_prompt", "generic_injection_ml"),
    ("allow", "language"): ("scanner_engine", "applicability_skip"),
    ("allow", "code"): ("scanner_engine", "degraded"),
    ("report", "emoji"): ("scanner_engine", "value_reported_failure"),
    ("report", "competitors"): ("malicious_prompt", "custom_malicious_list"),
    ("allow", "competitors"): ("malicious_prompt", "custom_benign_list"),
    ("detector-block", "secret_and_key_entity"): ("scanner_engine", "exception_failure"),
    ("transform", "confidential_and_pii_entity"): ("malicious_prompt", "model_intent"),
    ("alert", "custom_entity"): ("malicious_prompt", "app_intent"),
    ("report", "malicious_entity"): ("topic", "topics_pipeline"),
    ("failure-block", "malicious_prompt"): ("topic", "toxicity_pipeline"),
    ("degraded", "topic"): ("topic", "both_pipelines_unavailable"),
    ("tool-listing", "mcp_validation"): ("mcp_validation", "scan"),
    ("access-rule-early-block", "none"): ("scanner_engine", "access_rule_early_block"),
}

#: Components reached by paths that are not guard evaluations at all: the
#: export destination boundary and the prompt-list match kinds. Without their
#: own cases the coverage oracle correctly reports them unreached.
STANDALONE: tuple[tuple[str, str, str, str], ...] = (
    ("credential-url", "export-target-config", "export_destination", "posture_unset"),
    ("credential-url", "export-target-config", "export_destination", "generic_address_policy"),
    ("credential-url", "export-target-config", "export_destination", "malformed_translation"),
    ("credential-url", "export-target-config", "export_destination", "embedded_address_policy"),
    ("unrecognised-confidential-sentence", "prompt-list-pattern", "prompt_list", "match_substring"),
    ("unrecognised-confidential-sentence", "prompt-list-pattern", "prompt_list", "match_exact"),
    ("unrecognised-confidential-sentence", "prompt-list-pattern", "prompt_list", "match_regex"),
)


def _collectors_for(capture: CaptureMode, placement: str) -> tuple[str, ...]:
    """The collector set a case must sweep, declared per case.

    Not defaulted: a case that silently stops declaring a collector must not
    keep its identity.
    """
    base = (
        "database",
        "http-response-body",
        "http-response-headers",
        "http-status",
        "app-log",
        "uvicorn-access-log",
        "uvicorn-error-log",
        "stderr",
        "artifact-bytes",
    )
    if placement in ("policy-name", "rule-set-detector-config", "prompt-list-pattern"):
        return base + (
            "browser-dom",
            "browser-state",
            "browser-storage",
            "browser-console",
            "browser-network",
        )
    if capture is CaptureMode.ON:
        return base + ("transport-bytes",)
    return base


def _paths_for(leaf: str) -> tuple[tuple[str, str, str], ...]:
    """(branch, detector, event) triples this leaf must exercise."""
    if leaf.startswith("mcp-"):
        return (("tool-listing", "mcp_validation", "tool_listing"),)
    if leaf == "access-rule-name":
        return (("access-rule-early-block", "none", "input"),)
    if leaf == "competitor-phrase":
        return (("report", "competitors", "input"), ("allow", "competitors", "input"))
    if leaf in ("aws-key", "bearer", "password"):
        return (("detector-block", "secret_and_key_entity", "input"),)
    if leaf in ("email", "ssn", "card"):
        return (("transform", "confidential_and_pii_entity", "input"),)
    if leaf == "custom-match":
        return (("alert", "custom_entity", "input"),)
    if leaf in ("credential-url", "query-url"):
        return (("report", "malicious_entity", "input"),)
    if leaf == "malicious-metadata":
        return (("failure-block", "malicious_prompt", "input"),)
    if leaf == "unrecognised-confidential-sentence":
        return (("degraded", "topic", "input"),)
    # The classifiers emit no exact value -- DetectorResult has no source/value
    # field -- so their cases rest on the evaluated-input witness. They are here
    # because "every detector" is declared, and a detector that reports nothing
    # is exactly the one whose omission nobody notices.
    return (
        ("allow", "malicious_prompt", "input"),
        ("allow", "language", "input"),
        ("allow", "code", "input"),
        ("report", "emoji", "output"),
    )


def _operation_for(placement: str) -> str:
    return {
        "access-rule-name": "access-rule-admin",
        "policy-name": "policy-admin",
        "prompt-list-pattern": "settings-admin",
        "export-target-config": "settings-admin",
        "threat-intelligence-config": "settings-admin",
        "rule-set-detector-config": "policy-admin",
        "model-intent-statement": "settings-admin",
    }.get(placement, "guard")


def _grant_for(placement: str) -> str:
    return "admin" if _operation_for(placement) != "guard" else "api"


def _build() -> tuple[Case, ...]:
    """The execution manifest, generated from the DOMAINS.

    From the domains, never from the cases -- an oracle comparing the cases
    with something derived from the cases agrees unconditionally.
    """
    cases: list[Case] = []
    for leaf in LEAVES:
        for placement in APPLICABLE[leaf]:
            for capture in (CaptureMode.OFF, CaptureMode.ON):
                for representation in REPRESENTATIONS:
                    for branch, detector, event in _paths_for(leaf):
                        component, sub_path = REACHES[(branch, detector)]
                        cases.append(
                            Case(
                                leaf=leaf,
                                placement=placement,
                                branch=branch,
                                detector=detector,
                                event=event,
                                component=component,
                                sub_path=sub_path,
                                capture=capture,
                                operation=_operation_for(placement),
                                grant=_grant_for(placement),
                                representation=representation,
                                collectors=_collectors_for(capture, placement),
                            )
                        )
    for leaf, placement, component, sub_path in STANDALONE:
        for capture in (CaptureMode.OFF, CaptureMode.ON):
            for representation in REPRESENTATIONS:
                cases.append(
                    Case(
                        leaf=leaf,
                        placement=placement,
                        branch="allow",
                        detector="none",
                        event="input",
                        component=component,
                        sub_path=sub_path,
                        capture=capture,
                        operation=_operation_for(placement),
                        grant=_grant_for(placement),
                        representation=representation,
                        collectors=_collectors_for(capture, placement),
                    )
                )
    return tuple(sorted(cases))


#: The manifest itself. Tasks 4-6 select from these rows.
CASES: tuple[Case, ...] = _build()
