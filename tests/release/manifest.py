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
    "artifact-bytes",
)


@dataclass(frozen=True, order=True)
class Case:
    """One row of the execution manifest, over the seven declared axes."""

    leaf: str
    placement: str
    component: str
    sub_path: str
    capture: CaptureMode
    operation: str
    grant: str
    representation: str
    collectors: tuple[str, ...]

    @property
    def identity(self) -> str:
        return (
            f"{self.leaf}@{self.placement}/{self.component}.{self.sub_path}"
            f"/{self.capture.value}/{self.operation}/{self.grant}/{self.representation}"
        )


#: Components this manifest exercises, as identity strings. Compared with the
#: generated inventory in both directions.
#:
#: MCP description and parameters carry a fact rather than coverage: the
#: detector reads only `function.name`, so nothing evaluates them. Recording
#: that as "not evaluated by this component" is honest; giving them a green
#: case would not be.
NOT_EVALUATED: dict[str, str] = {
    "mcp-description": "MCPValidationDetector reads only function.name",
    "mcp-parameters": "MCPValidationDetector reads only function.name",
}
