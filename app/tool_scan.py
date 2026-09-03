"""Scanning of MCP tool definitions.

An injection placed in a tool description reached no detector: ``guard.py``
builds the scanned text from messages, and tools arrive separately. Only the
structural validator read them, and it compares names.

This module extracts the model-readable text from each tool definition and
evaluates it, per tool, outside the engine's aggregate state machine — that
machine keeps one running text and one merged result, and a per-tool pass
cannot share it without later tools overwriting earlier findings.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

#: Bounds on one tool definition, enforced *during* the walk.
#:
#: A tree of enormous non-string scalars, or extreme nesting, does unbounded
#: structural work while staying far below any text limit, so the structure is
#: bounded as well as the text. Checking after a full walk would mean doing the
#: work first, which is what these exist to prevent.
#:
#: The numbers are ceilings on abuse, not tuning knobs: the largest real tool
#: definition measured extracts 243 tokens, and no observed server advertises
#: anything near this many tools.
MAX_TOOLS = 128
MAX_DEPTH = 32
MAX_NODES = 10_000
MAX_ARRAY_LENGTH = 1_000
MAX_KEYS = 1_000
MAX_STRING_LENGTH = 8_192
MAX_CHARACTERS = 16_384


class ToolScanRefusal(Exception):
    """A tool definition exceeded a declared bound.

    Deliberately not a detector failure. Routing it through
    ``on_detector_failure`` would not block, because that setting defaults to
    report — so an oversized definition would be passed uninspected, which is
    the bypass this refuses.
    """

    def __init__(self, index: int, reason: str) -> None:
        self.index = index
        self.reason = reason
        super().__init__(f"tool at index {index}: {reason}")


@dataclass(frozen=True)
class ToolFinding:
    """One tool's verdict. The tool is identified by position, never by name.

    Names are caller-supplied and may duplicate — the structural validator
    exists partly to flag exactly that — so a name would implicate the wrong
    tool. The index is assigned by the server from the received list.
    """

    index: int
    detected: bool
    detector: str
    confidence: float | None = None


def extract_tool_strings(tool: Any, index: int) -> list[str]:
    """Collect every string value and every object key from one definition.

    Returned separately, not joined. Joining them destroys the signal: the
    same injection that scores 0.999 alone scores 0.039 once the surrounding
    schema keywords are concatenated in front of it, which is far below any
    workable threshold. A scanner built that way walks everything and detects
    nothing.

    Not an allowlist of fields, either. JSON Schema carries model-readable text
    in ``enum``, ``const``, ``title``, ``default``, ``examples``, in property
    *names*, and in nested schemas reached through ``items``, ``$defs``,
    ``anyOf`` and friends -- and the request model accepts arbitrary extension
    keys, so no keyword list can be complete.

    The walk is iterative so a deeply nested definition cannot exhaust the
    interpreter stack before a bound fires.
    """
    parts: list[str] = []
    characters = 0
    nodes = 0
    keys = 0
    stack: list[tuple[Any, int]] = [(tool, 0)]

    while stack:
        node, depth = stack.pop()

        nodes += 1
        if nodes > MAX_NODES:
            raise ToolScanRefusal(index, f"definition visits more than {MAX_NODES} nodes")
        if depth > MAX_DEPTH:
            raise ToolScanRefusal(index, f"definition nests deeper than {MAX_DEPTH}")

        if isinstance(node, dict):
            for key, value in node.items():
                keys += 1
                if keys > MAX_KEYS:
                    raise ToolScanRefusal(index, f"definition carries more than {MAX_KEYS} keys")
                if isinstance(key, str):
                    characters = _collect(parts, key, characters, index)
                stack.append((value, depth + 1))

        elif isinstance(node, list):
            if len(node) > MAX_ARRAY_LENGTH:
                raise ToolScanRefusal(
                    index, f"definition contains an array longer than {MAX_ARRAY_LENGTH}"
                )
            for item in node:
                stack.append((item, depth + 1))

        elif isinstance(node, str):
            characters = _collect(parts, node, characters, index)

        # Numbers, booleans and nulls carry no model-readable text.

    return parts


def _collect(parts: list[str], text: str, characters: int, index: int) -> int:
    if len(text) > MAX_STRING_LENGTH:
        raise ToolScanRefusal(
            index, f"definition contains a string longer than {MAX_STRING_LENGTH} characters"
        )
    characters += len(text)
    if characters > MAX_CHARACTERS:
        raise ToolScanRefusal(
            index, f"definition extracts more than {MAX_CHARACTERS} characters of text"
        )
    parts.append(text)
    return characters


@dataclass(frozen=True)
class ToolScanOutcome:
    """Per-tool verdicts, plus any detector that could not deliver one."""

    findings: list[ToolFinding]
    failed_detectors: list[str]

    @property
    def detected(self) -> bool:
        return any(f.detected for f in self.findings)


def scan_tools(
    tools: list[Any],
    malicious_prompt: Any | None,
    hidden_instructions: Any | None,
    batch_size: int = 16,
) -> ToolScanOutcome:
    """Evaluate every tool definition, one verdict each.

    Each extracted string is judged on its own, and a tool is flagged if any of
    its strings is. Strings are de-duplicated across the whole listing before
    classification -- schema keywords repeat in every definition, so this is
    the difference between one inference and hundreds.

    Raises :class:`ToolScanRefusal` if a definition breaches a declared bound.
    That is a request-level refusal, not a detector failure: detector failures
    default to *report*, which would pass the uninspected definition through.

    Enforcement is explicit here rather than inherited from ``can_block``. The
    shipped policy configures hidden-instruction handling as redaction, and
    there is nothing to write a redaction back into -- a tool definition is not
    content returned to the caller.

    What this does not catch: an injection spread across several fields so that
    no single field reads as one. Each string is judged alone, which is what
    makes the detection work at all.
    """
    per_tool = [extract_tool_strings(tool, index) for index, tool in enumerate(tools)]
    findings: list[ToolFinding] = []
    failed: list[str] = []
    decided: set[int] = set()

    def _fail(name: str) -> None:
        if name not in failed:
            failed.append(name)

    if hidden_instructions is not None:
        for index, strings in enumerate(per_tool):
            for text in strings:
                try:
                    result = hidden_instructions.scan(text)
                except Exception:
                    _fail("hidden_instructions")
                    break
                if getattr(result, "detected", False):
                    findings.append(
                        ToolFinding(index=index, detected=True, detector="hidden_instructions")
                    )
                    decided.add(index)
                    break

    if malicious_prompt is None:
        return ToolScanOutcome(findings=sorted(findings, key=lambda f: f.index),
                               failed_detectors=failed)

    for index, strings in enumerate(per_tool):
        if index in decided:
            continue
        for text in strings:
            matched = malicious_prompt.matches_malicious_list(text)
            if matched is None:
                _fail("malicious_prompt")
                break
            if matched:
                findings.append(
                    ToolFinding(index=index, detected=True, detector="malicious_prompt",
                                confidence=1.0)
                )
                decided.add(index)
                break

    # Capacity is checked before classification, so a string too long to be read
    # in one pass is refused rather than truncated and scored.
    unique: dict[str, float] = {}
    for index, strings in enumerate(per_tool):
        if index in decided:
            continue
        for text in strings:
            if not text.strip():
                continue
            over = malicious_prompt.tool_text_exceeds_capacity(text)
            if over is None:
                _fail("malicious_prompt")
                return ToolScanOutcome(
                    findings=sorted(findings, key=lambda f: f.index), failed_detectors=failed
                )
            if over:
                raise ToolScanRefusal(
                    index, "definition contains text longer than the classifier can read at once"
                )
            unique[text] = 0.0

    if unique:
        texts = list(unique)
        try:
            scores = malicious_prompt.classify_tool_texts(texts, batch_size=batch_size)
        except Exception:
            _fail("malicious_prompt")
            return ToolScanOutcome(
                findings=sorted(findings, key=lambda f: f.index), failed_detectors=failed
            )
        unique.update(dict(zip(texts, scores, strict=True)))

        threshold = malicious_prompt.injection_threshold
        for index, strings in enumerate(per_tool):
            if index in decided:
                continue
            best = max((unique.get(t, 0.0) for t in strings if t.strip()), default=0.0)
            if best >= threshold:
                findings.append(
                    ToolFinding(index=index, detected=True, detector="malicious_prompt",
                                confidence=best)
                )

    return ToolScanOutcome(findings=sorted(findings, key=lambda f: f.index),
                           failed_detectors=failed)
