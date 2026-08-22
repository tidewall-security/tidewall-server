"""MCP Validation detector — structural checks on tool definitions.

Detects:
- Duplicate tool names (exact match)
- Similar tool names (above similarity threshold)

Only runs on tool_listing event type. On block, returns filtered_tools
listing which tools to remove. On report, logs issues only.

Injection detection in tool descriptions is handled by the existing
MaliciousPromptDetector when run on tool_listing events — this detector
only does structural validation.
"""

from __future__ import annotations

import logging
from difflib import SequenceMatcher
from typing import Any

from .base import BaseDetector, DetectorResult

logger = logging.getLogger(__name__)


class MCPValidationDetector(BaseDetector):
    """Structural validation of MCP tool definitions."""

    def __init__(self, config: dict[str, Any]) -> None:
        super().__init__(config)
        self._threshold = config.get("similarity_threshold", 0.8)

    @property
    def name(self) -> str:
        return "mcp_validation"

    # release:component mcp_validation/name_similarity -- reads function.name only
    def scan(self, text: str, **kwargs: Any) -> DetectorResult:
        tools = kwargs.get("tools", [])
        if not tools:
            return DetectorResult(detected=False)

        # Extract tool names
        names: list[tuple[str, dict]] = []
        for tool in tools:
            func = tool.get("function", {}) if isinstance(tool, dict) else {}
            name = func.get("name", "")
            if name:
                names.append((name, tool))

        if len(names) < 2:
            return DetectorResult(detected=False)

        issues: list[dict[str, Any]] = []
        flagged_tools: set[str] = set()

        # Check all pairs for similarity
        for i in range(len(names)):
            for j in range(i + 1, len(names)):
                name_a, _ = names[i]
                name_b, _ = names[j]

                similarity = SequenceMatcher(None, name_a.lower(), name_b.lower()).ratio()

                if similarity >= self._threshold:
                    issues.append(
                        {
                            "type": "duplicate_name",
                            "tools": [name_a, name_b],
                            "similarity": round(similarity, 4),
                            "detail": f"Tool names '{name_a}' and '{name_b}' are "
                            f"{'identical' if similarity == 1.0 else 'similar'} "
                            f"(similarity={similarity:.2f})",
                        }
                    )
                    flagged_tools.add(name_a)
                    flagged_tools.add(name_b)

        if not issues:
            return DetectorResult(detected=False)

        # Build response
        action_label = "blocked" if self.can_block else "reported"

        data: dict[str, Any] = {
            "action": action_label,
            "issues": issues,
            "similarity_threshold": self._threshold,
        }

        # On block: list the flagged tools for filtering
        if self.can_block:
            data["filtered_tools"] = sorted(flagged_tools)
        else:
            data["filtered_tools"] = []

        return DetectorResult(
            detected=True,
            data=data,
        )
