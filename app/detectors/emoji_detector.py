from __future__ import annotations

import logging
import re
import unicodedata
from typing import Any

from .base import BaseDetector, DetectorResult

logger = logging.getLogger(__name__)

_EMOJI_PATTERN = re.compile(
    "["
    "\U0001f600-\U0001f64f"  # emoticons
    "\U0001f300-\U0001f5ff"  # symbols & pictographs
    "\U0001f680-\U0001f6ff"  # transport & map symbols
    "\U0001f1e0-\U0001f1ff"  # flags
    "\U00002702-\U000027b0"  # dingbats
    "\U000024c2-\U0001f251"  # enclosed characters
    "\U0000200d"  # zero width joiner
    "\U0000fe0f"  # variation selector
    "]+",
    re.UNICODE,
)


def _emoji_slug(char: str) -> str:
    """Derive a slug from the unicode name of the emoji character."""
    try:
        name = unicodedata.name(char, "")
        if name:
            return name.lower().replace(" ", "_").replace("-", "_")
    except (TypeError, ValueError):
        pass
    return "unknown"


class EmojiDetector(BaseDetector):
    """Detects emoji characters in text using regex."""

    def __init__(self, config: dict[str, Any]) -> None:
        super().__init__(config)

    @property
    def name(self) -> str:
        return "emoji"

    def scan(self, text: str, **kwargs: Any) -> DetectorResult:
        # release:component emoji/pattern_match -- the pattern ran over the text
        matches = _EMOJI_PATTERN.findall(text)

        if not matches:
            return DetectorResult(detected=False)

        emojis: list[dict[str, str]] = []
        seen: set[str] = set()
        for match in matches:
            for char in match:
                # Skip zero-width joiner and variation selector
                if char in ("\u200d", "\ufe0f"):
                    continue
                if char not in seen:
                    seen.add(char)
                    emojis.append(
                        {
                            "slug": _emoji_slug(char),
                            "char": char,
                        }
                    )

        if not emojis:
            return DetectorResult(detected=False)

        # release:component emoji/reported -- emoji found and carried into the result
        action = "blocked" if self.can_block else "reported"

        return DetectorResult(
            detected=True,
            data={
                "action": action,
                "emojis": emojis,
            },
        )
