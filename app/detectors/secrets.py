"""Secrets detector — scans text for API keys, tokens, etc.

Uses the ``detect-secrets`` library. Each plugin is a single-purpose secret
detector (e.g. AWS key, GitHub token, JWT). We run the full default plugin set
and replace every detected span with ``[REDACTED]`` so downstream code doesn't
see secrets.

The detect-secrets API is line-oriented: ``scan_line()`` yields
``PotentialSecret`` objects whose ``.secret_value`` is the raw match.
We replace each value with the literal token ``[REDACTED]`` and record the
position in the sanitized output for downstream processing.
"""

from __future__ import annotations

import logging
from typing import Any

from app.services.redactor import Redactor

from .base import BaseDetector, DetectorResult, FailureCode

logger = logging.getLogger(__name__)


class SecretsDetector(BaseDetector):
    """Detects API keys / secrets via the detect-secrets library."""

    def __init__(self, config: dict[str, Any]) -> None:
        super().__init__(config)
        # Per-rule overrides (e.g. action="hash" for API_KEY) — we look up by type.
        self._rules = {r["type"]: r for r in config.get("rules", [])}
        self._redactor = Redactor()
        # detect-secrets plugin set. The high-entropy detectors
        # (``Base64HighEntropyString``, ``HexHighEntropyString``) and
        # ``KeywordDetector`` are intentionally excluded: they were designed
        # for source-code scanning where short tokens are rare, and they
        # over-fire on natural-language prompts (every word looks high-entropy
        # to detect-secrets' defaults). Pattern-based vendor detectors below
        # cover the realistic API-key shapes our users will paste.
        # release:component secrets/plugin_set -- eighteen plugins, each a distinct value shape
        self._plugins = [
            {"name": "AWSKeyDetector"},
            {"name": "AzureStorageKeyDetector"},
            {"name": "BasicAuthDetector"},
            {"name": "CloudantDetector"},
            {"name": "DiscordBotTokenDetector"},
            {"name": "GitHubTokenDetector"},
            {"name": "IbmCloudIamDetector"},
            {"name": "IbmCosHmacDetector"},
            {"name": "JwtTokenDetector"},
            {"name": "MailchimpDetector"},
            {"name": "NpmDetector"},
            {"name": "PrivateKeyDetector"},
            {"name": "SendGridDetector"},
            {"name": "SlackDetector"},
            {"name": "SoftlayerDetector"},
            {"name": "SquareOAuthDetector"},
            {"name": "StripeDetector"},
            {"name": "TwilioKeyDetector"},
        ]

    @property
    def name(self) -> str:
        return "secrets"

    def scan(self, text: str, **kwargs: Any) -> DetectorResult:
        try:
            from detect_secrets.core.scan import scan_line
            from detect_secrets.settings import transient_settings
        except ImportError:
            logger.warning("detect-secrets not installed — SecretsDetector unavailable")
            return DetectorResult.failed(FailureCode.DEPENDENCY_MISSING)

        sanitized_lines: list[str] = []
        # Tracks position in sanitized output of each [REDACTED] token we
        # insert. Built during the same pass that does the replacement so we
        # never have to re-scan; this avoids the false-positive that arises
        # when user input legitimately contains the literal [REDACTED] string.
        sanitized_offset = 0
        entities: list[dict[str, Any]] = []

        with transient_settings({"plugins_used": self._plugins}):
            for line in text.splitlines(keepends=True):
                redacted_line = line
                for secret in scan_line(line):
                    if not secret.secret_value:
                        continue
                    rule = self._rules.get("API_KEY", {"action": "replacement"})
                    redaction = self._redactor.redact("[REDACTED]", "API_KEY", rule)
                    # Walk every occurrence of this secret in the line. Required
                    # because detect-secrets dedupes by value/hash and yields
                    # each unique secret only once even if it appears multiple
                    # times in the input — without this loop, repeated copies
                    # of the same key would leak through unredacted.
                    search_from = 0
                    while True:
                        idx = redacted_line.find(secret.secret_value, search_from)
                        if idx == -1:
                            break
                        # start_pos is the position in the final sanitized
                        # output: this line's offset plus the match offset.
                        entities.append(
                            {
                                "type": "API_KEY",
                                "value": redaction["redacted"],
                                "action": redaction["action_label"],
                                "start_pos": sanitized_offset + idx,
                            }
                        )
                        redacted_line = (
                            redacted_line[:idx] + "[REDACTED]" + redacted_line[idx + len(secret.secret_value) :]
                        )
                        # Advance past the just-inserted [REDACTED] so we don't
                        # match the same span again on the next iteration.
                        search_from = idx + len("[REDACTED]")
                sanitized_lines.append(redacted_line)
                sanitized_offset += len(redacted_line)

        if not entities:
            return DetectorResult(detected=False)

        sanitized = "".join(sanitized_lines)
        return DetectorResult(
            detected=True,
            data={"entities": entities},
            sanitized_text=sanitized,
        )
