"""Redaction service — applies per-entity-type redaction methods.

Supports: replacement, mask, partial_mask, hash, defang, report.
FPE (format-preserving encryption) is deferred to Phase 7a.
"""

from __future__ import annotations

import hashlib
from typing import Any


class Redactor:
    """Applies redaction to a detected entity value based on its rule config."""

    def __init__(self, fpe_service: Any = None) -> None:
        self._fpe_service = fpe_service

    def redact(
        self,
        value: str,
        entity_type: str,
        rule: dict[str, Any],
    ) -> dict[str, Any]:
        """Redact a single entity value according to its rule.

        Args:
            value: The original detected value (e.g., "234-56-7890")
            entity_type: The entity type (e.g., "US_SSN")
            rule: Per-entity-type rule config with at least {"action": "..."}

        Returns:
            Dict with "redacted" (new value), "action_label" (AIDR-style export format),
            and "original" (the input value).
        """
        action = rule.get("action", "replacement")

        if action == "replacement":
            replacement_value = rule.get("replacement_value", f"<{entity_type}>")
            return {"redacted": replacement_value, "action_label": "redacted:replaced", "original": value}

        elif action == "mask":
            mask_char = rule.get("mask_char", "*")
            return {"redacted": mask_char * len(value), "action_label": "redacted:masked", "original": value}

        elif action == "partial_mask":
            return self._partial_mask(value, rule)

        elif action == "hash":
            salt = rule.get("salt", "")
            hashed = hashlib.sha256(f"{value}{salt}".encode()).hexdigest()[:12]
            return {"redacted": hashed, "action_label": "redacted:hashed", "original": value}

        elif action == "fpe":
            if self._fpe_service is None:
                replacement_value = rule.get("replacement_value", f"<{entity_type}>")
                return {"redacted": replacement_value, "action_label": "redacted:replaced", "original": value}
            radix = 10 if value.replace("-", "").replace(" ", "").replace("(", "").replace(")", "").isdigit() else 36
            encrypted, fpe_ctx = self._fpe_service.encrypt(value, radix=radix)
            return {
                "redacted": encrypted,
                "action_label": "redacted:encrypted",
                "original": value,
                "fpe_context": fpe_ctx,
            }

        elif action == "defang":
            return self._defang(value, entity_type)

        elif action == "report":
            return {"redacted": value, "action_label": "reported", "original": value}

        else:
            # Unknown action — fall back to replacement
            return {"redacted": f"<{entity_type}>", "action_label": "redacted:replaced", "original": value}

    def _partial_mask(self, value: str, rule: dict[str, Any]) -> dict[str, Any]:
        """Mask characters, preserving left/right unmasked and ignoring specified chars."""
        mask_char = rule.get("mask_char", "*")
        unmasked_left = rule.get("unmasked_left", 0)
        unmasked_right = rule.get("unmasked_right", 0)
        chars_to_ignore = set(rule.get("chars_to_ignore", ""))

        chars = list(value)
        maskable_indices = [i for i, c in enumerate(chars) if c not in chars_to_ignore]

        # Determine which maskable positions to mask
        mask_start = unmasked_left
        mask_end = len(maskable_indices) - unmasked_right

        for idx, pos in enumerate(maskable_indices):
            if mask_start <= idx < mask_end:
                chars[pos] = mask_char

        return {"redacted": "".join(chars), "action_label": "redacted:masked", "original": value}

    def _defang(self, value: str, entity_type: str) -> dict[str, Any]:
        """Defang IPs, URLs, and domains by inserting brackets around dots."""
        if entity_type in ("IP", "IP_ADDRESS"):
            defanged = value.replace(".", "[.]")
        elif entity_type in ("URL",):
            # Defang dots in the domain portion, not the path
            # Split on :// first
            if "://" in value:
                scheme, rest = value.split("://", 1)
                if "/" in rest:
                    domain, path = rest.split("/", 1)
                    defanged = f"{scheme}://{domain.replace('.', '[.]')}/{path}"
                else:
                    defanged = f"{scheme}://{rest.replace('.', '[.]')}"
            else:
                defanged = value.replace(".", "[.]")
        else:
            # DOMAIN and everything else
            defanged = value.replace(".", "[.]")

        return {"redacted": defanged, "action_label": "defanged", "original": value}
