"""Extract IPs, URLs, and domains from text.

Deduplicates: domains inside URLs are not extracted separately.
IPs inside URLs are not extracted separately.
"""

from __future__ import annotations

import re
from typing import Any

# IPv4 pattern — 4 octets
_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")

# URL pattern — http:// or https://
_URL = re.compile(r"https?://[^\s<>\"']+")

# Domain pattern — word.word.tld (at least 2 dots or known TLDs)
_DOMAIN = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:[a-zA-Z]{2,})\b")

# Common non-domain words that match the domain regex
_DOMAIN_IGNORE = {"e.g", "i.e", "etc.com"}


def extract_entities(text: str) -> list[dict[str, Any]]:
    """Extract IPs, URLs, and domains from text with deduplication.

    Returns list of {"type": "IP"|"URL"|"DOMAIN", "value": str, "start_pos": int}
    """
    entities: list[dict[str, Any]] = []
    url_spans: list[tuple[int, int]] = []

    # 1. URLs first (highest priority)
    for match in _URL.finditer(text):
        entities.append(
            {
                "type": "URL",
                "value": match.group(0).rstrip(".,;:)"),
                "start_pos": match.start(),
            }
        )
        url_spans.append((match.start(), match.end()))

    def _inside_url(pos: int) -> bool:
        return any(s <= pos < e for s, e in url_spans)

    # 2. IPs (skip if inside a URL)
    for match in _IPV4.finditer(text):
        if not _inside_url(match.start()):
            entities.append(
                {
                    "type": "IP",
                    "value": match.group(0),
                    "start_pos": match.start(),
                }
            )

    # 3. Domains (skip if inside a URL or matches an IP)
    ip_values = {e["value"] for e in entities if e["type"] == "IP"}
    for match in _DOMAIN.finditer(text):
        value = match.group(0)
        if _inside_url(match.start()):
            continue
        if value in ip_values:
            continue
        if value.lower() in _DOMAIN_IGNORE:
            continue
        # Must have at least one dot and not be just numbers
        if "." not in value:
            continue
        parts = value.split(".")
        if all(p.isdigit() for p in parts):
            continue  # It's an IP, not a domain
        entities.append(
            {
                "type": "DOMAIN",
                "value": value,
                "start_pos": match.start(),
            }
        )

    return entities
