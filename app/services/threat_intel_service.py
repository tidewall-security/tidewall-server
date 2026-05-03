"""Threat intelligence service — local blocklists + external API checks.

Checks entities against configured blocklists and optional external
threat intelligence APIs (URLhaus, OTX). External APIs are deferred
to a future enhancement — this implementation covers local blocklists.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


class ThreatIntelService:
    """Checks IPs, URLs, and domains against threat intelligence sources."""

    def __init__(self, config: dict[str, Any]) -> None:
        blocklists = config.get("local_blocklists", {})
        self._blocked_ips: set[str] = set(blocklists.get("ips", []))
        self._blocked_domains: list[str] = blocklists.get("domains", [])
        self._blocked_urls: set[str] = set(blocklists.get("urls", []))

        # External API config (stubs — actual API calls are a future enhancement)
        self._urlhaus_enabled = config.get("builtin", {}).get("urlhaus", False)
        self._otx_enabled = config.get("builtin", {}).get("otx", {}).get("enabled", False)

    def is_malicious(self, value: str, entity_type: str) -> bool:
        """Check if an entity is malicious against all configured sources.

        Args:
            value: The entity value (IP, URL, or domain)
            entity_type: "IP", "URL", or "DOMAIN"

        Returns:
            True if the entity matches any blocklist or threat intel source.
        """
        if entity_type == "IP":
            return self._check_ip(value)
        elif entity_type == "URL":
            return self._check_url(value)
        elif entity_type == "DOMAIN":
            return self._check_domain(value)
        return False

    def _check_ip(self, ip: str) -> bool:
        """Check IP against local blocklist."""
        if ip in self._blocked_ips:
            return True
        # CIDR matching (basic — /8, /16, /24)
        for blocked in self._blocked_ips:
            if "/" in blocked:
                if self._cidr_match(ip, blocked):
                    return True
        return False

    def _check_url(self, url: str) -> bool:
        """Check URL against local blocklist."""
        return url in self._blocked_urls

    def _check_domain(self, domain: str) -> bool:
        """Check domain against local blocklist with wildcard support."""
        domain_lower = domain.lower()
        for pattern in self._blocked_domains:
            pattern_lower = pattern.lower()
            if pattern_lower.startswith("*."):
                # Wildcard: *.evil.com matches sub.evil.com, deep.sub.evil.com
                suffix = pattern_lower[1:]  # .evil.com
                if domain_lower.endswith(suffix) and domain_lower != suffix.lstrip("."):
                    return True
            elif domain_lower == pattern_lower:
                return True
        return False

    @staticmethod
    def _cidr_match(ip: str, cidr: str) -> bool:
        """CIDR matching using the standard library ipaddress module."""
        import ipaddress

        try:
            return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            return False
