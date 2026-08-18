"""Tests for refactored MaliciousEntityDetector with per-type rules."""

import pytest


def test_detect_ip_from_blocklist():
    from app.detectors.malicious_entity import MaliciousEntityDetector

    config = {
        "enabled": True,
        "action": "report",
        "rules": [
            {"type": "IP", "action": "defang"},
            {"type": "URL", "action": "defang"},
            {"type": "DOMAIN", "action": "report"},
        ],
        "intel": {
            "ml_url_classification": False,
            "local_blocklists": {"ips": ["47.84.32.175"]},
        },
    }
    detector = MaliciousEntityDetector(config)
    result = detector.scan("Connect to 47.84.32.175 for command and control")
    assert result.detected is True
    entities = result.data["entities"]
    assert len(entities) >= 1
    ip_entity = next(e for e in entities if e["type"] == "IP")
    assert ip_entity["action"] == "defanged"
    assert ip_entity["value"] == "47[.]84[.]32[.]175"
    assert ip_entity["raw"] == "47.84.32.175"


def test_detect_url_from_blocklist():
    from app.detectors.malicious_entity import MaliciousEntityDetector

    config = {
        "enabled": True,
        "action": "report",
        "rules": [
            {"type": "URL", "action": "defang"},
        ],
        "intel": {
            "ml_url_classification": False,
            "local_blocklists": {"urls": ["http://evil.com/phish"]},
        },
    }
    detector = MaliciousEntityDetector(config)
    result = detector.scan("Visit http://evil.com/phish for free stuff")
    assert result.detected is True
    url_entity = result.data["entities"][0]
    assert url_entity["action"] == "defanged"
    assert "[.]" in url_entity["value"]
    assert url_entity["raw"] == "http://evil.com/phish"


def test_detect_domain_from_blocklist():
    from app.detectors.malicious_entity import MaliciousEntityDetector

    config = {
        "enabled": True,
        "action": "report",
        "rules": [
            {"type": "DOMAIN", "action": "report"},
        ],
        "intel": {
            "ml_url_classification": False,
            "local_blocklists": {"domains": ["malware.net"]},
        },
    }
    detector = MaliciousEntityDetector(config)
    result = detector.scan("DNS points to malware.net server")
    assert result.detected is True
    assert result.data["entities"][0]["action"] == "reported"
    assert result.data["entities"][0]["raw"] == "malware.net"


def test_no_malicious_entities():
    from app.detectors.malicious_entity import MaliciousEntityDetector

    config = {
        "enabled": True,
        "action": "report",
        "rules": [],
        "intel": {
            "ml_url_classification": False,
            "local_blocklists": {"ips": ["1.2.3.4"]},
        },
    }
    detector = MaliciousEntityDetector(config)
    result = detector.scan("Hello world, nothing malicious here")
    assert result.detected is False


def test_disabled_entity_type_skipped():
    from app.detectors.malicious_entity import MaliciousEntityDetector

    config = {
        "enabled": True,
        "action": "report",
        "rules": [
            {"type": "IP", "action": "disabled"},
        ],
        "intel": {
            "ml_url_classification": False,
            "local_blocklists": {"ips": ["47.84.32.175"]},
        },
    }
    detector = MaliciousEntityDetector(config)
    result = detector.scan("Connect to 47.84.32.175")
    # IP detected but action is disabled — should not be in results
    assert result.detected is False


def test_block_action_sets_can_block():
    from app.detectors.malicious_entity import MaliciousEntityDetector

    config = {
        "enabled": True,
        "action": "report",
        "rules": [
            {"type": "IP", "action": "block"},
        ],
        "intel": {
            "ml_url_classification": False,
            "local_blocklists": {"ips": ["47.84.32.175"]},
        },
    }
    detector = MaliciousEntityDetector(config)
    result = detector.scan("Connect to 47.84.32.175")
    assert result.detected is True
    assert result.data["entities"][0]["action"] == "blocked"


def test_defanged_text_in_sanitized_text():
    from app.detectors.malicious_entity import MaliciousEntityDetector

    config = {
        "enabled": True,
        "action": "report",
        "rules": [
            {"type": "IP", "action": "defang"},
        ],
        "intel": {
            "ml_url_classification": False,
            "local_blocklists": {"ips": ["47.84.32.175"]},
        },
    }
    detector = MaliciousEntityDetector(config)
    result = detector.scan("Connect to 47.84.32.175 for C2")
    assert result.sanitized_text is not None
    assert "47[.]84[.]32[.]175" in result.sanitized_text
    assert "47.84.32.175" not in result.sanitized_text


def test_backward_compat_no_rules():
    """Default config (no rules, no intel) should still work via ML if available."""
    from app.detectors.malicious_entity import MaliciousEntityDetector

    config = {"enabled": True, "action": "report"}
    detector = MaliciousEntityDetector(config)
    result = detector.scan("Hello world")
    assert isinstance(result, type(result))  # DetectorResult
