"""Tests for ThreatIntelService — local blocklists and external checks."""

import pytest


def test_empty_blocklists_no_match():
    from app.services.threat_intel_service import ThreatIntelService

    svc = ThreatIntelService(config={})
    assert svc.is_malicious("192.168.1.1", "IP") is False
    assert svc.is_malicious("http://safe.com", "URL") is False
    assert svc.is_malicious("safe.com", "DOMAIN") is False


def test_local_ip_blocklist_match():
    from app.services.threat_intel_service import ThreatIntelService

    svc = ThreatIntelService(config={"local_blocklists": {"ips": ["192.168.1.1", "10.0.0.0/8"]}})
    assert svc.is_malicious("192.168.1.1", "IP") is True
    assert svc.is_malicious("192.168.1.2", "IP") is False


def test_local_domain_blocklist_match():
    from app.services.threat_intel_service import ThreatIntelService

    svc = ThreatIntelService(config={"local_blocklists": {"domains": ["evil.com", "*.malware.net"]}})
    assert svc.is_malicious("evil.com", "DOMAIN") is True
    assert svc.is_malicious("sub.malware.net", "DOMAIN") is True
    assert svc.is_malicious("safe.com", "DOMAIN") is False


def test_local_url_blocklist_match():
    from app.services.threat_intel_service import ThreatIntelService

    svc = ThreatIntelService(config={"local_blocklists": {"urls": ["http://phishing.example.com/login"]}})
    assert svc.is_malicious("http://phishing.example.com/login", "URL") is True
    assert svc.is_malicious("http://safe.example.com", "URL") is False


def test_domain_wildcard_matching():
    from app.services.threat_intel_service import ThreatIntelService

    svc = ThreatIntelService(config={"local_blocklists": {"domains": ["*.evil.com"]}})
    assert svc.is_malicious("sub.evil.com", "DOMAIN") is True
    assert svc.is_malicious("deep.sub.evil.com", "DOMAIN") is True
    assert svc.is_malicious("evil.com", "DOMAIN") is False  # Wildcard needs at least one prefix
    assert svc.is_malicious("notevil.com", "DOMAIN") is False
