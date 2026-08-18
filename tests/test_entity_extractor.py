"""Tests for entity extraction from text."""

import pytest


def test_extract_ipv4():
    from app.services.entity_extractor import extract_entities

    entities = extract_entities("Connect to 192.168.1.1 for access")
    ips = [e for e in entities if e["type"] == "IP"]
    assert len(ips) == 1
    assert ips[0]["value"] == "192.168.1.1"
    assert ips[0]["start_pos"] == 11


def test_extract_multiple_ips():
    from app.services.entity_extractor import extract_entities

    entities = extract_entities("Servers: 10.0.0.1 and 172.16.0.5")
    ips = [e for e in entities if e["type"] == "IP"]
    assert len(ips) == 2


def test_extract_url():
    from app.services.entity_extractor import extract_entities

    entities = extract_entities("Visit http://evil.com/phish for details")
    urls = [e for e in entities if e["type"] == "URL"]
    assert len(urls) == 1
    assert urls[0]["value"] == "http://evil.com/phish"


def test_extract_https_url():
    from app.services.entity_extractor import extract_entities

    entities = extract_entities("Go to https://example.com/page?q=1")
    urls = [e for e in entities if e["type"] == "URL"]
    assert len(urls) == 1
    assert "https://example.com" in urls[0]["value"]


def test_extract_domain():
    from app.services.entity_extractor import extract_entities

    entities = extract_entities("DNS points to malware.example.com today")
    domains = [e for e in entities if e["type"] == "DOMAIN"]
    assert len(domains) >= 1
    assert any("malware.example.com" in d["value"] for d in domains)


def test_no_entities():
    from app.services.entity_extractor import extract_entities

    entities = extract_entities("Hello world, nothing here")
    assert len(entities) == 0


def test_url_not_duplicated_as_domain():
    from app.services.entity_extractor import extract_entities

    entities = extract_entities("Visit http://evil.com/path")
    urls = [e for e in entities if e["type"] == "URL"]
    domains = [e for e in entities if e["type"] == "DOMAIN"]
    # The domain in the URL should not be extracted separately
    assert len(urls) == 1
    domain_values = [d["value"] for d in domains]
    assert "evil.com" not in domain_values


def test_ip_not_extracted_from_url():
    from app.services.entity_extractor import extract_entities

    entities = extract_entities("Visit http://1.2.3.4/path")
    urls = [e for e in entities if e["type"] == "URL"]
    ips = [e for e in entities if e["type"] == "IP"]
    assert len(urls) == 1
    # IP inside URL should not be duplicated as a standalone IP
    assert len(ips) == 0
