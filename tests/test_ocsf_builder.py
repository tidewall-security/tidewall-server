"""Tests for OCSF Data Security Finding event builder."""


def test_build_ocsf_blocked_event():
    from app.services.ocsf_builder import build_ocsf_event

    event = build_ocsf_event(
        status="blocked",
        request_id="tw_abc123",
        timestamp="2026-03-28T12:00:00Z",
        summary="malicious_prompt: blocked",
        policy_name="browser-protect",
        event_type="input",
        detectors={"malicious_prompt": {"detected": True, "data": {"action": "blocked"}}},
        user_id="mallory@external.com",
        app_id="chatbot",
        model="gpt-4o",
        llm_provider="openai",
        collector_type="application",
        api_key_name="prod-collector",
    )
    assert event["class_uid"] == 2006
    assert event["class_name"] == "Data Security Finding"
    assert event["action_id"] == 2  # Denied
    assert event["disposition_id"] == 2  # Blocked
    assert event["severity_id"] == 4  # High
    assert event["message"] == "malicious_prompt: blocked"
    assert event["finding_info"]["uid"] == "tw_abc123"
    assert event["actor"]["user"]["uid"] == "mallory@external.com"
    assert len(event["attacks"]) > 0
    assert event["attacks"][0]["technique"]["uid"] == "AML.T0051"


def test_build_ocsf_transformed_event():
    from app.services.ocsf_builder import build_ocsf_event

    event = build_ocsf_event(
        status="transformed",
        request_id="tw_def456",
        timestamp="2026-03-28T12:00:00Z",
        summary="confidential_and_pii_entity: redacted",
        policy_name="app-protect",
        event_type="input",
        detectors={"confidential_and_pii_entity": {"detected": True}},
        user_id="user@corp.com",
    )
    assert event["action_id"] == 1  # Allowed
    assert event["disposition_id"] == 10  # Corrected
    assert event["severity_id"] == 3  # Medium
    assert event["attacks"][0]["technique"]["uid"] == "AML.T0057"


def test_build_ocsf_allowed_event():
    from app.services.ocsf_builder import build_ocsf_event

    event = build_ocsf_event(
        status="allowed",
        request_id="tw_ghi789",
        timestamp="2026-03-28T12:00:00Z",
        summary="No threats detected.",
        policy_name="default",
        event_type="input",
        detectors={},
    )
    assert event["action_id"] == 1  # Allowed
    assert event["disposition_id"] == 1  # Allowed
    assert event["severity_id"] == 1  # Info
    assert event["attacks"] == []


def test_build_ocsf_alerted_event():
    from app.services.ocsf_builder import build_ocsf_event

    event = build_ocsf_event(
        status="alerted",
        request_id="tw_jkl012",
        timestamp="2026-03-28T12:00:00Z",
        summary="malicious_prompt: alerted (report-only)",
        policy_name="monitor",
        event_type="input",
        detectors={"malicious_prompt": {"detected": True}},
    )
    assert event["action_id"] == 1  # Allowed (report-only didn't block)
    assert event["severity_id"] == 4  # High


def test_ocsf_has_unmapped_tidewall_fields():
    from app.services.ocsf_builder import build_ocsf_event

    event = build_ocsf_event(
        status="blocked",
        request_id="prq_test",
        timestamp="2026-03-28T12:00:00Z",
        summary="test",
        policy_name="p",
        event_type="input",
        detectors={"malicious_prompt": {"detected": True}},
        model="gpt-4o",
        llm_provider="openai",
        collector_type="application",
    )
    tidewall = event["unmapped"]["tidewall"]
    assert tidewall["model_name"] == "gpt-4o"
    assert tidewall["provider"] == "openai"
    assert tidewall["event_type"] == "input"
    assert tidewall["collector_type"] == "application"
    assert "findings" in tidewall


def test_build_aidr_compat_format():
    from app.services.ocsf_builder import build_aidr_compat_event

    event = build_aidr_compat_event(
        status="blocked",
        request_id="tw_abc123",
        timestamp="2026-03-28T12:00:00Z",
        summary="malicious_prompt: blocked",
        policy_name="browser-protect",
        event_type="input",
        detectors={"malicious_prompt": {"detected": True}},
        user_id="mallory@external.com",
        app_id="chatbot",
        model="gpt-4o",
        llm_provider="openai",
        collector_type="application",
        api_key_name="prod-collector",
    )
    assert event["event_simpleName"] == "TidewallPromptDataEvent"
    assert event["Vendor"]["status"] == "blocked"
    assert event["Vendor"]["actor_name"] == "mallory@external.com"
    assert event["Vendor"]["model_name"] == "gpt-4o"
    assert event["Vendor"]["aiguard_config"]["policy"] == "browser-protect"
