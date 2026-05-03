"""Tests for MCPValidationDetector — tool name validation."""
import pytest


def test_no_tools_not_detected():
    from app.detectors.mcp_validation import MCPValidationDetector
    detector = MCPValidationDetector({"enabled": True, "action": "block", "similarity_threshold": 0.8})
    result = detector.scan("", tools=[])
    assert result.detected is False


def test_unique_tools_not_detected():
    from app.detectors.mcp_validation import MCPValidationDetector
    detector = MCPValidationDetector({"enabled": True, "action": "block", "similarity_threshold": 0.8})
    tools = [
        {"type": "function", "function": {"name": "get_weather", "description": "Gets weather"}},
        {"type": "function", "function": {"name": "send_email", "description": "Sends email"}},
    ]
    result = detector.scan("", tools=tools)
    assert result.detected is False


def test_exact_duplicate_names_detected():
    from app.detectors.mcp_validation import MCPValidationDetector
    detector = MCPValidationDetector({"enabled": True, "action": "block", "similarity_threshold": 0.8})
    tools = [
        {"type": "function", "function": {"name": "get_data", "description": "Gets data v1"}},
        {"type": "function", "function": {"name": "get_data", "description": "Gets data v2"}},
    ]
    result = detector.scan("", tools=tools)
    assert result.detected is True
    assert any(i["type"] == "duplicate_name" for i in result.data["issues"])


def test_similar_names_detected():
    from app.detectors.mcp_validation import MCPValidationDetector
    detector = MCPValidationDetector({"enabled": True, "action": "block", "similarity_threshold": 0.8})
    tools = [
        {"type": "function", "function": {"name": "get_user_data", "description": "A"}},
        {"type": "function", "function": {"name": "get_userData", "description": "B"}},
    ]
    result = detector.scan("", tools=tools)
    assert result.detected is True
    assert any(i["type"] == "duplicate_name" for i in result.data["issues"])
    assert result.data["issues"][0]["similarity"] >= 0.8


def test_low_similarity_not_detected():
    from app.detectors.mcp_validation import MCPValidationDetector
    detector = MCPValidationDetector({"enabled": True, "action": "block", "similarity_threshold": 0.8})
    tools = [
        {"type": "function", "function": {"name": "get_weather", "description": "A"}},
        {"type": "function", "function": {"name": "send_email", "description": "B"}},
    ]
    result = detector.scan("", tools=tools)
    assert result.detected is False


def test_custom_threshold():
    from app.detectors.mcp_validation import MCPValidationDetector
    detector = MCPValidationDetector({"enabled": True, "action": "block", "similarity_threshold": 0.5})
    tools = [
        {"type": "function", "function": {"name": "get_data", "description": "A"}},
        {"type": "function", "function": {"name": "set_data", "description": "B"}},
    ]
    result = detector.scan("", tools=tools)
    # get_data vs set_data has ~0.75 similarity — above 0.5 threshold
    assert result.detected is True


def test_block_action_returns_filtered_tools():
    from app.detectors.mcp_validation import MCPValidationDetector
    detector = MCPValidationDetector({"enabled": True, "action": "block", "similarity_threshold": 0.8})
    tools = [
        {"type": "function", "function": {"name": "safe_tool", "description": "Safe"}},
        {"type": "function", "function": {"name": "get_data", "description": "V1"}},
        {"type": "function", "function": {"name": "get_data", "description": "V2"}},
    ]
    result = detector.scan("", tools=tools)
    assert result.detected is True
    assert "filtered_tools" in result.data
    # Duplicates should be in the filtered list
    assert "get_data" in result.data["filtered_tools"]


def test_report_action_no_filtering():
    from app.detectors.mcp_validation import MCPValidationDetector
    detector = MCPValidationDetector({"enabled": True, "action": "report", "similarity_threshold": 0.8})
    tools = [
        {"type": "function", "function": {"name": "get_data", "description": "V1"}},
        {"type": "function", "function": {"name": "get_data", "description": "V2"}},
    ]
    result = detector.scan("", tools=tools)
    assert result.detected is True
    assert result.data.get("filtered_tools") is None or result.data.get("filtered_tools") == []


def test_tools_passed_via_kwargs():
    """Detector receives tools via kwargs, not text."""
    from app.detectors.mcp_validation import MCPValidationDetector
    detector = MCPValidationDetector({"enabled": True, "action": "block", "similarity_threshold": 0.8})
    # text is empty, tools come via kwargs
    result = detector.scan("some text content", tools=[
        {"type": "function", "function": {"name": "dup", "description": "A"}},
        {"type": "function", "function": {"name": "dup", "description": "B"}},
    ])
    assert result.detected is True
