"""Two defects found while wiring an MCP proxy to the guard.

Both are the same shape as the rest of this area: a check that produced a
confident answer about content it had never seen.
"""

from __future__ import annotations

import pytest
import yaml

from app.detectors.mcp_validation import MCPValidationDetector
from app.tool_scan import tool_name


@pytest.fixture(scope="module")
def policy():
    return yaml.safe_load(open("policy.yaml"))


class TestToolShapes:
    """A name-based check must read the shape the caller actually sends."""

    @pytest.mark.parametrize(
        "tool, expected",
        [
            ({"type": "function", "function": {"name": "search"}}, "search"),
            ({"name": "search", "description": "d", "inputSchema": {}}, "search"),
            ({"function": {"name": ""}, "name": "fallback"}, "fallback"),
            ({"function": "not-a-dict", "name": "top"}, "top"),
            ({"description": "no name at all"}, ""),
            ("not-a-dict", ""),
        ],
    )
    def test_the_name_is_read_from_either_shape(self, tool, expected):
        assert tool_name(tool) == expected

    def test_similar_names_are_found_in_mcp_shaped_tools(self):
        """The case that could not be detected at all.

        The detector read `tool["function"]["name"]`, which no MCP-shaped tool
        has, so every name came back empty and was skipped -- it reported
        "nothing found" for input it had not looked at. An MCP proxy sends
        exactly this shape.
        """
        detector = MCPValidationDetector({"similarity_threshold": 0.95})
        tools = [
            {"name": "get_weather", "description": "Get the weather."},
            {"name": "get_weathr", "description": "Get the weather."},
        ]
        assert detector.scan("", tools=tools).detected

    def test_similar_names_are_still_found_in_openai_shaped_tools(self):
        detector = MCPValidationDetector({"similarity_threshold": 0.95})
        tools = [
            {"type": "function", "function": {"name": "get_weather"}},
            {"type": "function", "function": {"name": "get_weathr"}},
        ]
        assert detector.scan("", tools=tools).detected

    def test_ordinary_distinct_names_are_left_alone(self):
        """Names that merely share a prefix are not a finding.

        Measured across 671 names from 103 public MCP servers, the code
        default of 0.8 flags 7% of all tools -- these among them.
        """
        detector = MCPValidationDetector({"similarity_threshold": 0.95})
        tools = [
            {"name": "excel_add_sheet"},
            {"name": "excel_read_sheet"},
            {"name": "clear_sql_database"},
            {"name": "create_sql_database"},
            {"name": "calculate_distance"},
            {"name": "calculate_distance_km"},
        ]
        assert not detector.scan("", tools=tools).detected


class TestEmptyScan:
    """A tool listing carries its content in `tools`, so the scanned text is
    empty. Neither detector may invent a verdict about it."""

    @pytest.mark.parametrize("text", ["", "   ", "\n\t "])
    def test_the_topic_detector_does_not_fail_on_blank_text(self, text, policy):
        from app.detectors.topic import TopicDetector

        result = TopicDetector((policy["detectors"]).get("topic") or {}).scan(text)
        assert result.detected is False
        # It raised ValueError here, which surfaced as `degraded: true` on
        # every tool listing. Under on_detector_failure: block that would have
        # refused all of them.
        assert result.status.value == "ok", result.status

    @pytest.mark.parametrize("text", ["", "   ", "\n\t "])
    def test_the_language_detector_does_not_detect_on_blank_text(self, text, policy):
        from app.detectors.language import LanguageDetector

        # It classified empty text as some language, found that language absent
        # from the allow-list, and reported a violation on no content at all.
        result = LanguageDetector((policy["detectors"]).get("language") or {}).scan(text)
        assert result.detected is False


class TestPolicyPinsTheOperatingPoint:
    def test_mcp_validation_reports_rather_than_filtering(self, policy):
        """Blocking removes BOTH tools in a flagged pair, and nothing here can
        tell which is the impostor."""
        config = policy["detectors"]["mcp_validation"]
        assert config["enabled"] is True
        assert config["action"] == "report"

    def test_the_similarity_threshold_is_the_measured_one(self, policy):
        # 0.8 (the code default) flags 7% of real tools. Raising this back
        # without re-measuring reintroduces that.
        assert policy["detectors"]["mcp_validation"]["similarity_threshold"] == 0.95
