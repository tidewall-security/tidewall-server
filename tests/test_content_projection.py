"""The projection shared by the content read endpoint and content export.

One function, so the two cannot select different fields. Before this, the logic
was private to the route module and a second caller would have duplicated it.
"""

from __future__ import annotations

import pytest

from app.services.content_projection import Corrupt, project_content


def _matches_json():
    return (
        '{"schema_version": 1, "matches": [{"detector": "d", "match_type": "T",'
        ' "rule_id": null, "source": {"kind": "message", "index": 0,'
        ' "field": "content", "role": null}, "value": "v", "occurrences": 1}]}'
    )


def test_matches_view_projects_only_matches():
    out = project_content(
        view="matches",
        captured_raw="2026-08-19 00:00:00.000000",
        expires_raw=None,
        input_raw='[{"content": "prompt"}]',
        output_raw=None,
        matches_raw=_matches_json(),
    )
    assert set(out) == {"captured_at", "expires_at", "matches"}
    assert out["captured_at"] == "2026-08-19T00:00:00Z"
    assert out["matches"]["matches"][0]["value"] == "v"


def test_matches_view_does_not_decode_the_prompt():
    # Corrupt input must not fail a matches projection: this view never reads it,
    # and a caller without the full grant should not have the prompt decoded on
    # their behalf.
    out = project_content(
        view="matches",
        captured_raw="2026-08-19 00:00:00.000000",
        expires_raw=None,
        input_raw="{not json",
        output_raw=None,
        matches_raw=_matches_json(),
    )
    assert out["matches"] is not None


def test_full_view_includes_messages_tools_and_output():
    out = project_content(
        view="full",
        captured_raw="2026-08-19 00:00:00.000000",
        expires_raw="2026-08-20 00:00:00.000000",
        input_raw='{"messages": [{"content": "p"}], "tools": [{"name": "t"}]}',
        output_raw='[{"content": "r"}]',
        matches_raw=None,
    )
    assert out["messages"] == [{"content": "p"}]
    assert out["tools"] == [{"name": "t"}]
    assert out["output"] == [{"content": "r"}]
    assert out["matches"] is None
    assert out["expires_at"] == "2026-08-20T00:00:00Z"


@pytest.mark.parametrize(
    "matches_raw",
    [
        '{"schema_version": 2, "matches": []}',
        '{"schema_version": 1, "matches": [{"detector": "d"}]}',
    ],
)
def test_an_unexpected_match_shape_is_corrupt(matches_raw):
    with pytest.raises(Corrupt):
        project_content(
            view="matches",
            captured_raw="2026-08-19 00:00:00.000000",
            expires_raw=None,
            input_raw=None,
            output_raw=None,
            matches_raw=matches_raw,
        )
