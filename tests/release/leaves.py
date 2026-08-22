"""Shape the planted value to the case's LEAF.

The leaf axis says WHAT KIND of value is planted, and a detector that looks
for a credit card will correctly ignore an opaque canary string. Feeding every
case the same shapeless token made 27 cases declare `pii/entities_redacted`
and observe `pii/no_entities` -- not a defect in the detectors, a defect in
the driver.

Each shape EMBEDS the canary, so an occurrence found anywhere is still
attributable to the case that planted it. A shape that dropped the canary
would make every leak anonymous.
"""

from __future__ import annotations


class NoShapeForLeaf(Exception):
    """A leaf with no shaping rule. NOT a pass -- the case cannot be driven."""


def shape(leaf: str, canary: str) -> str:
    """The text to plant for `leaf`, embedding `canary`."""
    if leaf == "email":
        return f"contact {canary.lower()}@example.com about it"
    if leaf == "card":
        # A Luhn-valid test number, with the canary alongside so the
        # occurrence remains attributable.
        return f"card 4111111111111111 ref {canary}"
    if leaf == "ssn":
        # A FIXED, known-recognised value, with the canary alongside. Deriving
        # the digits from the canary made detection canary-dependent: some
        # derived strings are not SSN-shaped, so the same case passed or failed
        # according to which canary it drew.
        return f"ssn 078-05-1120 ref {canary}"
    if leaf == "random-canary":
        # Opaque by definition, but carrying an emoji so an emoji case can
        # reach its detected branch.
        return f"{canary} \U0001f600"
    if leaf in ("mcp-name", "mcp-description", "mcp-parameters"):
        return canary
    raise NoShapeForLeaf(f"no shaping rule for leaf {leaf!r}; the case cannot be driven")


def tools_for(leaf: str, canary: str) -> list[dict] | None:
    """MCP cases are driven by TOOLS, not by text.

    `mcp_validation` reads `function.name` and nothing else, so a description
    or parameter case plants there and the detector correctly never evaluates
    it -- which is the recorded NOT_EVALUATED fact, exercised rather than
    asserted.
    """
    if leaf == "mcp-name":
        return [
            {"function": {"name": f"get_{canary.lower()}", "description": "a", "parameters": {}}},
            {"function": {"name": f"get_{canary.lower()}s", "description": "b", "parameters": {}}},
        ]
    if leaf == "mcp-description":
        return [
            {"function": {"name": "alpha_tool", "description": canary, "parameters": {}}},
            {"function": {"name": "alpha_tools", "description": canary, "parameters": {}}},
        ]
    if leaf == "mcp-parameters":
        return [
            {"function": {"name": "beta_tool", "description": "a", "parameters": {"p": canary}}},
            {"function": {"name": "beta_tools", "description": "b", "parameters": {"p": canary}}},
        ]
    return None
