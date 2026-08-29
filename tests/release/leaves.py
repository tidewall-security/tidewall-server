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


#: States whose meaning is "the component ran and found NOTHING". A case
#: declaring one of these must be planted with a value that finds nothing, or
#: it reaches the detected state as well and the declared-component check
#: passes without distinguishing them.
NEGATIVE_STATES: frozenset[str] = frozenset({"pattern_match", "no_entities"})


def shape(leaf: str, canary: str, sub_path: str = "") -> str:
    """The text to plant for `leaf`, embedding `canary`.

    `sub_path` selects between the found-something and found-nothing forms.
    Without it, an emoji case declaring `pattern_match` was planted with an
    emoji and reached `reported` too -- so the check passed, but would have
    passed for a case declaring either state.
    """
    if sub_path in NEGATIVE_STATES:
        # Opaque, and deliberately carrying nothing any detector matches.
        return f"{canary} nothing of interest here"

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
        # reach its detected branch. The found-nothing form is returned above.
        return f"{canary} \U0001f600"
    if leaf == "custom-match":
        # A custom entity is whatever an operator configured, so the canary
        # itself is the value: there is no format to imitate.
        return f"custom entity {canary} in the message"
    if leaf in ("mcp-name", "mcp-description", "mcp-parameters"):
        return canary
    raise NoShapeForLeaf(f"no shaping rule for leaf {leaf!r}; the case cannot be driven")


def captured_value(leaf: str, canary: str) -> str:
    """What capture SHOULD hold for this leaf: the value the detector matches.

    Not the canary. For `email` and `custom-match` the canary IS inside the
    matched value, so the two coincide. For `card` and `ssn` it is deliberately
    alongside -- a canary cannot be Luhn-valid, and deriving SSN digits from it
    made detection canary-dependent (see `shape`). Capture stores what the
    detector matched, so asserting the canary reaches it asked capture to hold a
    string the detector never saw. That is unsatisfiable by construction, and it
    is what 91 of these cases were failing on.

    Keep this in step with `shape`: the two describe the same fixture from
    either end, and a leaf added to one belongs in the other.
    """
    if leaf == "email":
        return f"{canary.lower()}@example.com"
    if leaf == "card":
        return "4111111111111111"
    if leaf == "ssn":
        return "078-05-1120"
    if leaf == "custom-match":
        return canary
    raise NoShapeForLeaf(f"no captured-value rule for leaf {leaf!r}")


#: `custom_entity` matches nothing without a pattern, so a bare
#: `{"enabled": True}` left 98 cases asserting capture of a value no detector
#: had found. The pattern is the canary itself, which is what an operator
#: configuring a custom entity is doing.
def detector_config(detector: str, canary: str) -> dict:
    """The config a case needs for its detector to actually fire."""
    if detector == "custom_entity":
        # A list of PATTERN STRINGS. `compile_pattern` refuses anything else,
        # and the refusal is swallowed -- a dict here left the detector with no
        # patterns and no complaint.
        return {"enabled": True, "patterns": [canary]}
    return {"enabled": True}


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
