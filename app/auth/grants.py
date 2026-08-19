"""Content grants: the closed vocabulary, its validator, and the one implication.

Grants are deliberately orthogonal to the role. An admin administers policies;
that is a different question from whether they may read the prompts, and every
product surveyed for this work separates the two. There is no super-user path to
content.

Everything about grants lives here so the enforcement points cannot diverge:
nobody else parses the stored JSON, compares grant strings, or knows that the
full-content grant implies the matches one.
"""

from __future__ import annotations

MATCHES_READ = "interaction:matches:read"
CONTENT_READ = "interaction:content:read"
CONTENT_EXPORT = "interaction:content:export"

#: The whole vocabulary. A string outside it is not ignored, lowercased or
#: prefix-matched -- it makes the credential invalid.
GRANTS: frozenset[str] = frozenset({MATCHES_READ, CONTENT_READ, CONTENT_EXPORT})

#: Only these roles may hold a grant at all, and only with a policy binding.
GRANTABLE_ROLES: frozenset[str] = frozenset({"viewer", "admin"})

VIEWS: frozenset[str] = frozenset({"matches", "full"})


class GrantError(ValueError):
    """A credential's grants are not valid.

    Raised at key creation, where it becomes a useful 400, and at
    authentication, where it makes the credential invalid -- a generic 401,
    never a 403, because 403 would confirm the bearer secret is real and merely
    misconfigured.
    """


def validate_grants(role: object, policy_id: object, raw: object) -> frozenset[str]:
    """The single validator. Returns the frozen set, or raises.

    ``None`` and ``[]`` both normalise to the empty set: every key that existed
    before this step has ``NULL``, including the bootstrap admin, and that is
    the compatible case rather than a defect.
    """
    if raw is None:
        return frozenset()
    if not isinstance(raw, list):
        raise GrantError("grants must be a list")
    if len(raw) > len(GRANTS):
        # Cannot be legitimate: the vocabulary is closed and duplicates are
        # rejected below, so anything longer is either padding or an attack.
        raise GrantError("too many grants")

    seen: set[str] = set()
    for item in raw:
        if not isinstance(item, str):
            raise GrantError("grants must be strings")
        if item not in GRANTS:
            raise GrantError("unknown grant")
        if item in seen:
            raise GrantError("duplicate grant")
        seen.add(item)

    if not seen:
        return frozenset()

    # Null binding never means "all policies" for content. It means no content.
    if role not in GRANTABLE_ROLES:
        raise GrantError("grants require the viewer or admin role")
    if not isinstance(policy_id, str) or not policy_id:
        raise GrantError("grants require a policy binding")

    return frozenset(seen)


def allows_view(grants: frozenset[str], view: str) -> bool:
    """The one implication, and the only place it is derived.

    Holding the full-content grant permits the matches view.

    An earlier version of this docstring said the implication is "never returned
    by an API". Step 7 made that false: /v1/me/capabilities reports effective
    operation booleans, so a full-grant holder is told matches is available. The
    invariant that was actually load-bearing is narrower, and this is it:

        this function is the sole derivation point, and an API may report its
        boolean result to the authenticated caller. A derived grant *string* is
        still never persisted and never returned.

    Derivation stays in one place; representation as a capability is new.
    """
    if view == "matches":
        return MATCHES_READ in grants or CONTENT_READ in grants
    if view == "full":
        return CONTENT_READ in grants
    return False


def grant_for(view: str) -> str:
    """The authorization rule a view exercises, for the audit.

    The least-privilege grant sufficient for the view, not the strongest one the
    caller happens to hold: a key with both grants asking for matches exercised
    the matches rule, and recording otherwise would make the audit depend on
    unrelated grants attached to the same key. What was *held* remains on the
    key record.
    """
    if view == "matches":
        return MATCHES_READ
    if view == "full":
        return CONTENT_READ
    raise ValueError(f"no grant for view {view!r}")
