"""What an export is allowed to carry (P0-6, step 2).

`ScanResult.detectors` was passed straight into every export format. It goes
verbatim into OCSF `unmapped.tidewall.findings`, AIDR `Vendor.findings` and the
raw format, and detector payloads carry exactly what the product exists to keep
out of downstream systems:

- `custom_entity` records the matched `value` and its `start_pos`;
- `malicious_entity` records `raw`, the unmodified URL including any
  credentials or tokens in it;
- any future detector's `data` is an unrestricted dict, so whatever it puts
  there ships too.

So the audit record leaves the boundary carrying the content it was created to
protect, before anyone looks at `/v1/logs` at all.

## Allowlist, not denylist

This projects to a fixed shape rather than stripping known-bad keys. A denylist
is wrong here for a reason that is structural, not stylistic: it is a promise
about every field that exists now and every field anyone adds later. The first
detector to introduce a differently-named value field would ship it, and
nothing would fail. An allowlist means a new field is invisible until someone
decides it is safe, which is the direction the mistake should fall.

What survives: detector name, whether it fired, its status, degradation,
per-component status and failure codes, and the *types* it matched with counts.
What does not: values, offsets, placeholders, URLs, rule text, and anything
unrecognised.
"""

from __future__ import annotations

from typing import Any

EVIDENCE_SCHEMA_VERSION = 1

# Entity type names are drawn from detector taxonomies and policy-defined
# labels, so they are bounded but not fully enumerable here. Cap them instead.
_MAX_TYPE_LENGTH = 64
_MAX_TYPES_PER_DETECTOR = 50
_MAX_DETECTORS = 50


def _safe_type_name(value: Any) -> str | None:
    """A type label, or nothing.

    Labels come from detector taxonomies and policy configuration, so they are
    not attacker-controlled in the ordinary case — but they reach a SIEM, and a
    label is not worth trusting unconditionally when the cost of being wrong is
    the thing this module exists to prevent.
    """
    if not isinstance(value, str) or not value:
        return None
    if len(value) > _MAX_TYPE_LENGTH:
        return None
    if not all(c.isalnum() or c in "_-." for c in value):
        return None
    return value


def _entity_counts(data: Any) -> list[dict[str, Any]]:
    """Types and counts, never values.

    Reading only `type` from each entity is the whole point: the sibling keys
    are `value`, `raw`, `start_pos` and `placeholder`.
    """
    if not isinstance(data, dict):
        return []
    entities = data.get("entities")
    if not isinstance(entities, list):
        return []

    counts: dict[str, int] = {}
    for entity in entities:
        if not isinstance(entity, dict):
            continue
        name = _safe_type_name(entity.get("type"))
        if name is None:
            continue
        counts[name] = counts.get(name, 0) + 1

    ordered = sorted(counts.items())[:_MAX_TYPES_PER_DETECTOR]
    return [{"type": name, "count": count} for name, count in ordered]


def _components(raw: Any) -> dict[str, Any]:
    """Per-component status only — the diagnostic half, never the content."""
    if not isinstance(raw, dict):
        return {}
    out: dict[str, Any] = {}
    for name, value in raw.items():
        safe_name = _safe_type_name(name)
        if safe_name is None or not isinstance(value, dict):
            continue
        entry: dict[str, Any] = {}
        for key in ("status", "failure_code", "skip_reason"):
            candidate = _safe_type_name(value.get(key))
            if candidate is not None:
                entry[key] = candidate
        out[safe_name] = entry
    return out


def project_detectors(detectors: Any) -> dict[str, Any]:
    """Reduce a scan's detector payloads to what may leave the boundary.

    Accepts the raw structure and returns the only shape exports are allowed to
    carry. Callers cannot opt out: the export functions take this and nothing
    else, so there is no parameter left through which raw detectors can be
    passed.
    """
    projected: dict[str, Any] = {}
    if not isinstance(detectors, dict):
        return {"schema_version": EVIDENCE_SCHEMA_VERSION, "detectors": {}}

    for name, payload in list(detectors.items())[:_MAX_DETECTORS]:
        safe_name = _safe_type_name(name)
        if safe_name is None or not isinstance(payload, dict):
            continue

        entry: dict[str, Any] = {"detected": bool(payload.get("detected"))}

        status = _safe_type_name(payload.get("status"))
        if status is not None:
            entry["status"] = status
        if payload.get("degraded"):
            entry["degraded"] = True

        counts = _entity_counts(payload.get("data"))
        if counts:
            entry["entities"] = counts

        components = _components(payload.get("components"))
        if components:
            entry["components"] = components

        projected[safe_name] = entry

    return {"schema_version": EVIDENCE_SCHEMA_VERSION, "detectors": projected}
