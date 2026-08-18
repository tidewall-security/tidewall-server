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

from app.detectors.base import DetectorStatus, FailureCode, SkipReason

EVIDENCE_SCHEMA_VERSION = 1

# Closed vocabularies, resolved from the enums rather than restated here, so a
# new code cannot be silently unexportable and a hostile string cannot pass for
# one.
_FAILURE_CODES = frozenset(code.value for code in FailureCode)
_SKIP_REASONS = frozenset(reason.value for reason in SkipReason)
_STATUSES = frozenset(status.value for status in DetectorStatus)

# Entity type names are drawn from detector taxonomies and policy-defined
# labels, so they are bounded but not fully enumerable here. Cap them instead.
_MAX_TYPE_LENGTH = 64
_MAX_TYPES_PER_DETECTOR = 50
_MAX_DETECTORS = 50
_MAX_COMPONENTS = 50
# A count is a count, not an arbitrary integer crossing to a SIEM.
_MAX_COUNT = 1_000_000


# A closed vocabulary. A character check is not an allowlist: sixty-four
# characters of [A-Za-z0-9_.-] is room for an API key, a token, an account ID
# or an email-like identifier without the @. No current detector puts a matched
# value in `type`, but "no detector does this today" is not a property this
# module can enforce, and echoing an arbitrary string is exactly the shape of
# leak it exists to stop.
KNOWN_ENTITY_TYPES = frozenset(
    {
        # Presidio / PII taxonomy
        "PERSON",
        "EMAIL_ADDRESS",
        "PHONE_NUMBER",
        "CREDIT_CARD",
        "IBAN_CODE",
        "IP_ADDRESS",
        "US_SSN",
        "US_PASSPORT",
        "US_DRIVER_LICENSE",
        "US_BANK_NUMBER",
        "US_ITIN",
        "UK_NHS",
        "UK_NINO",
        "LOCATION",
        "DATE_TIME",
        "NRP",
        "URL",
        "CRYPTO",
        "MEDICAL_LICENSE",
        "AU_ABN",
        "AU_ACN",
        "AU_TFN",
        "AU_MEDICARE",
        "SG_NRIC_FIN",
        "IN_PAN",
        "IN_AADHAAR",
        "IN_VEHICLE_REGISTRATION",
        "IN_PASSPORT",
        "IN_VOTER",
        # Tidewall detector categories. "IP" is what entity_extractor actually
        # emits; I had invented IPV4/IPV6, which nothing produces — so a real
        # malicious-IP finding was collapsed to OTHER until a drift test caught
        # it.
        "API_KEY",
        "SECRET",
        "CUSTOM",
        "COMPETITOR",
        "DOMAIN",
        "IP",
        "EMOJI",
        "CODE",
        "TOPIC",
        "LANGUAGE",
        "TOOL",
    }
)
# What an unrecognised label becomes. The count still tells an analyst that
# something fired; the label does not tell them anything the label might be.
UNKNOWN_TYPE = "OTHER"


def _safe_identifier(value: Any) -> str | None:
    """A bounded identifier for names and status codes.

    Used for detector names, component names and status/failure codes, which
    are produced by this codebase rather than by matched content.
    """
    if not isinstance(value, str) or not value:
        return None
    if len(value) > _MAX_TYPE_LENGTH:
        return None
    if not all(c.isalnum() or c in "_-." for c in value):
        return None
    return value


def _safe_type_name(value: Any) -> str:
    """Map a label onto the closed vocabulary, or to UNKNOWN_TYPE."""
    if not isinstance(value, str):
        return UNKNOWN_TYPE
    return value if value in KNOWN_ENTITY_TYPES else UNKNOWN_TYPE


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
        counts[name] = counts.get(name, 0) + 1
        if len(counts) > _MAX_TYPES_PER_DETECTOR:
            # Bound the working set, not just the output slice.
            break

    ordered = sorted(counts.items())[:_MAX_TYPES_PER_DETECTOR]
    return [{"type": name, "count": count} for name, count in ordered]


def _has_unclassified(data: Any) -> bool:
    """Whether any label fell outside the known vocabulary.

    OTHER is a fail-closed bucket, not a taxonomy entry. Without saying so, an
    analyst cannot tell an unrecognised label from a detector that genuinely
    reports OTHER, and cannot tell that the vocabulary needs updating.
    """
    if not isinstance(data, dict):
        return False
    entities = data.get("entities")
    if not isinstance(entities, list):
        return False
    return any(
        isinstance(e, dict) and isinstance(e.get("type"), str) and e["type"] not in KNOWN_ENTITY_TYPES for e in entities
    )


def _components(raw: Any) -> dict[str, Any]:
    """Per-component status only — the diagnostic half, never the content."""
    if not isinstance(raw, dict):
        return {}
    out: dict[str, Any] = {}
    for name, value in raw.items():
        # Component names are produced by composite detectors in this codebase,
        # so they are bounded identifiers rather than a closed enum — but they
        # are still length- and charset-checked, and never echoed from caller
        # input, because the caller never reaches this structure.
        safe_name = _safe_identifier(name)
        if safe_name is None or not isinstance(value, dict):
            continue
        entry: dict[str, Any] = {}
        for key, allowed in (("status", _STATUSES), ("failure_code", _FAILURE_CODES), ("skip_reason", _SKIP_REASONS)):
            candidate = value.get(key)
            if isinstance(candidate, str) and candidate in allowed:
                entry[key] = candidate
        out[safe_name] = entry
        if len(out) >= _MAX_COMPONENTS:
            break
    return out


def _known_detector_names() -> frozenset[str]:
    """The detectors that exist, resolved from the engine's own registry.

    A lexical check is not a vocabulary: any 64-character identifier passed it,
    so {"REVEALSECRETSNOW": {"detected": true}} was stored and served. That is
    the same arbitrary-evidence bypass moved from a value to a key.

    Imported lazily to avoid a cycle: the scanner imports this module.
    """
    from app.scanner_engine import _DETECTOR_REGISTRY

    return frozenset(_DETECTOR_REGISTRY)


# Only this one. Treating every underscore-prefixed key as reserved meant
# {"_REVEALSECRETSNOW": {...}} was reserved metadata too.
_DEGRADED_KEY = "_degraded"


def project_detectors(detectors: Any) -> dict[str, Any]:
    """Reduce a scan's detector payloads to what may leave the boundary.

    Returns a detector map with the same *shape* as the input, because the
    export builders derive their finding types and MITRE mappings by iterating
    it. Returning a versioned envelope here instead silently emptied
    ``finding_info.types`` and ``attacks`` in both OCSF and AIDR — the safe
    payload was present but every derived field was false.

    ``ExportService.emit`` applies this, so no caller can opt out by passing
    the raw structure.
    """
    projected: dict[str, Any] = {}
    if not isinstance(detectors, dict):
        return projected

    known = _known_detector_names()

    for name, payload in list(detectors.items())[:_MAX_DETECTORS]:
        if not isinstance(name, str) or not isinstance(payload, dict):
            continue

        # Reserved scan metadata, generated by the engine rather than derived
        # from the request. `_degraded` names which detectors could not run,
        # which is the answer to "was this verdict complete" — dropping it
        # would turn an incomplete scan into an apparently clean one.
        if name == _DEGRADED_KEY:
            projected[name] = {
                "degraded": bool(payload.get("degraded")),
                # Names, from the same closed vocabulary.
                "failed_detectors": [
                    d for d in (payload.get("failed_detectors") or []) if isinstance(d, str) and d in known
                ][:_MAX_DETECTORS],
            }
            continue

        # A detector that does not exist is not evidence.
        if name not in known:
            continue
        safe_name = name

        entry: dict[str, Any] = {"detected": bool(payload.get("detected"))}

        status = payload.get("status")
        if isinstance(status, str) and status in _STATUSES:
            entry["status"] = status
        # Dropping these was a contract regression, not a privacy gain: they
        # are the difference between "a dependency is missing", "the model
        # would not load", "the configuration is invalid" and "the scan blew
        # up", which is exactly what a caller or operator acts on.
        #
        # Checked for enum membership, not merely identifier shape. Saying in a
        # comment that they are fixed enum values while accepting any 64-char
        # identifier is the same overclaiming this work keeps removing —
        # "sk_live_SECRET" is identifier-shaped.
        for key, allowed in (("failure_code", _FAILURE_CODES), ("skip_reason", _SKIP_REASONS)):
            code = payload.get(key)
            if isinstance(code, str) and code in allowed:
                entry[key] = code
        if payload.get("degraded"):
            entry["degraded"] = True

        # Already-projected input keeps its counts. emit() projects
        # unconditionally, so without this a caller passing a safe structure
        # would silently lose its analytics — a quiet wrong answer rather than
        # a loud one.
        #
        # The counts are re-validated rather than trusted. Recognising a shape
        # is not the same as trusting its contents: an untyped dict carrying
        # `entities` without `data` would otherwise be an unbounded integer
        # channel into every export format.
        if isinstance(payload.get("entities"), list) and "data" not in payload:
            preserved: list[dict[str, Any]] = []
            for candidate in payload["entities"][:_MAX_TYPES_PER_DETECTOR]:
                if not isinstance(candidate, dict):
                    continue
                count = candidate.get("count")
                if not isinstance(count, int) or isinstance(count, bool):
                    continue
                if not (1 <= count <= _MAX_COUNT):
                    continue
                preserved.append({"type": _safe_type_name(candidate.get("type")), "count": count})
            if preserved:
                entry["entities"] = preserved
            if payload.get("unclassified_types") is True:
                entry["unclassified_types"] = True

        counts = _entity_counts(payload.get("data"))
        if counts:
            entry["entities"] = counts
        if _has_unclassified(payload.get("data")):
            entry["unclassified_types"] = True

        components = _components(payload.get("components"))
        if components:
            entry["components"] = components

        projected[safe_name] = entry

    return projected
