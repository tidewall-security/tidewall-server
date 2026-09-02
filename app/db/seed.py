"""First-boot seeding: populate policies table from policy.yaml."""

from __future__ import annotations

import logging
from copy import deepcopy
from pathlib import Path
from typing import Any

import yaml
from sqlalchemy.orm import Session

from app.db.models import Policy, RuleSet
from app.models import EVENT_TYPES
from app.services.policy_validation import validate_detectors

logger = logging.getLogger(__name__)


def _validated_seed_flag(value: object) -> bool:
    """A real boolean, not a truthy value.

    YAML `raw_content_enabled: "false"` is a non-empty string, so bool() made
    it True — turning prompt capture ON from configuration that reads as off.
    A privacy boundary must not invert on a quoting mistake.
    """
    if not isinstance(value, bool):
        raise ValueError("raw_content_enabled must be true or false, not a string or number")
    return value


def _validated_seed_retention(value: object) -> int | None:
    """Retention from YAML, or None for no expiry.

    Rejects rather than coerces: `true` is not one day, and a string is not a
    number. A seed file that says something unenforceable should fail loudly at
    first boot rather than quietly become a different policy.
    """
    if value is None:
        return None
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise ValueError("raw_content_retention_days must be a positive integer or null")
    return value


def seed_from_yaml(session: Session, yaml_path: str | Path) -> None:
    """Seed the database from a policy YAML file.

    Only runs if the policies table is empty. This ensures the YAML
    file is used for first-boot only — subsequent boots use the DB.
    """
    existing = session.query(Policy).first()
    if existing is not None:
        logger.debug("Policies table already has data — skipping seed")
        return

    path = Path(yaml_path)
    if not path.exists():
        logger.warning("Seed file %s not found — skipping", path)
        return

    with open(path, encoding="utf-8") as f:
        raw: dict[str, Any] = yaml.safe_load(f)

    if not isinstance(raw, dict):
        logger.error("Invalid YAML — expected mapping at top level")
        return

    policy_name = raw.get("name", "default_policy")
    report_only = raw.get("report_only", False)
    detectors = raw.get("detectors", {})

    policy = Policy(
        name=policy_name,
        type="application",
        description="Default policy seeded from policy.yaml",
        report_only=report_only,
        on_detector_failure=raw.get("on_detector_failure", "report"),
        # Read here too, or an exported enabled policy used as the first-boot
        # configuration silently seeds capture off and loses its retention
        # window — a round trip that drops a security setting.
        raw_content_enabled=_validated_seed_flag(raw.get("raw_content_enabled", False)),
        raw_content_retention_days=_validated_seed_retention(raw.get("raw_content_retention_days")),
        is_default=True,
    )
    session.add(policy)
    session.flush()

    # The seed path writes the ORM directly rather than going through
    # PolicyService, so it bypassed detector validation entirely. A shipped
    # policy.yaml naming a detector that does not exist would be stored and
    # silently enforce nothing.
    validate_detectors(detectors or {})

    # Every event type the schema accepts, read from EVENT_TYPES rather than
    # restated here. Seeding only "input" and "output" left three event types
    # with no rule set, and the guard silently resolved them to the input engine
    # -- so tool surfaces were scanned under the input policy while appearing to
    # have none of their own. A restated tuple is what let that persist; reading
    # the set means a sixth event type cannot be added without this loop
    # covering it.
    #
    # Sorted for deterministic ordering: EVENT_TYPES is a frozenset.
    #
    # `detectors` only. RuleSet also carries `report_only` and `access_rules`,
    # and tool events inherit neither today -- the route reads the requested
    # event type's own row for both and finds nothing. Copying those would newly
    # apply input's access rules to tool events, which can block before any
    # detector runs.
    # Per-surface overrides, merged over the base detectors for the named event
    # type. Validated rather than merely read: an override naming an event type
    # that does not exist would configure nothing at all, which is the
    # accepted-but-not-honoured pattern this codebase keeps finding.
    overrides = raw.get("event_overrides") or {}
    unknown = set(overrides) - set(EVENT_TYPES)
    if unknown:
        raise ValueError(f"event_overrides names event types that do not exist: {sorted(unknown)}")

    for event_type in sorted(EVENT_TYPES):
        merged = deepcopy(detectors) if detectors else {}
        for det_name, det_override in (overrides.get(event_type) or {}).items():
            merged.setdefault(det_name, {}).update(det_override)
        validate_detectors(merged)
        rule_set = RuleSet(
            policy_id=policy.id,
            event_type=event_type,
            detectors=merged,
        )
        session.add(rule_set)

    session.commit()
    logger.info("Seeded policy '%s' with %d detectors", policy_name, len(detectors))
