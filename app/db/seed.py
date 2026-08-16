"""First-boot seeding: populate policies table from policy.yaml."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml
from sqlalchemy.orm import Session

from app.db.models import Policy, RuleSet
from app.services.policy_validation import validate_detectors

logger = logging.getLogger(__name__)


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
        is_default=True,
    )
    session.add(policy)
    session.flush()

    # The seed path writes the ORM directly rather than going through
    # PolicyService, so it bypassed detector validation entirely. A shipped
    # policy.yaml naming a detector that does not exist would be stored and
    # silently enforce nothing.
    validate_detectors(detectors or {})

    for event_type in ("input", "output"):
        rule_set = RuleSet(
            policy_id=policy.id,
            event_type=event_type,
            detectors=detectors,
        )
        session.add(rule_set)

    session.commit()
    logger.info("Seeded policy '%s' with %d detectors", policy_name, len(detectors))
