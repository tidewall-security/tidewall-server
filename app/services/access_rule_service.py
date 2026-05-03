"""Access rule CRUD operations."""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy.orm import Session

from app.db.models import AccessRule

logger = logging.getLogger(__name__)


class AccessRuleService:
    """Manages access rule CRUD within rule sets."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def list_rules(self, rule_set_id: str) -> list[AccessRule]:
        return self._session.query(AccessRule).filter_by(rule_set_id=rule_set_id).order_by(AccessRule.sort_order).all()

    def get_rule(self, rule_id: str) -> AccessRule | None:
        return self._session.get(AccessRule, rule_id)

    def create_rule(
        self,
        rule_set_id: str,
        name: str,
        conditions: dict[str, Any],
        then_action: str = "continue",
        else_action: str = "continue",
    ) -> AccessRule:
        # Auto-increment sort_order
        max_order = (
            self._session.query(AccessRule.sort_order)
            .filter_by(rule_set_id=rule_set_id)
            .order_by(AccessRule.sort_order.desc())
            .first()
        )
        next_order = (max_order[0] + 1) if max_order else 0

        rule = AccessRule(
            rule_set_id=rule_set_id,
            name=name,
            conditions=conditions,
            then_action=then_action,
            else_action=else_action,
            sort_order=next_order,
        )
        self._session.add(rule)
        self._session.commit()
        logger.info("Created access rule '%s' (sort_order=%d)", name, next_order)
        return rule

    def update_rule(
        self,
        rule_id: str,
        name: str | None = None,
        conditions: dict[str, Any] | None = None,
        then_action: str | None = None,
        else_action: str | None = None,
        sort_order: int | None = None,
    ) -> AccessRule:
        rule = self._session.get(AccessRule, rule_id)
        if rule is None:
            raise ValueError(f"Access rule {rule_id} not found")
        if name is not None:
            rule.name = name
        if conditions is not None:
            rule.conditions = conditions
        if then_action is not None:
            rule.then_action = then_action
        if else_action is not None:
            rule.else_action = else_action
        if sort_order is not None:
            rule.sort_order = sort_order
        self._session.commit()
        return rule

    def delete_rule(self, rule_id: str) -> None:
        rule = self._session.get(AccessRule, rule_id)
        if rule is None:
            raise ValueError(f"Access rule {rule_id} not found")
        self._session.delete(rule)
        self._session.commit()
        logger.info("Deleted access rule '%s'", rule.name)
