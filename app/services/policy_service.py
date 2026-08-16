"""Policy CRUD and scanner engine cache."""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy.orm import Session

from app.config import OnDetectorFailure
from app.db.models import Policy, RuleSet
from app.scanner_engine import ScannerEngine
from app.services.policy_validation import validate_detectors

logger = logging.getLogger(__name__)


class PolicyService:
    """Manages policy CRUD and maintains a cache of ScannerEngines.

    The engine cache is keyed by (policy_id, event_type). Engines are built
    lazily on first access and invalidated when the corresponding rule set
    is updated.

    Accepts either a pre-existing session (for backward compatibility with
    tests) or a session_factory.  When session_factory is provided, every
    DB-touching method creates a short-lived session that is closed at the
    end of the call, avoiding stale-session bugs.
    """

    def __init__(self, session: Session | None = None, session_factory: Any = None, use_onnx: bool = False) -> None:
        self._session = session
        self._session_factory = session_factory
        self._use_onnx = use_onnx
        self._engine_cache: dict[tuple[str, str], ScannerEngine] = {}

    def _get_session(self) -> tuple[Session, bool]:
        """Return (session, should_close).

        If a session_factory is available, create a fresh session (caller
        must close).  Otherwise fall back to the long-lived self._session
        for backward compatibility with tests.
        """
        if self._session_factory is not None:
            return self._session_factory(), True
        if self._session is not None:
            return self._session, False
        raise RuntimeError("PolicyService has no session or session_factory")

    # ---- Read ----

    def list_policies(self) -> list[Policy]:
        session, should_close = self._get_session()
        try:
            return session.query(Policy).order_by(Policy.name).all()
        finally:
            if should_close:
                session.close()

    def get_policy(self, policy_id: str) -> Policy | None:
        session, should_close = self._get_session()
        try:
            return session.get(Policy, policy_id)
        finally:
            if should_close:
                session.close()

    def get_default_policy(self) -> Policy | None:
        session, should_close = self._get_session()
        try:
            return session.query(Policy).filter_by(is_default=True).first()
        finally:
            if should_close:
                session.close()

    def get_rule_set(self, policy_id: str, event_type: str) -> RuleSet | None:
        from sqlalchemy.orm import joinedload

        session, should_close = self._get_session()
        try:
            return (
                session.query(RuleSet)
                .options(joinedload(RuleSet.access_rules))
                .filter_by(policy_id=policy_id, event_type=event_type)
                .first()
            )
        finally:
            if should_close:
                session.close()

    # ---- Create ----

    def create_policy(
        self,
        name: str,
        type: str = "application",
        description: str | None = None,
        report_only: bool = False,
        is_default: bool = False,
        detectors: dict[str, Any] | None = None,
        on_detector_failure: str = OnDetectorFailure.REPORT.value,
    ) -> Policy:
        # Validate before writing anything. A policy that cannot be enforced
        # as written is rejected while the administrator is looking at it,
        # rather than accepted and then quietly not applied — which is
        # indistinguishable from applied-and-found-nothing.
        validate_detectors(detectors or {})

        session, should_close = self._get_session()
        try:
            policy = Policy(
                name=name,
                type=type,
                description=description,
                report_only=report_only,
                on_detector_failure=OnDetectorFailure(on_detector_failure).value,
                is_default=is_default,
            )
            session.add(policy)
            session.flush()

            # Create default input + output rule sets
            for event_type in ("input", "output"):
                rs = RuleSet(
                    policy_id=policy.id,
                    event_type=event_type,
                    detectors=detectors or {},
                )
                session.add(rs)

            session.commit()
            logger.info("Created policy '%s' (id=%s)", name, policy.id)
            return policy
        finally:
            if should_close:
                session.close()

    # ---- Update ----

    def update_policy(
        self,
        policy_id: str,
        name: str | None = None,
        description: str | None = None,
        report_only: bool | None = None,
    ) -> Policy:
        session, should_close = self._get_session()
        try:
            policy = session.get(Policy, policy_id)
            if policy is None:
                raise ValueError(f"Policy {policy_id} not found")

            if name is not None:
                policy.name = name
            if description is not None:
                policy.description = description
            if report_only is not None:
                policy.report_only = report_only

            session.commit()
            return policy
        finally:
            if should_close:
                session.close()

    def update_rule_set(
        self,
        policy_id: str,
        event_type: str,
        detectors: dict[str, Any],
    ) -> RuleSet:
        validate_detectors(detectors or {})

        session, should_close = self._get_session()
        try:
            rs = session.query(RuleSet).filter_by(policy_id=policy_id, event_type=event_type).first()
            if rs is None:
                raise ValueError(f"RuleSet for policy={policy_id}, event_type={event_type} not found")

            rs.detectors = detectors
            session.commit()

            # Invalidate cached engine for this (policy_id, event_type)
            cache_key = (policy_id, event_type)
            self._engine_cache.pop(cache_key, None)
            logger.info("Updated rule set %s/%s — engine cache invalidated", policy_id, event_type)

            return rs
        finally:
            if should_close:
                session.close()

    # ---- Delete ----

    def delete_policy(self, policy_id: str) -> None:
        session, should_close = self._get_session()
        try:
            policy = session.get(Policy, policy_id)
            if policy is None:
                raise ValueError(f"Policy {policy_id} not found")
            if policy.is_default:
                raise ValueError("Cannot delete the default policy")

            # Invalidate all cached engines for this policy
            keys_to_remove = [k for k in self._engine_cache if k[0] == policy_id]
            for k in keys_to_remove:
                del self._engine_cache[k]

            session.delete(policy)
            session.commit()
            logger.info("Deleted policy '%s' (id=%s)", policy.name, policy_id)
        finally:
            if should_close:
                session.close()

    # ---- Engine cache ----

    def get_engine(self, policy_id: str, event_type: str) -> ScannerEngine:
        """Get or build a ScannerEngine for the given policy and event type."""
        cache_key = (policy_id, event_type)
        if cache_key in self._engine_cache:
            return self._engine_cache[cache_key]

        session, should_close = self._get_session()
        try:
            rs = session.query(RuleSet).filter_by(policy_id=policy_id, event_type=event_type).first()
            if rs is None:
                raise ValueError(f"No rule set for policy={policy_id}, event_type={event_type}")

            policy = session.get(Policy, policy_id)
            report_only = policy.report_only if policy else False
            on_detector_failure = OnDetectorFailure(
                (policy.on_detector_failure if policy else None) or OnDetectorFailure.REPORT.value
            )

            engine = ScannerEngine.from_detectors(
                rs.detectors,
                report_only=report_only,
                session_factory=self._session_factory,
                use_onnx=self._use_onnx,
                on_detector_failure=on_detector_failure,
            )
            self._engine_cache[cache_key] = engine
            logger.info(
                "Built ScannerEngine for policy=%s event_type=%s (%d detectors)",
                policy_id,
                event_type,
                len(rs.detectors),
            )
            return engine
        finally:
            if should_close:
                session.close()
