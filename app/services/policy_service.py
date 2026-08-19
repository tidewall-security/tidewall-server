"""Policy CRUD and scanner engine cache."""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.config import OnDetectorFailure
from app.db.models import APIKey, Device, Policy, RegistrationToken, RuleSet
from app.scanner_engine import ScannerEngine
from app.services.policy_validation import validate_detectors

logger = logging.getLogger(__name__)


def _validated_retention(days: int | None) -> int | None:
    """Retention in days, or None for no expiry.

    None is the configured default: the product owner chose configurable
    retention with no default expiry and no size cap. That is deliberate and
    differs from every comparable product researched, so it is recorded here
    rather than left to be rediscovered.
    """
    if days is None:
        return None
    if not isinstance(days, int) or isinstance(days, bool) or days < 1:
        raise ValueError("raw_content_retention_days must be a positive number of days, or null for no expiry")
    return days


class PolicyInUseError(Exception):
    """Raised when deleting a policy would silently rebind devices to the default."""


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

    def __init__(self, session: Session | None = None, session_factory: Any = None) -> None:
        self._session = session
        self._session_factory = session_factory
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
        raw_content_enabled: bool = False,
        raw_content_retention_days: int | None = None,
    ) -> Policy:
        # Validate before writing anything. A policy that cannot be enforced
        # as written is rejected while the administrator is looking at it,
        # rather than accepted and then quietly not applied — which is
        # indistinguishable from applied-and-found-nothing.
        validate_detectors(detectors or {})
        retention = _validated_retention(raw_content_retention_days)

        session, should_close = self._get_session()
        try:
            policy = Policy(
                name=name,
                type=type,
                description=description,
                report_only=report_only,
                on_detector_failure=OnDetectorFailure(on_detector_failure).value,
                is_default=is_default,
                # Accepted as parameters and then never assigned, so creating an
                # enabled policy returned 201 with capture silently off. That is
                # precisely the state this step exists to make impossible.
                raw_content_enabled=raw_content_enabled,
                raw_content_retention_days=retention,
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
        on_detector_failure: str | None = None,
        raw_content_enabled: bool | None = None,
        raw_content_retention_days: int | None = None,
        retention_supplied: bool = False,
    ) -> Policy:
        if on_detector_failure is not None:
            on_detector_failure = OnDetectorFailure(on_detector_failure).value

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
            if on_detector_failure is not None:
                policy.on_detector_failure = on_detector_failure
            if raw_content_enabled is not None:
                policy.raw_content_enabled = raw_content_enabled
            if retention_supplied:
                # Explicit flag, because None is a meaningful value here: it
                # means "no expiry", not "leave unchanged". Without it there is
                # no way to turn a retention window back off.
                policy.raw_content_retention_days = _validated_retention(raw_content_retention_days)

            session.commit()

            # Engines are cached on (policy_id, event_type) and hold a snapshot
            # of the policy, so report_only and on_detector_failure would keep
            # their old values on every cached engine until restart. An
            # administrator tightening enforcement would see the write succeed
            # and nothing change — the same shape of defect as a policy write
            # never reaching the live engine.
            self.invalidate_engines(policy_id)
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

            # A null policy binding is read as "use the default" at guard time,
            # so deleting a policy still in use must not be allowed to null one:
            # it would move devices onto rules nobody chose for them, with
            # nothing in the request saying so. A device's scope is fixed at
            # enrolment, so reassignment has to be an explicit act.
            #
            # This count only produces a message worth reading. It is not the
            # guarantee — it is not atomic with the delete, so an enrolment
            # landing between the two would still slip through. Both foreign
            # keys are ON DELETE RESTRICT, and that is what holds.
            devices = session.query(Device).filter_by(policy_id=policy_id).count()
            tokens = session.query(RegistrationToken).filter_by(policy_id=policy_id).count()
            # API keys too. APIKey.policy_id is ON DELETE SET NULL, and an
            # unbound admin reads and deletes globally — so deleting a policy
            # silently promoted a policy-scoped administrator to an
            # organisation-wide one, which is a privilege escalation performed
            # by an unrelated administrative action.
            keys = session.query(APIKey).filter_by(policy_id=policy_id).count()
            if devices or tokens or keys:
                raise PolicyInUseError(
                    f"Policy {policy_id} is still bound to {devices} device(s), "
                    f"{tokens} registration token(s) and {keys} API key(s). Remove them first."
                )

            # Invalidate all cached engines for this policy
            keys_to_remove = [k for k in self._engine_cache if k[0] == policy_id]
            for k in keys_to_remove:
                del self._engine_cache[k]

            session.delete(policy)
            try:
                session.commit()
            except IntegrityError as e:
                # Something bound itself to the policy after the count above.
                session.rollback()
                raise PolicyInUseError(
                    f"Policy {policy_id} became bound to a device or registration token "
                    "while it was being deleted. Remove them first."
                ) from e
            logger.info("Deleted policy '%s' (id=%s)", policy.name, policy_id)
        finally:
            if should_close:
                session.close()

    # ---- Engine cache ----

    def invalidate_engines(self, policy_id: str) -> None:
        """Drop cached engines for a policy so the next request rebuilds them."""
        stale = [key for key in self._engine_cache if key[0] == policy_id]
        for key in stale:
            self._engine_cache.pop(key, None)
        if stale:
            logger.info("Invalidated %d cached engine(s) for policy=%s", len(stale), policy_id)

    def invalidate_all_engines(self) -> None:
        """Drop every cached engine.

        Global prompt lists are not owned by a policy, so a change to one can
        affect any cached engine. Detectors compile those lists at construction
        and hold the result, which means correcting a bad row would otherwise
        leave every cached engine reporting a construction failure that is no
        longer true — until an unrelated policy edit or a restart.
        """
        count = len(self._engine_cache)
        self._engine_cache.clear()
        if count:
            logger.info("Invalidated all %d cached engine(s) after a global list change", count)

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
