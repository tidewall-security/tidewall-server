"""Policy CRUD endpoints — replaces policy_api.py."""

from __future__ import annotations

from typing import Any

import yaml
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import Response
from pydantic import BaseModel

from app.auth.dependencies import require_role
from app.config import OnDetectorFailure
from app.services.policy_validation import PolicyValidationError

router = APIRouter(prefix="/v1/policies", tags=["policies"])


class CreatePolicyRequest(BaseModel):
    name: str
    type: str = "application"
    description: str | None = None
    report_only: bool = False
    on_detector_failure: OnDetectorFailure = OnDetectorFailure.REPORT
    detectors: dict[str, Any] = {}


class UpdatePolicyRequest(BaseModel):
    name: str | None = None
    description: str | None = None
    on_detector_failure: OnDetectorFailure | None = None
    report_only: bool | None = None


class UpdateRuleSetRequest(BaseModel):
    detectors: dict[str, Any]


def _policy_to_dict(policy) -> dict:
    return {
        "id": policy.id,
        "name": policy.name,
        "type": policy.type,
        "description": policy.description,
        "report_only": policy.report_only,
        "on_detector_failure": policy.on_detector_failure,
        "is_default": policy.is_default,
        "created_at": str(policy.created_at),
        "updated_at": str(policy.updated_at),
        "rule_sets": [
            {
                "id": rs.id,
                "event_type": rs.event_type,
                "detectors": rs.detectors,
            }
            for rs in policy.rule_sets
        ],
    }


@router.get("", dependencies=[Depends(require_role("viewer"))])
async def list_policies(request: Request) -> list[dict]:
    session = request.app.state.session_factory()
    try:
        from app.services.policy_service import PolicyService

        svc = PolicyService(session)
        return [_policy_to_dict(p) for p in svc.list_policies()]
    finally:
        session.close()


@router.post("", status_code=201, dependencies=[Depends(require_role("admin"))])
async def create_policy(body: CreatePolicyRequest, request: Request) -> dict:
    session = request.app.state.session_factory()
    try:
        from app.services.policy_service import PolicyService

        svc = PolicyService(session)
        policy = svc.create_policy(
            name=body.name,
            type=body.type,
            description=body.description,
            report_only=body.report_only,
            detectors=body.detectors,
            on_detector_failure=body.on_detector_failure,
        )
        return _policy_to_dict(policy)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        session.close()


@router.get("/{policy_id}", dependencies=[Depends(require_role("viewer"))])
async def get_policy(policy_id: str, request: Request) -> dict:
    session = request.app.state.session_factory()
    try:
        from app.services.policy_service import PolicyService

        svc = PolicyService(session)
        policy = svc.get_policy(policy_id)
        if policy is None:
            raise HTTPException(status_code=404, detail="Policy not found")
        return _policy_to_dict(policy)
    finally:
        session.close()


@router.patch("/{policy_id}", dependencies=[Depends(require_role("admin"))])
async def update_policy(policy_id: str, body: UpdatePolicyRequest, request: Request) -> dict:
    session = request.app.state.session_factory()
    try:
        from app.services.policy_service import PolicyService

        svc = PolicyService(session)
        policy = svc.update_policy(
            policy_id,
            name=body.name,
            description=body.description,
            report_only=body.report_only,
            on_detector_failure=body.on_detector_failure.value if body.on_detector_failure else None,
        )
        # The write above ran on a throwaway PolicyService whose engine cache is
        # not the live one, so its invalidation reached nothing. Invalidate on
        # the application-scoped service too, or an administrator tightening
        # enforcement gets a 200 and no behaviour change until restart.
        #
        # This is a targeted fix, not a general one: the throwaway-service
        # pattern is P0-5's root cause and every other policy-mutating route has
        # the same problem. The activation protocol replaces this wholesale.
        live_svc = getattr(request.app.state, "policy_service", None)
        if live_svc is not None:
            live_svc.invalidate_engines(policy_id)
        return _policy_to_dict(policy)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    finally:
        session.close()


@router.delete("/{policy_id}", status_code=204, dependencies=[Depends(require_role("admin"))])
async def delete_policy(policy_id: str, request: Request) -> None:
    session = request.app.state.session_factory()
    try:
        from app.services.policy_service import PolicyService

        svc = PolicyService(session)
        svc.delete_policy(policy_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        session.close()


@router.get("/{policy_id}/rule-sets/{event_type}", dependencies=[Depends(require_role("viewer"))])
async def get_rule_set(policy_id: str, event_type: str, request: Request) -> dict:
    session = request.app.state.session_factory()
    try:
        from app.services.policy_service import PolicyService

        svc = PolicyService(session)
        rs = svc.get_rule_set(policy_id, event_type)
        if rs is None:
            raise HTTPException(status_code=404, detail="Rule set not found")
        return {
            "id": rs.id,
            "policy_id": rs.policy_id,
            "event_type": rs.event_type,
            "detectors": rs.detectors,
        }
    finally:
        session.close()


@router.patch("/{policy_id}/rule-sets/{event_type}", dependencies=[Depends(require_role("admin"))])
async def update_rule_set(policy_id: str, event_type: str, body: UpdateRuleSetRequest, request: Request) -> dict:
    session = request.app.state.session_factory()
    try:
        from app.services.policy_service import PolicyService

        svc = PolicyService(session)
        rs = svc.update_rule_set(policy_id, event_type, body.detectors)
        return {
            "id": rs.id,
            "policy_id": rs.policy_id,
            "event_type": rs.event_type,
            "detectors": rs.detectors,
        }
    except PolicyValidationError as e:
        # A rejected policy is the administrator's mistake to fix, not a
        # missing resource. Mapping it to 404 told them the rule set did not
        # exist, which is both wrong and unactionable.
        raise HTTPException(status_code=400, detail=str(e)) from None
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e)) from None
    finally:
        session.close()


class CreateAccessRuleRequest(BaseModel):
    name: str
    conditions: dict[str, Any] = {}
    then_action: str = "continue"
    else_action: str = "continue"


class UpdateAccessRuleRequest(BaseModel):
    name: str | None = None
    conditions: dict[str, Any] | None = None
    then_action: str | None = None
    else_action: str | None = None
    sort_order: int | None = None


def _rule_to_dict(rule) -> dict:
    return {
        "id": rule.id,
        "rule_set_id": rule.rule_set_id,
        "name": rule.name,
        "conditions": rule.conditions,
        "then_action": rule.then_action,
        "else_action": rule.else_action,
        "sort_order": rule.sort_order,
    }


@router.get(
    "/{policy_id}/rule-sets/{event_type}/access-rules",
    dependencies=[Depends(require_role("viewer"))],
)
async def list_access_rules(policy_id: str, event_type: str, request: Request) -> list[dict]:
    session = request.app.state.session_factory()
    try:
        from app.services.access_rule_service import AccessRuleService
        from app.services.policy_service import PolicyService

        psvc = PolicyService(session)
        rs = psvc.get_rule_set(policy_id, event_type)
        if rs is None:
            raise HTTPException(status_code=404, detail="Rule set not found")
        arsvc = AccessRuleService(session)
        return [_rule_to_dict(r) for r in arsvc.list_rules(rs.id)]
    finally:
        session.close()


@router.post(
    "/{policy_id}/rule-sets/{event_type}/access-rules",
    status_code=201,
    dependencies=[Depends(require_role("admin"))],
)
async def create_access_rule(policy_id: str, event_type: str, body: CreateAccessRuleRequest, request: Request) -> dict:
    session = request.app.state.session_factory()
    try:
        from app.services.access_rule_service import AccessRuleService
        from app.services.policy_service import PolicyService

        psvc = PolicyService(session)
        rs = psvc.get_rule_set(policy_id, event_type)
        if rs is None:
            raise HTTPException(status_code=404, detail="Rule set not found")
        arsvc = AccessRuleService(session)
        rule = arsvc.create_rule(
            rule_set_id=rs.id,
            name=body.name,
            conditions=body.conditions,
            then_action=body.then_action,
            else_action=body.else_action,
        )
        return _rule_to_dict(rule)
    finally:
        session.close()


@router.patch(
    "/{policy_id}/rule-sets/{event_type}/access-rules/{rule_id}",
    dependencies=[Depends(require_role("admin"))],
)
async def update_access_rule(
    policy_id: str, event_type: str, rule_id: str, body: UpdateAccessRuleRequest, request: Request
) -> dict:
    session = request.app.state.session_factory()
    try:
        from app.services.access_rule_service import AccessRuleService

        arsvc = AccessRuleService(session)
        rule = arsvc.update_rule(
            rule_id,
            name=body.name,
            conditions=body.conditions,
            then_action=body.then_action,
            else_action=body.else_action,
            sort_order=body.sort_order,
        )
        return _rule_to_dict(rule)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    finally:
        session.close()


@router.delete(
    "/{policy_id}/rule-sets/{event_type}/access-rules/{rule_id}",
    status_code=204,
    dependencies=[Depends(require_role("admin"))],
)
async def delete_access_rule(policy_id: str, event_type: str, rule_id: str, request: Request) -> None:
    session = request.app.state.session_factory()
    try:
        from app.services.access_rule_service import AccessRuleService

        arsvc = AccessRuleService(session)
        arsvc.delete_rule(rule_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    finally:
        session.close()


@router.post("/import", status_code=201, dependencies=[Depends(require_role("admin"))])
async def import_policy(body: dict, request: Request) -> dict:
    """Import a policy from a YAML-format dict (same structure as policy.yaml)."""
    session = request.app.state.session_factory()
    try:
        from app.services.policy_service import PolicyService

        svc = PolicyService(session)

        name = body.get("name", "imported-policy")
        report_only = body.get("report_only", False)
        detectors = body.get("detectors", {})

        policy = svc.create_policy(
            name=name,
            type=body.get("type", "application"),
            description=body.get("description"),
            report_only=report_only,
            detectors=detectors,
            on_detector_failure=body.get("on_detector_failure", "report"),
        )
        return _policy_to_dict(policy)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        session.close()


@router.get("/{policy_id}/export", dependencies=[Depends(require_role("viewer"))])
async def export_policy(policy_id: str, request: Request) -> Response:
    """Export a policy as YAML (same format as policy.yaml)."""
    session = request.app.state.session_factory()
    try:
        from app.services.policy_service import PolicyService

        svc = PolicyService(session)
        policy = svc.get_policy(policy_id)
        if policy is None:
            raise HTTPException(status_code=404, detail="Policy not found")

        input_rs = svc.get_rule_set(policy_id, "input")
        detectors = input_rs.detectors if input_rs else {}

        yaml_data = {
            "name": policy.name,
            "type": policy.type,
            "report_only": policy.report_only,
            "detectors": detectors,
        }

        yaml_str = yaml.dump(yaml_data, default_flow_style=False, sort_keys=False)
        return Response(
            content=yaml_str,
            media_type="application/x-yaml",
            headers={"Content-Disposition": f'attachment; filename="{policy.name}.yaml"'},
        )
    finally:
        session.close()
