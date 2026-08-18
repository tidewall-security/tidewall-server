"""Settings endpoints — global prompt lists, threat intel, export targets."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from app.auth.dependencies import require_role
from app.services.policy_validation import PolicyValidationError, validate_cidr

router = APIRouter(prefix="/v1/settings", tags=["settings"])


class CreatePromptListRequest(BaseModel):
    list_type: str  # "benign" | "malicious"
    pattern: str
    match_type: str = "substring"  # "substring" | "regex" | "exact"
    description: str | None = None


class UpdatePromptListRequest(BaseModel):
    pattern: str | None = None
    match_type: str | None = None
    description: str | None = None


def _entry_to_dict(entry) -> dict:
    return {
        "id": entry.id,
        "list_type": entry.list_type,
        "pattern": entry.pattern,
        "match_type": entry.match_type,
        "description": entry.description,
        "created_by": entry.created_by,
        "created_at": str(entry.created_at),
    }


@router.get("/prompt-lists", dependencies=[Depends(require_role("admin"))])
async def list_prompt_lists(request: Request, type: str | None = None) -> list[dict]:
    session = request.app.state.session_factory()
    try:
        from app.services.prompt_list_service import PromptListService

        svc = PromptListService(session)
        return [_entry_to_dict(e) for e in svc.list_entries(list_type=type)]
    finally:
        session.close()


@router.post("/prompt-lists", status_code=201, dependencies=[Depends(require_role("admin"))])
async def create_prompt_list(body: CreatePromptListRequest, request: Request) -> dict:
    if body.list_type not in ("benign", "malicious"):
        raise HTTPException(status_code=400, detail="list_type must be 'benign' or 'malicious'")
    session = request.app.state.session_factory()
    try:
        from app.services.prompt_list_service import PromptListService

        svc = PromptListService(session)
        entry = svc.create(
            list_type=body.list_type,
            pattern=body.pattern,
            match_type=body.match_type,
            description=body.description,
        )
        return _entry_to_dict(entry)
    except PolicyValidationError as e:
        # Uncaught, this surfaced as a 500: the request is well formed, the
        # pattern is simply one the safe engine will not run.
        raise HTTPException(status_code=400, detail=str(e)) from None
    finally:
        session.close()


@router.put("/prompt-lists/{entry_id}", dependencies=[Depends(require_role("admin"))])
async def update_prompt_list(entry_id: str, body: UpdatePromptListRequest, request: Request) -> dict:
    session = request.app.state.session_factory()
    try:
        from app.services.prompt_list_service import PromptListService

        svc = PromptListService(session)
        entry = svc.update(entry_id, pattern=body.pattern, match_type=body.match_type, description=body.description)
        return _entry_to_dict(entry)
    except PolicyValidationError as e:
        # Must precede the ValueError arm: PolicyValidationError is a
        # ValueError, so the broad catch below reported a rejected pattern as
        # "entry not found" — which is both wrong and unactionable.
        raise HTTPException(status_code=400, detail=str(e)) from None
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    finally:
        session.close()


@router.delete("/prompt-lists/{entry_id}", status_code=204, dependencies=[Depends(require_role("admin"))])
async def delete_prompt_list(entry_id: str, request: Request) -> None:
    session = request.app.state.session_factory()
    try:
        from app.services.prompt_list_service import PromptListService

        svc = PromptListService(session)
        svc.delete(entry_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    finally:
        session.close()


class CreateExportTargetRequest(BaseModel):
    name: str
    type: str  # "webhook" | "syslog"
    config: dict[str, Any]
    format: str = "ocsf"  # "ocsf" | "aidr_compat" | "raw"
    events: list[str]  # ["blocked", "alerted", "transformed", "reported"]
    enabled: bool = True


class UpdateExportTargetRequest(BaseModel):
    name: str | None = None
    config: dict[str, Any] | None = None
    format: str | None = None
    events: list[str] | None = None
    enabled: bool | None = None


def _target_to_dict(target) -> dict:
    return {
        "id": target.id,
        "name": target.name,
        "type": target.type,
        "config": target.config,
        "format": target.format,
        "events": target.events,
        "enabled": target.enabled,
        "created_at": str(target.created_at),
    }


@router.get("/export-targets", dependencies=[Depends(require_role("admin"))])
async def list_export_targets(request: Request) -> list[dict]:
    session = request.app.state.session_factory()
    try:
        from app.db.models import ExportTarget

        return [_target_to_dict(t) for t in session.query(ExportTarget).all()]
    finally:
        session.close()


@router.post("/export-targets", status_code=201, dependencies=[Depends(require_role("admin"))])
async def create_export_target(body: CreateExportTargetRequest, request: Request) -> dict:
    if body.type not in ("webhook", "syslog"):
        raise HTTPException(status_code=400, detail="type must be 'webhook' or 'syslog'")
    if body.format not in ("ocsf", "aidr_compat", "raw"):
        raise HTTPException(status_code=400, detail="format must be 'ocsf', 'aidr_compat', or 'raw'")
    session = request.app.state.session_factory()
    try:
        from app.db.models import ExportTarget

        target = ExportTarget(
            name=body.name,
            type=body.type,
            config=body.config,
            format=body.format,
            events=body.events,
            enabled=body.enabled,
        )
        session.add(target)
        session.commit()
        return _target_to_dict(target)
    finally:
        session.close()


@router.patch("/export-targets/{target_id}", dependencies=[Depends(require_role("admin"))])
async def update_export_target(target_id: str, body: UpdateExportTargetRequest, request: Request) -> dict:
    session = request.app.state.session_factory()
    try:
        from app.db.models import ExportTarget

        target = session.get(ExportTarget, target_id)
        if target is None:
            raise HTTPException(status_code=404, detail="Export target not found")
        if body.name is not None:
            target.name = body.name
        if body.config is not None:
            target.config = body.config
        if body.format is not None:
            target.format = body.format
        if body.events is not None:
            target.events = body.events
        if body.enabled is not None:
            target.enabled = body.enabled
        session.commit()
        return _target_to_dict(target)
    finally:
        session.close()


@router.delete("/export-targets/{target_id}", status_code=204, dependencies=[Depends(require_role("admin"))])
async def delete_export_target(target_id: str, request: Request) -> None:
    session = request.app.state.session_factory()
    try:
        from app.db.models import ExportTarget

        target = session.get(ExportTarget, target_id)
        if target is None:
            raise HTTPException(status_code=404, detail="Export target not found")
        session.delete(target)
        session.commit()
    finally:
        session.close()


class ThreatIntelConfigRequest(BaseModel):
    builtin: dict[str, Any] = {}  # {urlhaus: bool, otx: {enabled: bool, api_key: str}}
    local_blocklists: dict[str, list[str]] = {}  # {ips: [], domains: [], urls: []}


@router.get("/threat-intel", dependencies=[Depends(require_role("admin"))])
async def get_threat_intel_config(request: Request) -> dict:
    """Return current threat intel configuration.

    Note: Threat intel config is stored in the default policy's malicious_entity
    detector config under the 'intel' key. This endpoint reads it from there.
    """
    session = request.app.state.session_factory()
    try:
        from app.services.policy_service import PolicyService

        svc = PolicyService(session)
        default = svc.get_default_policy()
        if default is None:
            return {"builtin": {}, "local_blocklists": {}}
        rs = svc.get_rule_set(default.id, "input")
        if rs is None:
            return {"builtin": {}, "local_blocklists": {}}
        me_config = rs.detectors.get("malicious_entity", {})
        intel = me_config.get("intel", {})
        return {
            "builtin": intel.get("builtin", {}),
            "local_blocklists": intel.get("local_blocklists", {}),
            "ml_url_classification": intel.get("ml_url_classification", True),
        }
    finally:
        session.close()


@router.put("/threat-intel", dependencies=[Depends(require_role("admin"))])
async def update_threat_intel_config(body: ThreatIntelConfigRequest, request: Request) -> dict:
    """Update threat intel configuration in the default policy."""

    # An invalid CIDR returns "not malicious" at runtime, so a typo silently
    # removes the blocklist entry it expressed.
    for i, entry in enumerate(body.local_blocklists.get("ips", []) or []):
        try:
            validate_cidr(entry if "/" in entry else f"{entry}/32", where=f"local_blocklists.ips[{i}]")
        except PolicyValidationError as e:
            raise HTTPException(status_code=400, detail=str(e)) from None
    session = request.app.state.session_factory()
    try:
        from app.services.policy_service import PolicyService

        svc = PolicyService(session)
        default = svc.get_default_policy()
        if default is None:
            raise HTTPException(status_code=404, detail="No default policy")
        rs = svc.get_rule_set(default.id, "input")
        if rs is None:
            raise HTTPException(status_code=404, detail="No input rule set")

        # Update the intel config within the malicious_entity detector
        detectors = dict(rs.detectors)
        me_config = dict(detectors.get("malicious_entity", {"enabled": True, "action": "report"}))
        me_config["intel"] = {
            "builtin": body.builtin,
            "local_blocklists": body.local_blocklists,
            "ml_url_classification": me_config.get("intel", {}).get("ml_url_classification", True),
        }
        detectors["malicious_entity"] = me_config
        svc.update_rule_set(default.id, "input", detectors)

        return {"status": "ok", "intel": me_config["intel"]}
    finally:
        session.close()


class CreateModelIntentRequest(BaseModel):
    statement: str
    category: str | None = None
    enabled: bool = True


class UpdateModelIntentRequest(BaseModel):
    statement: str | None = None
    category: str | None = None
    enabled: bool | None = None


def _intent_to_dict(intent) -> dict:
    return {
        "id": intent.id,
        "statement": intent.statement,
        "category": intent.category,
        "enabled": intent.enabled,
        "created_at": str(intent.created_at),
    }


@router.get("/model-intent", dependencies=[Depends(require_role("admin"))])
async def list_model_intents(request: Request) -> list[dict]:
    session = request.app.state.session_factory()
    try:
        from app.db.models import ModelIntent

        intents = session.query(ModelIntent).order_by(ModelIntent.created_at.desc()).all()
        return [_intent_to_dict(i) for i in intents]
    finally:
        session.close()


@router.post("/model-intent", status_code=201, dependencies=[Depends(require_role("admin"))])
async def create_model_intent(body: CreateModelIntentRequest, request: Request) -> dict:
    session = request.app.state.session_factory()
    try:
        from app.db.models import ModelIntent

        intent = ModelIntent(
            statement=body.statement,
            category=body.category,
            enabled=body.enabled,
        )
        session.add(intent)
        session.commit()
        return _intent_to_dict(intent)
    finally:
        session.close()


@router.put("/model-intent/{intent_id}", dependencies=[Depends(require_role("admin"))])
async def update_model_intent(intent_id: str, body: UpdateModelIntentRequest, request: Request) -> dict:
    session = request.app.state.session_factory()
    try:
        from app.db.models import ModelIntent

        intent = session.get(ModelIntent, intent_id)
        if intent is None:
            raise HTTPException(status_code=404, detail="Model intent not found")
        if body.statement is not None:
            intent.statement = body.statement
        if body.category is not None:
            intent.category = body.category
        if body.enabled is not None:
            intent.enabled = body.enabled
        session.commit()
        return _intent_to_dict(intent)
    finally:
        session.close()


@router.delete("/model-intent/{intent_id}", status_code=204, dependencies=[Depends(require_role("admin"))])
async def delete_model_intent(intent_id: str, request: Request) -> None:
    session = request.app.state.session_factory()
    try:
        from app.db.models import ModelIntent

        intent = session.get(ModelIntent, intent_id)
        if intent is None:
            raise HTTPException(status_code=404, detail="Model intent not found")
        session.delete(intent)
        session.commit()
    finally:
        session.close()
