"""POST /v1/guard_chat_completions — main guard evaluation endpoint.

This is the core of Tidewall.  Every LLM request/response that needs
protection flows through this single endpoint.  The processing pipeline is:

    1. **Policy resolution** — find the caller's bound policy (via API key)
       or fall back to the system default.
    2. **Access rules** — evaluate allow/block rules BEFORE any ML work.
       If a rule blocks, return immediately (zero detector cost).
    3. **Detector scan** — run the ScannerEngine, which executes enabled
       detectors in priority order (blockers → redactors → reporters).
       See ``scanner_engine.py`` for ordering details.
    4. **Post-processing** — if text was redacted, rebuild individual
       messages so the caller gets a clean ``guard_output``.
    5. **Status computation** — map scan results to one of five statuses:
       ``allowed | reported | alerted | blocked | transformed``.
       ``report_only`` mode downgrades blocks → alerts and transforms → reports.
    6. **Logging & export** — persist to the interaction log and fire
       webhooks/syslog asynchronously (fire-and-forget).

"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request

from app.auth.dependencies import require_role
from app.config import OnDetectorFailure
from app.detectors.base import FailureCode
from app.models import GuardRequest, GuardResponse, GuardResult
from app.utils import now_iso as _now_iso

logger = logging.getLogger(__name__)

router = APIRouter()


@router.post(
    "/v1/guard_chat_completions",
    response_model=GuardResponse,
    dependencies=[Depends(require_role("api"))],
)
async def guard_chat_completions(body: GuardRequest, request: Request) -> GuardResponse:
    """Evaluate a chat completion request against the caller's policy.

    Runs access rules first (cheap), then ML detectors (expensive).
    Returns a GuardResponse with block/transform/report verdicts plus
    an optional ``guard_output`` containing sanitized messages.
    """
    # Services are initialized once at startup and stored on app.state
    policy_svc = request.app.state.policy_service
    vault_mgr = request.app.state.vault_manager
    log = request.app.state.interaction_log

    request_time = _now_iso()

    # Flatten all message content into a single string for detectors that
    # operate on the full conversation (e.g. prompt injection, topic).
    messages = body.guard_input.get("messages", [])
    event_type = body.event_type
    all_text = " ".join(m.get("content", "") for m in messages)
    tools = body.guard_input.get("tools", [])

    device_id = getattr(request.state, "device_id", None)

    # Resolve policy — use API key's bound policy if available, else default
    bound_policy_id = getattr(request.state, "policy_id", None)
    if bound_policy_id:
        policy = policy_svc.get_policy(bound_policy_id)
    else:
        policy = policy_svc.get_default_policy()
    if policy is None:
        raise HTTPException(status_code=500, detail="No default policy configured")

    policy_id = policy.id
    policy_name = policy.name

    # Get or build the ScannerEngine for this (policy, event_type)
    try:
        engine = policy_svc.get_engine(policy_id, event_type)
    except ValueError:
        engine = policy_svc.get_engine(policy_id, "input")

    # --- Access rule evaluation (runs BEFORE detectors) ---
    from app.services.rule_evaluator import evaluate_access_rules

    rule_set = policy_svc.get_rule_set(policy_id, event_type)
    effective_report_only = False
    if rule_set and rule_set.report_only is not None:
        effective_report_only = rule_set.report_only
    elif policy and policy.report_only:
        effective_report_only = policy.report_only


    access_rules_data: list[dict[str, Any]] = []
    access_rules_result: dict[str, Any] = {"action": "continue", "matched_rules": [], "blocked": False}

    if rule_set and rule_set.access_rules:
        access_rules_data = [
            {
                "name": ar.name,
                "conditions": ar.conditions,
                "then_action": ar.then_action,
                "else_action": ar.else_action,
            }
            for ar in rule_set.access_rules
        ]
        request_metadata = {
            "user_id": body.user_id or "",
            "app_id": body.app_id or "",
            "app_name": (body.extra_info or {}).get("app_name", "") if body.extra_info else "",
            "model": body.model or "",
            "llm_provider": body.llm_provider or "",
            "source_ip": body.source_ip or "",
        }
        try:
            access_rules_result = evaluate_access_rules(access_rules_data, request_metadata)
        except ValueError:
            # A stored rule the evaluator cannot apply. Validation rejects these
            # at write time, so reaching here means an unvalidated write path.
            # Blocking is the honest response: the rule might have blocked this
            # request and we cannot tell. Raising would 500 and produce no audit
            # record at all.
            logger.error("Access rule could not be evaluated; blocking", exc_info=True)
            access_rules_result = {
                "action": "block",
                "matched_rules": [{"name": "invalid-rule", "matched": True, "action": "block"}],
                "blocked": True,
            }

    # If access rules blocked, return immediately without running detectors
    if access_rules_result["blocked"]:
        response_time = _now_iso()
        request_id = f"tw_{uuid.uuid4().hex[:16]}"
        summary = f"Blocked by access rule: {access_rules_result['matched_rules'][-1]['name']}"

        response = GuardResponse(
            request_id=request_id,
            request_time=request_time,
            response_time=response_time,
            status="Success",
            summary=summary,
            result=GuardResult(
                blocked=True,
                transformed=False,
                guard_output=None,
                policy=policy_name,
                detectors={},
                access_rules={
                    r["name"]: {"matched": r["matched"], "action": r["action"]}
                    for r in access_rules_result["matched_rules"]
                },
                fpe_context=None,
            ),
        )

        await asyncio.to_thread(
            log.log_event,
            request_id=request_id,
            timestamp=response_time,
            event_type=event_type,
            policy=policy_name,
            blocked=True,
            transformed=False,
            status="blocked",
            latency_ms=0,
            summary=summary,
            input_messages=messages,
            output_messages=None,
            detectors_json={},
            app_id=body.app_id,
            user_id=body.user_id,
            llm_provider=body.llm_provider,
            model=body.model,
            source_ip=body.source_ip,
            device_id=device_id,
        )
        # Export to configured targets (fire-and-forget)
        try:
            export_svc = request.app.state.export_service
            await export_svc.emit(
                status="blocked",
                request_id=request_id,
                timestamp=response_time,
                summary=summary,
                policy_name=policy_name,
                event_type=event_type,
                detectors={},
                user_id=body.user_id,
                app_id=body.app_id,
                model=body.model,
                llm_provider=body.llm_provider,
                source_ip=body.source_ip,
            )
        except Exception:
            pass  # Never block guard response on export failure
        return response

    # Create a per-request vault for reversible redaction.  PII/secrets
    # detectors write original values into this vault keyed by placeholder
    # tokens.  The vault is later persisted so that /v1/unredact can
    # recover the originals using the fpe_context token.
    vault_id, vault = vault_mgr.create_vault()

    # Detectors use synchronous ML inference (torch, ONNX) so we offload
    # the entire scan to a thread to keep the async event loop responsive.
    t0 = time.monotonic()
    scan_result = await asyncio.to_thread(engine.scan, all_text, event_type, vault_id, vault, tools, messages)
    latency_ms = (time.monotonic() - t0) * 1000

    # If any redacting detector mutated text, we need to re-scan each
    # message individually so the caller gets per-message sanitized output
    # (the initial scan only checked the concatenated text).
    guard_output: dict | None = None
    fpe_context: str | None = None

    redaction_failed = False
    if scan_result.transformed:
        transformed_msgs: list[dict] = []
        reconstruction_failed = False
        for msg in messages:
            content = msg.get("content", "")
            if not content.strip():
                transformed_msgs.append({"role": msg.get("role", "user"), "content": content})
                continue

            try:
                msg_result = await asyncio.to_thread(engine.scan_single, content, vault_id, vault)
            except Exception:
                logger.error("Message reconstruction raised", exc_info=True)
                scan_result.record_failure("_reconstruction", FailureCode.RECONSTRUCTION_FAILED, action="redact")
                reconstruction_failed = True
                break

            if msg_result.enforcement_degraded or msg_result.guard_output_text is None:
                # A redactor failed on this message. `guard_output_text` is
                # deliberately None; falling back to `content` here would emit
                # the original unredacted text, which is precisely what the
                # failed redactor existed to prevent.
                # Merge both the failure objects (which enforcement reads) and
                # the detector payload (which the response, audit row and export
                # read). Copying only the former left the per-message failure
                # invisible everywhere a human would look for it.
                scan_result.failures.extend(msg_result.failures)
                scan_result.detectors.update(msg_result.detectors)
                reconstruction_failed = True
                break

            transformed_msgs.append({"role": msg.get("role", "user"), "content": msg_result.guard_output_text})

        if reconstruction_failed:
            # Discard every message assembled so far, not just the failing one:
            # the caller must not receive a partially sanitised conversation.
            transformed_msgs = []
            scan_result.transformed = False
            guard_output = None
            fpe_context = None
            redaction_failed = True
        else:
            guard_output = {"messages": transformed_msgs}
            fpe_context = vault_mgr.encode_fpe_context(vault_id)

    # Handle MCP tool filtering (tool_listing events). Skipped after a failed
    # redaction: rebuilding a guard_output there would re-populate the field the
    # discard just cleared.
    if event_type == "tool_listing" and tools and not redaction_failed:
        mcp_det = scan_result.detectors.get("mcp_validation", {})
        if mcp_det.get("detected") and mcp_det.get("data", {}).get("action") == "blocked":
            filtered_names = set(mcp_det["data"].get("filtered_tools", []))
            if filtered_names:
                safe_tools = [t for t in tools if t.get("function", {}).get("name", "") not in filtered_names]
                if guard_output is None:
                    guard_output = {}
                guard_output["tools"] = safe_tools
                scan_result.transformed = True

    # Detector failure enforcement (P0-2).
    #
    # A blocking or redacting detector that could not run means the request was
    # never actually protected. Allowing it here — which is what happened before
    # this existed — returns HTTP 200 with "No threats detected" for content
    # nothing inspected.
    #
    # This is evaluated *before* the report_only downgrade below, deliberately:
    # report_only exists so an operator can trial a policy without affecting
    # traffic, but a detector failure is not a policy verdict to shadow, it is
    # the absence of one. Documented as a change to what report_only guarantees.
    failure_blocked = False
    if scan_result.enforcement_degraded and engine.on_detector_failure is OnDetectorFailure.BLOCK:
        failed_names = sorted({f.name for f in scan_result.failures if f.enforcing})
        logger.error("Blocking request: enforcing detectors failed: %s", ", ".join(failed_names))
        scan_result.blocked = True
        failure_blocked = True
        # Never return content the failed detectors did not get to inspect.
        scan_result.transformed = False
        guard_output = None
        fpe_context = None
        scan_result.summary_parts.append(
            f"Blocked: required detectors could not run ({', '.join(failed_names)})."
        )

    # Compute 5-value status.  In report_only mode, destructive actions
    # (block/transform) are downgraded so the request is never actually
    # modified — useful for shadow-mode evaluation of new policies.
    if failure_blocked:
        # Not downgraded by report_only: see above.
        status = "blocked"
    elif effective_report_only:
        if scan_result.blocked:
            status = "alerted"
            scan_result.blocked = False
        elif scan_result.transformed:
            status = "reported"
            scan_result.transformed = False
            guard_output = None
            fpe_context = None
        elif scan_result.detectors and any(
            d.get("detected") for d in scan_result.detectors.values() if isinstance(d, dict)
        ):
            status = "reported"
        else:
            status = "allowed"
    else:
        if scan_result.blocked:
            status = "blocked"
        elif scan_result.transformed:
            status = "transformed"
        elif scan_result.detectors and any(
            d.get("detected") for d in scan_result.detectors.values() if isinstance(d, dict)
        ):
            status = "reported"
        else:
            status = "allowed"

    # Build response
    response_time = _now_iso()
    request_id = f"tw_{uuid.uuid4().hex[:16]}"
    summary = " ".join(scan_result.summary_parts) or "No threats detected."

    response = GuardResponse(
        request_id=request_id,
        request_time=request_time,
        response_time=response_time,
        status="Success",
        summary=summary,
        result=GuardResult(
            blocked=scan_result.blocked,
            transformed=scan_result.transformed,
            guard_output=guard_output,
            policy=policy_name,
            detectors=scan_result.detectors,
            access_rules={
                r["name"]: {"matched": r["matched"], "action": r["action"]}
                for r in access_rules_result["matched_rules"]
            },
            fpe_context=fpe_context,
        ),
    )

    # Log interaction
    await asyncio.to_thread(
        log.log_event,
        request_id=request_id,
        timestamp=response_time,
        event_type=event_type,
        policy=policy_name,
        blocked=scan_result.blocked,
        transformed=scan_result.transformed,
        status=status,
        latency_ms=latency_ms,
        summary=summary,
        input_messages=messages,
        output_messages=guard_output.get("messages") if guard_output else None,
        detectors_json=scan_result.detectors,
        app_id=body.app_id,
        user_id=body.user_id,
        llm_provider=body.llm_provider,
        model=body.model,
        source_ip=body.source_ip,
        device_id=device_id,
    )
    if device_id:
        try:
            dev_session = request.app.state.session_factory()
            try:
                from app.services.device_service import DeviceService

                DeviceService(dev_session).update_last_seen(device_id)
            finally:
                dev_session.close()
        except Exception:
            pass  # Never block guard response on device tracking
    # Export to configured targets (fire-and-forget)
    try:
        export_svc = request.app.state.export_service
        await export_svc.emit(
            status=status,
            request_id=request_id,
            timestamp=response_time,
            summary=summary,
            policy_name=policy_name,
            event_type=event_type,
            detectors=scan_result.detectors,
            user_id=body.user_id,
            app_id=body.app_id,
            model=body.model,
            llm_provider=body.llm_provider,
            source_ip=body.source_ip,
        )
    except Exception:
        pass  # Never block guard response on export failure

    return response
