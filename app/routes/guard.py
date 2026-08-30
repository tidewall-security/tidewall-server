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
from app.interaction_log import _validated as _safe_meta
from app.interaction_log import _validated_ip as _safe_ip
from app.models import GuardRequest, GuardResponse, GuardResult
from app.services.safe_export_evidence import project_detectors
from app.services.safe_logging import describe, report
from app.utils import now_iso as _now_iso

logger = logging.getLogger(__name__)


def _build_collector(messages: list[dict]) -> Any:
    """Set up exact-match capture, or give up on it.

    Wrapped whole. Constructing the collector and its sources sits outside the
    scan, so an exception here turned a request that capture-off would have
    scanned into a 500 — optional audit deciding whether the guard runs at all.
    """
    try:
        from app.services.audit_evidence import MatchCollector, SourceRef

        collector = MatchCollector()
        # Per message, with each one's offset into the flattened text, so a
        # match is attributed to the message it actually came from rather than
        # to the first one.
        segments = []
        cursor = 0
        for index, message in enumerate(messages or []):
            segment_text = str(message.get("content") or "")
            segments.append(
                (
                    SourceRef(
                        kind="message",
                        index=index,
                        field="content",
                        # Roles are caller data, not internal discriminators.
                        role=_safe_role(message.get("role")),
                    ),
                    segment_text,
                    cursor,
                )
            )
            cursor += len(segment_text) + 1  # the single space the flattening inserts
        collector.register_flattened(segments)
        return collector
    except Exception as exc:
        report(logger, "warning", "exact-match capture setup failed; continuing without it", exc)
        return None


def _safe_role(value: object) -> str | None:
    """A role that provenance can record, or nothing.

    Dropped rather than rejected: the role is a nice-to-have on an audit
    record, and refusing the request because a caller used "human/operator"
    would make enabling capture change the API contract.
    """
    if not isinstance(value, str) or not value:
        return None
    # ASCII, matching what SourceRef will accept. isalnum() passes Unicode
    # letters, so a role like "rôle" cleared this check and was then rejected
    # downstream — failing the request rather than dropping the role.
    ok = all(("a" <= c <= "z") or ("A" <= c <= "Z") or ("0" <= c <= "9") or c in "_-." for c in value)
    if len(value) > 64 or not ok:
        return None
    return value


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
    # Validated at the boundary, handed on as plain dicts. Everything downstream
    # -- the collector, the engine, the interaction record -- takes list[dict],
    # and the model exists to stop malformed shapes reaching them, not to change
    # what they receive. `extra="allow"` means a real OpenAI message keeps its
    # `name`, `tool_calls` and the rest through model_dump().
    messages = [m.model_dump() for m in body.guard_input.messages]
    event_type = body.event_type
    all_text = " ".join(m.get("content", "") for m in messages)
    tools = body.guard_input.tools

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

    # release:component access_rules/early_block -- blocks before any detector runs
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
        except ValueError as exc:
            # A stored rule the evaluator cannot apply. Validation rejects these
            # at write time, so reaching here means an unvalidated write path.
            # Blocking is the honest response: the rule might have blocked this
            # request and we cannot tell. Raising would 500 and produce no audit
            # record at all.
            logger.error("Access rule could not be evaluated; blocking: %s", describe(exc))
            access_rules_result = {
                "action": "block",
                "matched_rules": [{"name": "invalid-rule", "matched": True, "action": "block"}],
                "blocked": True,
            }

    # If access rules blocked, return immediately without running detectors
    if access_rules_result["blocked"]:
        response_time = _now_iso()
        request_id = f"tw_{uuid.uuid4().hex[:16]}"
        # A rule name is an arbitrary control-plane value — operators put tenant
        # names, customer identifiers and incident references in them. That was
        # already the reason exports get a fixed string, the reason the stored
        # `summary` column was removed outright, and it applies just as much to
        # the response: this one goes to the caller, who is frequently an end
        # user reading it in a browser, and who has no relationship with the
        # operator's naming scheme.
        #
        # The caller learns it was blocked and by what kind of thing. Which rule
        # is the operator's question, answerable from their own logs.
        summary = "Blocked by access rule"
        export_summary = summary

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
                # Keyed by position, not by name. The key WAS the rule name,
                # which put an arbitrary control-plane value in a response body
                # for every blocked request. Nothing reads this map by name —
                # neither the dashboard nor the extension — and the caller's
                # question is "was I blocked and how", not "what did you call
                # the rule".
                access_rules={
                    str(index): {"matched": r["matched"], "action": r["action"]}
                    for index, r in enumerate(access_rules_result["matched_rules"])
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
            # The resolved policy, not the caller's binding, which may be null.
            policy_id=policy.id,
            api_key_id=getattr(request.state, "api_key_id", None),
            evidence={},
            # Blocking before detectors run is a normal outcome, not an error
            # path — without this, capture-on quietly meant capture-on-except-
            # when-an-access-rule-fired.
            content={"input": messages, "output": None, "matches": None, "tools": tools},
            # Resolved when the request was admitted, so a mid-request policy
            # change cannot retroactively capture or suppress this one.
            capture_enabled=bool(getattr(policy, "raw_content_enabled", False)),
            retention_days=getattr(policy, "raw_content_retention_days", None),
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
                summary=export_summary,
                policy_name=policy_name,
                event_type=event_type,
                detectors={},
                # The same normalisation storage applies. Otherwise the
                # caller-content channel simply crosses a different sink.
                user_id=_safe_meta(body.user_id, "user_id"),
                app_id=_safe_meta(body.app_id, "app_id"),
                model=_safe_meta(body.model, "model"),
                llm_provider=_safe_meta(body.llm_provider, "llm_provider"),
                source_ip=_safe_ip(body.source_ip),
            )
        except Exception:
            pass  # Never block guard response on export failure
        return response

    # Create a per-request vault for reversible redaction.  PII/secrets
    # detectors write original values into this vault keyed by placeholder
    # tokens.  The vault is later persisted so that /v1/unredact can
    # recover the originals using the fpe_context token.
    # Only a key with a policy BINDING owns anything. `bound_policy_id` above,
    # not `policy_id` below it: the latter falls back to the default policy,
    # which decides how to SCAN. If it decided ownership, every unbound key's
    # vaults would land in one shared pool that moves whenever an administrator
    # changes the default.
    #
    # An unbound key still gets redaction -- the detector emits its own
    # placeholders when handed no vault -- it just gets no way to reverse it.
    if bound_policy_id:
        vault_id, vault = vault_mgr.create_vault()
    else:
        # Creation now refuses an unbound `api` key, so reaching here means the
        # bootstrap admin -- installed before any policy exists -- or a key whose
        # policy was deleted, which sets the binding to NULL. Either way the
        # caller is about to get a redaction with no token and no explanation,
        # so name the key and the reason rather than leave a null field to be
        # puzzled over.
        report(
            logger,
            "warning",
            f"api key {getattr(request.state, 'api_key_id', None)} has no policy binding, "
            "so its redactions cannot be reversed; bind it to a policy to enable reversal",
        )
        vault_id, vault = None, None

    # Detectors use synchronous ML inference (torch, ONNX) so we offload
    # the entire scan to a thread to keep the async event loop responsive.
    t0 = time.monotonic()
    # A collector only when capture is on. Detectors that hold an original
    # value report into it, and each match is validated against the text they
    # were given — provenance rather than a value copied out of a payload.
    capture_enabled = bool(getattr(policy, "raw_content_enabled", False))
    match_collector = _build_collector(messages) if capture_enabled else None

    scan_result = await asyncio.to_thread(
        engine.scan, all_text, event_type, vault_id, vault, tools, messages, match_collector
    )

    captured_matches = None
    if match_collector is not None:
        try:
            groups = match_collector.finalize()
            captured_matches = {
                "schema_version": 1,
                "matches": [g.as_storable() for g in groups],
            }
        except Exception as exc:
            # Capture failing must not fail the scan that already succeeded.
            report(logger, "warning", "exact match capture failed", exc)
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
            except Exception as exc:
                logger.error("Message reconstruction raised: %s", describe(exc))
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
            # No vault means an unbound key: redaction happened, using the
            # detector's own placeholders, and nothing can reverse it. A token
            # here would promise a reversal with no mapping behind it.
            fpe_context = vault_mgr.encode_fpe_context(vault_id) if vault_id else None

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

    # Detector failure enforcement.
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
        scan_result.summary_parts.append(f"Blocked: required detectors could not run ({', '.join(failed_names)}).")

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

    # --- Write the vault back ---
    #
    # Here, and nowhere earlier, because here is the first point at which the
    # response's disposition is settled. `fpe_context` is created above after a
    # successful reconstruction and cleared again twice — by the detector
    # failure block and by report_only — so a save placed after the scan would
    # store the placeholder-to-original mapping, which is the PII itself, for
    # requests that end up carrying no way to retrieve it.
    #
    # Both `engine.scan` and every `engine.scan_single` were awaited above, so
    # the worker thread has finished populating the vault and this does not
    # race it.
    if fpe_context is not None:
        try:
            saved = vault_mgr.save(
                vault_id,
                vault,
                # `bound_policy_id`, not the resolved `policy_id`. Substituting
                # the resolved one here changes no behaviour and cannot be
                # killed by a test: a vault is only created when the key IS
                # bound, and for a bound key the resolver returns that same
                # binding, so the two are necessarily equal wherever this runs.
                #
                # Written this way regardless, because the equality is a
                # consequence of the guard above rather than a property of the
                # resolver. If the vault ever gets created unconditionally, the
                # resolved value would silently become the default policy and
                # every unbound key's vaults would land in one shared pool.
                policy_id=bound_policy_id,
                created_by_key_id=getattr(request.state, "api_key_id", None),
            )
        except Exception as exc:
            # Reported through the wrapper, like every other report in this
            # route that is not itself the security decision: an operator's
            # broken log filter raises straight through Logger.handle, and a
            # request whose disposition is already settled must not become a
            # 500 because it could not be written about.
            report(logger, "error", f"vault {vault_id} could not be saved", exc)
            saved = False
        if not saved:
            # A token whose vault was never written promises a reversal that
            # cannot happen — the same silent failure this endpoint keeps
            # producing, one layer up. The redaction itself stands and the
            # caller still gets it; it is only irreversible.
            report(logger, "warning", f"vault {vault_id} was not stored; no reversal is offered")
            fpe_context = None

    # Degradation is recorded as a reserved entry in the detectors payload,
    # which the interaction row and every export format already carry verbatim.
    # Without this, OCSF/AIDR/raw consumers would have to infer degradation by
    # walking nested per-detector status or parsing the summary string — the
    # value would reach them, but only indirectly, which is the same
    # produced-but-not-consumed shape this work keeps tripping over.
    failed_detector_names = sorted({f.name for f in scan_result.failures} | set(scan_result.partial))
    if scan_result.degraded:
        scan_result.detectors["_degraded"] = {
            "degraded": True,
            "failed_detectors": failed_detector_names,
        }

    # Build response
    response_time = _now_iso()
    request_id = f"tw_{uuid.uuid4().hex[:16]}"
    summary = " ".join(scan_result.summary_parts)
    if not summary:
        if scan_result.degraded:
            # "No threats detected" is a lie when part of the scan did not run.
            # Under on_detector_failure=report this is the only signal the
            # caller gets, so it must not claim a complete clean scan.
            summary = "Scan incomplete: one or more detectors could not run."
        else:
            summary = "No threats detected."

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
            # The response carries the same unsafe detector payload the exports
            # did — custom_entity's matched value and start_pos,
            # malicious_entity's unmodified URL. The caller supplied the
            # content, so this is not disclosure to a new party, but a response
            # body fans out further than the request did: proxies, APM tools,
            # browser devtools and the caller's own logging all see it. The
            # caller acts on `guard_output`, not on exact values.
            detectors=project_detectors(scan_result.detectors),
            # Keyed by position, exactly as the blocked path above. Two sites
            # build this map and both must stay identical: fixing one would
            # leave the rule name in every response that was NOT blocked, which
            # is most of them.
            access_rules={
                str(index): {"matched": r["matched"], "action": r["action"]}
                for index, r in enumerate(access_rules_result["matched_rules"])
            },
            fpe_context=fpe_context,
            degraded=scan_result.degraded,
            failed_detectors=failed_detector_names,
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
        policy_id=policy.id,
        api_key_id=getattr(request.state, "api_key_id", None),
        evidence=project_detectors(scan_result.detectors),
        # Offered, not stored: log_event captures only if the policy says so.
        content={
            "input": messages,
            "output": guard_output.get("messages") if guard_output else None,
            # Tools are scanned, so a captured tool-input or tool-listing event
            # without them is an incomplete record of what was evaluated.
            "tools": tools,
            # Exact matches await the detector wiring: the typed channel from
            # step 1 exists but no detector reports through it yet, so this is
            "matches": captured_matches,
        },
        capture_enabled=capture_enabled,
        retention_days=getattr(policy, "raw_content_retention_days", None),
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
