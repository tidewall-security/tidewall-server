"""Builds OCSF Data Security Finding (class 2006) events and AIDR-style-format events.

OCSF: Standard envelope for SIEM routing/correlation.
AI-specific fields in unmapped.tidewall (pending OCSF GenAI extension).
AIDR-style: Vendor.* namespace matching TidewallPromptDataEvent format.
"""

from __future__ import annotations

from typing import Any

# MITRE ATLAS mapping — static, per detector
_ATLAS_MAP: dict[str, dict[str, str]] = {
    "malicious_prompt": {
        "technique_id": "AML.T0051",
        "technique_name": "LLM Prompt Injection",
        "tactic": "Execution",
    },
    "confidential_and_pii_entity": {
        "technique_id": "AML.T0057",
        "technique_name": "LLM Data Leakage",
        "tactic": "Exfiltration",
    },
    "secret_and_key_entity": {
        "technique_id": "AML.T0057",
        "technique_name": "LLM Data Leakage",
        "tactic": "Credential Access",
    },
    "topic": {
        "technique_id": "AML.T0048.001",
        "technique_name": "External Harms: Reputational Harm",
        "tactic": "Impact",
    },
    "malicious_entity": {
        "technique_id": "AML.T0051",
        "technique_name": "LLM Prompt Injection",
        "tactic": "Execution",
    },
    "competitors": {
        "technique_id": "AML.T0048.000",
        "technique_name": "External Harms: Financial Harm",
        "tactic": "Impact",
    },
}

# Status → OCSF field mappings
_STATUS_MAP: dict[str, dict[str, int]] = {
    "allowed": {"action_id": 1, "disposition_id": 1, "severity_id": 1},
    "reported": {"action_id": 1, "disposition_id": 1, "severity_id": 3},
    "alerted": {"action_id": 1, "disposition_id": 1, "severity_id": 4},
    "transformed": {"action_id": 1, "disposition_id": 10, "severity_id": 3},
    "blocked": {"action_id": 2, "disposition_id": 2, "severity_id": 4},
}

_ACTION_NAMES = {1: "Allowed", 2: "Denied"}
_DISPOSITION_NAMES = {1: "Allowed", 2: "Blocked", 10: "Corrected"}
_SEVERITY_NAMES = {1: "Informational", 2: "Low", 3: "Medium", 4: "High", 5: "Critical"}


def _build_attacks(detectors: dict[str, Any]) -> list[dict[str, Any]]:
    """Build MITRE ATLAS attacks array from detector results."""
    attacks = []
    seen = set()
    for det_name, det_result in detectors.items():
        if not isinstance(det_result, dict) or not det_result.get("detected"):
            continue
        mapping = _ATLAS_MAP.get(det_name)
        if mapping and mapping["technique_id"] not in seen:
            attacks.append(
                {
                    "tactic": {"name": mapping["tactic"]},
                    "technique": {
                        "name": mapping["technique_name"],
                        "uid": mapping["technique_id"],
                    },
                }
            )
            seen.add(mapping["technique_id"])
    return attacks


def build_ocsf_event(
    *,
    status: str,
    request_id: str,
    timestamp: str,
    summary: str,
    policy_name: str,
    event_type: str,
    detectors: dict[str, Any],
    user_id: str | None = None,
    app_id: str | None = None,
    model: str | None = None,
    llm_provider: str | None = None,
    collector_type: str | None = None,
    api_key_name: str | None = None,
    source_ip: str | None = None,
    guard_input: Any = None,
    guard_output: Any = None,
    fpe_context: str | None = None,
) -> dict[str, Any]:
    """Build an OCSF Data Security Finding (class 2006) event."""
    status_map = _STATUS_MAP.get(status, _STATUS_MAP["allowed"])
    attacks = _build_attacks(detectors)

    # Detected detector names for finding types
    detected_types = [name for name, result in detectors.items() if isinstance(result, dict) and result.get("detected")]

    event: dict[str, Any] = {
        "class_uid": 2006,
        "class_name": "Data Security Finding",
        "category_uid": 2,
        "category_name": "Findings",
        "activity_id": 1,
        "activity_name": "Create",
        "severity_id": status_map["severity_id"],
        "severity": _SEVERITY_NAMES.get(status_map["severity_id"], "Unknown"),
        "time": timestamp,
        "action_id": status_map["action_id"],
        "action": _ACTION_NAMES.get(status_map["action_id"], "Unknown"),
        "disposition_id": status_map["disposition_id"],
        "disposition": _DISPOSITION_NAMES.get(status_map["disposition_id"], "Unknown"),
        "message": summary,
        "finding_info": {
            "uid": request_id,
            "title": f"{detected_types[0]} Detected" if detected_types else "AI Interaction",
            "desc": summary,
            "types": detected_types,
            "created_time": timestamp,
        },
        "attacks": attacks,
        "metadata": {
            "version": "1.3.0",
            "product": {
                "name": "Tidewall",
                "vendor_name": "Open Source",
                "version": "0.2.0",
            },
        },
        "unmapped": {
            "tidewall": {
                "model_name": model,
                "provider": llm_provider,
                "event_type": event_type,
                "collector_type": collector_type,
                "policy": policy_name,
                "findings": detectors,
                "fpe_context": fpe_context,
            },
        },
    }

    # Actor
    if user_id:
        event["actor"] = {"user": {"uid": user_id, "name": user_id}}

    # API info
    if app_id or api_key_name:
        event["api"] = {
            "operation": "guard_chat_completions",
            "service": {"name": app_id or "tidewall"},
        }

    # Source endpoint
    if source_ip:
        event["src_endpoint"] = {"ip": source_ip}

    return event


def build_aidr_compat_event(
    *,
    status: str,
    request_id: str,
    timestamp: str,
    summary: str,
    policy_name: str,
    event_type: str,
    detectors: dict[str, Any],
    user_id: str | None = None,
    app_id: str | None = None,
    model: str | None = None,
    llm_provider: str | None = None,
    collector_type: str | None = None,
    api_key_name: str | None = None,
    source_ip: str | None = None,
    guard_input: Any = None,
    guard_output: Any = None,
    fpe_context: str | None = None,
) -> dict[str, Any]:
    """Build a AIDR-style TidewallPromptDataEvent."""
    attacks = _build_attacks(detectors)

    return {
        "event_simpleName": "TidewallPromptDataEvent",
        "source": "tidewall",
        "timestamp": timestamp,
        "Vendor": {
            "actor_name": user_id,
            "aiguard_config": {
                "policy": policy_name,
                "service": "tidewall",
            },
            "application_id": app_id,
            "authn_info": {
                "identity_name": api_key_name,
            }
            if api_key_name
            else None,
            "collector_type": collector_type,
            "event_type": event_type,
            "findings": detectors,
            "model_name": model,
            "provider": llm_provider,
            "start_time": timestamp,
            "status": status,
            "summary": summary,
            "trace_id": request_id,
            "transformed": status == "transformed",
            "user_id": user_id,
        },
        "mitre_atlas": [
            {
                "technique_id": a["technique"]["uid"],
                "technique_name": a["technique"]["name"],
                "tactic": a["tactic"]["name"],
            }
            for a in attacks
        ]
        if attacks
        else None,
    }
