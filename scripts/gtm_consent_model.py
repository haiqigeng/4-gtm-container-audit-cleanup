#!/usr/bin/env python3
"""Build deterministic effective-consent route facts from a GTM export."""

from __future__ import annotations

import json
import re
from collections import defaultdict
from typing import Any
from urllib.parse import urlsplit

from gtm_lib import as_list, refs, stable_hash, walk_json_fields
from gtm_vendor_registry import (
    behavior_bearing_vendor_text,
    detect_vendor_text,
    vendor_records,
)

CONSENT_PURPOSES = (
    "analytics_storage",
    "ad_storage",
    "ad_user_data",
    "ad_personalization",
    "functionality_storage",
    "personalization_storage",
    "security_storage",
)
MEDIA_CATEGORIES = {"media", "affiliate", "publisher"}
GOOGLE_NATIVE_CONSENT_TYPES = {
    "awct",
    "flc",
    "gaawe",
    "gaawc",
    "gclidw",
    "googtag",
    "sp",
}
MANUAL_CONSENT_STATUSES = {
    "NOTSET": "NOT_SET",
    "NOTNEEDED": "NOT_NEEDED",
    "NEEDED": "NEEDED",
}
SERVER_ROUTE_KEY_RE = re.compile(
    r"^(?:transporturl|servercontainerurl|taggingserverurl|firstpartyurl|serverurl)$",
    re.I,
)
CONSENT_SIGNAL_RE = re.compile(
    r"consent|optanon|onetrust|didomi|cookiebot|\bcmp\b",
    re.I,
)
URL_RE = re.compile(r"https?://[^\s\"'<>\\)]+", re.I)
FORWARDING_METADATA_SUFFIXES = (
    ".accountId",
    ".containerId",
    ".fingerprint",
    ".path",
    ".tagId",
    ".triggerId",
    ".variableId",
    ".name",
    ".type",
)
FORWARDING_NON_PAYLOAD_PATH_TOKENS = (
    ".firingTriggerId",
    ".blockingTriggerId",
    ".setupTag",
    ".teardownTag",
    ".scheduleStartMs",
    ".scheduleEndMs",
)


def consent_purpose(name: str) -> str:
    normalized = re.sub(r"[\s.-]+", "_", name.lower())
    return next((purpose for purpose in CONSENT_PURPOSES if purpose in normalized), "")


def consent_values(obj: dict[str, Any], source_path: str = "$") -> list[dict[str, str]]:
    rows = []
    for fact in walk_json_fields(obj, source_path):
        json_path = str(fact.get("json_path") or "")
        if any(token in json_path for token in FORWARDING_NON_PAYLOAD_PATH_TOKENS) or (
            json_path.endswith(FORWARDING_METADATA_SUFFIXES)
        ):
            continue
        searchable = f"{fact['json_path']} {fact.get('value_preview') or ''}"
        if not any(purpose in searchable.lower() for purpose in CONSENT_PURPOSES) and not re.search(
            r"consent|optanon|didomi", searchable, re.I
        ):
            continue
        rows.append(
            {
                "json_path": fact["json_path"],
                "value_hash": fact["value_hash"],
                "value_preview": str(fact.get("value_preview") or ""),
            }
        )
    return rows


def server_route_hosts(obj: dict[str, Any]) -> list[str]:
    """Extract hosts only from explicit GTM server-routing fields and values."""
    route_values: list[Any] = []

    def normalized_key(value: Any) -> str:
        return re.sub(r"[^a-z0-9]", "", str(value or "").lower())

    def visit(value: Any) -> None:
        if isinstance(value, dict):
            parameter_key = normalized_key(value.get("key"))
            if SERVER_ROUTE_KEY_RE.fullmatch(parameter_key):
                route_values.extend(
                    value[field]
                    for field in ("value", "list", "map")
                    if field in value
                )
            for key, child in value.items():
                if SERVER_ROUTE_KEY_RE.fullmatch(normalized_key(key)):
                    route_values.append(child)
                elif key != "key":
                    visit(child)
        elif isinstance(value, list):
            pair_values = {
                normalized_key(item.get("key")): item.get("value")
                for item in value
                if isinstance(item, dict) and "key" in item and "value" in item
            }
            routed_parameter = pair_values.get("parameter") or pair_values.get(
                "parametername"
            )
            if SERVER_ROUTE_KEY_RE.fullmatch(normalized_key(routed_parameter)):
                for paired_key in ("parametervalue", "configuredvalue"):
                    if paired_key in pair_values:
                        route_values.append(pair_values[paired_key])
            for item in value:
                visit(item)

    visit(obj)
    if SERVER_ROUTE_KEY_RE.fullmatch(normalized_key(obj.get("name"))):
        route_values.extend(
            parameter[field]
            for parameter in as_list(obj.get("parameter"))
            if isinstance(parameter, dict)
            for field in ("value", "list", "map")
            if field in parameter
        )

    hosts = set()
    text = json.dumps(route_values, ensure_ascii=False)
    for match in URL_RE.finditer(text):
        try:
            host = urlsplit(match.group(0).rstrip(".,);\"")).hostname
        except ValueError:
            host = None
        if host:
            hosts.add(host.lower())
    return sorted(hosts)


def referenced_variables(
    obj: dict[str, Any], variables: list[dict[str, Any]]
) -> list[tuple[int, dict[str, Any]]]:
    """Resolve the exported variable chain without interpreting its business meaning."""
    by_name: dict[str, list[tuple[int, dict[str, Any]]]] = {}
    for index, variable in enumerate(variables):
        name = str(variable.get("name") or "")
        if name:
            by_name.setdefault(name, []).append((index, variable))
    queue = sorted(refs(obj))
    visited: set[str] = set()
    resolved: list[tuple[int, dict[str, Any]]] = []
    while queue:
        reference = queue.pop(0)
        if reference in visited:
            continue
        visited.add(reference)
        targets = by_name.get(reference, [])
        if not targets:
            continue
        for index, variable in targets:
            resolved.append((index, variable))
            queue.extend(sorted(refs(variable) - visited))
    return resolved


def forwarding_consent_values(
    obj: dict[str, Any], source_path: str, via_variable: str = ""
) -> list[dict[str, str]]:
    """Return consent-like payload evidence, excluding local consentSettings metadata."""
    rows = []
    for fact in consent_values(obj, source_path):
        json_path = str(fact.get("json_path") or "")
        parameter_match = re.search(r"\.parameter\[(\d+)\]", json_path)
        parameter_key = ""
        if parameter_match:
            position = int(parameter_match.group(1))
            parameters = as_list(obj.get("parameter"))
            if position < len(parameters) and isinstance(parameters[position], dict):
                parameter_key = str(parameters[position].get("key") or "").lower()
        if (
            ".consentSettings" in json_path
            or any(token in json_path for token in FORWARDING_NON_PAYLOAD_PATH_TOKENS)
            or json_path.endswith(FORWARDING_METADATA_SUFFIXES)
            or parameter_key in {"event", "eventname", "event_name", "action"}
            or (not via_variable and parameter_key in {"html", "javascript"})
        ):
            continue
        searchable = f"{json_path} {fact.get('value_preview') or ''} {via_variable}"
        if not consent_purpose(searchable) and not CONSENT_SIGNAL_RE.search(searchable):
            continue
        rows.append({**fact, "via_variable": via_variable})
    return rows


def tag_consent_route(
    tag: dict[str, Any],
    source_path: str = "$",
    variables: list[dict[str, Any]] | None = None,
    root_path: str = "$.containerVersion",
) -> dict[str, Any]:
    serialized_behavior = behavior_bearing_vendor_text(tag, "tag")
    matches = vendor_records(serialized_behavior)
    vendor, category = detect_vendor_text(serialized_behavior)
    detected_vendors = [str(match.get("name") or "") for match in matches]
    detected_categories = sorted(
        {str(match.get("category") or "unclassified") for match in matches}
    )
    raw_settings = tag.get("consentSettings")
    settings_shape_valid = raw_settings is None or isinstance(raw_settings, dict)
    settings = raw_settings if isinstance(raw_settings, dict) else {}
    raw_status = str(settings.get("consentStatus") or "").strip()
    status_key = re.sub(r"[^A-Z]", "", raw_status.upper())
    status = MANUAL_CONSENT_STATUSES.get(status_key, raw_status.upper() or "MISSING")
    status_known = status in {*MANUAL_CONSENT_STATUSES.values(), "MISSING"}
    additional_checks = status == "NEEDED"
    blockers = sorted(str(value) for value in as_list(tag.get("blockingTriggerId")))
    consent_references = sorted(
        reference
        for reference in refs(tag)
        if consent_purpose(reference) or re.search(r"consent|optanon|didomi", reference, re.I)
    )
    tag_type = str(tag.get("type") or "").lower()
    native_capability = tag_type in GOOGLE_NATIVE_CONSENT_TYPES
    variable_chain = referenced_variables(tag, variables or [])
    forwarding_evidence = forwarding_consent_values(tag, source_path)
    server_hosts = set(server_route_hosts(tag))
    forwarding_variables: set[str] = set()
    for index, variable in variable_chain:
        variable_name = str(variable.get("name") or "")
        variable_path = f"{root_path}.variable[{index}]"
        variable_evidence = forwarding_consent_values(
            variable,
            variable_path,
            via_variable=variable_name,
        )
        if variable_evidence:
            forwarding_variables.add(variable_name)
            forwarding_evidence.extend(variable_evidence)
        server_hosts.update(server_route_hosts(variable))

    forwarded_purposes = sorted(
        {
            purpose
            for row in forwarding_evidence
            for purpose in [
                consent_purpose(
                    f"{row.get('json_path') or ''} {row.get('value_preview') or ''} "
                    f"{row.get('via_variable') or ''}"
                )
            ]
            if purpose
        }
    )
    forwarded_cmp_signal = bool(server_hosts) and any(
        CONSENT_SIGNAL_RE.search(
            f"{row.get('json_path') or ''} {row.get('value_preview') or ''} "
            f"{row.get('via_variable') or ''}"
        )
        for row in forwarding_evidence
    )
    if not status_known:
        control_status = "unrecognized_consent_status"
    elif additional_checks:
        control_status = "explicit_export_control"
    elif blockers:
        control_status = "blocker_control_candidate"
    elif server_hosts and forwarding_evidence:
        control_status = "server_forwarding_candidate"
    elif server_hosts:
        control_status = "server_contract_unproven"
    elif native_capability:
        control_status = "native_consent_capability"
    elif consent_references:
        control_status = "consent_signal_review"
    else:
        control_status = "unproven_export_control"
    return {
        "vendor": vendor,
        "vendor_category": category,
        "detected_vendors": detected_vendors,
        "detected_vendor_categories": detected_categories,
        "consent_settings_shape_valid": settings_shape_valid,
        "raw_consent_status": raw_status,
        "consent_status": status,
        "consent_status_known": status_known,
        "additional_consent_checks_visible": additional_checks,
        "blocking_trigger_ids": blockers,
        "consent_variable_references": consent_references,
        "native_consent_capability": native_capability,
        "server_routing_hosts": sorted(server_hosts),
        "server_consent_forwarding_variables": (
            sorted(forwarding_variables) if server_hosts else []
        ),
        "server_consent_forwarding_evidence": forwarding_evidence if server_hosts else [],
        "detected_consent_payload_purposes": forwarded_purposes,
        "forwarded_consent_purposes": forwarded_purposes if server_hosts else [],
        "forwarded_cmp_signal_visible": forwarded_cmp_signal,
        "server_enforcement_visibility": (
            "not_visible_in_web_export" if server_hosts else "not_applicable"
        ),
        "consent_source_values": consent_values(tag, source_path),
        "effective_control_status": control_status,
        "requires_media_consent_review": any(
            value in MEDIA_CATEGORIES for value in detected_categories
        ),
    }


def consent_variable_conflicts(variables: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[str, list[tuple[dict[str, Any], str]]] = defaultdict(list)
    for variable in variables:
        purpose = consent_purpose(str(variable.get("name") or ""))
        if not purpose:
            continue
        payload = {
            key: value
            for key, value in variable.items()
            if key not in {"variableId", "name", "accountId", "containerId", "fingerprint", "path"}
        }
        groups[stable_hash(payload)].append((variable, purpose))
    conflicts = []
    for logic_hash, group in sorted(groups.items()):
        purposes = sorted({purpose for _variable, purpose in group})
        if len(group) < 2 or len(purposes) < 2:
            continue
        conflicts.append(
            {
                "logic_hash": logic_hash,
                "purposes": purposes,
                "variables": [variable for variable, _purpose in group],
            }
        )
    return conflicts
