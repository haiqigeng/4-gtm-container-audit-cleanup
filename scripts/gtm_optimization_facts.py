#!/usr/bin/env python3
"""Extract neutral facts for valid-but-non-optimal GTM configurations.

The scanner records repetition, ownership, effective settings, execution
topology, and consent/routing evidence.  It intentionally does not decide that
an observed candidate should be changed.
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

from gtm_audit_contract import CONSENT_ROUTE_CLASSES
from gtm_configuration_facts import build_consumers, object_consumers
from gtm_consent_model import server_route_hosts
from gtm_lib import (
    as_list,
    container_root_path,
    container_version,
    refs,
    source_descriptor,
    stable_hash,
)
from gtm_relationships import object_records, trigger_conditions

GOOGLE_TAG_TYPES = frozenset({"googtag", "gaawe", "gaawc", "gclidw", "flc", "fls"})
GOOGLE_CONFIGURATION_TYPES = frozenset({"googtag", "gaawc"})
GOOGLE_EVENT_TYPES = frozenset({"gaawe", "googtag"})
SETTINGS_VARIABLE_TYPES = {
    "gtcs": "configuration",
    "gtes": "event",
}
SETTINGS_REFERENCE_KEYS = {
    "configuration": (
        "configSettingsVariable",
        "configurationSettingsVariable",
    ),
    "event": ("eventSettingsVariable",),
}
SETTINGS_TABLE_KEYS = {
    "configuration": ("configSettingsTable", "configurationSettingsTable"),
    "event": ("eventSettingsTable",),
}
EVENT_SPECIFIC_PARAMETERS = frozenset(
    {
        "affiliation",
        "coupon",
        "currency",
        "form_id",
        "form_name",
        "items",
        "method",
        "payment_type",
        "search_term",
        "shipping",
        "shipping_tier",
        "tax",
        "transaction_id",
        "value",
    }
)
CONSENT_TERMS = re.compile(
    r"consent|didomi|onetrust|optanon|cookiebot|analytics_storage|ad_storage|"
    r"ad_user_data|ad_personalization|enabled[_ -]?vendors|active[_ -]?groups|"
    r"purpose(?:s)?[_ -]?(?:enabled|consent|status)",
    re.I,
)
CMP_EVENT_NAMES = {
    "didomi-consent": "Didomi",
    "didomi-ready": "Didomi",
    "didomi-consent-changed": "Didomi",
    "OneTrustGroupsUpdated": "OneTrust",
    "OTConsentApplied": "OneTrust",
}


def _parameters(obj: dict[str, Any]) -> list[dict[str, Any]]:
    return [row for row in as_list(obj.get("parameter")) if isinstance(row, dict)]


def _parameter_index(obj: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    result: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for parameter in _parameters(obj):
        key = str(parameter.get("key") or "")
        if key:
            result[key].append(parameter)
    return dict(result)


def _scalar(parameter: dict[str, Any]) -> str:
    value = parameter.get("value")
    return "" if isinstance(value, (dict, list)) or value is None else str(value)


def _map_values(row: dict[str, Any]) -> dict[str, Any]:
    values: dict[str, Any] = {}
    for item in as_list(row.get("map")):
        if not isinstance(item, dict):
            continue
        key = str(item.get("key") or "")
        if not key:
            continue
        if "value" in item:
            values[key] = item.get("value")
        elif "list" in item:
            values[key] = item.get("list")
        elif "map" in item:
            values[key] = item.get("map")
    return values


def _table_rows(
    obj: dict[str, Any],
    table_keys: tuple[str, ...],
    source_path: str,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    indexes = _parameter_index(obj)
    for table_key in table_keys:
        for parameter in indexes.get(table_key, []):
            for row_index, row in enumerate(as_list(parameter.get("list"))):
                if not isinstance(row, dict):
                    continue
                values = _map_values(row)
                name = next(
                    (
                        str(values[key])
                        for key in ("parameter", "name", "property", "fieldName")
                        if values.get(key) is not None
                    ),
                    "",
                )
                value = next(
                    (
                        values[key]
                        for key in (
                            "parameterValue",
                            "value",
                            "propertyValue",
                            "fieldValue",
                        )
                        if key in values
                    ),
                    None,
                )
                if not name:
                    # Preserve unfamiliar current-schema rows as facts. They
                    # remain auditable without pretending to understand them.
                    name = "__unresolved_row__:" + stable_hash(values, 12)
                rows.append(
                    {
                        "table_key": table_key,
                        "parameter_name": name,
                        "configured_value": value,
                        "value_sha256": stable_hash(value, 32),
                        "referenced_variables": sorted(refs(value)),
                        "source_json_path": (
                            f"{source_path}.parameter[{_parameters(obj).index(parameter)}]"
                            f".list[{row_index}]"
                        ),
                    }
                )
    return rows


def _setting_reference(
    obj: dict[str, Any], scope: str, source_path: str
) -> dict[str, Any] | None:
    indexes = _parameter_index(obj)
    for key in SETTINGS_REFERENCE_KEYS[scope]:
        for parameter in indexes.get(key, []):
            raw = _scalar(parameter)
            if not raw:
                continue
            names = sorted(refs(raw))
            return {
                "parameter_key": key,
                "raw_value": raw,
                "referenced_variable_names": names,
                "source_json_path": (
                    f"{source_path}.parameter[{_parameters(obj).index(parameter)}].value"
                ),
            }
    return None


def _settings_variables(
    cv: dict[str, Any], root_path: str
) -> tuple[dict[str, dict[str, Any]], list[dict[str, Any]]]:
    by_name: dict[str, dict[str, Any]] = {}
    rows: list[dict[str, Any]] = []
    for index, variable in enumerate(as_list(cv.get("variable"))):
        if not isinstance(variable, dict):
            continue
        variable_type = str(variable.get("type") or "")
        scope = SETTINGS_VARIABLE_TYPES.get(variable_type)
        if not scope:
            continue
        name = str(variable.get("name") or "")
        key = f"variable:{variable.get('variableId') or name}"
        path = f"{root_path}.variable[{index}]"
        setting_rows = _table_rows(variable, SETTINGS_TABLE_KEYS[scope], path)
        record = {
            "object_key": key,
            "object_name": name,
            "variable_type": variable_type,
            "settings_scope": scope,
            "settings": setting_rows,
            "settings_sha256": stable_hash(
                [
                    (row["parameter_name"], row["value_sha256"])
                    for row in setting_rows
                ],
                32,
            ),
            "source_json_path": path,
        }
        rows.append(record)
        if name:
            by_name[name] = record
    return by_name, rows


def _event_names(obj: dict[str, Any]) -> list[str]:
    values = []
    for key in ("eventName", "event", "event_name"):
        for parameter in _parameter_index(obj).get(key, []):
            value = _scalar(parameter).strip()
            if value:
                values.append(value)
    return list(dict.fromkeys(values))


def _effective_settings_for_tag(
    tag: dict[str, Any],
    tag_key: str,
    tag_path: str,
    scope: str,
    variables_by_name: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    reference = _setting_reference(tag, scope, tag_path)
    inherited_rows: list[dict[str, Any]] = []
    resolved_keys: list[str] = []
    unresolved_names: list[str] = []
    for name in (reference or {}).get("referenced_variable_names", []):
        variable = variables_by_name.get(name)
        if not variable or variable.get("settings_scope") != scope:
            unresolved_names.append(name)
            continue
        resolved_keys.append(str(variable["object_key"]))
        inherited_rows.extend(variable.get("settings", []))
    local_rows = _table_rows(tag, SETTINGS_TABLE_KEYS[scope], tag_path)

    inherited_by_name = {
        str(row["parameter_name"]): row for row in inherited_rows
    }
    local_by_name = {str(row["parameter_name"]): row for row in local_rows}
    effective_rows = []
    for name in sorted(set(inherited_by_name) | set(local_by_name)):
        inherited = inherited_by_name.get(name)
        local = local_by_name.get(name)
        selected = local or inherited or {}
        origin = (
            "local_override"
            if inherited and local
            else "local"
            if local
            else "inherited"
        )
        effective_rows.append(
            {
                "parameter_name": name,
                "configured_value": selected.get("configured_value"),
                "value_sha256": selected.get("value_sha256"),
                "origin": origin,
                "inherited_value_sha256": (
                    inherited.get("value_sha256") if inherited else ""
                ),
                "local_value_sha256": local.get("value_sha256") if local else "",
                "intentional_override_requires_judgment": bool(inherited and local),
                "source_json_paths": [
                    path
                    for path in (
                        inherited.get("source_json_path") if inherited else "",
                        local.get("source_json_path") if local else "",
                    )
                    if path
                ],
            }
        )
    return {
        "object_key": tag_key,
        "settings_scope": scope,
        "settings_reference": reference or {},
        "resolved_settings_variable_keys": sorted(resolved_keys),
        "unresolved_settings_variable_names": sorted(unresolved_names),
        "inherited_settings": inherited_rows,
        "local_settings": local_rows,
        "effective_settings": effective_rows,
        "effective_settings_sha256": stable_hash(
            [
                (row["parameter_name"], row["value_sha256"], row["origin"])
                for row in effective_rows
            ],
            32,
        ),
    }


def _shared_setting_candidates(
    effective_rows: list[dict[str, Any]],
    tags_by_key: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    groups: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for tag_settings in effective_rows:
        key = str(tag_settings["object_key"])
        tag = tags_by_key[key]
        events = _event_names(tag)
        for row in tag_settings.get("effective_settings", []):
            groups[
                (
                    str(tag_settings["settings_scope"]),
                    str(row["parameter_name"]),
                    str(row["value_sha256"]),
                )
            ].append(
                {
                    "object_key": key,
                    "event_names": events,
                    "origin": row["origin"],
                    "settings_variable_keys": sorted(
                        str(value)
                        for value in as_list(
                            tag_settings.get("resolved_settings_variable_keys")
                        )
                    ),
                    "source_json_paths": row["source_json_paths"],
                }
            )
    candidates: list[dict[str, Any]] = []
    for (scope, name, value_hash), members in sorted(groups.items()):
        object_keys = sorted({str(row["object_key"]) for row in members})
        if len(object_keys) < 2:
            continue
        inherited_owner_sets = {
            tuple(row.get("settings_variable_keys", [])) for row in members
        }
        already_owned_by_one_shared_variable = (
            all(row.get("origin") == "inherited" for row in members)
            and len(inherited_owner_sets) == 1
            and bool(next(iter(inherited_owner_sets), ()))
        )
        if already_owned_by_one_shared_variable:
            continue
        events = sorted(
            {
                event
                for member in members
                for event in member.get("event_names", [])
            }
        )
        event_specific_across_distinct_events = (
            scope == "event" and name.casefold() in EVENT_SPECIFIC_PARAMETERS and len(events) > 1
        )
        payload = {
            "candidate_type": f"shared_{scope}_setting",
            "settings_scope": scope,
            "parameter_name": name,
            "value_sha256": value_hash,
            "consumer_object_keys": object_keys,
            "configured_event_names": events,
            "source_json_paths": sorted(
                {
                    path
                    for member in members
                    for path in member.get("source_json_paths", [])
                }
            ),
            "compatibility_checks": {
                "same_effective_value": True,
                "event_specific_across_distinct_events": event_specific_across_distinct_events,
                "source_type_shape_timing_consent_route_destination_ownership": "audit_required",
                "local_override_intent": "audit_required",
            },
            "candidate_status": "neutral_candidate_not_a_verdict",
        }
        payload["candidate_id"] = "OPT-SET-" + stable_hash(payload, 16).upper()
        candidates.append(payload)
    return candidates


def _trigger_event_values(trigger: dict[str, Any]) -> list[str]:
    values: list[str] = []
    conditions = trigger_conditions(trigger)
    for condition in conditions:
        if "_event" not in condition and "event" not in condition.casefold():
            continue
        quoted = re.findall(r"(?:==|equals?|contains?|matches?)[^A-Za-z0-9_-]*([A-Za-z0-9_.:-]+)", condition, re.I)
        values.extend(quoted)
    for parameter in _parameters(trigger):
        key = str(parameter.get("key") or "").casefold()
        value = _scalar(parameter).strip()
        if value and key in {"eventname", "customeventname"}:
            values.append(value)
    serialized = json.dumps(trigger, ensure_ascii=False)
    for event in CMP_EVENT_NAMES:
        if event.casefold() in serialized.casefold():
            values.append(event)
    return [value for value in dict.fromkeys(values) if value != "_event"]


def _contains_consent_control_condition(conditions: list[str]) -> bool:
    for condition in conditions:
        reduced = condition
        for event in CMP_EVENT_NAMES:
            reduced = re.sub(re.escape(event), "", reduced, flags=re.I)
        reduced = re.sub(r"\b_event\b", "", reduced, flags=re.I)
        if CONSENT_TERMS.search(reduced):
            return True
    return False


def trigger_control_fact(trigger: dict[str, Any], path: str = "$") -> dict[str, Any]:
    conditions = trigger_conditions(trigger)
    serialized = json.dumps(trigger, ensure_ascii=False)
    return {
        "trigger_id": str(trigger.get("triggerId") or ""),
        "object_key": f"trigger:{trigger.get('triggerId') or ''}",
        "object_name": str(trigger.get("name") or ""),
        "trigger_type": str(trigger.get("type") or ""),
        "event_names": _trigger_event_values(trigger),
        "conditions": conditions,
        "contains_consent_condition": _contains_consent_control_condition(
            conditions
        ),
        "cmp_contract_candidates": sorted(
            {
                vendor
                for event, vendor in CMP_EVENT_NAMES.items()
                if event.casefold() in serialized.casefold()
            }
        ),
        "source_json_path": path,
        "configuration_sha256": stable_hash(trigger, 32),
    }


def _explicit_priority(tag: dict[str, Any]) -> tuple[bool, int | None, str]:
    if "tagFiringPriority" not in tag:
        return False, None, ""
    raw = tag.get("tagFiringPriority")
    try:
        return True, int(str(raw)), str(raw)
    except (TypeError, ValueError):
        return True, None, str(raw)


def _consent_metadata(tag: dict[str, Any]) -> dict[str, Any]:
    settings = tag.get("consentSettings")
    status = ""
    required = []
    if isinstance(settings, dict):
        status = str(settings.get("consentStatus") or "")
        for key in ("consentType", "consentTypes"):
            raw = settings.get(key)
            if isinstance(raw, list):
                required.extend(str(value) for value in raw)
            elif raw:
                required.append(str(raw))
    # Search configured keys and values only. A synthetic field name such as
    # ``consentSettings`` would make every tag look consent-relevant.
    serialized = json.dumps(
        [tag.get("parameter", []), settings or {}],
        ensure_ascii=False,
    )
    return {
        "consent_status": status,
        "additional_consent_types": sorted(set(required)),
        "has_additional_consent_check": bool(
            status and status not in {"NOT_SET", "NOT_NEEDED"}
        ),
        "contains_consent_value": bool(CONSENT_TERMS.search(serialized)),
    }


def client_consent_gate_facts(
    tag: dict[str, Any],
    trigger_facts_by_id: dict[str, dict[str, Any]],
) -> dict[str, bool]:
    """Describe visible client-side consent gating without judging its design."""

    firing = [
        trigger_facts_by_id[trigger_id]
        for trigger_id in sorted(
            str(value) for value in as_list(tag.get("firingTriggerId"))
        )
        if trigger_id in trigger_facts_by_id
    ]
    blockers = [
        trigger_facts_by_id[trigger_id]
        for trigger_id in sorted(
            str(value) for value in as_list(tag.get("blockingTriggerId"))
        )
        if trigger_id in trigger_facts_by_id
    ]
    consent = _consent_metadata(tag)
    positive_consent = any(row["contains_consent_condition"] for row in firing)
    blocker_consent = any(row["contains_consent_condition"] for row in blockers)
    additional_check = bool(consent["has_additional_consent_check"])
    return {
        "positive_route_contains_consent": positive_consent,
        "blocker_contains_consent": blocker_consent,
        "additional_consent_check_visible": additional_check,
        "client_consent_gate_visible": (
            positive_consent or blocker_consent or additional_check
        ),
    }


def _control_topology(
    cv: dict[str, Any],
    root_path: str,
    shared_objects: dict[str, dict[str, Any]],
    effective_settings_by_tag: dict[str, list[dict[str, Any]]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    trigger_by_id = {
        str(trigger.get("triggerId") or ""): trigger_control_fact(
            trigger, f"{root_path}.trigger[{index}]"
        )
        for index, trigger in enumerate(as_list(cv.get("trigger")))
        if isinstance(trigger, dict)
    }
    rows: list[dict[str, Any]] = []
    priority_candidates: list[dict[str, Any]] = []
    tags = [row for row in as_list(cv.get("tag")) if isinstance(row, dict)]
    tag_routes = {
        f"tag:{tag.get('tagId') or ''}": {
            str(value) for value in as_list(tag.get("firingTriggerId"))
        }
        for tag in tags
    }
    for index, tag in enumerate(tags):
        key = f"tag:{tag.get('tagId') or ''}"
        firing_ids = sorted(str(value) for value in as_list(tag.get("firingTriggerId")))
        blocking_ids = sorted(str(value) for value in as_list(tag.get("blockingTriggerId")))
        firing = [trigger_by_id[value] for value in firing_ids if value in trigger_by_id]
        blockers = [trigger_by_id[value] for value in blocking_ids if value in trigger_by_id]
        explicit, priority, priority_raw = _explicit_priority(tag)
        effective_rows = effective_settings_by_tag.get(key, [])
        shared = shared_objects.get(key, {})
        effective_route_hosts = {
            host
            for setting in effective_rows
            if re.sub(
                r"[^a-z0-9]", "", str(setting.get("parameter_name") or "").casefold()
            )
            in {
                "transporturl",
                "servercontainerurl",
                "taggingserverurl",
                "firstpartyurl",
                "serverurl",
            }
            for host in server_route_hosts(
                {
                    "parameter": [
                        {
                            "key": setting.get("parameter_name"),
                            "value": setting.get("configured_value"),
                        }
                    ]
                }
            )
        }
        route_hosts = sorted(
            {
                *server_route_hosts(tag),
                *effective_route_hosts,
                *as_list(
                    (shared.get("effective_consent_route") or {}).get(
                        "server_routing_hosts"
                    )
                ),
            }
        )
        consent_forwarding_settings = [
            {
                "settings_scope": setting.get("settings_scope"),
                "parameter_name": setting.get("parameter_name"),
                "configured_value": setting.get("configured_value"),
                "origin": setting.get("origin"),
                "source_json_paths": setting.get("source_json_paths", []),
            }
            for setting in effective_rows
            if CONSENT_TERMS.search(str(setting.get("parameter_name") or ""))
            or CONSENT_TERMS.search(str(setting.get("configured_value") or ""))
        ]
        consent = _consent_metadata(tag)
        client_gate = client_consent_gate_facts(
            tag,
            {
                trigger_id: trigger_by_id[trigger_id]
                for trigger_id in {*firing_ids, *blocking_ids}
                if trigger_id in trigger_by_id
            },
        )
        positive_consent = client_gate["positive_route_contains_consent"]
        blocker_consent = client_gate["blocker_contains_consent"]
        coeligible = sorted(
            other_key
            for other_key, other_routes in tag_routes.items()
            if other_key != key and set(firing_ids) & other_routes
        )
        cmp_events = sorted(
            {
                event
                for trigger in firing
                for event in trigger["event_names"]
                if event in CMP_EVENT_NAMES
            }
        )
        direct_vendor_signals = sorted(
            {
                value
                for value in as_list(
                    (shared.get("vendor_event_contract") or {}).get("vendors")
                )
                if str(value)
            }
        )
        row = {
            "object_key": key,
            "object_name": str(tag.get("name") or ""),
            "tag_type": str(tag.get("type") or ""),
            "paused": bool(tag.get("paused")),
            "source_json_path": f"{root_path}.tag[{index}]",
            "firing_trigger_ids": firing_ids,
            "blocking_trigger_ids": blocking_ids,
            "firing_triggers": firing,
            "blocking_triggers": blockers,
            "eligible_event_model": {
                "positive_routes_are_or": True,
                "conditions_inside_trigger_are_and": True,
                "matching_blocker_suppresses_eligibility": True,
            },
            "sequence_setup": as_list(tag.get("setupTag")),
            "sequence_teardown": as_list(tag.get("teardownTag")),
            "tag_firing_option": str(tag.get("tagFiringOption") or ""),
            "schedule_start_ms": tag.get("scheduleStartMs"),
            "schedule_end_ms": tag.get("scheduleEndMs"),
            "explicit_firing_priority": explicit,
            "firing_priority": priority,
            "firing_priority_raw": priority_raw,
            "same_trigger_competitor_keys": coeligible,
            "positive_route_contains_consent": positive_consent,
            "blocker_contains_consent": blocker_consent,
            "cmp_lifecycle_event_candidates": cmp_events,
            "server_route_hosts": route_hosts,
            "consent_forwarding_settings": consent_forwarding_settings,
            "consent_metadata": consent,
            "direct_vendor_signals": direct_vendor_signals,
            "route_classification": {
                "selected_class": "",
                "allowed_classes": list(CONSENT_ROUTE_CLASSES),
                "selection_requires_semantic_audit": True,
            },
        }
        row["control_topology_sha256"] = stable_hash(row, 32)
        rows.append(row)
        if explicit:
            candidate = {
                "candidate_type": "explicit_firing_priority",
                "object_key": key,
                "source_json_path": f"{root_path}.tag[{index}].tagFiringPriority",
                "configured_value": priority_raw,
                "parsed_value": priority,
                "same_trigger_competitor_keys": coeligible,
                "sequencing_present": bool(tag.get("setupTag") or tag.get("teardownTag")),
                "candidate_status": "neutral_candidate_not_a_verdict",
            }
            candidate["candidate_id"] = "OPT-PRI-" + stable_hash(candidate, 16).upper()
            priority_candidates.append(candidate)
    return rows, priority_candidates


def build_optimization_facts(
    export_path: Path,
    shared_facts: dict[str, Any],
) -> dict[str, Any]:
    data = json.loads(export_path.read_text(encoding="utf-8"))
    cv = container_version(data)
    root_path = container_root_path(data)
    records = object_records(cv, root_path)
    shared_by_key = {
        str(row.get("object_key") or ""): row
        for row in as_list(shared_facts.get("objects"))
    }
    variables_by_name, settings_variables = _settings_variables(cv, root_path)
    tags_by_key = {
        f"tag:{tag.get('tagId') or ''}": tag
        for tag in as_list(cv.get("tag"))
        if isinstance(tag, dict)
    }
    effective_settings: list[dict[str, Any]] = []
    for index, tag in enumerate(as_list(cv.get("tag"))):
        if not isinstance(tag, dict):
            continue
        tag_type = str(tag.get("type") or "")
        if tag_type not in GOOGLE_TAG_TYPES:
            continue
        key = f"tag:{tag.get('tagId') or ''}"
        path = f"{root_path}.tag[{index}]"
        scopes = []
        if tag_type in GOOGLE_CONFIGURATION_TYPES or any(
            name in _parameter_index(tag)
            for name in (*SETTINGS_REFERENCE_KEYS["configuration"], *SETTINGS_TABLE_KEYS["configuration"])
        ):
            scopes.append("configuration")
        if tag_type in GOOGLE_EVENT_TYPES or any(
            name in _parameter_index(tag)
            for name in (*SETTINGS_REFERENCE_KEYS["event"], *SETTINGS_TABLE_KEYS["event"])
        ):
            scopes.append("event")
        for scope in dict.fromkeys(scopes):
            effective_settings.append(
                _effective_settings_for_tag(tag, key, path, scope, variables_by_name)
            )

    consumers = build_consumers(cv, root_path)
    for row in settings_variables:
        variable = next(
            (
                item
                for item in as_list(cv.get("variable"))
                if isinstance(item, dict)
                and f"variable:{item.get('variableId') or item.get('name') or ''}"
                == row["object_key"]
            ),
            {},
        )
        row["consumer_object_keys"] = sorted(
            {
                str(item.get("consumer_key") or "")
                for item in object_consumers("variable", variable, consumers)
                if str(item.get("consumer_key") or "")
            }
        )
        row["consumer_count"] = len(row["consumer_object_keys"])

    effective_settings_by_tag: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for surface in effective_settings:
        for setting in as_list(surface.get("effective_settings")):
            if isinstance(setting, dict):
                effective_settings_by_tag[str(surface.get("object_key") or "")].append(
                    {**setting, "settings_scope": surface.get("settings_scope")}
                )
    topology, priority_candidates = _control_topology(
        cv,
        root_path,
        shared_by_key,
        effective_settings_by_tag,
    )
    shared_candidates = _shared_setting_candidates(effective_settings, tags_by_key)

    all_candidates = [*shared_candidates, *priority_candidates]
    payload = {
        **source_descriptor(export_path),
        "kind": "gtm_neutral_optimization_facts",
        "schema_version": 1,
        "shared_facts_sha256": shared_facts.get("shared_facts_sha256"),
        "settings_variables": sorted(settings_variables, key=lambda row: row["object_key"]),
        "effective_google_settings": sorted(
            effective_settings,
            key=lambda row: (row["object_key"], row["settings_scope"]),
        ),
        "tag_control_topology": sorted(topology, key=lambda row: row["object_key"]),
        "optimization_candidates": sorted(
            all_candidates, key=lambda row: str(row["candidate_id"])
        ),
        "counts": {
            "google_tag_objects": len(
                [
                    record
                    for record in records.get("tag", [])
                    if record.get("object_type") in GOOGLE_TAG_TYPES
                ]
            ),
            "settings_variables": len(settings_variables),
            "effective_settings_surfaces": len(effective_settings),
            "explicit_firing_priorities": len(priority_candidates),
            "optimization_candidates": len(all_candidates),
            "control_topologies": len(topology),
        },
        "fact_boundary": (
            "Candidates record source-visible repetition or control topology only; "
            "they do not assert defect, benefit, equivalence, consent legality, or target state."
        ),
    }
    payload["optimization_facts_sha256"] = stable_hash(payload, 64)
    return payload
