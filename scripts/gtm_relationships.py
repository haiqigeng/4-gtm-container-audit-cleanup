#!/usr/bin/env python3
"""Generate source-bound GTM cross-object comparison candidates.

The candidates are deterministic review obligations, not findings. Architecture
review must decide whether similar objects are duplicates, intentional variants,
complementary implementations, conflicting logic, or unrelated.
"""

from __future__ import annotations

import argparse
import difflib
import json
import re
import unicodedata
from collections import defaultdict
from collections.abc import Iterable
from itertools import combinations
from pathlib import Path
from typing import Any

from gtm_configuration_facts import parameter_static_values
from gtm_consent_model import consent_variable_conflicts, tag_consent_route
from gtm_lib import (
    BEHAVIOR_NEUTRAL_FIELDS,
    ID_KEYS,
    SEMANTIC_LAYERS,
    as_list,
    behavior_projection,
    code_identity_text,
    comparable,
    container_root_path,
    container_version,
    is_system_trigger_reference,
    object_id,
    refs,
    source_descriptor,
    source_integrity_findings,
    stable_hash,
    strip_nonbehavior_comments,
    trigger_group_members,
    walk_json_fields,
)
from gtm_vendor_registry import behavior_bearing_vendor_text, vendor_record

COMMON_IGNORED = set(BEHAVIOR_NEUTRAL_FIELDS)
IDENTITY_IGNORED = {
    **{layer: COMMON_IGNORED | {ID_KEYS[layer], "name"} for layer in SEMANTIC_LAYERS},
}
TAG_ROUTE_FIELDS = {
    "firingTriggerId",
    "blockingTriggerId",
    "setupTag",
    "teardownTag",
    "tagFiringOption",
    "priority",
    "liveOnly",
    "paused",
    "parentFolderId",
    "notes",
    "scheduleStartMs",
    "scheduleEndMs",
    "monitoringMetadata",
    "monitoringMetadataTagNameKey",
    "consentSettings",
    "malwareDisabled",
}
TAG_EXECUTION_CONTROL_FIELDS = {
    "firingTriggerId",
    "blockingTriggerId",
    "setupTag",
    "teardownTag",
    "tagFiringOption",
    "priority",
    "liveOnly",
    "paused",
    "scheduleStartMs",
    "scheduleEndMs",
    "consentSettings",
    "malwareDisabled",
}
DESTINATION_KEY_RE = re.compile(
    r"(?:measurement|property|pixel|advertiser|conversion|destination|tag|account).*id$",
    re.I,
)
PRIMARY_EVENT_KEYS = {"event", "eventname", "event_name", "action"}
SECONDARY_EVENT_KEYS = {"eventtype", "event_type", "tracktype"}
GENERIC_EVENT_VALUES = {
    "config",
    "custom",
    "custom_event",
    "event",
    "set",
    "standard",
    "standard_event",
    "track",
}
GENERIC_CONFIG_TOKENS = {
    "boolean",
    "false",
    "integer",
    "http",
    "https",
    "list",
    "map",
    "metadata",
    "parameter",
    "template",
    "true",
    "value",
}
GENERIC_NAME_TOKENS = {
    "all",
    "block",
    "cjs",
    "consent",
    "copy",
    "dlv",
    "event",
    "global",
    "gtm",
    "tag",
    "test",
    "tg",
    "trigger",
    "variable",
}
NAME_SYNONYMS = {
    "achat": "purchase",
    "commande": "purchase",
    "order": "purchase",
    "transaction": "purchase",
    "view": "impression",
    "display": "impression",
    "affichage": "impression",
    "etape": "step",
    "q": "question",
    "devis": "quote",
    "quotation": "quote",
    "basket": "cart",
    "panier": "cart",
}
BUSINESS_EVENT_SYNONYMS = {
    "achat": "purchase",
    "completepayment": "purchase",
    "completepurchase": "purchase",
    "ordercomplete": "purchase",
    "ordercompleted": "purchase",
    "purchase": "purchase",
    "transaction": "purchase",
}
CUSTOM_CODE_EVENT_PATTERNS = (
    re.compile(r"\bfbq\s*\(\s*['\"](?:track|trackCustom)['\"]\s*,\s*['\"]([^'\"]+)", re.I),
    re.compile(r"\bttq\s*\.\s*track\s*\(\s*['\"]([^'\"]+)", re.I),
    re.compile(r"\bgtag\s*\(\s*['\"]event['\"]\s*,\s*['\"]([^'\"]+)", re.I),
    re.compile(r"\bsnaptr\s*\(\s*['\"]track['\"]\s*,\s*['\"]([^'\"]+)", re.I),
    re.compile(r"\bpintrk\s*\(\s*['\"]track['\"]\s*,\s*['\"]([^'\"]+)", re.I),
)
DATA_LAYER_PUSH_OBJECT_RE = re.compile(
    r"\bdataLayer\s*\.\s*push\s*\(\s*\{(?P<body>.{0,1800}?)\}\s*\)",
    re.I | re.S,
)
PUSH_EVENT_FIELD_RE = re.compile(
    r"(?:['\"]?event['\"]?)\s*:\s*['\"]([^'\"]+)['\"]",
    re.I,
)
DIMENSIONS_BY_LAYER = {
    "tag": [
        "purpose",
        "configuration",
        "execution_scope",
        "consumers",
        "output_payload",
        "consent_sequence",
    ],
    "trigger": ["purpose", "configuration", "execution_scope", "consumers"],
    "variable": ["purpose", "configuration", "consumers", "output_payload"],
    "zone": [
        "purpose",
        "configuration",
        "execution_scope",
        "consumers",
        "consent_sequence",
    ],
    "customTemplate": [
        "purpose",
        "configuration",
        "consumers",
        "output_payload",
        "consent_sequence",
    ],
    "client": [
        "purpose",
        "configuration",
        "execution_scope",
        "consumers",
        "output_payload",
        "consent_sequence",
    ],
    "gtagConfig": [
        "purpose",
        "configuration",
        "execution_scope",
        "consumers",
        "output_payload",
        "consent_sequence",
    ],
    "transformation": [
        "purpose",
        "configuration",
        "execution_scope",
        "consumers",
        "output_payload",
        "consent_sequence",
    ],
}
DISCOVERY_METHOD_BY_COMPARISON_TYPE = {
    "exact_configuration": "normalized_condition_and_route_variants",
    "duplicate_name": "semantic_name_and_business_term_variants",
    "same_tag_payload_different_route": "normalized_condition_and_route_variants",
    "same_vendor_destination_event": "consumer_destination_and_event_overlap",
    "same_vendor_event_family": "consumer_destination_and_event_overlap",
    "cross_vendor_event_family": "consumer_destination_and_event_overlap",
    "cross_vendor_consent_route_review": "consent_sequence_and_server_route_conflicts",
    "shared_configured_destination": "consumer_destination_and_event_overlap",
    "shared_destination_consent_inheritance_review": "consent_sequence_and_server_route_conflicts",
    "browser_server_event_route_family": "consumer_destination_and_event_overlap",
    "browser_server_consent_deduplication_review": "consent_sequence_and_server_route_conflicts",
    "browser_server_terminal_source_review": "terminal_source_formula_and_output_overlap",
    "behavior_portability_variant": "normalized_condition_and_route_variants",
    "shared_zone_child_container": "normalized_condition_and_route_variants",
    "shared_execution_trigger": "normalized_condition_and_route_variants",
    "related_trigger_scope_tag_family": "funnel_question_market_and_product_families",
    "multi_firing_route_consolidation_review": "normalized_condition_and_route_variants",
    "semantic_name_family_candidate": "semantic_name_and_business_term_variants",
    "shared_terminal_source": "terminal_source_formula_and_output_overlap",
    "shared_input_variable_logic": "terminal_source_formula_and_output_overlap",
    "shared_business_event_input": "terminal_source_formula_and_output_overlap",
    "different_consent_purposes_same_logic": "consent_sequence_and_server_route_conflicts",
    "consent_sequence_server_route_variant": "consent_sequence_and_server_route_conflicts",
    "cyclic_trigger_group_dependency": "normalized_condition_and_route_variants",
    "equivalent_custom_code": "terminal_source_formula_and_output_overlap",
    "equivalent_trigger_conditions": "normalized_condition_and_route_variants",
    "near_equivalent_trigger_conditions": "normalized_condition_and_route_variants",
    "trigger_condition_subset": "normalized_condition_and_route_variants",
    "shared_business_scope": "funnel_question_market_and_product_families",
    "data_layer_push_listener_near_miss": "consumer_destination_and_event_overlap",
    "spa_history_send_page_view_review": "consumer_destination_and_event_overlap",
}


def normalized_text(value: Any) -> str:
    text = unicodedata.normalize("NFKD", str(value or ""))
    text = "".join(char for char in text if not unicodedata.combining(char))
    return re.sub(r"\s+", " ", text).strip().lower()


def parameter_value(obj: dict[str, Any], key: str) -> Any:
    for parameter in as_list(obj.get("parameter")):
        if not isinstance(parameter, dict):
            continue
        if str(parameter.get("key") or "") != key:
            continue
        for value_key in ("value", "list", "map"):
            if value_key in parameter:
                return parameter.get(value_key)
    return None


def object_key(layer: str, obj: dict[str, Any]) -> str:
    return f"{layer}:{object_id(obj, ID_KEYS[layer])}"


def object_hash(obj: dict[str, Any]) -> str:
    return stable_hash(comparable(obj, COMMON_IGNORED))


def logic_anchors(obj: dict[str, Any], source_path: str) -> list[str]:
    ignored_suffixes = tuple(
        f".{field}"
        for field in (
            "accountId",
            "containerId",
            "workspaceId",
            "fingerprint",
            "path",
            "tagManagerUrl",
            "notes",
            "parentFolderId",
            "tagId",
            "triggerId",
            "variableId",
            "templateId",
            "clientId",
            "zoneId",
            "gtagConfigId",
            "transformationId",
            "name",
        )
    )
    facts = walk_json_fields(obj, source_path)
    anchors = [
        fact["json_path"] for fact in facts if not fact["json_path"].endswith(ignored_suffixes)
    ]
    return anchors or [fact["json_path"] for fact in facts]


def config_specificity_tokens(obj: dict[str, Any]) -> list[str]:
    semantic = {
        key: value
        for key, value in behavior_projection(obj).items()
        if key not in {*ID_KEYS.values(), "name"}
    }
    reference_tokens = {
        normalized_text(reference)
        for reference in refs(semantic)
        if len(normalized_text(reference)) >= 4
    }
    parameter_tokens: set[str] = set()
    for parameter in as_list(semantic.get("parameter")):
        if not isinstance(parameter, dict):
            continue
        key = normalized_text(parameter.get("key"))
        if len(key) >= 4 and key not in GENERIC_CONFIG_TOKENS:
            parameter_tokens.add(key)
    serialized = json.dumps(semantic, ensure_ascii=False)
    host_tokens: set[str] = set()
    for match in re.finditer(r"https?://([^/\s\"'<>]+)", serialized, re.I):
        host = normalized_text(match.group(1).rsplit("@", 1)[-1])
        if host:
            host_tokens.add(host)
    preview_tokens: set[str] = set()
    for fact in walk_json_fields(semantic):
        preview = str(fact.get("value_preview") or "")
        for token in re.findall(r"[A-Za-z][A-Za-z0-9_.-]{3,}", preview):
            normalized = normalized_text(token)
            if (
                normalized not in GENERIC_CONFIG_TOKENS
                and normalized.rstrip(".") not in {"http", "https"}
                and "@" not in normalized
            ):
                preview_tokens.add(normalized)
    ordered_tokens: list[str] = []
    for group in (
        host_tokens,
        reference_tokens,
        parameter_tokens,
        preview_tokens,
    ):
        for token in sorted(group):
            if token and token not in ordered_tokens:
                ordered_tokens.append(token)
    if not ordered_tokens:
        ordered_tokens.extend(
            normalized_text(token)
            for token in re.findall(r"[A-Za-z][A-Za-z0-9_.-]{3,}", str(obj.get("name") or ""))
        )
    return ordered_tokens[:60]


def object_records(
    cv: dict[str, Any], root_path: str = "$.containerVersion"
) -> dict[str, list[dict[str, Any]]]:
    records: dict[str, list[dict[str, Any]]] = {}
    for layer in SEMANTIC_LAYERS:
        layer_records = []
        for index, obj in enumerate(as_list(cv.get(layer))):
            source_path = f"{root_path}.{layer}[{index}]"
            layer_records.append(
                {
                    "layer": layer,
                    "index": index,
                    "object": obj,
                    "object_key": object_key(layer, obj),
                    "object_id": object_id(obj, ID_KEYS[layer]),
                    "object_name": str(obj.get("name") or ""),
                    "object_type": str(
                        obj.get("type")
                        or (layer if layer in {"customTemplate", "zone", "gtagConfig"} else "")
                    ),
                    "paused": bool(obj.get("paused")) if layer == "tag" else False,
                    "config_hash": object_hash(obj),
                    "source_json_path": source_path,
                    "evidence_anchors": logic_anchors(obj, source_path),
                    "specificity_tokens": config_specificity_tokens(obj),
                    "resolved_event_values": (
                        parameter_static_values(cv, obj, "eventName")
                        if layer == "tag"
                        else []
                    ),
                }
            )
        records[layer] = layer_records
    return records


def keyed_record_groups(
    records: Iterable[dict[str, Any]], key_fn: Any
) -> list[tuple[str, list[dict[str, Any]]]]:
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        key = key_fn(record)
        if key:
            groups[str(key)].append(record)
    return [(key, group) for key, group in sorted(groups.items()) if len(group) >= 2]


def group_records(records: Iterable[dict[str, Any]], key_fn: Any) -> list[list[dict[str, Any]]]:
    return [group for _, group in keyed_record_groups(records, key_fn)]


def nested_key_values(value: Any) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    if isinstance(value, dict):
        key = str(value.get("key") or "")
        scalar = value.get("value")
        if key and scalar is not None and not isinstance(scalar, (dict, list)):
            pairs.append((key, str(scalar)))
        for child in value.values():
            pairs.extend(nested_key_values(child))
    elif isinstance(value, list):
        for child in value:
            pairs.extend(nested_key_values(child))
    return pairs


def tag_contract(record: dict[str, Any]) -> dict[str, Any]:
    obj = record["object"]
    pairs = nested_key_values(obj.get("parameter", []))
    destinations = sorted(
        normalized_text(value)
        for key, value in pairs
        if (
            DESTINATION_KEY_RE.search(normalized_text(key))
            or normalized_text(key) == "conversionlabel"
        )
        and str(value).strip()
    )
    primary_events = sorted(
        normalized_text(value)
        for key, value in pairs
        if normalized_text(key) in PRIMARY_EVENT_KEYS
        and normalized_text(value) not in GENERIC_EVENT_VALUES
        and str(value).strip()
    )
    secondary_events = sorted(
        normalized_text(value)
        for key, value in pairs
        if normalized_text(key) in SECONDARY_EVENT_KEYS
        and normalized_text(value) not in GENERIC_EVENT_VALUES
        and str(value).strip()
    )
    resolved_events = sorted(
        {
            normalized_text(value)
            for value in as_list(record.get("resolved_event_values"))
            if normalized_text(value) not in GENERIC_EVENT_VALUES
        }
    )
    code_events = sorted(
        {
            normalized_text(match.group(1))
            for pattern in CUSTOM_CODE_EVENT_PATTERNS
            for match in pattern.finditer(custom_code(obj))
            if normalized_text(match.group(1)) not in GENERIC_EVENT_VALUES
        }
    )
    events = sorted(set(resolved_events or primary_events or secondary_events) | set(code_events))
    if not events:
        return {}
    vendor = str(
        vendor_record(behavior_bearing_vendor_text(obj, record["layer"])).get("name")
        or ""
    )
    return {
        "vendor": vendor,
        "type": record["object_type"],
        "destinations": destinations,
        "events": events,
    }


def tag_contract_key(record: dict[str, Any]) -> str:
    contract = tag_contract(record)
    return json.dumps(contract, sort_keys=True) if contract else ""


def tag_event_family_key(record: dict[str, Any]) -> str:
    contract = tag_contract(record)
    if not contract:
        return ""
    return json.dumps(
        {
            "vendor": contract["vendor"],
            "type": contract["type"],
            "events": contract["events"],
        },
        sort_keys=True,
    )


def tag_business_event_key(record: dict[str, Any]) -> str:
    contract = tag_contract(record)
    if not contract:
        return ""
    events = sorted(
        {
            BUSINESS_EVENT_SYNONYMS.get(
                re.sub(r"[^a-z0-9]+", "", normalized_text(value)),
                normalized_text(value),
            )
            for value in as_list(contract.get("events"))
        }
    )
    return json.dumps(events, sort_keys=True) if events else ""


def custom_code(obj: dict[str, Any]) -> str:
    for key in ("html", "javascript"):
        value = parameter_value(obj, key)
        if value is not None:
            return str(value)
    return ""


def pushed_data_layer_events(obj: dict[str, Any]) -> list[str]:
    code = strip_nonbehavior_comments(custom_code(obj))
    return sorted(
        {
            re.sub(r"\s+", " ", str(match.group(1) or "")).strip()
            for push in DATA_LAYER_PUSH_OBJECT_RE.finditer(code)
            for match in PUSH_EVENT_FIELD_RE.finditer(push.group("body"))
            if str(match.group(1) or "").strip()
        }
    )


def trigger_custom_event_values(record: dict[str, Any]) -> list[str]:
    values: set[str] = set()

    def visit(value: Any) -> None:
        if isinstance(value, dict):
            parameters = condition_parameters(value)
            left = re.sub(r"\s+", " ", str(parameters.get("arg0") or "")).strip()
            right = re.sub(r"\s+", " ", str(parameters.get("arg1") or "")).strip()
            if left in {"{{_event}}", "_event"} and right:
                values.add(right)
            for child in value.values():
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)

    visit(record["object"])
    return sorted(values)


def canonical_event_name(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", normalized_text(value))


def near_event_name(left: str, right: str) -> tuple[bool, float]:
    if left == right:
        return False, 1.0
    if left.casefold() == right.casefold():
        return True, 0.99
    left_key = canonical_event_name(left)
    right_key = canonical_event_name(right)
    if not left_key or not right_key:
        return False, 0.0
    if left_key == right_key:
        return True, 0.99
    if min(len(left_key), len(right_key)) < 5:
        return False, 0.0
    score = difflib.SequenceMatcher(
        None,
        left_key,
        right_key,
        autojunk=False,
    ).ratio()
    return score >= 0.9 and abs(len(left_key) - len(right_key)) <= 2, score


def add_push_listener_near_miss_candidates(
    builder: CandidateBuilder,
    tags: list[dict[str, Any]],
    triggers: list[dict[str, Any]],
) -> None:
    listeners = []
    for record in triggers:
        values = trigger_custom_event_values(record)
        if values:
            listeners.append((record, values))
    for tag in tags:
        pushed_events = pushed_data_layer_events(tag["object"])
        if not pushed_events:
            continue
        for trigger, listened_events in listeners:
            for pushed in pushed_events:
                for listened in listened_events:
                    matched, score = near_event_name(pushed, listened)
                    if not matched:
                        continue
                    builder.add(
                        "data_layer_push_listener_near_miss",
                        (tag, trigger),
                        (
                            f"{tag['object_key']} pushes dataLayer event {pushed!r}, while "
                            f"{trigger['object_key']} listens for near-matching "
                            f"{listened!r}. Confirm intentional spelling/casing before "
                            "changing either side."
                        ),
                        score,
                    )


def explicit_parameter_boolean(obj: dict[str, Any], key: str) -> bool | None:
    values = [
        value
        for parameter_key, value in nested_key_values(obj.get("parameter", []))
        if normalized_text(parameter_key) == normalized_text(key)
    ]
    if not values:
        return None
    value = normalized_text(values[-1])
    if value in {"true", "1"}:
        return True
    if value in {"false", "0"}:
        return False
    return None


def add_spa_page_view_candidates(
    builder: CandidateBuilder,
    tags: list[dict[str, Any]],
    triggers: list[dict[str, Any]],
    gtag_configs: list[dict[str, Any]],
) -> None:
    history_triggers = {
        str(record["object_id"]): record
        for record in triggers
        if str(record["object_type"] or "").upper() == "HISTORY_CHANGE"
    }
    if not history_triggers:
        return
    manual_page_views = []
    for tag in tags:
        event_values = {
            canonical_event_name(value)
            for value in as_list(tag_contract(tag).get("events"))
        }
        firing_ids = {
            str(value) for value in as_list(tag["object"].get("firingTriggerId"))
        }
        used_history = firing_ids & set(history_triggers)
        if "pageview" in event_values and used_history:
            manual_page_views.append((tag, used_history))

    google_configs = [
        record
        for record in [*tags, *gtag_configs]
        if str(
            vendor_record(
                behavior_bearing_vendor_text(record["object"], record["layer"])
            ).get("name")
            or ""
        )
        == "GA4 / Google tag"
        and (
            record["layer"] == "gtagConfig"
            or str(record["object"].get("type") or "").lower()
            in {"googtag", "gaawc"}
        )
        and not record.get("paused")
        and explicit_parameter_boolean(record["object"], "send_page_view") is not False
    ]
    for manual_tag, history_ids in manual_page_views:
        for google_config in google_configs:
            if google_config["object_key"] == manual_tag["object_key"]:
                continue
            members = [
                manual_tag,
                google_config,
                *[history_triggers[value] for value in sorted(history_ids)],
            ]
            builder.add(
                "spa_history_send_page_view_review",
                members,
                (
                    f"{manual_tag['object_key']} sends page_view on History Change while "
                    f"{google_config['object_key']} does not explicitly disable "
                    "send_page_view. Confirm GA4 Enhanced Measurement/property behavior "
                    "and retain exactly one virtual page-view sender per navigation."
                ),
                0.85,
            )


def condition_parameters(node: dict[str, Any]) -> dict[str, str]:
    values: dict[str, str] = {}
    for parameter in as_list(node.get("parameter")):
        if not isinstance(parameter, dict):
            continue
        key = str(parameter.get("key") or "")
        if key and parameter.get("value") is not None:
            values[key] = str(parameter.get("value"))
    return values


def regex_literal(pattern: str) -> tuple[str, str] | None:
    value = pattern
    if value.startswith("^") and value.endswith("$"):
        inner = value[1:-1]
        if not re.search(r"[.\\+*?\[\](){}|]", inner):
            return "EQUALS", inner
    if value.startswith(".*") and value.endswith(".*"):
        inner = value[2:-2]
        if inner and not re.search(r"[.\\+*?\[\](){}|]", inner):
            return "CONTAINS", inner
    return None


def normalized_condition(node: dict[str, Any]) -> str:
    operator = str(node.get("type") or "").upper()
    values = condition_parameters(node)
    left = normalized_text(values.get("arg0"))
    right = normalized_text(values.get("arg1"))
    if operator == "MATCH_REGEX":
        normalized = regex_literal(str(values.get("arg1") or ""))
        if normalized:
            operator, right = normalized[0], normalized_text(normalized[1])
    modifiers = sorted(
        [
            f"{key}={normalized_text(value)}"
            for key, value in values.items()
            if key not in {"arg0", "arg1"}
        ]
        + [
            f"{key}={normalized_text(value)}"
            for key, value in node.items()
            if key not in {"type", "parameter"} and not isinstance(value, (dict, list))
        ]
    )
    return f"{operator}|{left}|{right}|{'&'.join(modifiers)}"


def trigger_conditions(value: Any) -> list[str]:
    conditions: list[str] = []
    if isinstance(value, dict):
        operator = str(value.get("type") or "").upper()
        parameters = condition_parameters(value)
        if operator and "arg0" in parameters and "arg1" in parameters:
            conditions.append(normalized_condition(value))
        for child in value.values():
            conditions.extend(trigger_conditions(child))
    elif isinstance(value, list):
        for child in value:
            conditions.extend(trigger_conditions(child))
    return sorted(set(conditions))


def business_scope_tokens(record: dict[str, Any]) -> set[str]:
    obj = record["object"]
    text = normalized_text(
        " ".join(
            [
                record["object_name"],
                *trigger_conditions(obj),
            ]
        )
    )
    separated = re.sub(r"[_/.-]+", " ", text)
    tokens = {
        f"step:{int(match.group(1))}"
        for match in re.finditer(
            r"\b(?:q|question|step|etape|funnel\s+step)\s*0*(\d{1,3})\b",
            separated,
        )
    }
    for condition in trigger_conditions(obj):
        operator, left, right, _modifiers = condition.split("|", 3)
        del operator
        if left in {"{{_event}}", "_event"} and right:
            tokens.add(f"event:{right}")
    return tokens


def semantic_name_tokens(record: dict[str, Any]) -> set[str]:
    text = re.sub(r"[^a-z0-9]+", " ", normalized_text(record["object_name"]))
    values = []
    for token in text.split():
        canonical = NAME_SYNONYMS.get(token, token)
        if canonical in GENERIC_NAME_TOKENS or len(canonical) < 2:
            continue
        values.append(canonical)
    tokens = set(values)
    for match in re.finditer(r"\b(?:q|question|step|etape)\s*0*(\d{1,3})\b", text):
        tokens.add(f"step:{int(match.group(1))}")
    return tokens


def jaccard(left: set[str], right: set[str]) -> float:
    union = left | right
    return len(left & right) / len(union) if union else 0.0


class CandidateBuilder:
    def __init__(self) -> None:
        self._candidates: dict[tuple[str, ...], dict[str, Any]] = {}

    def add(
        self,
        comparison_type: str,
        records: Iterable[dict[str, Any]],
        basis: str,
        similarity_score: float,
    ) -> None:
        unique = {record["object_key"]: record for record in records}
        if len(unique) < 2:
            return
        members = [unique[key] for key in sorted(unique)]
        member_keys = tuple(record["object_key"] for record in members)
        current = self._candidates.get(member_keys)
        if current is None:
            layer_values = {record["layer"] for record in members}
            layer = next(iter(layer_values)) if len(layer_values) == 1 else "mixed"
            current = {
                "comparison_id": f"REL-{stable_hash(member_keys, 12).upper()}",
                "comparison_origin": "deterministic",
                "layer": layer,
                "candidate_object_keys": list(member_keys),
                "candidate_object_ids": [record["object_id"] for record in members],
                "candidate_object_names": [record["object_name"] for record in members],
                "candidate_object_types": [record["object_type"] for record in members],
                "candidate_config_hashes": {
                    record["object_key"]: record["config_hash"] for record in members
                },
                "candidate_source_paths": {
                    record["object_key"]: record["source_json_path"] for record in members
                },
                "candidate_paused_status": {
                    record["object_key"]: record["paused"] for record in members
                },
                "available_member_evidence_anchors": {
                    record["object_key"]: record["evidence_anchors"] for record in members
                },
                "candidate_specificity_tokens": {
                    record["object_key"]: record["specificity_tokens"] for record in members
                },
                "comparison_types": [],
                "candidate_basis": [],
                "similarity_score": 0.0,
                "required_comparison_dimensions": DIMENSIONS_BY_LAYER.get(
                    layer,
                    [
                        "purpose",
                        "configuration",
                        "execution_scope",
                        "consumers",
                        "output_payload",
                        "consent_sequence",
                    ],
                ),
            }
            self._candidates[member_keys] = current
        if comparison_type not in current["comparison_types"]:
            current["comparison_types"].append(comparison_type)
        if basis not in current["candidate_basis"]:
            current["candidate_basis"].append(basis)
        current["similarity_score"] = max(current["similarity_score"], similarity_score)

    def rows(self) -> list[dict[str, Any]]:
        rows = []
        for candidate in self._candidates.values():
            candidate["comparison_types"] = sorted(candidate["comparison_types"])
            candidate["comparison_type"] = candidate["comparison_types"][0]
            candidate["discovery_methods"] = sorted(
                {
                    DISCOVERY_METHOD_BY_COMPARISON_TYPE[comparison_type]
                    for comparison_type in candidate["comparison_types"]
                    if comparison_type in DISCOVERY_METHOD_BY_COMPARISON_TYPE
                }
            )
            candidate["candidate_basis"] = sorted(candidate["candidate_basis"])
            candidate["similarity_score"] = round(candidate["similarity_score"], 3)
            rows.append(candidate)
        return sorted(rows, key=lambda row: row["comparison_id"])


def add_exact_candidates(
    builder: CandidateBuilder, records: dict[str, list[dict[str, Any]]]
) -> None:
    for layer, layer_records in records.items():
        for group in group_records(
            layer_records,
            lambda record, current_layer=layer: stable_hash(
                comparable(record["object"], IDENTITY_IGNORED[current_layer])
            ),
        ):
            builder.add(
                "exact_configuration",
                group,
                "Objects share the same configuration after identity and export metadata are removed.",
                1.0,
            )
        for group in group_records(
            layer_records,
            lambda record: normalized_text(record["object_name"]),
        ):
            builder.add(
                "duplicate_name",
                group,
                "Objects share the same normalized name and require configuration comparison.",
                1.0,
            )

    for group in group_records(
        records.get("tag", []),
        lambda record: stable_hash(
            comparable(
                record["object"],
                IDENTITY_IGNORED["tag"] | TAG_ROUTE_FIELDS,
            )
        ),
    ):
        execution_control_signatures = {
            stable_hash(
                {
                    field: record["object"].get(field)
                    for field in sorted(TAG_EXECUTION_CONTROL_FIELDS)
                }
            )
            for record in group
        }
        if len(execution_control_signatures) < 2:
            continue
        builder.add(
            "same_tag_payload_different_route",
            group,
            "Tag payload configuration matches after trigger, schedule, folder, and note fields are removed.",
            1.0,
        )


def add_tag_family_candidates(builder: CandidateBuilder, tags: list[dict[str, Any]]) -> None:
    for key, group in keyed_record_groups(tags, tag_contract_key):
        contract = json.loads(key)
        builder.add(
            "same_vendor_destination_event",
            group,
            "Tags expose the same configured vendor "
            f"{contract['vendor']!r}, destination values {contract['destinations']!r}, "
            f"and event or action values {contract['events']!r}.",
            0.95,
        )
    for key, group in keyed_record_groups(tags, tag_event_family_key):
        contract = json.loads(key)
        builder.add(
            "same_vendor_event_family",
            group,
            "Tags expose the same configured vendor "
            f"{contract['vendor']!r} and event or action values {contract['events']!r}, "
            "including destination variants.",
            0.85,
        )
    for key, group in keyed_record_groups(tags, tag_business_event_key):
        vendors = {str(tag_contract(record).get("vendor") or "") for record in group}
        if len(vendors) < 2:
            continue
        builder.add(
            "cross_vendor_event_family",
            group,
            "Tags expose the same configured event or action values "
            f"{json.loads(key)!r} across vendor implementations.",
            0.75,
        )
        builder.add(
            "cross_vendor_consent_route_review",
            group,
            "Cross-vendor delivery of one business event requires an explicit comparison of "
            "consent ownership, browser/server routing, and deduplication responsibility.",
            0.75,
        )

    tags_by_trigger: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in tags:
        for trigger_id in sorted(
            {
                str(value)
                for value in as_list(record["object"].get("firingTriggerId"))
                if not is_system_trigger_reference(str(value))
            }
        ):
            tags_by_trigger[trigger_id].append(record)
    for trigger_id, group in sorted(tags_by_trigger.items()):
        if len(group) < 2:
            continue
        builder.add(
            "shared_execution_trigger",
            group,
            f"Tags share non-system firing trigger {trigger_id} and overlap on that execution path.",
            0.8,
        )


def add_consent_sequence_candidates(
    builder: CandidateBuilder,
    tags: list[dict[str, Any]],
    variables: list[dict[str, Any]],
) -> None:
    for key, group in keyed_record_groups(tags, tag_contract_key):
        signatures: dict[str, list[dict[str, Any]]] = defaultdict(list)
        routes: dict[str, dict[str, Any]] = {}
        for record in group:
            obj = record["object"]
            consent = tag_consent_route(obj, variables=variables)
            route = {
                "firing": sorted(str(value) for value in as_list(obj.get("firingTriggerId"))),
                "blocking": sorted(
                    str(value) for value in as_list(obj.get("blockingTriggerId"))
                ),
                "setup": as_list(obj.get("setupTag")),
                "teardown": as_list(obj.get("teardownTag")),
                "schedule_start": obj.get("scheduleStartMs"),
                "schedule_end": obj.get("scheduleEndMs"),
                "firing_option": obj.get("tagFiringOption"),
                "consent_status": consent.get("consent_status"),
                "effective_control": consent.get("effective_control_status"),
                "server_hosts": as_list(consent.get("server_routing_hosts")),
                "forwarded_purposes": as_list(
                    consent.get("forwarded_consent_purposes")
                ),
            }
            route_hash = stable_hash(route)
            signatures[route_hash].append(record)
            routes[route_hash] = route
        if len(signatures) < 2:
            continue
        contract = json.loads(key)
        builder.add(
            "consent_sequence_server_route_variant",
            group,
            "Tags share vendor, destination, and event contract "
            f"{contract!r} but expose different execution/consent/server-route signatures "
            f"{routes!r}; compare the routes before consolidation or retention.",
            0.95,
        )


def configured_destinations(record: dict[str, Any]) -> list[str]:
    return sorted(
        {
            normalized_text(value)
            for key, value in nested_key_values(record["object"].get("parameter", []))
            if (
                DESTINATION_KEY_RE.search(normalized_text(key))
                or normalized_text(key) == "conversionlabel"
            )
            and str(value).strip()
        }
    )


def add_destination_candidates(
    builder: CandidateBuilder, records: dict[str, list[dict[str, Any]]]
) -> None:
    destination_objects = records.get("tag", []) + records.get("gtagConfig", [])
    for key, group in keyed_record_groups(
        destination_objects,
        lambda record: json.dumps(configured_destinations(record))
        if configured_destinations(record)
        else "",
    ):
        builder.add(
            "shared_configured_destination",
            group,
            f"Objects share configured destination values {json.loads(key)!r}; compare "
            "configuration ownership, event role, routing, and consent inheritance.",
            0.9,
        )
        builder.add(
            "shared_destination_consent_inheritance_review",
            group,
            "Objects sharing one configured destination require an explicit comparison of "
            "consent inheritance and execution ownership.",
            0.9,
        )


def add_shared_business_input_candidates(
    builder: CandidateBuilder, tags: list[dict[str, Any]]
) -> None:
    groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for record in tags:
        event_key = tag_business_event_key(record)
        if not event_key:
            continue
        for reference in sorted(refs(record["object"])):
            groups[(event_key, normalized_text(reference))].append(record)
    for (event_key, reference), group in sorted(groups.items()):
        if len({record["object_key"] for record in group}) < 2:
            continue
        builder.add(
            "shared_business_event_input",
            group,
            f"Tags delivering business event family {json.loads(event_key)!r} read shared "
            f"GTM input {reference!r}; compare source ownership, transformations, and output use.",
            0.8,
        )


def add_browser_server_route_candidates(
    builder: CandidateBuilder, records: dict[str, list[dict[str, Any]]]
) -> None:
    tags = records.get("tag", [])
    for config in records.get("gtagConfig", []):
        destinations = set(configured_destinations(config))
        if not destinations:
            continue
        server_values = [
            value
            for key, value in nested_key_values(config["object"].get("parameter", []))
            if normalized_text(key) in {"server_container_url", "transport_url"}
            and str(value).strip()
        ]
        if not server_values:
            continue
        seed_tags = [
            tag for tag in tags if destinations & set(configured_destinations(tag))
        ]
        business_events = {
            tag_business_event_key(tag)
            for tag in seed_tags
            if tag_business_event_key(tag)
        }
        for event_key in sorted(business_events):
            event_tags = [tag for tag in tags if tag_business_event_key(tag) == event_key]
            if len(event_tags) < 2:
                continue
            members = [config, *event_tags]
            server_hosts = sorted(
                {
                    match.group(1).rsplit("@", 1)[-1].lower()
                    for value in server_values
                    for match in re.finditer(r"https?://([^/\s\"'<>]+)", value, re.I)
                }
            )
            basis = (
                f"Google tag configuration {config['object_key']} routes destination(s) "
                f"{sorted(destinations)!r} toward server host(s) {server_hosts!r}, while tags "
                f"{[tag['object_key'] for tag in event_tags]!r} deliver business event family "
                f"{json.loads(event_key)!r}; compare browser/server duplication and ownership."
            )
            builder.add("browser_server_event_route_family", members, basis, 0.95)
            builder.add(
                "browser_server_consent_deduplication_review",
                members,
                "The browser/server event family requires one explicit decision for consent "
                "enforcement, downstream routing, event_id or transaction_id deduplication, "
                "and the system of record.",
                0.95,
            )
            builder.add(
                "browser_server_terminal_source_review",
                members,
                "The browser/server family must compare the terminal transaction_id, event_id, "
                "value, currency, and item sources used for downstream payload and deduplication.",
                0.95,
            )


def add_zone_candidates(builder: CandidateBuilder, zones: list[dict[str, Any]]) -> None:
    for key, group in keyed_record_groups(
        zones,
        lambda record: json.dumps(
            sorted(
                {
                    str(child.get("publicId") or "").strip()
                    for child in as_list(record["object"].get("childContainer"))
                    if isinstance(child, dict) and str(child.get("publicId") or "").strip()
                }
            )
        ),
    ):
        child_ids = json.loads(key)
        if not child_ids:
            continue
        builder.add(
            "shared_zone_child_container",
            group,
            f"Zones govern the same child container set {child_ids!r}; compare boundaries, "
            "type restrictions, and ownership before retaining both.",
            1.0,
        )


def add_tag_trigger_scope_candidates(
    builder: CandidateBuilder,
    tags: list[dict[str, Any]],
    triggers: list[dict[str, Any]],
) -> None:
    trigger_tokens: dict[str, set[str]] = {}
    for trigger in triggers:
        trigger_id = str(trigger["object_id"])
        tokens = {token for token in business_scope_tokens(trigger) if token.startswith("step:")}
        conditions = trigger_conditions(trigger["object"])
        if conditions:
            tokens.add(f"conditions:{trigger['object_type']}:{stable_hash(conditions)}")
        trigger_tokens[trigger_id] = tokens

    tags_by_scope: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for tag in tags:
        tag_tokens: set[str] = set()
        for trigger_id in as_list(tag["object"].get("firingTriggerId")):
            tag_tokens.update(trigger_tokens.get(str(trigger_id), set()))
        for token in tag_tokens:
            tags_by_scope[token].append(tag)
    for token, group in sorted(tags_by_scope.items()):
        if len({record["object_key"] for record in group}) < 2:
            continue
        builder.add(
            "related_trigger_scope_tag_family",
            group,
            f"Tags fire through triggers sharing normalized scope {token!r}.",
            0.75,
        )


def add_multi_firing_route_candidates(
    builder: CandidateBuilder,
    tags: list[dict[str, Any]],
    triggers: list[dict[str, Any]],
) -> None:
    triggers_by_id = {str(record["object_id"]): record for record in triggers}
    for tag in tags:
        trigger_ids = sorted(
            {
                str(value)
                for value in as_list(tag["object"].get("firingTriggerId"))
                if not is_system_trigger_reference(str(value))
            }
        )
        members = [triggers_by_id[value] for value in trigger_ids if value in triggers_by_id]
        if len(members) < 2:
            continue
        builder.add(
            "multi_firing_route_consolidation_review",
            members,
            (
                f"Tag {tag['object_key']} fires through {len(members)} non-system triggers "
                f"{trigger_ids!r}; compare their event types, predicates, exclusions, and "
                "readability before deciding whether one canonical route can preserve the OR logic."
            ),
            0.7,
        )


def add_semantic_name_candidates(
    builder: CandidateBuilder,
    records: dict[str, list[dict[str, Any]]],
) -> None:
    for layer, layer_records in records.items():
        by_key = {record["object_key"]: record for record in layer_records}
        token_sets = {
            record["object_key"]: semantic_name_tokens(record) for record in layer_records
        }
        inverted: dict[str, set[str]] = defaultdict(set)
        for key, tokens in token_sets.items():
            for token in tokens:
                inverted[token].add(key)
        pairs: set[tuple[str, str]] = set()
        for keys in inverted.values():
            pairs.update(combinations(sorted(keys), 2))
        for left_key, right_key in sorted(pairs):
            left_tokens = token_sets[left_key]
            right_tokens = token_sets[right_key]
            if not left_tokens or not right_tokens:
                continue
            score = jaccard(left_tokens, right_tokens)
            shared_scope = {
                token for token in left_tokens & right_tokens if token.startswith("step:")
            }
            if score < 0.67 and not shared_scope:
                continue
            builder.add(
                "semantic_name_family_candidate",
                (by_key[left_key], by_key[right_key]),
                (
                    f"{layer} names normalize to related business tokens "
                    f"{sorted(left_tokens & right_tokens)!r}; names are only a discovery signal, "
                    "so compare complete configuration chains before any consolidation."
                ),
                max(0.6, score),
            )


PORTABILITY_TOKEN_RE = re.compile(
    r"\bGTM-(?=[A-Z0-9]{4,12}\b)(?=[A-Z0-9]*\d)[A-Z0-9]+\b|"
    r"\b(?:dev|development|stage|staging|qa|uat|sandbox|preprod|prod|production|live)\b|"
    r"(?:localhost|127\.0\.0\.1)",
    re.I,
)


def add_portability_candidates(
    builder: CandidateBuilder,
    records: dict[str, list[dict[str, Any]]],
) -> None:
    """Compare environment/container variants without treating metadata as behavior."""

    def normalize(value: Any) -> Any:
        if isinstance(value, dict):
            return {key: normalize(item) for key, item in value.items()}
        if isinstance(value, list):
            return [normalize(item) for item in value]
        if not isinstance(value, str):
            return value
        text = re.sub(
            r"\bGTM-(?=[A-Z0-9]{4,12}\b)(?=[A-Z0-9]*\d)[A-Z0-9]+\b",
            "<gtm-container>",
            value,
            flags=re.I,
        )
        text = re.sub(
            r"\b(?:dev|development|stage|staging|qa|uat|sandbox|preprod|"
            r"prod|production|live)\b",
            "<environment>",
            text,
            flags=re.I,
        )
        return re.sub(r"(?:localhost|127\.0\.0\.1)", "<environment-host>", text, flags=re.I)

    for layer, layer_records in records.items():
        groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
        signals_by_key: dict[str, list[str]] = {}
        for record in layer_records:
            behavior = comparable(
                behavior_projection(record["object"]),
                IDENTITY_IGNORED[layer],
            )
            serialized = json.dumps(behavior, ensure_ascii=False, sort_keys=True)
            signals = sorted(set(PORTABILITY_TOKEN_RE.findall(serialized)))
            if not signals:
                continue
            key = stable_hash(normalize(behavior))
            groups[key].append(record)
            signals_by_key[record["object_key"]] = signals
        for signature, group in sorted(groups.items()):
            if len(group) < 2:
                continue
            builder.add(
                "behavior_portability_variant",
                group,
                (
                    "Behavior-bearing configuration becomes equivalent only after replacing "
                    "environment/container literals; compare the exact routes and parameterize "
                    "or retain them deliberately. Signals: "
                    + json.dumps(
                        {
                            record["object_key"]: signals_by_key[record["object_key"]]
                            for record in group
                        },
                        ensure_ascii=False,
                        sort_keys=True,
                    )
                    + f"; normalized signature={signature}."
                ),
                0.9,
            )


def add_variable_candidates(builder: CandidateBuilder, variables: list[dict[str, Any]]) -> None:
    for key, group in keyed_record_groups(
        variables,
        lambda record: (
            f"{record['object_type']}|{parameter_value(record['object'], 'name')}"
            if parameter_value(record["object"], "name")
            else ""
        ),
    ):
        builder.add(
            "shared_terminal_source",
            group,
            "Variables share configured type and terminal source "
            f"{key!r} and require consumer comparison.",
            1.0,
        )

    def shared_input_key(record: dict[str, Any]) -> str:
        references = sorted(refs(record["object"]))
        if not references or record["object_type"] == "v":
            return ""
        return json.dumps({"type": record["object_type"], "references": references}, sort_keys=True)

    for key, group in keyed_record_groups(variables, shared_input_key):
        shared = json.loads(key)
        builder.add(
            "shared_input_variable_logic",
            group,
            "Variables of type "
            f"{shared['type']!r} consume the same GTM inputs {shared['references']!r} "
            "but may map them differently.",
            0.85,
        )

    records_by_id = {str(record["object_id"]): record for record in variables}
    source_variables = [record["object"] for record in variables]
    for conflict in consent_variable_conflicts(source_variables):
        members = [
            records_by_id.get(str(variable.get("variableId") or variable.get("name") or ""))
            for variable in conflict["variables"]
        ]
        builder.add(
            "different_consent_purposes_same_logic",
            [member for member in members if member],
            (
                f"Consent purposes {conflict['purposes']!r} share exported logic signature "
                f"{conflict['logic_hash']}; compare CMP category semantics before retaining "
                "or separating the variables."
            ),
            1.0,
        )


def add_code_candidates(
    builder: CandidateBuilder, records: dict[str, list[dict[str, Any]]]
) -> None:
    for layer in ("tag", "variable"):
        for code_hash, group in keyed_record_groups(
            records.get(layer, []),
            lambda record: (
                stable_hash(code_identity_text(custom_code(record["object"])))
                if custom_code(record["object"])
                else ""
            ),
        ):
            builder.add(
                "equivalent_custom_code",
                group,
                "Custom code is byte-equivalent after line-ending normalization "
                f"under signature {code_hash}.",
                1.0,
            )


def add_trigger_candidates(builder: CandidateBuilder, triggers: list[dict[str, Any]]) -> None:
    for key, group in keyed_record_groups(
        triggers,
        lambda record: (
            json.dumps(
                {
                    "type": record["object_type"],
                    "conditions": trigger_conditions(record["object"]),
                },
                sort_keys=True,
            )
            if trigger_conditions(record["object"])
            else ""
        ),
    ):
        condition_count = len(json.loads(key)["conditions"])
        builder.add(
            "equivalent_trigger_conditions",
            group,
            "Trigger conditions normalize to the same operator, variable, value, and "
            f"modifier set with {condition_count} condition(s) under signature "
            f"{stable_hash(key)}.",
            1.0,
        )

    by_type: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in triggers:
        by_type[record["object_type"]].append(record)
    for type_records in by_type.values():
        records_by_key = {record["object_key"]: record for record in type_records}
        condition_sets = {
            record["object_key"]: set(trigger_conditions(record["object"]))
            for record in type_records
        }
        inverted: dict[str, set[str]] = defaultdict(set)
        for record_key, conditions in condition_sets.items():
            for condition in conditions:
                inverted[condition].add(record_key)
        candidate_pairs: set[tuple[str, str]] = set()
        for keys in inverted.values():
            candidate_pairs.update(combinations(sorted(keys), 2))

        for left_key, right_key in sorted(candidate_pairs):
            left = records_by_key[left_key]
            right = records_by_key[right_key]
            left_conditions = condition_sets[left_key]
            right_conditions = condition_sets[right_key]
            if left_conditions == right_conditions:
                continue
            score = jaccard(left_conditions, right_conditions)
            if score >= 0.8:
                builder.add(
                    "near_equivalent_trigger_conditions",
                    (left, right),
                    "Trigger condition sets reach at least 80 percent Jaccard similarity after normalization.",
                    score,
                )
            shared_scope = business_scope_tokens(left) & business_scope_tokens(right)
            if shared_scope and (
                left_conditions < right_conditions or right_conditions < left_conditions
            ):
                builder.add(
                    "trigger_condition_subset",
                    (left, right),
                    "One trigger condition set is a strict subset of another within a shared event or step scope.",
                    len(left_conditions & right_conditions)
                    / max(len(left_conditions), len(right_conditions)),
                )

    scoped_groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in triggers:
        for token in business_scope_tokens(record):
            if not token.startswith("step:"):
                continue
            scoped_groups[f"{record['object_type']}|{token}"].append(record)
    for scope_key, group in sorted(scoped_groups.items()):
        if len({record["object_key"] for record in group}) < 2:
            continue
        builder.add(
            "shared_business_scope",
            group,
            f"Triggers share canonical scope {scope_key.split('|', 1)[1]!r} despite differing names or conditions.",
            0.7,
        )


def add_trigger_group_cycle_candidates(
    builder: CandidateBuilder, triggers: list[dict[str, Any]]
) -> None:
    groups = {
        str(record["object_id"]): record
        for record in triggers
        if record["object_type"] == "TRIGGER_GROUP"
    }
    reported: set[tuple[str, ...]] = set()

    def visit(current: str, active: tuple[str, ...]) -> None:
        if current in active:
            cycle = active[active.index(current) :] + (current,)
            identity = tuple(sorted(set(cycle[:-1])))
            if len(identity) < 2 or identity in reported:
                return
            reported.add(identity)
            builder.add(
                "cyclic_trigger_group_dependency",
                [groups[value] for value in identity],
                "Trigger groups form the cyclic dependency " + " -> ".join(cycle) + ".",
                1.0,
            )
            return
        record = groups.get(current)
        if not record:
            return
        for child in trigger_group_members(record["object"]):
            if str(child) in groups:
                visit(str(child), (*active, current))

    for trigger_id in sorted(groups):
        visit(trigger_id, ())


def relationship_candidates(
    cv: dict[str, Any], root_path: str = "$.containerVersion"
) -> list[dict[str, Any]]:
    records = object_records(cv, root_path)
    builder = CandidateBuilder()
    add_exact_candidates(builder, records)
    add_tag_family_candidates(builder, records.get("tag", []))
    add_shared_business_input_candidates(builder, records.get("tag", []))
    add_consent_sequence_candidates(
        builder,
        records.get("tag", []),
        [record["object"] for record in records.get("variable", [])],
    )
    add_destination_candidates(builder, records)
    add_browser_server_route_candidates(builder, records)
    add_zone_candidates(builder, records.get("zone", []))
    add_variable_candidates(builder, records.get("variable", []))
    add_code_candidates(builder, records)
    add_trigger_candidates(builder, records.get("trigger", []))
    add_trigger_group_cycle_candidates(builder, records.get("trigger", []))
    add_push_listener_near_miss_candidates(
        builder,
        records.get("tag", []),
        records.get("trigger", []),
    )
    add_spa_page_view_candidates(
        builder,
        records.get("tag", []),
        records.get("trigger", []),
        records.get("gtagConfig", []),
    )
    add_tag_trigger_scope_candidates(
        builder,
        records.get("tag", []),
        records.get("trigger", []),
    )
    add_multi_firing_route_candidates(
        builder,
        records.get("tag", []),
        records.get("trigger", []),
    )
    add_portability_candidates(builder, records)
    add_semantic_name_candidates(builder, records)
    return builder.rows()


def scan_export(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    blocking_integrity = [
        row for row in source_integrity_findings(data) if row.get("blocking")
    ]
    if blocking_integrity:
        raise ValueError(
            "source integrity gate blocked relationship discovery: "
            + ", ".join(
                sorted(
                    str(row.get("finding_type") or "source_integrity_error")
                    for row in blocking_integrity
                )
            )
        )
    rows = relationship_candidates(container_version(data), container_root_path(data))
    return {
        **source_descriptor(path),
        "kind": "gtm_relationship_comparison_candidates",
        "schema_version": 1,
        "candidate_count": len(rows),
        "rows": rows,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("export", type=Path)
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()
    print(
        json.dumps(
            scan_export(args.export),
            ensure_ascii=False,
            indent=2 if args.pretty else None,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
