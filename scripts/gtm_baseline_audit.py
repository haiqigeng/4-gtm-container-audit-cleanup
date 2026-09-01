#!/usr/bin/env python3
"""Build internal deterministic operational candidate evidence.

The canonical v2 scan consumes these neutral candidates.  This module does not
own semantic verdicts and no longer exposes the standalone v1 scan command.
"""

from __future__ import annotations

import collections
import difflib
import json
import re
import unicodedata
from pathlib import Path
from typing import Any

from gtm_consent_model import consent_variable_conflicts, tag_consent_route
from gtm_custom_code_extract import expression_facts
from gtm_lib import (
    BEHAVIOR_NEUTRAL_FIELDS,
    ID_KEYS,
    SEMANTIC_LAYERS,
    as_list,
    behavior_projection,
    builtin_reference_names,
    code_identity_text,
    comparable,
    container_root_path,
    container_version,
    custom_template_ids,
    custom_template_type_index,
    is_system_trigger_reference,
    is_system_variable_reference,
    param_value,
    refs,
    source_descriptor,
    source_integrity_findings,
    stable_hash,
    stable_payload,
    system_reference_description,
    trigger_group_members,
)
from gtm_vendor_registry import behavior_bearing_vendor_text, detect_vendor_text

COMMON_IGNORED = set(BEHAVIOR_NEUTRAL_FIELDS)
TAG_ID_IGNORED = COMMON_IGNORED | {"tagId", "name"}
TAG_NORMALIZED_IGNORED = TAG_ID_IGNORED | {
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
    "monitoringMetadata",
    "monitoringMetadataTagNameKey",
    "consentSettings",
    "malwareDisabled",
}
TRIGGER_ID_IGNORED = COMMON_IGNORED | {"triggerId", "name"}
VARIABLE_ID_IGNORED = COMMON_IGNORED | {"variableId", "name"}

DESTINATION_KEY_RE = re.compile(
    r"(?:measurement|property|pixel|advertiser|conversion|destination|tag|account).*id$|"
    r"conversionlabel$|server_container_url$|transport_url$|endpoint$",
    re.I,
)
URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.I)
ALWAYS_TRUE_REGEX = {".*", "^.*$", ".+", "^.+$"}

# These rows are deterministic review obligations, not deterministic defects.
# A source-specific retained verdict is valid when the review proves that the
# visible distinction is intentional.
REVIEW_CANDIDATE_FINDING_TYPES = {
    "complex_trigger_candidate",
    "complex_zone_boundary_candidate",
    "duplicate_variable_path",
    "media_consent_route_requires_review",
    "normalized_duplicate_tag_signature",
    "same_contract_different_consent_control_candidate",
    "singleton_folder",
    "unicode_confusable_name_candidate",
    "unicode_name_integrity_candidate",
    "legacy_name_only_candidate",
    "universally_permissive_condition",
    "universally_permissive_zone_boundary",
}

# These findings depend on ownership or policy evidence that the export cannot
# decide. They may remain visible owner decisions with a concrete recommendation.
BUSINESS_DECISION_FINDING_TYPES = {
    "naming_policy_confirmation_required",
    "nested_trigger_groups",
    "paused_objects_for_lifecycle_review",
    # The export proves the condition, but not whether a paused implementation
    # is a retained rollback asset or how the analyst wants to organise the
    # surviving architecture. These must remain explicit, decision-ready work
    # rather than forcing an invented deletion or folder map.
    "used_only_by_paused_tags",
    "unfiled_objects",
    "overloaded_folder",
    "unbounded_zone_scope_review",
}


def operational_finding_class(finding_type: str) -> str:
    if finding_type in REVIEW_CANDIDATE_FINDING_TYPES:
        return "review_candidate"
    if finding_type in BUSINESS_DECISION_FINDING_TYPES:
        return "business_decision"
    return "deterministic_defect"
CONDITION_OPERATORS = {
    "EQUALS",
    "NOT_EQUALS",
    "CONTAINS",
    "DOES_NOT_CONTAIN",
    "STARTS_WITH",
    "ENDS_WITH",
    "MATCH_REGEX",
    "DOES_NOT_MATCH_REGEX",
    "GREATER_THAN",
    "LESS_THAN",
}


def canonical_unicode_text(value: str) -> str:
    normalized = unicodedata.normalize("NFKC", str(value or ""))
    normalized = "".join(
        " "
        if char == "\u00a0" or unicodedata.category(char) == "Zs"
        else ""
        if unicodedata.category(char) in {"Cc", "Cf"}
        else char
        for char in normalized
    )
    return re.sub(r"\s+", " ", normalized).strip()


def unicode_integrity_problems(value: str) -> list[str]:
    problems: list[str] = []
    categories = {unicodedata.category(char) for char in value}
    if any(category in {"Cc", "Cf"} for category in categories):
        problems.append("invisible/control Unicode character")
    if any(
        char != " " and (char == "\u00a0" or unicodedata.category(char) == "Zs")
        for char in value
    ):
        problems.append("non-standard Unicode whitespace")
    if unicodedata.normalize("NFKC", value) != value:
        problems.append("non-canonical Unicode form")
    return problems


def normalized_reference_name(value: str) -> str:
    return canonical_unicode_text(value).casefold()


def object_string_fields(
    cv: dict[str, Any], root_path: str
) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []

    def visit(
        value: Any,
        path: str,
        object_key_value: str,
    ) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                visit(child, f"{path}.{key}", object_key_value)
        elif isinstance(value, list):
            for index, child in enumerate(value):
                visit(child, f"{path}[{index}]", object_key_value)
        elif isinstance(value, str):
            rows.append(
                {
                    "object_key": object_key_value,
                    "json_path": path,
                    "value": value,
                }
            )

    for layer in SEMANTIC_LAYERS:
        for index, obj in enumerate(as_list(cv.get(layer))):
            visit(
                obj,
                f"{root_path}.{layer}[{index}]",
                f"{layer}:{object_id(obj, layer)}",
            )
    return rows


def reference_text_changes(
    cv: dict[str, Any],
    root_path: str,
    before_name: str,
    after_name: str,
    *,
    object_key_filter: set[str] | None = None,
) -> list[dict[str, Any]]:
    before_token = "{{" + before_name + "}}"
    after_token = "{{" + after_name + "}}"
    rows = []
    for fact in object_string_fields(cv, root_path):
        if object_key_filter and fact["object_key"] not in object_key_filter:
            continue
        before = fact["value"]
        after = before.replace(before_token, after_token)
        if after != before:
            rows.append(
                {
                    "object_key": fact["object_key"],
                    "json_path": fact["json_path"],
                    "before": before,
                    "after": after,
                }
            )
    return rows


def setup_reference_candidates(
    tags: list[dict[str, Any]],
    missing_name: str,
    consumer: dict[str, Any],
) -> list[dict[str, Any]]:
    target_norm = normalized_reference_name(missing_name)
    peer_usage: collections.Counter[str] = collections.Counter()
    consumer_type = str(consumer.get("type") or "")
    for tag in tags:
        if str(tag.get("type") or "") != consumer_type:
            continue
        for relation in ("setupTag", "teardownTag"):
            for item in as_list(tag.get(relation)):
                if isinstance(item, dict) and item.get("tagName"):
                    peer_usage[str(item.get("tagName"))] += 1
    rows = []
    for tag in tags:
        name = str(tag.get("name") or "")
        if not name:
            continue
        normalized = normalized_reference_name(name)
        score = difflib.SequenceMatcher(None, target_norm, normalized).ratio()
        if score < 0.55:
            continue
        rows.append(
            {
                "object_key": f"tag:{object_id(tag, 'tag')}",
                "object_name": name,
                "object_type": str(tag.get("type") or ""),
                "paused": bool(tag.get("paused")),
                "normalized_exact": normalized == target_norm,
                "name_similarity": round(score, 3),
                "same_consumer_tag_type": (
                    str(tag.get("type") or "") in {"googtag", consumer_type}
                ),
                "peer_sequence_consumers": peer_usage.get(name, 0),
            }
        )
    return sorted(
        rows,
        key=lambda row: (
            not row["normalized_exact"],
            -float(row["name_similarity"]),
            -int(row["peer_sequence_consumers"]),
            row["object_key"],
        ),
    )[:8]


def unique_setup_repair_candidate(
    candidates: list[dict[str, Any]],
) -> dict[str, Any] | None:
    if not candidates:
        return None
    exact = [row for row in candidates if row["normalized_exact"]]
    if len(exact) == 1:
        return exact[0]
    first = candidates[0]
    second_score = (
        float(candidates[1]["name_similarity"]) if len(candidates) > 1 else 0.0
    )
    if (
        float(first["name_similarity"]) >= 0.9
        and float(first["name_similarity"]) - second_score >= 0.08
        and first["same_consumer_tag_type"]
        and int(first["peer_sequence_consumers"]) >= 1
    ):
        return first
    return None


def signature(value: Any) -> str:
    return stable_hash(value)


def object_id(obj: dict[str, Any], layer: str) -> str:
    value = obj.get(ID_KEYS[layer]) or obj.get("name")
    return "" if value is None else str(value)


def object_name(obj: dict[str, Any]) -> str:
    return str(obj.get("name") or "")


def object_summary(obj: dict[str, Any], layer: str) -> dict[str, Any]:
    obj_type = str(obj.get("type") or ("customTemplate" if layer == "customTemplate" else ""))
    cfg_hash = signature(comparable(obj, COMMON_IGNORED))
    summary: dict[str, Any] = {
        "object_type": layer,
        "object_id": object_id(obj, layer),
        "object_name": object_name(obj),
        "type": obj_type,
        "config_hash": cfg_hash,
        "object_identity": "|".join(
            [layer, object_id(obj, layer), object_name(obj), obj_type, cfg_hash]
        ),
    }
    if layer == "tag":
        summary["paused"] = bool(obj.get("paused"))
    return summary


def code_value(obj: dict[str, Any]) -> str:
    value = param_value(obj, "html")
    if value is None:
        value = param_value(obj, "javascript")
    return "" if value is None else str(value)


def normalized_code(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def nested_parameter_pairs(value: Any) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    if isinstance(value, dict):
        key = str(value.get("key") or "")
        scalar = value.get("value")
        if key and scalar is not None and not isinstance(scalar, (dict, list)):
            pairs.append((key, str(scalar)))
        for child in value.values():
            pairs.extend(nested_parameter_pairs(child))
    elif isinstance(value, list):
        for child in value:
            pairs.extend(nested_parameter_pairs(child))
    return pairs


def condition_nodes(value: Any) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if isinstance(value, dict):
        operator = str(value.get("type") or "").upper()
        keys = {
            str(item.get("key") or "")
            for item in as_list(value.get("parameter"))
            if isinstance(item, dict)
        }
        if operator in CONDITION_OPERATORS and {"arg0", "arg1"}.issubset(keys):
            rows.append(value)
        for child in value.values():
            rows.extend(condition_nodes(child))
    elif isinstance(value, list):
        for child in value:
            rows.extend(condition_nodes(child))
    return rows


def condition_values(node: dict[str, Any]) -> tuple[str, str, str]:
    values = {
        str(item.get("key") or ""): str(item.get("value") or "")
        for item in as_list(node.get("parameter"))
        if isinstance(item, dict)
    }
    return str(node.get("type") or "").upper(), values.get("arg0", ""), values.get("arg1", "")


def normalized_condition(node: dict[str, Any]) -> str:
    operator, left, right = condition_values(node)
    if operator == "MATCH_REGEX":
        if right.startswith("^") and right.endswith("$"):
            inner = right[1:-1]
            if inner and not re.search(r"[.\\+*?\[\](){}|]", inner):
                operator, right = "EQUALS", inner
        elif right.startswith(".*") and right.endswith(".*"):
            inner = right[2:-2]
            if inner and not re.search(r"[.\\+*?\[\](){}|]", inner):
                operator, right = "CONTAINS", inner
    return "|".join([operator, left.strip(), right.strip()])


def exact_event_names(trigger: dict[str, Any]) -> set[str]:
    names: set[str] = set()
    for node in condition_nodes(trigger):
        operator, left, right = condition_values(node)
        if operator == "EQUALS" and left.strip() == "{{_event}}" and right.strip():
            names.add(right.strip())
    return names


UA_PROPERTY_RE = re.compile(r"\bUA-\d+(?:-\d+)+\b", re.I)
UA_TAG_PARAMETER_RE = re.compile(
    r"\b(?:trackingId|trackType|gaSettings|enableEcommerce|"
    r"enableEnhancedEcommerce|enhancedEcommerce|ecommerceMacroData)\b",
    re.I,
)
UA_LABEL_RE = re.compile(r"\b(?:UA|Universal Analytics|Enhanced Ecommerce)\b", re.I)
UA_ECOMMERCE_PATH_RE = re.compile(
    r"\becommerce\.(?:"
    r"purchase(?:\.(?:actionField|products)[A-Za-z0-9_\.\[\]]*)?|"
    r"add(?:\.products[A-Za-z0-9_\.\[\]]*)?|"
    r"remove(?:\.products[A-Za-z0-9_\.\[\]]*)?|"
    r"detail(?:\.products[A-Za-z0-9_\.\[\]]*)?|"
    r"checkout(?:\.(?:actionField|products)[A-Za-z0-9_\.\[\]]*)?|"
    r"impressions[A-Za-z0-9_\.\[\]]*|"
    r"currencyCode"
    r")",
    re.I,
)
FIXED_PRODUCT_INDEX_RE = re.compile(
    r"\becommerce\.(?:purchase|add|remove|detail|checkout)\.products"
    r"(?:\[\d+\]|\.\d+)(?:[A-Za-z0-9_\.\[\]]*)",
    re.I,
)
UA_STYLE_EVENT_RE = re.compile(
    r"(?<![A-Za-z0-9_])(?:"
    r"checkout_step(?:_\d+)?|checkoutOption|checkout_option|"
    r"productDetailImpression|purchaseImpression|productImpression|"
    r"productDetail|productClick|promotionClick|promotionView|"
    r"addToCart|removeFromCart"
    r")(?![A-Za-z0-9_])",
    re.I,
)

KNOWN_SCOPE_TOKENS = {
    "all",
    "eu",
    "fr",
    "de",
    "uk",
    "gb",
    "ch",
    "at",
    "be",
    "it",
    "nl",
    "us",
    "iggi",
    "aura",
    "smart",
    "boss",
    "brand",
    "branding",
}

KNOWN_EVENT_TOKENS = {
    "pageview",
    "page_view",
    "viewitem",
    "view_item",
    "viewcontent",
    "view_content",
    "viewitemlist",
    "view_item_list",
    "addtocart",
    "add_to_cart",
    "removefromcart",
    "remove_from_cart",
    "viewcart",
    "view_cart",
    "begincheckout",
    "begin_checkout",
    "checkout",
    "addshippinginfo",
    "add_shipping_info",
    "addpaymentinfo",
    "add_payment_info",
    "purchase",
    "login",
    "newsletter",
    "refer",
    "magazine",
    "contact",
    "formsubmit",
    "form_submit",
    "click",
    "linkclick",
    "link_click",
    "conversionlinker",
    "conversion_linker",
    "remarketing",
    "base",
    "insight",
    "popups",
}

VENDOR_ALIASES = {
    "google analytics 4": "GA4",
    "google ads": "GADS",
    "piano analytics": "PA",
    "tradedoubler": "TD",
    "the trade desk": "TTD",
    "display & video 360": "DV360",
    "display and video 360": "DV360",
    "facebook": "Meta",
    "meta": "Meta",
    "tiktok": "TikTok",
    "teads": "Teads",
    "amazon": "Amazon",
    "bing": "Bing",
    "linkedin": "LinkedIn",
    "pinterest": "Pinterest",
    "realytics": "Realytics",
    "poptin": "Poptin",
}

TRIGGER_PREFIX_BY_TYPE = {
    "CUSTOM_EVENT": "CE",
    "PAGEVIEW": "PV",
    "LINK_CLICK": "LC",
    "FORM_SUBMISSION": "FORM",
    "TRIGGER_GROUP": "TG",
}

VARIABLE_PREFIX_BY_TYPE = {
    "v": "DLV",
    "jsm": "CJS",
    "smm": "LT",
    "remm": "RT",
    "u": "URL",
    "c": "Const",
}


def short_matches(pattern: re.Pattern[str], text: str, limit: int = 8) -> list[str]:
    matches = sorted({match.group(0) for match in pattern.finditer(text)})
    return matches[:limit]


def name_parts(name: str) -> list[str]:
    return [part.strip() for part in name.split(" - ") if part.strip()]


def token(value: str) -> str:
    return re.sub(r"[^a-z0-9_]+", "", value.lower().replace(" ", "_"))


def is_scope_token(value: str) -> bool:
    parts = re.split(r"[\s_/().-]+", value.lower())
    return any(part in KNOWN_SCOPE_TOKENS for part in parts if part)


def is_event_token(value: str) -> bool:
    compact = token(value).replace("_", "")
    normalized = token(value)
    return normalized in KNOWN_EVENT_TOKENS or compact in {
        item.replace("_", "") for item in KNOWN_EVENT_TOKENS
    }

def vendor_label(value: str) -> str:
    cleaned = re.sub(r"\s+", " ", value.strip())
    normalized = cleaned.lower()
    if normalized in VENDOR_ALIASES:
        return VENDOR_ALIASES[normalized]
    if re.fullmatch(r"[A-Z0-9&]{2,8}", cleaned):
        return cleaned
    return cleaned


def strip_known_prefix(name: str, prefixes: set[str]) -> str:
    for prefix in sorted(prefixes, key=len, reverse=True):
        marker = f"{prefix} - "
        if name.startswith(marker):
            return name[len(marker) :].strip()
    return name.strip()


def proposed_tag_name(name: str, tag_order: str, selected_policy: str) -> tuple[str, str]:
    parts = name_parts(name)
    target_local_scope_event = (
        selected_policy == "local-normalized" and tag_order == "vendor_scope_event"
    )
    if len(parts) < 3:
        return (
            "",
            "Tag name does not contain enough vendor/event/scope tokens to propose a safe final name.",
        )
    vendor = vendor_label(parts[0])
    if target_local_scope_event:
        scope, event = parts[1], parts[2]
        proposed = f"{vendor} - {scope} - {event}"
        if not is_scope_token(scope) or not is_event_token(event):
            return proposed, "Existing tokens do not clearly prove local scope/event meaning."
        return proposed, ""
    event, scope = parts[1], parts[2]
    proposed = f"{vendor} - {event} - {scope}"
    if not is_event_token(event) or not is_scope_token(scope):
        return proposed, "Existing tokens do not clearly prove default event/scope meaning."
    return proposed, ""


def proposed_trigger_name(trigger: dict[str, Any], prefix: str) -> str:
    base = strip_known_prefix(
        object_name(trigger), set(TRIGGER_PREFIX_BY_TYPE.values()) | {"Block"}
    )
    return f"{prefix} - {base}" if base else ""


def proposed_variable_name(variable: dict[str, Any], prefix: str) -> str:
    base = strip_known_prefix(
        object_name(variable), set(VARIABLE_PREFIX_BY_TYPE.values()) | {"Util"}
    )
    return f"{prefix} - {base}" if base else ""


def proposed_folder_name(folder: dict[str, Any]) -> tuple[str, str]:
    parts = name_parts(object_name(folder))
    if not parts:
        return "", "Folder name has no usable area token."
    return parts[0], ""


def uniqueness_notes(candidates: dict[str, collections.Counter[str]], layer: str, name: str) -> str:
    if not name:
        return "No proposed final name."
    if candidates.get(layer, collections.Counter())[name] > 1:
        return "Proposed final name is not unique inside this GTM layer; add a scope token after owner confirmation."
    return ""


def infer_tag_order(tags: list[dict[str, Any]]) -> dict[str, Any]:
    counts: collections.Counter[str] = collections.Counter()
    examples: dict[str, list[str]] = collections.defaultdict(list)
    for tag in tags:
        parts = name_parts(object_name(tag))
        if len(parts) < 3:
            continue
        second_is_event = is_event_token(parts[1])
        third_is_event = is_event_token(parts[2])
        second_is_scope = is_scope_token(parts[1])
        third_is_scope = is_scope_token(parts[2])
        if second_is_event and third_is_scope:
            key = "vendor_event_scope"
        elif second_is_scope and third_is_event:
            key = "vendor_scope_event"
        else:
            key = "ambiguous"
        counts[key] += 1
        if len(examples[key]) < 5:
            examples[key].append(object_name(tag))

    total = sum(counts.values())
    if not total:
        return {
            "selected_policy": "default-standardized",
            "tag_order": "vendor_event_scope",
            "confidence": "low",
            "reason": "No dominant three-part tag naming pattern was detected.",
            "examples": {},
        }

    winner, winner_count = counts.most_common(1)[0]
    ratio = winner_count / total
    if winner in {"vendor_event_scope", "vendor_scope_event"} and ratio >= 0.6:
        return {
            "selected_policy": "local-normalized",
            "tag_order": winner,
            "confidence": "high" if ratio >= 0.75 else "medium",
            "reason": (
                f"{winner_count}/{total} parsable three-part tag names follow "
                f"{winner.replace('_', ' - ')} order."
            ),
            "examples": dict(examples),
        }
    return {
        "selected_policy": "default-standardized",
        "tag_order": "vendor_event_scope",
        "confidence": "medium" if ratio >= 0.45 else "low",
        "reason": "No reliable local tag naming order dominates the export.",
        "examples": dict(examples),
    }


def default_tag_issue(name: str, tag_order: str) -> str:
    parts = name_parts(name)
    if len(parts) < 3:
        return "tag name is not structured as Vendor - Event - Scope or a reliable local equivalent"
    if tag_order == "vendor_scope_event":
        if not is_scope_token(parts[1]) or not is_event_token(parts[2]):
            return "tag name does not match the detected local Vendor - Scope - Event order"
        return ""
    if not is_event_token(parts[1]) or not is_scope_token(parts[2]):
        return "tag name does not match the default Vendor - Event - Scope order"
    return ""


def trigger_required_prefix(trigger: dict[str, Any], blocking_trigger_ids: set[str]) -> str:
    trigger_id = str(trigger.get("triggerId") or "")
    if trigger_id in blocking_trigger_ids:
        return "Block"
    return TRIGGER_PREFIX_BY_TYPE.get(str(trigger.get("type") or ""), "")


def variable_required_prefix(variable: dict[str, Any]) -> str:
    return VARIABLE_PREFIX_BY_TYPE.get(str(variable.get("type") or ""), "")


def recognized_system_references(
    variable_consumers: dict[str, list[dict[str, str]]],
    trigger_consumers: dict[str, list[dict[str, str]]],
) -> dict[str, list[dict[str, Any]]]:
    return {
        "variable_references": [
            {
                "reference": ref,
                "description": system_reference_description("variable", ref),
                "consumers": consumers,
            }
            for ref, consumers in sorted(variable_consumers.items())
            if is_system_variable_reference(ref)
        ],
        "trigger_references": [
            {
                "reference": ref,
                "description": system_reference_description("trigger", ref),
                "consumers": consumers,
            }
            for ref, consumers in sorted(trigger_consumers.items())
            if is_system_trigger_reference(ref)
        ],
    }


def ua_style_signals(layer: str, obj: dict[str, Any]) -> list[str]:
    text = stable_payload(obj)
    name = object_name(obj)
    signals: list[str] = []
    tag_type = str(obj.get("type") or "").lower()

    if layer == "tag" and tag_type == "ua":
        signals.append("native Universal Analytics tag type")
    if layer == "tag" and tag_type == "ua" and UA_TAG_PARAMETER_RE.search(text):
        signals.append("Universal Analytics tag parameters")
    if UA_PROPERTY_RE.search(text):
        signals.append("UA property ID")
    if UA_LABEL_RE.search(name):
        signals.append("object name says UA, Universal Analytics, or Enhanced Ecommerce")

    old_paths = short_matches(UA_ECOMMERCE_PATH_RE, text)
    if old_paths:
        signals.append("old Universal Analytics ecommerce path(s): " + ", ".join(old_paths))

    fixed_indexes = short_matches(FIXED_PRODUCT_INDEX_RE, text)
    if fixed_indexes:
        signals.append("fixed product position path(s): " + ", ".join(fixed_indexes))

    legacy_events = short_matches(UA_STYLE_EVENT_RE, text)
    if legacy_events and signals:
        signals.append("legacy checkout/product event name(s): " + ", ".join(legacy_events))

    return signals


def add_ua_styled_setup_findings(
    builder: BaselineBuilder,
    tags: list[dict[str, Any]],
    triggers: list[dict[str, Any]],
    variables: list[dict[str, Any]],
    variable_consumers: dict[str, list[dict[str, Any]]],
    trigger_consumers: dict[str, list[dict[str, Any]]],
    root_path: str,
) -> None:
    module_name = "outdated_ua_styled_setup_objects"
    builder.add_module(module_name, len(tags) + len(triggers) + len(variables))
    existing_names = {
        layer: {
            str(item.get("name") or "").casefold()
            for item in items
            if str(item.get("name") or "")
        }
        for layer, items in (
            ("tag", tags),
            ("trigger", triggers),
            ("variable", variables),
        )
    }
    for layer, items in (("tag", tags), ("trigger", triggers), ("variable", variables)):
        for item_index, item in enumerate(items):
            signals = ua_style_signals(layer, item)
            if not signals:
                continue
            name_only = signals == [
                "object name says UA, Universal Analytics, or Enhanced Ecommerce"
            ]
            consumers = (
                variable_consumers.get(str(item.get("name") or ""), [])
                if layer == "variable"
                else trigger_consumers.get(str(item.get("triggerId") or ""), [])
                if layer == "trigger"
                else []
            )
            tag_by_id = {
                str(tag.get("tagId") or ""): tag for tag in tags
            }
            consumer_evidence = []
            for consumer in consumers:
                consumer_key = (
                    f"{consumer.get('object_type')}:{consumer.get('object_id')}"
                )
                source_tag = tag_by_id.get(str(consumer.get("object_id") or ""))
                consumer_evidence.append(
                    {
                        "object_key": consumer_key,
                        "object_name": str(consumer.get("object_name") or ""),
                        "object_type": (
                            str(source_tag.get("type") or "")
                            if source_tag
                            else str(consumer.get("object_type") or "")
                        ),
                        "destination_vendor": (
                            detect_vendor_text(
                                behavior_bearing_vendor_text(source_tag, "tag")
                            )[0]
                            if source_tag
                            else "Unclassified"
                        ),
                    }
                )
            current_name = str(item.get("name") or "")
            proposed_name = UA_LABEL_RE.sub("", current_name)
            proposed_name = re.sub(r"\(\s*\)|\[\s*\]", "", proposed_name)
            proposed_name = re.sub(
                r"(?:\s*[-\u2013\u2014|:]\s*){2,}", " - ", proposed_name
            )
            proposed_name = proposed_name.strip()
            proposed_name = re.sub(
                r"^(?:[-\u2013\u2014|:]\s*)+|(?:\s*[-\u2013\u2014|:])+$",
                "",
                proposed_name,
            )
            proposed_name = re.sub(r"\s{2,}", " ", proposed_name).strip()
            only_current_ga4_consumers = bool(consumer_evidence) and all(
                str(consumer.get("object_type") or "").lower() == "gaawe"
                or consumer.get("destination_vendor") == "GA4 / Google tag"
                for consumer in consumer_evidence
            )
            unique_proposed_name = bool(proposed_name) and (
                proposed_name.casefold() == current_name.casefold()
                or proposed_name.casefold() not in existing_names[layer]
            )
            deterministic_label_repair = (
                layer == "trigger"
                and name_only
                and only_current_ga4_consumers
                and proposed_name != current_name
                and unique_proposed_name
            )
            repair = {
                "status": (
                    "unique_ga4_label_cleanup"
                    if deterministic_label_repair
                    else "no_unique_container_target"
                ),
                "repair_kind": "object_name",
                "target_object_key": f"{layer}:{object_id(item, layer)}",
                "target_name": proposed_name if deterministic_label_repair else "",
                "changes": [],
                "renames": (
                    [
                        {
                            "object_key": f"{layer}:{object_id(item, layer)}",
                            "before": current_name,
                            "after": proposed_name,
                        }
                    ]
                    if deterministic_label_repair
                    else []
                ),
                "source_name_json_path": (
                    f"{root_path}.{layer}[{item_index}].name"
                    if deterministic_label_repair
                    else ""
                ),
            }
            builder.add_finding(
                module_name,
                (
                    "legacy_name_only_candidate"
                    if name_only
                    else "outdated_ua_styled_setup_object"
                ),
                layer,
                [object_summary(item, layer)],
                f"{layer}:{object_id(item, layer)}",
                (
                    "The object name contains a UA/Universal Analytics label, but the "
                    "exported object itself has no native UA type, UA property ID, or "
                    "old ecommerce path. Consuming routes are "
                    f"{consumer_evidence!r}."
                    if name_only
                    else "This object has legacy Universal Analytics-style setup signals: "
                    + "; ".join(signals)
                    + "."
                ),
                (
                    (
                        f"Rename {layer}:{object_id(item, layer)} from "
                        f"{current_name!r} to {proposed_name!r}; every visible consumer "
                        "is a current GA4 route, so the UA label is metadata-only."
                    )
                    if deterministic_label_repair
                    else "Judge the consuming tag type and destination before renaming; do not "
                    "classify this object as legacy from its label alone."
                    if name_only
                    else "Confirm whether the object is still needed. If it feeds current "
                    "GA4 or vendor tracking, migrate it to the current event/item data "
                    "format or document a legacy exception supported by container evidence."
                ),
                (
                    "cleanup_operation | documented_exception"
                    if deterministic_label_repair
                    else "cleanup_operation | documented_exception | "
                    "owner_decision_needed | keep"
                ),
                extra={
                    "consumer_route_evidence": consumer_evidence,
                    "deterministic_repair": repair,
                    "repair_affected_object_keys": (
                        [f"{layer}:{object_id(item, layer)}"]
                        if deterministic_label_repair
                        else []
                    ),
                    **(
                        {
                            "finding_class": "deterministic_defect",
                            "deterministic_action_candidate": "rename_candidate",
                        }
                        if deterministic_label_repair
                        else {}
                    ),
                },
            )


def deterministic_action_candidate(finding_type: str, default_action: str) -> str:
    text = f"{finding_type} {default_action}".lower()
    if "missing" in text or "resolve reference" in text or "triggerless" in text:
        return "fix_required"
    if "unused" in text or "delete candidate" in text:
        return "delete_candidate"
    if "duplicate" in text or "consolidate" in text or "canonical" in text:
        return "consolidate_candidate"
    if "name" in text or "rename" in text or "naming" in text:
        return "rename_candidate"
    if "universal analytics" in text or "legacy" in text or "ecommerce" in text:
        return "fix_required"
    return "owner_decision_needed"


class BaselineBuilder:
    def __init__(self) -> None:
        self.findings: list[dict[str, Any]] = []
        self.modules: dict[str, dict[str, Any]] = {}
        self.counters: collections.Counter[str] = collections.Counter()

    def _next_id(self, module_name: str) -> str:
        self.counters[module_name] += 1
        slug = re.sub(r"[^A-Z0-9]+", "_", module_name.upper()).strip("_")[:28]
        return f"BASE-{slug}-{self.counters[module_name]:03d}"

    def add_module(self, module_name: str, objects_scanned: int) -> None:
        self.modules[module_name] = {
            "module_name": module_name,
            "module_status": "pending",
            "objects_scanned": objects_scanned,
            "findings_count": 0,
        }

    def add_finding(
        self,
        module_name: str,
        finding_type: str,
        object_type: str,
        objects: list[dict[str, Any]],
        signature_key: str,
        deterministic_evidence: str,
        default_action: str,
        required_resolution: str = (
            "cleanup_operation | documented_exception | owner_decision_needed"
        ),
        extra: dict[str, Any] | None = None,
    ) -> None:
        module = self.modules[module_name]
        module["findings_count"] += 1
        module["module_status"] = "findings"
        finding_class = operational_finding_class(finding_type)
        if finding_class == "review_candidate" and "keep" not in {
            value.strip() for value in required_resolution.split("|")
        }:
            required_resolution = required_resolution + " | keep"
        row = {
            "module_name": module_name,
            "module_status": "findings",
            "objects_scanned": module["objects_scanned"],
            "finding_id": self._next_id(module_name),
            "finding_type": finding_type,
            "object_type": object_type,
            "object_ids": [obj.get("object_id", "") for obj in objects],
            "object_names": [obj.get("object_name", "") for obj in objects],
            "signature_key": signature_key,
            "deterministic_evidence": deterministic_evidence,
            "default_action": default_action,
            "source_lens": "deterministic",
            "finding_class": finding_class,
            "deterministic_action_candidate": deterministic_action_candidate(
                finding_type, default_action
            ),
            "object_identities": [
                obj.get("object_identity", "") for obj in objects if obj.get("object_identity")
            ],
            "operation_packet_required": True,
            "required_resolution": required_resolution,
        }
        if extra:
            row.update(extra)
        self.findings.append(row)

    def close_zero_modules(self) -> None:
        for module_name, module in self.modules.items():
            if module["findings_count"]:
                continue
            module["module_status"] = "zero_findings"
            self.findings.append(
                {
                    "module_name": module_name,
                    "module_status": "zero_findings",
                    "objects_scanned": module["objects_scanned"],
                    "finding_id": f"BASE-{re.sub(r'[^A-Z0-9]+', '_', module_name.upper()).strip('_')[:28]}-000",
                    "finding_type": "zero_findings",
                    "object_type": "module",
                    "object_ids": [],
                    "object_names": [],
                    "signature_key": "",
                    "deterministic_evidence": (
                        f"No deterministic findings produced by module {module_name} "
                        f"after scanning {module['objects_scanned']} object(s)."
                    ),
                    "default_action": "No cleanup action from this module.",
                    "source_lens": "deterministic",
                    "finding_class": "zero_result",
                    "deterministic_action_candidate": "not_applicable",
                    "object_identities": [],
                    "operation_packet_required": False,
                    "required_resolution": "not_applicable",
                }
            )


def group_by(items: list[dict[str, Any]], key_fn) -> dict[str, list[dict[str, Any]]]:
    groups: dict[str, list[dict[str, Any]]] = collections.defaultdict(list)
    for item in items:
        key = key_fn(item)
        if key:
            groups[str(key)].append(item)
    return dict(groups)


def add_duplicate_name_findings(
    builder: BaselineBuilder, module_name: str, layer: str, items: list[dict[str, Any]]
) -> None:
    builder.add_module(module_name, len(items))
    for name, group in sorted(group_by(items, object_name).items()):
        if len(group) < 2:
            continue
        builder.add_finding(
            module_name,
            "duplicate_name",
            layer,
            [object_summary(obj, layer) for obj in group],
            f"name:{name}",
            f"{len(group)} {layer} objects share the exact name {name!r}.",
            "Resolve naming ambiguity or document why identical names are intentional.",
        )


def add_signature_findings(
    builder: BaselineBuilder,
    module_name: str,
    finding_type: str,
    layer: str,
    items: list[dict[str, Any]],
    ignored: set[str],
    default_action: str,
) -> None:
    builder.add_module(module_name, len(items))
    groups = group_by(items, lambda obj: signature(comparable(obj, ignored)))
    for sig, group in sorted(groups.items()):
        if len(group) < 2:
            continue
        extra: dict[str, Any] = {}
        evidence = f"{len(group)} {layer} objects share deterministic signature {sig}."
        if layer == "trigger":
            shared_conditions = sorted(
                {
                    normalized_condition(node)
                    for node in condition_nodes(group[0])
                    if normalized_condition(node)
                }
            )
            if shared_conditions:
                extra["shared_normalized_conditions"] = shared_conditions
                evidence += f" Shared normalized conditions are {shared_conditions!r}."
        builder.add_finding(
            module_name,
            finding_type,
            layer,
            [object_summary(obj, layer) for obj in group],
            sig,
            evidence,
            default_action,
            extra=extra,
        )


def build_consumers(
    cv: dict[str, Any],
) -> tuple[
    dict[str, list[dict[str, Any]]],
    dict[str, list[dict[str, Any]]],
    dict[str, list[dict[str, Any]]],
]:
    variable_consumers: dict[str, list[dict[str, Any]]] = collections.defaultdict(list)
    trigger_consumers: dict[str, list[dict[str, Any]]] = collections.defaultdict(list)
    tag_consumers: dict[str, list[dict[str, Any]]] = collections.defaultdict(list)

    for layer in SEMANTIC_LAYERS:
        for obj in as_list(cv.get(layer)):
            for ref in sorted(refs(obj)):
                if layer == "variable" and ref == obj.get("name"):
                    continue
                variable_consumers[ref].append(object_summary(obj, layer))

    for tag in as_list(cv.get("tag")):
        summary = object_summary(tag, "tag")
        for trigger_id in as_list(tag.get("firingTriggerId")) + as_list(
            tag.get("blockingTriggerId")
        ):
            trigger_consumers[str(trigger_id)].append(summary)
        for relation in ("setupTag", "teardownTag"):
            for linked in as_list(tag.get(relation)):
                if not isinstance(linked, dict):
                    continue
                tag_name = str(linked.get("tagName") or "")
                if tag_name:
                    tag_consumers[tag_name].append({**summary, "consumer_relation": relation})

    for trigger in as_list(cv.get("trigger")):
        for member_id in trigger_group_members(trigger):
            trigger_consumers[str(member_id)].append(object_summary(trigger, "trigger"))

    for zone in as_list(cv.get("zone")):
        boundary = zone.get("boundary") if isinstance(zone.get("boundary"), dict) else {}
        for trigger_id in as_list(boundary.get("customEvaluationTriggerId")):
            trigger_consumers[str(trigger_id)].append(object_summary(zone, "zone"))

    return dict(variable_consumers), dict(trigger_consumers), dict(tag_consumers)


def build_execution_reachability(cv: dict[str, Any]) -> dict[str, Any]:
    """Resolve active and paused-only dependency subgraphs from configured roots."""
    records = {
        layer: as_list(cv.get(layer))
        for layer in (*SEMANTIC_LAYERS, "builtInVariable")
    }
    variable_keys: dict[str, list[str]] = collections.defaultdict(list)
    trigger_keys: dict[str, list[str]] = collections.defaultdict(list)
    tag_keys: dict[str, list[str]] = collections.defaultdict(list)
    template_keys: dict[str, list[str]] = collections.defaultdict(list)
    paused_tag_keys: set[str] = set()
    template_type_index = custom_template_type_index(records["customTemplate"])

    for layer, items in records.items():
        for obj in items:
            key = f"{layer}:{object_id(obj, layer)}"
            if layer in {"variable", "builtInVariable"}:
                names = (
                    builtin_reference_names(obj)
                    if layer == "builtInVariable"
                    else {object_name(obj)}
                )
                for name in names:
                    variable_keys[name].append(key)
                    normalized_name = normalized_reference_name(name)
                    if normalized_name and normalized_name != name:
                        variable_keys[normalized_name].append(key)
            elif layer == "trigger":
                trigger_keys[object_id(obj, layer)].append(key)
            elif layer == "tag":
                tag_keys[object_name(obj)].append(key)
                if obj.get("paused"):
                    paused_tag_keys.add(key)
            elif layer == "customTemplate":
                template_keys[object_id(obj, layer)].append(key)

    dependencies: dict[str, set[str]] = collections.defaultdict(set)
    for layer, items in records.items():
        for obj in items:
            source_key = f"{layer}:{object_id(obj, layer)}"
            for reference in refs(obj):
                dependencies[source_key].update(variable_keys.get(reference, []))
                # Resolve Unicode/whitespace variants conservatively for
                # reachability while retaining the exact unresolved reference
                # finding above.  If normalization is ambiguous, all matching
                # targets remain reachable, preventing unsafe deletion.
                dependencies[source_key].update(
                    variable_keys.get(normalized_reference_name(reference), [])
                )
            if layer == "tag":
                for trigger_id in as_list(obj.get("firingTriggerId")) + as_list(
                    obj.get("blockingTriggerId")
                ):
                    dependencies[source_key].update(trigger_keys.get(str(trigger_id), []))
                for relation in ("setupTag", "teardownTag"):
                    for sequence in as_list(obj.get(relation)):
                        if isinstance(sequence, dict):
                            dependencies[source_key].update(
                                tag_keys.get(str(sequence.get("tagName") or ""), [])
                            )
            elif layer == "trigger":
                for trigger_id in trigger_group_members(obj):
                    dependencies[source_key].update(trigger_keys.get(str(trigger_id), []))
            elif layer == "zone":
                boundary = obj.get("boundary")
                if isinstance(boundary, dict):
                    for trigger_id in as_list(boundary.get("customEvaluationTriggerId")):
                        dependencies[source_key].update(trigger_keys.get(str(trigger_id), []))
            for template_id in custom_template_ids(obj, template_type_index):
                dependencies[source_key].update(template_keys.get(template_id, []))

    configured_roots = {
        f"{layer}:{object_id(obj, layer)}"
        for layer in ("zone", "client", "gtagConfig", "transformation")
        for obj in records[layer]
    }
    active_tag_roots = {
        f"tag:{object_id(tag, 'tag')}"
        for tag in records["tag"]
        if not tag.get("paused") and bool(as_list(tag.get("firingTriggerId")))
    }

    def reachable(roots: set[str], blocked: set[str] | None = None) -> set[str]:
        blocked = blocked or set()
        visited: set[str] = set()
        queue = sorted(roots - blocked)
        while queue:
            current = queue.pop(0)
            if current in visited:
                continue
            visited.add(current)
            queue.extend(
                sorted(dependencies.get(current, set()) - visited - blocked - set(queue))
            )
        return visited

    active = reachable(active_tag_roots | configured_roots, paused_tag_keys)
    paused = reachable(paused_tag_keys) - active
    return {
        "active_root_keys": sorted(active_tag_roots | configured_roots),
        "paused_root_keys": sorted(paused_tag_keys),
        "active_object_keys": sorted(active),
        "paused_only_object_keys": sorted(paused),
        "dependency_edges": [
            {"from_object_key": source, "to_object_key": target}
            for source, targets in sorted(dependencies.items())
            for target in sorted(targets)
        ],
    }


def consumer_activity(consumers: list[dict[str, Any]]) -> tuple[int, int]:
    active = 0
    paused = 0
    for consumer in consumers:
        if consumer.get("object_type") == "tag" and consumer.get("paused"):
            paused += 1
        else:
            active += 1
    return active, paused


def build_lifecycle_matrix(
    cv: dict[str, Any],
    variable_consumers: dict[str, list[dict[str, Any]]],
    trigger_consumers: dict[str, list[dict[str, Any]]],
    tag_consumers: dict[str, list[dict[str, Any]]],
    reachability: dict[str, Any],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    layer_items = (
        ("tag", as_list(cv.get("tag"))),
        ("trigger", as_list(cv.get("trigger"))),
        ("variable", as_list(cv.get("variable"))),
        ("builtInVariable", as_list(cv.get("builtInVariable"))),
        ("zone", as_list(cv.get("zone"))),
        ("customTemplate", as_list(cv.get("customTemplate"))),
        ("folder", as_list(cv.get("folder"))),
        ("client", as_list(cv.get("client"))),
        ("gtagConfig", as_list(cv.get("gtagConfig"))),
        ("transformation", as_list(cv.get("transformation"))),
    )
    template_consumers: dict[str, list[dict[str, Any]]] = collections.defaultdict(list)
    folder_consumers: dict[str, list[dict[str, Any]]] = collections.defaultdict(list)
    active_keys = set(as_list(reachability.get("active_object_keys")))
    paused_only_keys = set(as_list(reachability.get("paused_only_object_keys")))
    active_roots = set(as_list(reachability.get("active_root_keys")))
    template_type_index = custom_template_type_index(
        as_list(cv.get("customTemplate"))
    )
    normalized_variable_consumers: dict[str, list[dict[str, Any]]] = collections.defaultdict(list)
    for reference, reference_consumers in variable_consumers.items():
        normalized_reference = normalized_reference_name(reference)
        if not normalized_reference or normalized_reference == reference:
            continue
        normalized_variable_consumers[normalized_reference].extend(reference_consumers)
    for layer, items in layer_items:
        if layer in {"customTemplate", "folder"}:
            continue
        for obj in items:
            summary = object_summary(obj, layer)
            for template_id in custom_template_ids(obj, template_type_index):
                template_consumers[template_id].append(summary)
            folder_id = obj.get("parentFolderId")
            if folder_id:
                folder_consumers[str(folder_id)].append(summary)

    for layer, items in layer_items:
        for obj in items:
            oid = object_id(obj, layer)
            current_key = f"{layer}:{oid}"
            if layer == "tag":
                consumers = tag_consumers.get(object_name(obj), [])
                paused_state = bool(obj.get("paused"))
                if paused_state:
                    usage = "paused"
                elif current_key in active_roots:
                    usage = "active_direct"
                elif current_key in active_keys:
                    usage = "active_sequenced"
                else:
                    usage = "active_without_route"
            elif layer == "trigger":
                consumers = trigger_consumers.get(oid, [])
                usage = (
                    "used"
                    if current_key in active_keys
                    else "used_only_by_paused_tags"
                    if current_key in paused_only_keys
                    else "unreferenced"
                )
            elif layer in {"variable", "builtInVariable"}:
                consumers = variable_consumers.get(object_name(obj), [])
                # A malformed Unicode/whitespace reference remains separately
                # reported by the exact missing-reference scan, while its
                # normalized consumer keeps the canonical target out of an
                # unsafe unused/deletion candidate.
                normalized_consumers = normalized_variable_consumers.get(
                    normalized_reference_name(object_name(obj)), []
                )
                if normalized_consumers:
                    consumers = list(consumers)
                    for consumer in normalized_consumers:
                        if consumer not in consumers:
                            consumers.append(consumer)
                usage = (
                    "used"
                    if current_key in active_keys
                    else "used_only_by_paused_tags"
                    if current_key in paused_only_keys
                    else "unreferenced"
                )
            elif layer == "customTemplate":
                consumers = template_consumers.get(oid, [])
                usage = (
                    "used"
                    if current_key in active_keys
                    else "used_only_by_paused_tags"
                    if current_key in paused_only_keys
                    else "unreferenced"
                )
            elif layer == "folder":
                consumers = folder_consumers.get(oid, [])
                member_keys = {
                    f"{item.get('object_type')}:{item.get('object_id')}" for item in consumers
                }
                usage = (
                    "used"
                    if member_keys & active_keys
                    else "used_only_by_paused_tags"
                    if member_keys & paused_only_keys
                    else "unreferenced"
                )
            else:
                consumers = []
                usage = "configured_root"

            active_count, paused_count = consumer_activity(consumers)
            if consumers and active_count == 0 and paused_count:
                usage = "used_only_by_paused_tags"
            rows.append(
                {
                    "object_key": current_key,
                    "layer": layer,
                    "object_id": oid,
                    "object_name": object_name(obj),
                    "paused": bool(obj.get("paused")) if layer == "tag" else False,
                    "usage_state": usage,
                    "consumer_count": len(consumers),
                    "active_consumer_count": active_count,
                    "paused_consumer_count": paused_count,
                    "consumer_keys": [
                        f"{item.get('object_type')}:{item.get('object_id')}" for item in consumers
                    ],
                }
            )
    return rows


def build_folder_topology(cv: dict[str, Any]) -> dict[str, Any]:
    folders = as_list(cv.get("folder"))
    layers = ("tag", "trigger", "variable", "client", "transformation")
    contents: dict[str, list[str]] = collections.defaultdict(list)
    unfiled: list[dict[str, str]] = []
    for layer in layers:
        for obj in as_list(cv.get(layer)):
            folder_id = obj.get("parentFolderId")
            if folder_id:
                contents[str(folder_id)].append(f"{layer}:{object_id(obj, layer)}")
            else:
                unfiled.append(
                    {
                        "object_key": f"{layer}:{object_id(obj, layer)}",
                        "object_name": object_name(obj),
                    }
                )
    folder_rows = []
    for folder in folders:
        folder_id = object_id(folder, "folder")
        members = contents.get(folder_id, [])
        folder_rows.append(
            {
                "folder_id": folder_id,
                "folder_name": object_name(folder),
                "member_count": len(members),
                "members": members,
                "topology_state": (
                    "empty"
                    if not members
                    else "singleton"
                    if len(members) == 1
                    else "overloaded"
                    if len(members) > 40
                    else "normal"
                ),
            }
        )
    return {"folders": folder_rows, "unfiled_objects": unfiled}


def build_destination_matrix(cv: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for layer in ("tag", "gtagConfig"):
        for obj in as_list(cv.get(layer)):
            behavior = behavior_projection(obj)
            pairs = nested_parameter_pairs(behavior.get("parameter", []))
            destinations = [
                {"field": key, "value": value}
                for key, value in pairs
                if DESTINATION_KEY_RE.search(key) and value.strip()
            ]
            urls = sorted(
                set(URL_RE.findall(code_value(behavior) + " " + stable_payload(behavior)))
            )
            vendor, category = detect_vendor_text(
                behavior_bearing_vendor_text(obj, layer)
            )
            rows.append(
                {
                    "object_key": f"{layer}:{object_id(obj, layer)}",
                    "object_layer": layer,
                    "object_name": object_name(obj),
                    "tag_name": object_name(obj) if layer == "tag" else "",
                    "paused": bool(obj.get("paused")) if layer == "tag" else False,
                    "vendor": vendor,
                    "vendor_category": category,
                    "destination_fields": destinations,
                    "configured_endpoints": urls,
                }
            )
    return rows


def add_lifecycle_findings(builder: BaselineBuilder, lifecycle: list[dict[str, Any]]) -> None:
    paused_tags = [row for row in lifecycle if row["layer"] == "tag" and row.get("paused")]
    builder.add_module("paused_tags", len(lifecycle))
    if paused_tags:
        builder.add_finding(
            "paused_tags",
            "paused_objects_for_lifecycle_review",
            "tag",
            [
                {
                    "object_id": row["object_id"],
                    "object_name": row["object_name"],
                }
                for row in paused_tags
            ],
            "paused_tags:" + ",".join(sorted(row["object_id"] for row in paused_tags)),
            f"{len(paused_tags)} tags are paused and remain part of the maintained container.",
            "Confirm rollback or migration purpose; retain documented exceptions and delete obsolete paused tags with their newly orphaned dependencies.",
            "owner_decision_needed | cleanup_operation | documented_exception",
        )

    candidates = [
        row
        for row in lifecycle
        if row["usage_state"] == "used_only_by_paused_tags"
        and row["layer"]
        in {"trigger", "variable", "builtInVariable", "customTemplate", "folder"}
    ]
    builder.add_module("used_only_by_paused_tags", len(lifecycle))
    for row in candidates:
        builder.add_finding(
            "used_only_by_paused_tags",
            "used_only_by_paused_tags",
            row["layer"],
            [
                {
                    "object_id": row["object_id"],
                    "object_name": row["object_name"],
                    "object_identity": row["object_key"],
                }
            ],
            row["object_key"],
            "The object has no active consumer; every export-visible consumer is a paused tag.",
            "Confirm the paused implementation is not a rollback requirement, then delete or retain as a documented exception.",
        )


def add_folder_topology_findings(builder: BaselineBuilder, topology: dict[str, Any]) -> None:
    unfiled = as_list(topology.get("unfiled_objects"))
    builder.add_module("unfiled_objects", len(unfiled))
    if unfiled:
        builder.add_finding(
            "unfiled_objects",
            "unfiled_objects",
            "folder",
            [
                {
                    "object_id": row["object_key"],
                    "object_name": row["object_name"],
                    "object_identity": row["object_key"],
                }
                for row in unfiled
            ],
            "unfiled:" + signature(sorted(row["object_key"] for row in unfiled)),
            f"{len(unfiled)} configurable objects have no parentFolderId in the export.",
            "Assign retained objects to the final folder architecture after behavior and consolidation decisions.",
        )

    folder_rows = as_list(topology.get("folders"))
    builder.add_module("singleton_folders", len(folder_rows))
    for row in folder_rows:
        if row.get("topology_state") != "singleton":
            continue
        builder.add_finding(
            "singleton_folders",
            "singleton_folder",
            "folder",
            [
                {
                    "object_id": row["folder_id"],
                    "object_name": row["folder_name"],
                    "object_identity": f"folder:{row['folder_id']}",
                }
            ],
            f"folder:{row['folder_id']}",
            f"Folder {row['folder_name']!r} contains exactly one configurable object.",
            "Merge, retain, or repurpose the folder only after the final object architecture is known.",
        )

    builder.add_module("overloaded_folders", len(folder_rows))
    for row in folder_rows:
        if row.get("topology_state") != "overloaded":
            continue
        builder.add_finding(
            "overloaded_folders",
            "overloaded_folder",
            "folder",
            [
                {
                    "object_id": row["folder_id"],
                    "object_name": row["folder_name"],
                    "object_identity": f"folder:{row['folder_id']}",
                }
            ],
            f"folder:{row['folder_id']}",
            f"Folder {row['folder_name']!r} contains {row['member_count']} configurable objects.",
            "Split only when the final vendor, event-family, or lifecycle architecture provides stable subgroups.",
        )


def condition_contradiction_details(nodes: list[dict[str, Any]]) -> list[str]:
    constraints_by_left: dict[str, list[tuple[str, str]]] = collections.defaultdict(list)
    for node in nodes:
        operator, left, right = condition_values(node)
        if left:
            constraints_by_left[left].append((operator, right))

    def numeric_values(
        constraints: list[tuple[str, str]], operator_name: str
    ) -> list[float]:
        values: list[float] = []
        for operator, right in constraints:
            if operator != operator_name:
                continue
            try:
                values.append(float(right))
            except ValueError:
                continue
        return values

    details: list[str] = []
    opposite_operators = (
        ("EQUALS", "NOT_EQUALS"),
        ("CONTAINS", "DOES_NOT_CONTAIN"),
        ("MATCH_REGEX", "DOES_NOT_MATCH_REGEX"),
    )
    for left, constraints in sorted(constraints_by_left.items()):
        constraint_set = set(constraints)
        equals_values = {right for operator, right in constraints if operator == "EQUALS"}
        if len(equals_values) > 1:
            details.append(f"{left} equals {sorted(equals_values)}")
        for positive, negative in opposite_operators:
            values = sorted(
                right
                for operator, right in constraint_set
                if operator == positive and (negative, right) in constraint_set
            )
            if values:
                details.append(f"{left} uses both {positive} and {negative} for {values}")
        for equals_value in sorted(equals_values):
            if "{{" in equals_value:
                continue
            for operator, right in constraints:
                if not right or "{{" in right:
                    continue
                impossible = (
                    (operator == "CONTAINS" and right not in equals_value)
                    or (operator == "DOES_NOT_CONTAIN" and right in equals_value)
                    or (operator == "STARTS_WITH" and not equals_value.startswith(right))
                    or (operator == "ENDS_WITH" and not equals_value.endswith(right))
                )
                if impossible:
                    details.append(
                        f"{left} equals {equals_value!r} but also requires {operator} {right!r}"
                    )

        greater_values = numeric_values(constraints, "GREATER_THAN")
        lesser_values = numeric_values(constraints, "LESS_THAN")
        if greater_values and lesser_values and max(greater_values) >= min(lesser_values):
            details.append(
                f"{left} must be greater than {max(greater_values)} and less than {min(lesser_values)}"
            )
    return sorted(set(details))


def add_condition_lint_findings(
    builder: BaselineBuilder,
    layer: str,
    obj: dict[str, Any],
    counts: collections.Counter[str],
) -> None:
    nodes = condition_nodes(obj)
    subject = "trigger" if layer == "trigger" else "Zone boundary"
    subject_lower = subject.lower()
    key = f"{layer}:{object_id(obj, layer)}"
    finding_types = (
        {
            "duplicate": "duplicate_trigger_condition",
            "invalid_regex": "invalid_trigger_regex",
            "permissive": "universally_permissive_condition",
            "contradiction": "contradictory_trigger_conditions",
            "complex": "complex_trigger_candidate",
        }
        if layer == "trigger"
        else {
            "duplicate": "duplicate_zone_boundary_condition",
            "invalid_regex": "invalid_zone_boundary_regex",
            "permissive": "universally_permissive_zone_boundary",
            "contradiction": "contradictory_zone_boundary_conditions",
            "complex": "complex_zone_boundary_candidate",
        }
    )
    normalized = [normalized_condition(node) for node in nodes]
    duplicate_conditions = sorted(
        value for value, count in collections.Counter(normalized).items() if count > 1
    )
    if duplicate_conditions:
        counts[f"{layer}_duplicate_conditions"] += 1
        builder.add_finding(
            "trigger_condition_lint",
            finding_types["duplicate"],
            layer,
            [object_summary(obj, layer)],
            f"{key}:duplicate-condition",
            f"The {subject_lower} repeats normalized condition(s): "
            + "; ".join(duplicate_conditions),
            f"Remove repeated conditions without changing the remaining {subject_lower} scope.",
        )

    for node in nodes:
        operator, _left, right = condition_values(node)
        if operator in {"MATCH_REGEX", "DOES_NOT_MATCH_REGEX"}:
            try:
                re.compile(right)
            except re.error as exc:
                counts[f"{layer}_invalid_regex"] += 1
                builder.add_finding(
                    "trigger_condition_lint",
                    finding_types["invalid_regex"],
                    layer,
                    [object_summary(obj, layer)],
                    f"{key}:regex:{signature(right)}",
                    f"The {subject_lower} contains invalid regular expression {right!r}: {exc}.",
                    "Correct the expression and preserve the intended matching scope.",
                )
        if operator == "MATCH_REGEX" and right.strip() in ALWAYS_TRUE_REGEX:
            counts[f"{layer}_permissive_regex"] += 1
            builder.add_finding(
                "trigger_condition_lint",
                finding_types["permissive"],
                layer,
                [object_summary(obj, layer)],
                f"{key}:permissive:{signature(right)}",
                f"The {subject_lower} contains a universally permissive regex {right!r}.",
                "Remove it if it adds no intentional documentation or safety boundary.",
            )

    contradictions = condition_contradiction_details(nodes)
    if contradictions:
        counts[f"{layer}_contradictions"] += 1
        builder.add_finding(
            "trigger_condition_lint",
            finding_types["contradiction"],
            layer,
            [object_summary(obj, layer)],
            f"{key}:contradiction",
            f"The {subject_lower} contains mutually exclusive AND conditions: "
            + "; ".join(contradictions),
            "Correct the mutually exclusive conditions or split the intended routes.",
        )

    if len(nodes) > 3:
        counts[f"{layer}_complex_conditions"] += 1
        builder.add_finding(
            "trigger_condition_lint",
            finding_types["complex"],
            layer,
            [object_summary(obj, layer)],
            f"{key}:complexity:{len(nodes)}",
            f"The {subject_lower} contains {len(nodes)} comparison conditions.",
            (
                "Review for redundant or reusable conditions; do not simplify unless "
                "execution scope remains identical."
            ),
            "cleanup_operation | documented_exception | owner_decision_needed",
        )


def add_trigger_lint_findings(
    builder: BaselineBuilder,
    tags: list[dict[str, Any]],
    triggers: list[dict[str, Any]],
    zones: list[dict[str, Any]],
    trigger_consumers: dict[str, list[dict[str, Any]]],
    root_path: str,
) -> dict[str, int]:
    trigger_by_id = {str(item.get("triggerId")): item for item in triggers}
    counts: collections.Counter[str] = collections.Counter()
    builder.add_module("trigger_condition_lint", len(triggers) + len(zones))

    for layer, items in (("trigger", triggers), ("zone", zones)):
        for obj in items:
            add_condition_lint_findings(builder, layer, obj, counts)

    builder.add_module("ineffective_blocking_triggers", len(tags))
    for tag_index, tag in enumerate(tags):
        firing_trigger_ids = [
            str(trigger_id) for trigger_id in as_list(tag.get("firingTriggerId"))
        ]
        firing_event_sets = [
            exact_event_names(trigger_by_id[trigger_id])
            for trigger_id in firing_trigger_ids
            if trigger_id in trigger_by_id
        ]
        if (
            not firing_trigger_ids
            or len(firing_event_sets) != len(firing_trigger_ids)
            or any(not events for events in firing_event_sets)
        ):
            continue
        firing_events = set().union(*firing_event_sets)
        ineffective_blockers: list[tuple[str, dict[str, Any], set[str]]] = []
        for blocker_id in as_list(tag.get("blockingTriggerId")):
            blocker = trigger_by_id.get(str(blocker_id))
            if not blocker:
                continue
            blocking_events = exact_event_names(blocker)
            if blocking_events and firing_events.isdisjoint(blocking_events):
                ineffective_blockers.append(
                    (str(blocker_id), blocker, blocking_events)
                )
        if not ineffective_blockers:
            continue
        counts["ineffective_blockers"] += len(ineffective_blockers)
        before_blockers = [
            str(value) for value in as_list(tag.get("blockingTriggerId"))
        ]
        ineffective_ids = {item[0] for item in ineffective_blockers}
        after_blockers = [
            blocker_id
            for blocker_id in before_blockers
            if blocker_id not in ineffective_ids
        ]
        tag_key = f"tag:{object_id(tag, 'tag')}"
        orphaned_blocker_ids = {
            blocker_id
            for blocker_id in ineffective_ids
            if {
                f"{consumer.get('object_type')}:{consumer.get('object_id')}"
                for consumer in trigger_consumers.get(blocker_id, [])
                if str(consumer.get("object_type") or "")
                and str(consumer.get("object_id") or "")
            }
            == {tag_key}
        }
        repair = {
            "status": "unique_ineffective_blocker_removal",
            "repair_kind": "blockingTriggerId",
            "target_object_key": tag_key,
            "target_name": str(tag.get("name") or ""),
            "changes": [
                {
                    "object_key": tag_key,
                    "json_path": (
                        f"{root_path}.tag[{tag_index}].blockingTriggerId"
                    ),
                    "before": before_blockers,
                    "after": after_blockers,
                }
            ],
            "renames": [],
            "deletions": [
                {
                    "object_key": f"trigger:{blocker_id}",
                    "reason": (
                        f"After removing its impossible blocker edge from {tag_key}, "
                        "the trigger has no remaining exported consumer."
                    ),
                }
                for blocker_id in sorted(orphaned_blocker_ids)
            ],
        }
        builder.add_finding(
            "ineffective_blocking_triggers",
            "ineffective_blocking_trigger",
            "tag",
            [
                object_summary(tag, "tag"),
                *[
                    object_summary(blocker, "trigger")
                    for _blocker_id, blocker, _events in ineffective_blockers
                ],
            ],
            f"{tag_key}:blockers:{','.join(sorted(ineffective_ids))}",
            (
                f"The tag fires only on {sorted(firing_events)}; blocker routes "
                + "; ".join(
                    f"{blocker_id} {blocker.get('name')!r} only on {sorted(events)}"
                    for blocker_id, blocker, events in ineffective_blockers
                )
                + " cannot intersect those firing events."
            ),
            (
                f"Remove blocker ID(s) {', '.join(sorted(ineffective_ids))} from "
                f"{tag_key} in one exact blockingTriggerId update; retain every other "
                "blocker unchanged."
                + (
                    " Delete newly orphaned trigger ID(s) "
                    + ", ".join(sorted(orphaned_blocker_ids))
                    + " in the same operation."
                    if orphaned_blocker_ids
                    else ""
                )
            ),
            "cleanup_operation | documented_exception",
            extra={
                "deterministic_repair": repair,
                "repair_affected_object_keys": [
                    tag_key,
                    *[
                        f"trigger:{blocker_id}"
                        for blocker_id in sorted(orphaned_blocker_ids)
                    ],
                ],
            },
        )
    return dict(counts)


def add_missing_reference_findings(
    builder: BaselineBuilder,
    cv: dict[str, Any],
    variable_consumers: dict[str, list[dict[str, Any]]],
    trigger_consumers: dict[str, list[dict[str, Any]]],
    root_path: str,
) -> None:
    tags = as_list(cv.get("tag"))
    triggers = as_list(cv.get("trigger"))
    variables = as_list(cv.get("variable"))
    builtins = as_list(cv.get("builtInVariable"))
    folders = as_list(cv.get("folder"))
    templates = as_list(cv.get("customTemplate"))
    zones = as_list(cv.get("zone"))
    clients = as_list(cv.get("client"))
    gtag_configs = as_list(cv.get("gtagConfig"))
    transformations = as_list(cv.get("transformation"))
    template_type_index = custom_template_type_index(templates)

    builder.add_module(
        "missing_references",
        len(tags)
        + len(triggers)
        + len(variables)
        + len(folders)
        + len(templates)
        + len(zones)
        + len(clients)
        + len(gtag_configs)
        + len(transformations),
    )

    variable_objects = [
        ("variable", item) for item in variables
    ] + [("builtInVariable", item) for item in builtins]
    variable_names = {item.get("name") for _layer, item in variable_objects}
    normalized_variable_targets: dict[str, list[tuple[str, dict[str, Any]]]] = (
        collections.defaultdict(list)
    )
    for target_layer, target in variable_objects:
        name = str(target.get("name") or "")
        if name:
            normalized_variable_targets[normalized_reference_name(name)].append(
                (target_layer, target)
            )
    for name in sorted(
        ref
        for ref in variable_consumers
        if ref not in variable_names and not is_system_variable_reference(ref)
    ):
        normalized_targets = normalized_variable_targets.get(
            normalized_reference_name(name), []
        )
        repair: dict[str, Any] = {
            "status": "no_unique_container_target",
            "repair_kind": "variable_reference",
            "target_object_key": "",
            "target_name": "",
            "changes": [],
            "renames": [],
        }
        if len(normalized_targets) == 1:
            target_layer, target = normalized_targets[0]
            target_name = str(target.get("name") or "")
            changes = reference_text_changes(
                cv,
                root_path,
                name,
                target_name,
            )
            if changes:
                repair = {
                    "status": "unique_normalized_target",
                    "repair_kind": "variable_reference",
                    "target_object_key": (
                        f"{target_layer}:{object_id(target, target_layer)}"
                    ),
                    "target_name": target_name,
                    "changes": changes,
                    "renames": [],
                }
        builder.add_finding(
            "missing_references",
            "undefined_variable_reference",
            "variable_reference",
            [{"object_id": name, "object_name": name}],
            f"var:{name}",
            f"Reference {{{{{name}}}}} is used but no variable or built-in with that name exists.",
            (
                f"Replace the corrupted reference with {repair['target_name']!r} at every "
                "listed source path."
                if repair["status"] == "unique_normalized_target"
                else "Resolve reference before cleanup execution; use fresh readback or "
                "restore/create the missing source."
            ),
            "cleanup_operation | documented_exception | owner_decision_needed",
            extra={
                "deterministic_repair": repair,
                "repair_affected_object_keys": sorted(
                    {
                        str(change.get("object_key") or "")
                        for change in as_list(repair.get("changes"))
                        if str(change.get("object_key") or "")
                    }
                ),
            },
        )

    trigger_ids = {str(trigger.get("triggerId")) for trigger in triggers}
    for trigger_id in sorted(
        ref
        for ref in trigger_consumers
        if ref not in trigger_ids and not is_system_trigger_reference(ref)
    ):
        builder.add_finding(
            "missing_references",
            "missing_trigger_reference",
            "trigger_reference",
            [{"object_id": trigger_id, "object_name": trigger_id}],
            f"trigger:{trigger_id}",
            f"Trigger ID {trigger_id} is consumed but no trigger with that ID exists.",
            "Resolve reference before cleanup execution; use fresh readback or restore/create the missing trigger.",
            "cleanup_operation | documented_exception | owner_decision_needed",
        )

    tag_names = {tag.get("name") for tag in tags}
    for tag_index, tag in enumerate(tags):
        for relation in ("setupTag", "teardownTag"):
            for ref_index, ref in enumerate(as_list(tag.get(relation))):
                if not isinstance(ref, dict):
                    continue
                tag_name = ref.get("tagName")
                if tag_name and tag_name not in tag_names:
                    candidates = setup_reference_candidates(tags, str(tag_name), tag)
                    target = unique_setup_repair_candidate(candidates)
                    repair = {
                        "status": "no_unique_container_target",
                        "repair_kind": relation,
                        "target_object_key": "",
                        "target_name": "",
                        "changes": [],
                        "renames": [],
                    }
                    if target:
                        repair = {
                            "status": "unique_peer_supported_target",
                            "repair_kind": relation,
                            "target_object_key": target["object_key"],
                            "target_name": target["object_name"],
                            "changes": [
                                {
                                    "object_key": f"tag:{object_id(tag, 'tag')}",
                                    "json_path": (
                                        f"{root_path}.tag[{tag_index}].{relation}"
                                        f"[{ref_index}].tagName"
                                    ),
                                    "before": tag_name,
                                    "after": target["object_name"],
                                }
                            ],
                            "renames": [],
                        }
                    builder.add_finding(
                        "missing_references",
                        f"missing_{relation}_reference",
                        "tag_reference",
                        [
                            object_summary(tag, "tag"),
                            {"object_id": tag_name, "object_name": tag_name},
                        ],
                        f"{relation}:{tag_name}",
                        f"Tag {tag.get('name')!r} references missing {relation} tag {tag_name!r}.",
                        (
                            f"Remap the missing sequence name to peer-supported tag "
                            f"{target['object_key']} — {target['object_name']}."
                            if target
                            else "Resolve sequencing reference before cleanup execution; "
                            "do not clear the sequencing edge by default."
                        ),
                        "cleanup_operation | documented_exception | owner_decision_needed",
                        extra={
                            "reference_resolution_candidates": candidates,
                            "deterministic_repair": repair,
                            "repair_affected_object_keys": [
                                f"tag:{object_id(tag, 'tag')}"
                            ],
                        },
                    )

    folder_ids = {str(folder.get("folderId")) for folder in folders}
    for layer, items in (
        ("tag", tags),
        ("trigger", triggers),
        ("variable", variables),
        ("zone", zones),
        ("client", clients),
        ("gtagConfig", gtag_configs),
        ("transformation", transformations),
    ):
        for item in items:
            folder_id = item.get("parentFolderId")
            if folder_id and str(folder_id) not in folder_ids:
                builder.add_finding(
                    "missing_references",
                    "missing_folder_reference",
                    layer,
                    [
                        object_summary(item, layer),
                        {"object_id": str(folder_id), "object_name": str(folder_id)},
                    ],
                    f"folder:{folder_id}",
                    f"{layer} {item.get('name')!r} references missing folder {folder_id}.",
                    "Restore folder reference or move object to an existing folder.",
                )

    template_ids = {str(template.get("templateId")) for template in templates}
    for layer, items in (
        ("tag", tags),
        ("variable", variables),
        ("client", clients),
        ("gtagConfig", gtag_configs),
        ("transformation", transformations),
    ):
        for item in items:
            for template_id in custom_template_ids(item, template_type_index):
                if template_id in template_ids:
                    continue
                builder.add_finding(
                    "missing_references",
                    "missing_custom_template_reference",
                    layer,
                    [
                        object_summary(item, layer),
                        {"object_id": template_id, "object_name": template_id},
                    ],
                    f"template:{template_id}",
                    f"{layer} {item.get('name')!r} uses custom template {template_id}, but it is not in customTemplate.",
                    "Restore or include the required custom template before cleanup execution.",
                )


def add_source_integrity_findings(
    builder: BaselineBuilder, data: dict[str, Any]
) -> list[dict[str, Any]]:
    findings = source_integrity_findings(data)
    try:
        cv = container_version(data)
    except ValueError:
        cv = {}
    builder.add_module(
        "source_integrity",
        sum(len(as_list(cv.get(layer))) for layer in ID_KEYS),
    )
    for finding in findings:
        layer = str(finding.get("layer") or "source")
        object_id_value = str(finding.get("object_id") or finding.get("object_index") or "")
        builder.add_finding(
            "source_integrity",
            str(finding.get("finding_type") or "source_integrity_error"),
            layer,
            [
                {
                    "object_id": object_id_value,
                    "object_name": str(finding.get("source_path") or "$"),
                    "object_identity": (
                        f"{layer}|{object_id_value}|{finding.get('source_path') or '$'}"
                    ),
                }
            ],
            signature(finding),
            str(finding.get("details") or "The source identity or shape is invalid."),
            (
                "Obtain a corrected complete export or resolve the source identity conflict "
                "before claiming a complete audit or synthesising target operations."
            ),
            "owner_decision_needed | documented_exception | cleanup_operation",
            {"source_integrity_finding": finding},
        )
    return findings


def add_unused_findings(
    builder: BaselineBuilder,
    cv: dict[str, Any],
    lifecycle: list[dict[str, Any]],
) -> None:
    triggers = as_list(cv.get("trigger"))
    variables = as_list(cv.get("variable"))
    builtins = as_list(cv.get("builtInVariable"))
    folders = as_list(cv.get("folder"))
    templates = as_list(cv.get("customTemplate"))
    tags = as_list(cv.get("tag"))
    clients = as_list(cv.get("client"))
    gtag_configs = as_list(cv.get("gtagConfig"))
    transformations = as_list(cv.get("transformation"))
    lifecycle_by_key = {
        str(row.get("object_key") or ""): row for row in lifecycle
    }

    builder.add_module("unused_variables", len(variables) + len(builtins))
    for layer, items in (("variable", variables), ("builtInVariable", builtins)):
        for variable in items:
            key = f"{layer}:{object_id(variable, layer)}"
            if lifecycle_by_key.get(key, {}).get("usage_state") != "unreferenced":
                continue
            builder.add_finding(
                "unused_variables",
                "unused_built_in_variable" if layer == "builtInVariable" else "unused_object",
                layer,
                [object_summary(variable, layer)],
                key,
                (
                    "No active export-visible execution root reaches this enabled built-in "
                    "variable."
                    if layer == "builtInVariable"
                    else "No active export-visible execution root reaches this variable or "
                    "its dependency chain."
                ),
                (
                    "Disable the unused built-in after confirming no active tag, trigger, or "
                    "reachable variable references it."
                    if layer == "builtInVariable"
                    else "Delete candidate only after configuration and architecture review "
                    "confirm no export-visible dependency or intentional staged role."
                ),
            )

    builder.add_module("unused_triggers", len(triggers))
    for trigger in triggers:
        key = f"trigger:{object_id(trigger, 'trigger')}"
        if lifecycle_by_key.get(key, {}).get("usage_state") != "unreferenced":
            continue
        builder.add_finding(
            "unused_triggers",
            "unused_object",
            "trigger",
            [object_summary(trigger, "trigger")],
            f"trigger:{object_id(trigger, 'trigger')}",
            "No active tag, Zone, or reachable trigger group reaches this trigger ID.",
            "Delete candidate after architecture review confirms it is not a future or staged trigger.",
        )

    builder.add_module("tags_without_firing_triggers", len(tags))
    for tag in tags:
        key = f"tag:{object_id(tag, 'tag')}"
        if lifecycle_by_key.get(key, {}).get("usage_state") != "active_without_route":
            continue
        builder.add_finding(
            "tags_without_firing_triggers",
            "tag_without_firing_trigger",
            "tag",
            [object_summary(tag, "tag")],
            f"tag:{object_id(tag, 'tag')}",
            "Active tag has no firing trigger and is not reachable through an active setup/teardown chain.",
            "Fix, pause/delete, or document why the tag is intentionally triggerless.",
        )

    builder.add_module("unused_custom_templates", len(templates))
    template_type_index = custom_template_type_index(templates)
    used_template_ids = {
        template_id
        for item in tags + variables + clients + gtag_configs + transformations
        for template_id in custom_template_ids(item, template_type_index)
    }
    for template in templates:
        template_id = str(template.get("templateId"))
        key = f"customTemplate:{template_id}"
        if (
            template_id in used_template_ids
            and lifecycle_by_key.get(key, {}).get("usage_state") != "unreferenced"
        ):
            continue
        builder.add_finding(
            "unused_custom_templates",
            "unused_object",
            "customTemplate",
            [object_summary(template, "customTemplate")],
            f"template:{template_id}",
            "No active export-visible execution root reaches this custom template ID.",
            "Delete candidate only after confirming no workspace/template dependency remains.",
        )

    builder.add_module("unused_folders", len(folders))
    used_folder_ids = {
        str(item.get("parentFolderId"))
        for item in tags + triggers + variables + clients + transformations
        if item.get("parentFolderId")
    }
    for folder in folders:
        folder_id = str(folder.get("folderId"))
        key = f"folder:{folder_id}"
        if (
            folder_id in used_folder_ids
            and lifecycle_by_key.get(key, {}).get("usage_state") != "unreferenced"
        ):
            continue
        builder.add_finding(
            "unused_folders",
            "unused_object",
            "folder",
            [object_summary(folder, "folder")],
            f"folder:{folder_id}",
            "No active export-visible object is assigned to this folder.",
            "Delete or repurpose after owner confirms folder is not needed for organization.",
        )


def add_trigger_group_findings(
    builder: BaselineBuilder,
    triggers: list[dict[str, Any]],
    trigger_consumers: dict[str, list[dict[str, Any]]],
) -> None:
    builder.add_module("single_member_trigger_groups", len(triggers))
    trigger_by_id = {str(trigger.get("triggerId")): trigger for trigger in triggers}
    for trigger in triggers:
        if trigger.get("type") != "TRIGGER_GROUP":
            continue
        members = trigger_group_members(trigger)
        if len(members) != 1:
            continue
        child = trigger_by_id.get(members[0])
        objects = [object_summary(trigger, "trigger")]
        if child:
            objects.append(object_summary(child, "trigger"))
        group_id = object_id(trigger, "trigger")
        consumers = trigger_consumers.get(group_id, [])
        consumer_labels = sorted(
            f"{item.get('object_type')}:{item.get('object_id')}:{item.get('object_name')}"
            for item in consumers
        )
        child_is_group = bool(child and child.get("type") == "TRIGGER_GROUP")
        child_consumes_group = bool(
            child and group_id in {str(value) for value in trigger_group_members(child)}
        )
        dependency_first = child_is_group or child_consumes_group
        safe_order = (
            "Resolve the nested or cyclic group dependency before any consumer remap; "
            "then prove the resulting route is acyclic."
            if dependency_first
            else "Remap the listed consumers to the child first, verify references, and only then delete the group."
        )
        builder.add_finding(
            "single_member_trigger_groups",
            "single_member_trigger_group",
            "trigger",
            objects,
            f"trigger_group:{object_id(trigger, 'trigger')}->{members[0]}",
            (
                f"Trigger group {trigger.get('name')!r} contains exactly one child trigger "
                f"{members[0]}; export-visible consumers are {consumer_labels!r}."
            ),
            safe_order,
            extra={
                "consumer_objects": consumers,
                "child_trigger_id": members[0],
                "safe_remediation_order": safe_order,
                "cycle_or_nested_dependency_first": dependency_first,
            },
        )

    builder.add_module("trigger_group_structure", len(triggers))
    groups = {
        str(trigger.get("triggerId") or ""): trigger
        for trigger in triggers
        if trigger.get("type") == "TRIGGER_GROUP" and trigger.get("triggerId") is not None
    }
    for trigger_id, trigger in sorted(groups.items()):
        invalid_details: list[str] = []
        latent_duplicate_values: set[str] = set()
        raw_parameters = trigger.get("parameter")
        if raw_parameters is not None and not isinstance(raw_parameters, list):
            invalid_details.append("parameter is not an array")
        for parameter_index, parameter in enumerate(as_list(raw_parameters)):
            if not isinstance(parameter, dict):
                invalid_details.append(
                    f"parameter[{parameter_index}] is not an object"
                )
                continue
            if parameter.get("key") != "triggerIds":
                continue
            raw_members = parameter.get("list")
            if not isinstance(raw_members, list):
                invalid_details.append(
                    f"parameter[{parameter_index}].list is not an array"
                )
                continue
            invalid_member_indexes = [
                member_index
                for member_index, member in enumerate(raw_members)
                if not isinstance(member, dict)
                or not str(member.get("value") or "").strip()
            ]
            if invalid_member_indexes:
                invalid_details.append(
                    f"parameter[{parameter_index}].list has invalid entries at "
                    f"{invalid_member_indexes}"
                )
            valid_values = {
                str(member.get("value") or "").strip()
                for member in raw_members
                if isinstance(member, dict) and str(member.get("value") or "").strip()
            }
            malformed_scalar_values = {
                str(member).strip()
                for member in raw_members
                if not isinstance(member, dict) and str(member).strip()
            }
            latent_duplicate_values.update(valid_values & malformed_scalar_values)
        if latent_duplicate_values:
            invalid_details.append(
                "malformed scalar entries repeat valid member values "
                f"{sorted(latent_duplicate_values)!r}"
            )
        if invalid_details:
            builder.add_finding(
                "trigger_group_structure",
                "invalid_trigger_group_member_structure",
                "trigger",
                [object_summary(trigger, "trigger")],
                f"invalid_group_structure:{trigger_id}",
                "Trigger group member structure is malformed: "
                + "; ".join(invalid_details)
                + ".",
                "Restore an array of triggerIds entries with one nonblank value per member.",
                extra={
                    "latent_duplicate_member_values": sorted(latent_duplicate_values),
                    "malformed_values_are_not_treated_as_valid_edges": True,
                },
            )
        members = [str(value) for value in trigger_group_members(trigger)]
        if not members:
            builder.add_finding(
                "trigger_group_structure",
                "empty_trigger_group",
                "trigger",
                [object_summary(trigger, "trigger")],
                f"empty_group:{trigger_id}",
                f"Trigger group {trigger.get('name')!r} has no child trigger.",
                "Delete the empty group after confirming no tag still references it.",
            )
        duplicates = sorted(
            member for member, count in collections.Counter(members).items() if count > 1
        )
        if duplicates:
            builder.add_finding(
                "trigger_group_structure",
                "duplicate_trigger_group_members",
                "trigger",
                [object_summary(trigger, "trigger")],
                f"duplicate_members:{trigger_id}:{','.join(duplicates)}",
                f"Trigger group {trigger.get('name')!r} repeats member IDs {duplicates!r}.",
                "Keep each required child trigger once and preserve the intended group semantics.",
            )
        nested = sorted({member for member in members if member in groups and member != trigger_id})
        if nested:
            builder.add_finding(
                "trigger_group_structure",
                "nested_trigger_groups",
                "trigger",
                [
                    object_summary(groups[group_id], "trigger")
                    for group_id in [trigger_id, *nested]
                ],
                f"nested_groups:{trigger_id}:{','.join(nested)}",
                f"Trigger group {trigger.get('name')!r} contains nested trigger groups {nested!r}.",
                (
                    "Confirm the nested AND semantics are intentional; otherwise flatten the "
                    "route while preserving every consumer and child condition."
                ),
                "cleanup_operation | documented_exception | owner_decision_needed",
            )

    reported_cycles: set[tuple[str, ...]] = set()

    def visit(current: str, path: tuple[str, ...]) -> None:
        if current in path:
            cycle = path[path.index(current) :] + (current,)
            identity = tuple(sorted(set(cycle[:-1])))
            if identity in reported_cycles:
                return
            reported_cycles.add(identity)
            objects = [object_summary(groups[group_id], "trigger") for group_id in identity]
            builder.add_finding(
                "trigger_group_structure",
                "cyclic_trigger_groups",
                "trigger",
                objects,
                "cycle:" + "->".join(cycle),
                "Trigger groups form a cyclic dependency: " + " -> ".join(cycle) + ".",
                "Break the cycle and remap every tag or parent group to an acyclic trigger route.",
            )
            return
        trigger = groups.get(current)
        if not trigger:
            return
        for member in trigger_group_members(trigger):
            if str(member) in groups:
                visit(str(member), (*path, current))

    for trigger_id in sorted(groups):
        visit(trigger_id, ())


def tag_sequence_entries(tag: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for relation in ("setupTag", "teardownTag"):
        for index, item in enumerate(as_list(tag.get(relation))):
            if not isinstance(item, dict):
                continue
            rows.append(
                {
                    "relation": relation,
                    "index": index,
                    "target_name": str(item.get("tagName") or ""),
                    "settings": item,
                }
            )
    return rows


def add_tag_sequence_findings(builder: BaselineBuilder, tags: list[dict[str, Any]]) -> None:
    builder.add_module("tag_sequence_structure", len(tags))
    tags_by_name: dict[str, list[dict[str, Any]]] = collections.defaultdict(list)
    for tag in tags:
        tags_by_name[object_name(tag)].append(tag)

    sequence_graph: dict[str, set[str]] = collections.defaultdict(set)
    tag_by_key = {f"tag:{object_id(tag, 'tag')}": tag for tag in tags}
    for tag in tags:
        source_key = f"tag:{object_id(tag, 'tag')}"
        source_name = object_name(tag)
        for relation in ("setupTag", "teardownTag"):
            raw_entries = tag.get(relation)
            if raw_entries is not None and not isinstance(raw_entries, list):
                builder.add_finding(
                    "tag_sequence_structure",
                    "invalid_tag_sequence_shape",
                    "tag",
                    [object_summary(tag, "tag")],
                    f"{source_key}:{relation}:invalid-shape",
                    f"Tag {source_name!r} exports {relation} as a non-array value.",
                    "Restore the GTM sequence array before evaluating or changing its order.",
                )
            for index, item in enumerate(as_list(raw_entries)):
                if not isinstance(item, dict):
                    builder.add_finding(
                        "tag_sequence_structure",
                        "invalid_tag_sequence_entry",
                        "tag",
                        [object_summary(tag, "tag")],
                        f"{source_key}:{relation}:{index}:invalid-entry",
                        f"Tag {source_name!r} has a non-object {relation} entry at index {index}.",
                        "Restore a sequence object with a valid tagName and failure-control setting.",
                    )
                elif not str(item.get("tagName") or "").strip():
                    builder.add_finding(
                        "tag_sequence_structure",
                        "tag_sequence_target_missing_name",
                        "tag",
                        [object_summary(tag, "tag")],
                        f"{source_key}:{relation}:{index}:missing-name",
                        f"Tag {source_name!r} has a {relation} entry without tagName at index {index}.",
                        "Bind the sequence to an existing uniquely named tag or remove the empty entry.",
                    )
        entries = tag_sequence_entries(tag)
        by_relation_target = collections.Counter(
            (row["relation"], row["target_name"]) for row in entries
        )
        for (relation, target_name), count in sorted(by_relation_target.items()):
            if count > 1:
                builder.add_finding(
                    "tag_sequence_structure",
                    "duplicate_tag_sequence_reference",
                    "tag",
                    [object_summary(tag, "tag")],
                    f"{source_key}:{relation}:{target_name}:duplicate",
                    f"Tag {source_name!r} repeats {relation} target {target_name!r} {count} times.",
                    "Keep the required sequence target once and preserve its failure-control setting.",
                )
        setup_targets = {
            row["target_name"] for row in entries if row["relation"] == "setupTag"
        }
        teardown_targets = {
            row["target_name"] for row in entries if row["relation"] == "teardownTag"
        }
        for target_name in sorted(setup_targets & teardown_targets):
            builder.add_finding(
                "tag_sequence_structure",
                "conflicting_tag_sequence_roles",
                "tag",
                [object_summary(tag, "tag")],
                f"{source_key}:both:{target_name}",
                f"Tag {source_name!r} uses {target_name!r} as both setup and teardown.",
                "Confirm the intended before/after behavior and keep the target in only the correct role.",
                "cleanup_operation | documented_exception | owner_decision_needed",
            )
        for row in entries:
            target_name = row["target_name"]
            relation = row["relation"]
            targets = tags_by_name.get(target_name, [])
            self_reference = target_name == source_name and bool(target_name)
            if self_reference:
                builder.add_finding(
                    "tag_sequence_structure",
                    "self_referential_tag_sequence",
                    "tag",
                    [object_summary(tag, "tag")],
                    f"{source_key}:{relation}:self",
                    f"Tag {source_name!r} references itself as {relation}.",
                    "Remove the self-reference and restore the intended acyclic sequence.",
                )
            if len(targets) > 1:
                builder.add_finding(
                    "tag_sequence_structure",
                    "ambiguous_tag_sequence_reference",
                    "tag",
                    [object_summary(tag, "tag"), *[object_summary(item, "tag") for item in targets]],
                    f"{source_key}:{relation}:{target_name}:ambiguous",
                    f"Sequence target name {target_name!r} resolves to {len(targets)} tags.",
                    "Make tag names unique, then bind the sequence to the intended target.",
                )
                continue
            if self_reference:
                continue
            if len(targets) == 1:
                target = targets[0]
                target_key = f"tag:{object_id(target, 'tag')}"
                sequence_graph[source_key].add(target_key)
                if not tag.get("paused") and target.get("paused"):
                    builder.add_finding(
                        "tag_sequence_structure",
                        "active_sequence_targets_paused_tag",
                        "tag",
                        [object_summary(tag, "tag"), object_summary(target, "tag")],
                        f"{source_key}:{relation}:{target_key}:paused",
                        f"Active tag {source_name!r} sequences paused tag {target_name!r}.",
                        "Activate the required target or remove/remap the ineffective sequence.",
                    )

    reported_cycles: set[tuple[str, ...]] = set()
    visit_state: dict[str, int] = {}

    def visit(current: str, path: tuple[str, ...]) -> None:
        if current in path:
            cycle = path[path.index(current) :] + (current,)
            identity = tuple(sorted(set(cycle[:-1])))
            if identity in reported_cycles:
                return
            reported_cycles.add(identity)
            builder.add_finding(
                "tag_sequence_structure",
                "cyclic_tag_sequence",
                "tag",
                [object_summary(tag_by_key[key], "tag") for key in identity],
                "tag_sequence_cycle:" + "->".join(cycle),
                "Setup/teardown sequencing forms a cycle: " + " -> ".join(cycle) + ".",
                "Break the cycle and preserve one explicit acyclic execution order.",
            )
            return
        if visit_state.get(current) == 2:
            return
        visit_state[current] = 1
        for target in sorted(sequence_graph.get(current, set())):
            visit(target, (*path, current))
        visit_state[current] = 2

    for tag_key in sorted(tag_by_key):
        visit(tag_key, ())


VALID_TAG_FIRING_OPTIONS = {"UNLIMITED", "ONCEPEREVENT", "ONCEPERLOAD"}


def add_tag_execution_control_findings(
    builder: BaselineBuilder, tags: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    builder.add_module("tag_execution_controls", len(tags))
    rows: list[dict[str, Any]] = []
    for tag in tags:
        start_raw = tag.get("scheduleStartMs")
        end_raw = tag.get("scheduleEndMs")

        def parsed_timestamp(value: Any) -> int | None:
            try:
                return int(str(value)) if value not in {None, ""} else None
            except (TypeError, ValueError):
                return None

        start = parsed_timestamp(start_raw)
        end = parsed_timestamp(end_raw)
        firing_option = str(tag.get("tagFiringOption") or "")
        normalized_option = re.sub(r"[^A-Z]", "", firing_option.upper())
        row = {
            "object_key": f"tag:{object_id(tag, 'tag')}",
            "tag_name": object_name(tag),
            "paused": bool(tag.get("paused")),
            "live_only": bool(tag.get("liveOnly")),
            "schedule_start_ms": start_raw,
            "schedule_end_ms": end_raw,
            "tag_firing_option": firing_option,
            "has_setup_sequence": bool(as_list(tag.get("setupTag"))),
            "has_teardown_sequence": bool(as_list(tag.get("teardownTag"))),
        }
        rows.append(row)
        if (
            (start_raw not in {None, ""} and start is None)
            or (end_raw not in {None, ""} and end is None)
        ):
            builder.add_finding(
                "tag_execution_controls",
                "invalid_tag_schedule_timestamp",
                "tag",
                [object_summary(tag, "tag")],
                f"{row['object_key']}:invalid-schedule",
                f"Tag schedule contains a non-integer boundary: start={start_raw!r}, end={end_raw!r}.",
                "Replace malformed schedule boundaries with valid millisecond timestamps or remove them.",
            )
        if start is not None and end is not None and start >= end:
            builder.add_finding(
                "tag_execution_controls",
                "invalid_tag_schedule_order",
                "tag",
                [object_summary(tag, "tag")],
                f"{row['object_key']}:schedule-order",
                f"Tag schedule starts at {start} and ends at {end}; the active interval is empty or reversed.",
                "Correct the schedule interval or remove obsolete scheduling controls.",
            )
        if firing_option and normalized_option not in VALID_TAG_FIRING_OPTIONS:
            builder.add_finding(
                "tag_execution_controls",
                "unrecognized_tag_firing_option",
                "tag",
                [object_summary(tag, "tag")],
                f"{row['object_key']}:firing-option:{firing_option}",
                f"Tag uses unrecognized tagFiringOption {firing_option!r}.",
                "Confirm the exported enum and restore a supported GTM firing option.",
            )
    return rows


def add_zone_structure_findings(
    builder: BaselineBuilder, zones: list[dict[str, Any]]
) -> None:
    builder.add_module("zone_structure", len(zones))
    for zone in zones:
        zone_key = f"zone:{object_id(zone, 'zone')}"
        children = zone.get("childContainer")
        child_rows = as_list(children)
        if children is not None and not isinstance(children, list):
            builder.add_finding(
                "zone_structure",
                "invalid_zone_child_container_shape",
                "zone",
                [object_summary(zone, "zone")],
                f"{zone_key}:invalid-child-shape",
                "Zone childContainer is not an array in the export.",
                "Obtain a valid complete export or restore the Zone child-container list.",
            )
        child_ids = [
            str(child.get("publicId") or "")
            for child in child_rows
            if isinstance(child, dict)
        ]
        if not child_rows:
            builder.add_finding(
                "zone_structure",
                "zone_without_child_container",
                "zone",
                [object_summary(zone, "zone")],
                f"{zone_key}:no-child",
                "Zone contains no exported child container.",
                "Attach the intended child container or remove the obsolete Zone after owner confirmation.",
            )
        invalid_children = [
            index
            for index, child in enumerate(child_rows)
            if not isinstance(child, dict) or not str(child.get("publicId") or "").strip()
        ]
        if invalid_children:
            builder.add_finding(
                "zone_structure",
                "invalid_zone_child_container",
                "zone",
                [object_summary(zone, "zone")],
                f"{zone_key}:invalid-children:{','.join(map(str, invalid_children))}",
                f"Zone child container entries at indexes {invalid_children} have no publicId.",
                "Restore valid child-container identities before relying on the Zone.",
            )
        duplicates = sorted(
            child_id
            for child_id, count in collections.Counter(child_ids).items()
            if child_id and count > 1
        )
        if duplicates:
            builder.add_finding(
                "zone_structure",
                "duplicate_zone_child_container",
                "zone",
                [object_summary(zone, "zone")],
                f"{zone_key}:duplicate-children:{','.join(duplicates)}",
                f"Zone repeats child container public IDs {duplicates!r}.",
                "Keep each intended child container once.",
            )
        raw_boundary = zone.get("boundary")
        if raw_boundary is not None and not isinstance(raw_boundary, dict):
            builder.add_finding(
                "zone_structure",
                "invalid_zone_boundary_shape",
                "zone",
                [object_summary(zone, "zone")],
                f"{zone_key}:invalid-boundary-shape",
                "Zone boundary is not an object in the export.",
                "Restore the Zone boundary object before relying on its scope.",
            )
        boundary = raw_boundary if isinstance(raw_boundary, dict) else {}
        for field in ("condition", "customEvaluationTriggerId"):
            if field in boundary and not isinstance(boundary.get(field), list):
                builder.add_finding(
                    "zone_structure",
                    "invalid_zone_boundary_field_shape",
                    "zone",
                    [object_summary(zone, "zone")],
                    f"{zone_key}:invalid-boundary-{field}",
                    f"Zone boundary field {field} is not an array in the export.",
                    "Restore the exported Zone boundary array and re-evaluate its scope.",
                )
        if not as_list(boundary.get("condition")) and not as_list(
            boundary.get("customEvaluationTriggerId")
        ):
            builder.add_finding(
                "zone_structure",
                "unbounded_zone_scope_review",
                "zone",
                [object_summary(zone, "zone")],
                f"{zone_key}:unbounded",
                "Zone has no exported boundary condition or custom evaluation trigger.",
                "Confirm that an all-scope Zone is intentional or add the required boundary.",
                "cleanup_operation | documented_exception | owner_decision_needed",
            )
        raw_restrictions = zone.get("typeRestriction")
        if raw_restrictions is not None and not isinstance(raw_restrictions, dict):
            builder.add_finding(
                "zone_structure",
                "invalid_zone_type_restriction_shape",
                "zone",
                [object_summary(zone, "zone")],
                f"{zone_key}:invalid-type-restriction-shape",
                "Zone typeRestriction is not an object in the export.",
                "Restore the Zone type-restriction object before relying on its allowlist.",
            )
        restrictions = raw_restrictions if isinstance(raw_restrictions, dict) else {}
        if "whitelistedTypeId" in restrictions and not isinstance(
            restrictions.get("whitelistedTypeId"), list
        ):
            builder.add_finding(
                "zone_structure",
                "invalid_zone_type_allowlist_shape",
                "zone",
                [object_summary(zone, "zone")],
                f"{zone_key}:invalid-type-allowlist-shape",
                "Zone whitelistedTypeId is not an array in the export.",
                "Restore the exported type allowlist and confirm each permitted tag type.",
            )
        if restrictions.get("enable") and not as_list(restrictions.get("whitelistedTypeId")):
            builder.add_finding(
                "zone_structure",
                "empty_enabled_zone_type_allowlist",
                "zone",
                [object_summary(zone, "zone")],
                f"{zone_key}:empty-type-allowlist",
                "Zone enables type restrictions but exports no whitelisted type IDs.",
                "Confirm an intentional deny-all policy or restore the required type allowlist.",
                "cleanup_operation | documented_exception | owner_decision_needed",
            )


def add_duplicate_code_findings(
    builder: BaselineBuilder, tags: list[dict[str, Any]], variables: list[dict[str, Any]]
) -> None:
    custom_objects: list[tuple[str, dict[str, Any], str]] = []
    for tag in tags:
        code = code_value(tag)
        if code:
            custom_objects.append(("tag", tag, code))
    for variable in variables:
        code = code_value(variable)
        if code:
            custom_objects.append(("variable", variable, code))

    builder.add_module("duplicate_custom_code", len(custom_objects))
    groups: dict[str, list[tuple[str, dict[str, Any], str]]] = collections.defaultdict(list)
    for layer, obj, code in custom_objects:
        identity = code_identity_text(code)
        if identity.strip():
            groups[signature(identity)].append((layer, obj, identity))

    for code_hash, group in sorted(groups.items()):
        if len(group) < 2:
            continue
        builder.add_finding(
            "duplicate_custom_code",
            "duplicate_custom_code",
            "custom_code",
            [object_summary(obj, layer) for layer, obj, _ in group],
            code_hash,
            f"{len(group)} custom-code objects share the same exact code identity hash {code_hash}.",
            "Consolidate or document why identical code must remain separate.",
        )


def add_builtin_mirror_findings(
    builder: BaselineBuilder,
    variables: list[dict[str, Any]],
    builtins: list[dict[str, Any]],
) -> None:
    builtin_names = {object_name(item) for item in builtins if object_name(item)}
    builder.add_module("variables_mirroring_builtins", len(variables))
    return_re = re.compile(
        r"^function\s*\([^)]*\)\s*\{\s*return\s+\{\{([^{}]+)\}\}\s*;?\s*\}\s*;?$",
        re.I,
    )
    for variable in variables:
        code = normalized_code(code_value(variable))
        match = return_re.match(code)
        if not match or match.group(1) not in builtin_names:
            continue
        builtin_name = match.group(1)
        builder.add_finding(
            "variables_mirroring_builtins",
            "variable_mirrors_builtin",
            "variable",
            [object_summary(variable, "variable")],
            f"variable:{object_id(variable, 'variable')}:builtin:{builtin_name}",
            f"The custom JavaScript variable only returns built-in variable {builtin_name!r}.",
            f"Remap consumers directly to {{{{{builtin_name}}}}} and delete the wrapper after output-equivalence verification.",
        )


def add_custom_formula_findings(
    builder: BaselineBuilder,
    variables: list[dict[str, Any]],
) -> None:
    custom_variables = [variable for variable in variables if code_value(variable)]
    builder.add_module("custom_variable_formula_logic", len(custom_variables))
    for variable in custom_variables:
        formula = expression_facts(code_value(variable))
        if not formula.get("fixed_slot_aggregation"):
            continue
        expressions = [
            str(row.get("expression") or "")
            for row in as_list(formula.get("return_expressions"))
            if row.get("expression")
        ]
        builder.add_finding(
            "custom_variable_formula_logic",
            "fixed_slot_business_formula",
            "variable",
            [object_summary(variable, "variable")],
            f"fixed_formula:{object_id(variable, 'variable')}:{signature(expressions)}",
            (
                "The custom JavaScript variable adds numbered value slots in return formula(s): "
                + "; ".join(expressions[:3])
                + ". This is not a scalable total for variable-length products or funnel items."
            ),
            (
                "Trace every consumer and replace the fixed-slot formula with the canonical "
                "event total or an item-array calculation that includes quantity and numeric coercion."
            ),
            extra={"formula_facts": formula},
        )


def add_consent_logic_findings(
    builder: BaselineBuilder,
    tags: list[dict[str, Any]],
    variables: list[dict[str, Any]],
    root_path: str,
) -> None:
    conflicts = consent_variable_conflicts(variables)
    builder.add_module("consent_variable_logic", len(variables))
    for conflict in conflicts:
        logic_hash = conflict["logic_hash"]
        purposes = conflict["purposes"]
        group = conflict["variables"]
        builder.add_finding(
            "consent_variable_logic",
            "different_consent_purposes_share_logic",
            "variable",
            [object_summary(variable, "variable") for variable in group],
            f"consent_logic:{logic_hash}",
            (
                f"Consent outputs {purposes!r} use the same exported condition or configuration "
                f"signature {logic_hash}. Analytics and advertising consent must not be assumed "
                "equivalent without an explicit CMP mapping."
            ),
            (
                "Compare each variable with the CMP category contract and separate the logic, "
                "or record the approved reason the purposes intentionally share one condition."
            ),
        )

    builder.add_module("media_tag_consent_route", len(tags))
    media_tags: list[tuple[dict[str, Any], dict[str, Any]]] = []
    tag_routes: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for index, tag in enumerate(tags):
        route = tag_consent_route(
            tag,
            source_path=f"{root_path}.tag[{index}]",
            variables=variables,
            root_path=root_path,
        )
        tag_routes.append((tag, route))
        if not route["consent_settings_shape_valid"]:
            builder.add_finding(
                "media_tag_consent_route",
                "invalid_consent_settings_shape",
                "tag",
                [object_summary(tag, "tag")],
                f"consent_settings_shape:{object_id(tag, 'tag')}",
                "Tag consentSettings is not an object in the export.",
                "Restore a valid consentSettings object before evaluating the tag's control route.",
            )
        if route["raw_consent_status"] and not route["consent_status_known"]:
            builder.add_finding(
                "media_tag_consent_route",
                "unrecognized_manual_consent_status",
                "tag",
                [object_summary(tag, "tag")],
                f"consent_status:{object_id(tag, 'tag')}:{route['raw_consent_status']}",
                f"Tag exports unrecognized manual consent status {route['raw_consent_status']!r}.",
                "Restore one of the official GTM manual-consent status values and re-evaluate the route.",
            )
        if not route["requires_media_consent_review"]:
            continue
        if route["effective_control_status"] in {
            "explicit_export_control",
            "native_consent_capability",
            "server_forwarding_candidate",
        }:
            continue
        media_tags.append((tag, route))
    for tag, route in media_tags:
        builder.add_finding(
            "media_tag_consent_route",
            "media_consent_route_requires_review",
            "tag",
            [object_summary(tag, "tag")],
            f"media_consent:{object_id(tag, 'tag')}:{route['effective_control_status']}",
            (
                f"Detected vendors {route['detected_vendors']!r} have effective export control status "
                f"{route['effective_control_status']!r}, consentSettings status "
                f"{route['consent_status']!r}, blockers {route['blocking_trigger_ids']!r}, "
                f"native capability {route['native_consent_capability']!r}, and server hosts "
                f"{route['server_routing_hosts']!r}. Forwarded purposes "
                f"{route['forwarded_consent_purposes']!r} and forwarding variables "
                f"{route['server_consent_forwarding_variables']!r} do not yet establish an "
                "effective client or server consent contract."
            ),
            (
                "Resolve the effective path from CMP state to client execution or server forwarding. "
                "Do not add a client blocker when a complete server-enforced consent contract is "
                "already exported; add or repair control only when that contract is absent or partial."
            ),
            "cleanup_operation | documented_exception | owner_decision_needed",
            extra={"effective_consent_route": route},
        )

    contract_groups: dict[str, list[tuple[dict[str, Any], dict[str, Any]]]] = (
        collections.defaultdict(list)
    )
    for tag, route in tag_routes:
        pairs = nested_parameter_pairs(tag.get("parameter", []))
        events = sorted(
            {
                value
                for key, value in pairs
                if re.sub(r"[^a-z]", "", key.lower()) == "eventname" and value.strip()
            }
        )
        destinations = sorted(
            {
                f"{key.lower()}={value}"
                for key, value in pairs
                if DESTINATION_KEY_RE.search(key) and value.strip()
            }
        )
        if not events or not destinations:
            continue
        contract_key = stable_payload(
            {
                "type": str(tag.get("type") or ""),
                "events": events,
                "destinations": destinations,
            }
        )
        contract_groups[contract_key].append((tag, route))

    for contract_key, group in sorted(contract_groups.items()):
        if len(group) < 2:
            continue
        control_rows = [
            {
                "object_key": f"tag:{object_id(tag, 'tag')}",
                "consent_status": route["consent_status"],
                "additional_consent_checks_visible": route[
                    "additional_consent_checks_visible"
                ],
                "blocking_trigger_ids": route["blocking_trigger_ids"],
                "effective_control_status": route["effective_control_status"],
                "server_routing_hosts": route["server_routing_hosts"],
                "forwarded_consent_purposes": route["forwarded_consent_purposes"],
            }
            for tag, route in group
        ]
        if len({stable_payload(row | {"object_key": ""}) for row in control_rows}) < 2:
            continue
        contract = json.loads(contract_key)
        builder.add_finding(
            "media_tag_consent_route",
            "same_contract_different_consent_control_candidate",
            "tag",
            [object_summary(tag, "tag") for tag, _route in group],
            f"consent_control_collision:{signature(contract)}",
            (
                f"Tags share exact exported event(s) {contract['events']!r}, destination(s) "
                f"{contract['destinations']!r}, and tag type {contract['type']!r}, but their "
                "visible consent-control routes differ. This proves a control collision candidate, "
                "not which route is correct."
            ),
            (
                "Run configuration review for each route, then retain both only when their "
                "business scope and effective consent contracts are independently justified."
            ),
            "cleanup_operation | documented_exception | owner_decision_needed",
            extra={
                "shared_event_destination_contract": contract,
                "consent_control_comparison": control_rows,
            },
        )


def add_name_hygiene_findings(
    builder: BaselineBuilder, cv: dict[str, Any], root_path: str
) -> None:
    items: list[tuple[str, dict[str, Any]]] = []
    for layer in (
        "tag",
        "trigger",
        "variable",
        "folder",
        "zone",
        "customTemplate",
        "client",
        "gtagConfig",
        "transformation",
    ):
        items.extend((layer, item) for item in as_list(cv.get(layer)))
    builder.add_module("name_hygiene", len(items))

    confusable_ascii = str.maketrans(
        {
            "Α": "A",
            "А": "A",
            "Β": "B",
            "В": "B",
            "Ε": "E",
            "Е": "E",
            "Η": "H",
            "Н": "H",
            "Ι": "I",
            "І": "I",
            "Κ": "K",
            "К": "K",
            "Μ": "M",
            "М": "M",
            "Ν": "N",
            "О": "O",
            "Ο": "O",
            "Ρ": "P",
            "Р": "P",
            "С": "C",
            "Τ": "T",
            "Т": "T",
            "Χ": "X",
            "Х": "X",
            "а": "a",
            "е": "e",
            "о": "o",
            "р": "p",
            "с": "c",
            "х": "x",
            "у": "y",
            "і": "i",
            "ј": "j",
        }
    )

    def confusable_skeleton(value: str) -> str:
        return canonical_unicode_text(value).translate(confusable_ascii).casefold()

    by_layer_and_skeleton: dict[tuple[str, str], list[dict[str, Any]]] = (
        collections.defaultdict(list)
    )
    names_by_layer: dict[str, list[str]] = collections.defaultdict(list)
    for item_layer, item in items:
        names_by_layer[item_layer].append(object_name(item))
    variable_targets: dict[str, list[tuple[str, dict[str, Any]]]] = (
        collections.defaultdict(list)
    )
    for target_layer in ("variable", "builtInVariable"):
        for target in as_list(cv.get(target_layer)):
            target_name = str(target.get("name") or "")
            if target_name:
                variable_targets[normalized_reference_name(target_name)].append(
                    (target_layer, target)
                )
    for layer, item in items:
        name = object_name(item)
        problems = []
        if not name:
            problems.append("blank name")
        if name != name.strip():
            problems.append("leading/trailing whitespace")
        if re.search(r"\s{2,}", name):
            problems.append("repeated whitespace")
        if re.search(r"\s+-\s+-\s+", name) or "--" in name:
            problems.append("duplicated separator")
        unicode_problems = unicode_integrity_problems(name)
        problems.extend(unicode_problems)
        if name:
            by_layer_and_skeleton[(layer, confusable_skeleton(name))].append(item)
        if not problems:
            pass
        else:
            canonical_name = canonical_unicode_text(name)
            collision = bool(
                canonical_name
                and any(
                    other != name
                    and canonical_unicode_text(other).casefold()
                    == canonical_name.casefold()
                    for other in names_by_layer[layer]
                )
            )
            repair_changes: list[dict[str, Any]] = []
            if unicode_problems and canonical_name and not collision:
                if layer in {"variable", "builtInVariable"}:
                    repair_changes.extend(
                        reference_text_changes(
                            cv,
                            root_path,
                            name,
                            canonical_name,
                        )
                    )
                elif layer == "tag":
                    for fact in object_string_fields(cv, root_path):
                        if (
                            fact["json_path"].endswith(".tagName")
                            and fact["value"] == name
                        ):
                            repair_changes.append(
                                {
                                    "object_key": fact["object_key"],
                                    "json_path": fact["json_path"],
                                    "before": name,
                                    "after": canonical_name,
                                }
                            )
            repair = {
                "status": (
                    "unique_canonical_name"
                    if unicode_problems and canonical_name and not collision
                    else "normalization_collision"
                    if unicode_problems and collision
                    else "not_applicable"
                ),
                "repair_kind": "object_name",
                "target_object_key": f"{layer}:{object_id(item, layer)}",
                "target_name": canonical_name,
                "changes": repair_changes,
                "renames": (
                    [
                        {
                            "object_key": f"{layer}:{object_id(item, layer)}",
                            "before": name,
                            "after": canonical_name,
                        }
                    ]
                    if unicode_problems and canonical_name and not collision
                    else []
                ),
            }
            builder.add_finding(
                "name_hygiene",
                (
                    "unicode_name_integrity_candidate"
                    if unicode_problems and collision
                    else "unicode_name_integrity"
                    if unicode_problems
                    else "name_hygiene"
                ),
                layer,
                [object_summary(item, layer)],
                f"name:{object_id(item, layer)}",
                f"Name hygiene issue(s): {', '.join(problems)}.",
                (
                    "Rename to the generated canonical visible spelling and update every "
                    "name-based reference atomically."
                    if unicode_problems
                    else "Fix naming as part of the naming standardization stage or document an exception."
                ),
                extra={
                    "deterministic_repair": repair,
                    "repair_affected_object_keys": sorted(
                        {
                            f"{layer}:{object_id(item, layer)}",
                            *(
                                str(change.get("object_key") or "")
                                for change in repair_changes
                                if str(change.get("object_key") or "")
                            ),
                        }
                    ),
                },
            )

        for reference in sorted(refs(item)):
            reference_problems = unicode_integrity_problems(reference)
            if not reference_problems:
                continue
            targets = variable_targets.get(normalized_reference_name(reference), [])
            repair = {
                "status": "no_unique_container_target",
                "repair_kind": "variable_reference",
                "target_object_key": "",
                "target_name": "",
                "changes": [],
                "renames": [],
            }
            if len(targets) == 1:
                target_layer, target = targets[0]
                target_name = str(target.get("name") or "")
                changes = reference_text_changes(
                    cv,
                    root_path,
                    reference,
                    target_name,
                    object_key_filter={f"{layer}:{object_id(item, layer)}"},
                )
                if changes:
                    repair = {
                        "status": "unique_normalized_target",
                        "repair_kind": "variable_reference",
                        "target_object_key": (
                            f"{target_layer}:{object_id(target, target_layer)}"
                        ),
                        "target_name": target_name,
                        "changes": changes,
                        "renames": [],
                    }
            builder.add_finding(
                "name_hygiene",
                "unicode_reference_integrity",
                layer,
                [object_summary(item, layer)],
                f"reference:{object_id(item, layer)}:{signature(reference)}",
                (
                    f"Variable reference {reference!r} contains "
                    f"{', '.join(reference_problems)}."
                ),
                (
                    f"Replace the reference with exact target {repair['target_name']!r}."
                    if repair["status"] == "unique_normalized_target"
                    else "Resolve the intended variable identity; do not guess when more "
                    "than one variable could be the target."
                ),
                extra={
                    "deterministic_repair": repair,
                    "repair_affected_object_keys": [
                        f"{layer}:{object_id(item, layer)}"
                    ],
                },
            )

    for (layer, skeleton), group in sorted(by_layer_and_skeleton.items()):
        visible_names = {object_name(item) for item in group}
        if len(group) < 2 or len(visible_names) < 2:
            continue
        if not any(
            unicode_integrity_problems(name)
            or canonical_unicode_text(name).casefold() != skeleton
            for name in visible_names
        ):
            continue
        builder.add_finding(
            "name_hygiene",
            "unicode_confusable_name_candidate",
            layer,
            [object_summary(item, layer) for item in group],
            f"unicode_confusable:{layer}:{signature(sorted(visible_names))}",
            (
                f"Names {sorted(visible_names)!r} collapse to the same Unicode-confusable "
                f"skeleton {skeleton!r}; source identity does not prove whether they are "
                "intentional variants."
            ),
            (
                "Confirm the intended identities, then rename and remap atomically when the "
                "visual collision is accidental; otherwise retain a source-specific exception."
            ),
        )


def naming_candidate_counts(
    tags: list[dict[str, Any]],
    triggers: list[dict[str, Any]],
    variables: list[dict[str, Any]],
    folders: list[dict[str, Any]],
    tag_order: str,
    selected: str,
    blocking_trigger_ids: set[str],
) -> dict[str, collections.Counter[str]]:
    counts: dict[str, collections.Counter[str]] = collections.defaultdict(
        collections.Counter
    )
    for tag in tags:
        if default_tag_issue(object_name(tag), tag_order):
            proposed, _ = proposed_tag_name(object_name(tag), tag_order, selected)
            if proposed:
                counts["tag"][proposed] += 1
    for trigger in triggers:
        prefix = trigger_required_prefix(trigger, blocking_trigger_ids)
        if prefix and not object_name(trigger).startswith(f"{prefix} - "):
            proposed = proposed_trigger_name(trigger, prefix)
            if proposed:
                counts["trigger"][proposed] += 1
    for variable in variables:
        prefix = variable_required_prefix(variable)
        if prefix and not object_name(variable).startswith(f"{prefix} - "):
            proposed = proposed_variable_name(variable, prefix)
            if proposed:
                counts["variable"][proposed] += 1
    for folder in folders:
        if " - " in object_name(folder):
            proposed, _ = proposed_folder_name(folder)
            if proposed:
                counts["folder"][proposed] += 1
    return counts


def add_tag_naming_findings(
    builder: BaselineBuilder,
    tags: list[dict[str, Any]],
    module_name: str,
    tag_order: str,
    selected: str,
    candidate_counts: dict[str, collections.Counter[str]],
) -> None:
    pattern = (
        "Vendor - Scope - Event"
        if selected == "local-normalized" and tag_order == "vendor_scope_event"
        else "Vendor - Event - Scope"
    )
    for tag in tags:
        name = object_name(tag)
        issue = default_tag_issue(name, tag_order)
        if not issue:
            continue
        proposed, rename_blocker = proposed_tag_name(name, tag_order, selected)
        uniqueness_blocker = uniqueness_notes(candidate_counts, "tag", proposed)
        blocker = "; ".join(
            item for item in (rename_blocker, uniqueness_blocker) if item
        )
        builder.add_finding(
            module_name,
            "naming_architecture_mismatch",
            "tag",
            [object_summary(tag, "tag")],
            f"tag_name:{object_id(tag, 'tag')}",
            f"{issue}. Selected naming policy is {selected}; target tag pattern is {pattern}.",
            (
                "Rename after behavior, scope, and destination are confirmed. Use the "
                "selected naming policy and keep every final tag name unique."
            ),
            extra={
                "source_lens": "inferred_policy_candidate",
                "policy_confirmation_required": True,
                "selected_naming_policy": selected,
                "target_naming_pattern": pattern,
                "proposed_final_name": proposed,
                "rename_blocker": blocker,
                "rename_candidate_unique": not bool(uniqueness_blocker),
            },
        )


def add_trigger_naming_findings(
    builder: BaselineBuilder,
    triggers: list[dict[str, Any]],
    module_name: str,
    selected: str,
    blocking_trigger_ids: set[str],
    candidate_counts: dict[str, collections.Counter[str]],
) -> None:
    for trigger in triggers:
        prefix = trigger_required_prefix(trigger, blocking_trigger_ids)
        if not prefix or object_name(trigger).startswith(f"{prefix} - "):
            continue
        proposed = proposed_trigger_name(trigger, prefix)
        uniqueness_blocker = uniqueness_notes(candidate_counts, "trigger", proposed)
        builder.add_finding(
            module_name,
            "naming_architecture_mismatch",
            "trigger",
            [object_summary(trigger, "trigger")],
            f"trigger_name:{object_id(trigger, 'trigger')}",
            (
                f"Trigger type {trigger.get('type')!r} should use prefix {prefix!r} "
                "under the selected trigger architecture."
            ),
            (
                "Rename trigger after confirming event, condition, blocking role, and "
                "trigger-group consumers."
            ),
            extra={
                "source_lens": "inferred_policy_candidate",
                "policy_confirmation_required": True,
                "selected_naming_policy": selected,
                "target_naming_pattern": f"{prefix} - event_or_condition",
                "proposed_final_name": proposed,
                "rename_blocker": uniqueness_blocker,
                "rename_candidate_unique": not bool(uniqueness_blocker),
            },
        )


def add_variable_naming_findings(
    builder: BaselineBuilder,
    variables: list[dict[str, Any]],
    module_name: str,
    selected: str,
    candidate_counts: dict[str, collections.Counter[str]],
) -> None:
    for variable in variables:
        prefix = variable_required_prefix(variable)
        if not prefix or object_name(variable).startswith(f"{prefix} - "):
            continue
        proposed = proposed_variable_name(variable, prefix)
        uniqueness_blocker = uniqueness_notes(candidate_counts, "variable", proposed)
        builder.add_finding(
            module_name,
            "naming_architecture_mismatch",
            "variable",
            [object_summary(variable, "variable")],
            f"variable_name:{object_id(variable, 'variable')}",
            (
                f"Variable type {variable.get('type')!r} should use prefix {prefix!r} "
                "under the selected variable naming policy."
            ),
            (
                "Rename variable after dependency sweep across tags, triggers, variables, "
                "templates, Custom HTML, and Custom JavaScript."
            ),
            extra={
                "source_lens": "inferred_policy_candidate",
                "policy_confirmation_required": True,
                "selected_naming_policy": selected,
                "target_naming_pattern": f"{prefix} - name_or_source",
                "proposed_final_name": proposed,
                "rename_blocker": uniqueness_blocker,
                "rename_candidate_unique": not bool(uniqueness_blocker),
            },
        )


def add_folder_naming_findings(
    builder: BaselineBuilder,
    folders: list[dict[str, Any]],
    module_name: str,
    selected: str,
    candidate_counts: dict[str, collections.Counter[str]],
) -> None:
    for folder in folders:
        if " - " not in object_name(folder):
            continue
        proposed, rename_blocker = proposed_folder_name(folder)
        uniqueness_blocker = uniqueness_notes(candidate_counts, "folder", proposed)
        blocker = "; ".join(
            item for item in (rename_blocker, uniqueness_blocker) if item
        )
        builder.add_finding(
            module_name,
            "folder_naming_review",
            "folder",
            [object_summary(folder, "folder")],
            f"folder_name:{object_id(folder, 'folder')}",
            (
                "Folder name contains a scope separator. Default folder policy starts with "
                "area-only folders unless object volume requires deeper ranging."
            ),
            "Keep or simplify folder naming after counting objects per area.",
            "owner_decision_needed | cleanup_operation | documented_exception",
            extra={
                "source_lens": "inferred_policy_candidate",
                "policy_confirmation_required": True,
                "selected_naming_policy": selected,
                "target_naming_pattern": "Area",
                "proposed_final_name": proposed,
                "rename_blocker": blocker,
                "rename_candidate_unique": not bool(uniqueness_blocker),
            },
        )


def add_naming_architecture_findings(
    builder: BaselineBuilder, cv: dict[str, Any], naming_policy: dict[str, Any]
) -> None:
    tags = as_list(cv.get("tag"))
    triggers = as_list(cv.get("trigger"))
    variables = as_list(cv.get("variable"))
    folders = as_list(cv.get("folder"))
    templates = as_list(cv.get("customTemplate"))
    module_name = "naming_architecture_standardization"
    builder.add_module(
        module_name, len(tags) + len(triggers) + len(variables) + len(folders) + len(templates)
    )

    tag_order = str(naming_policy.get("tag_order") or "vendor_event_scope")
    selected = str(naming_policy.get("selected_policy") or "default-standardized")
    if selected != "local-normalized":
        builder.add_finding(
            module_name,
            "naming_policy_confirmation_required",
            "container",
            [],
            "naming_policy:unconfirmed",
            (
                "The export has no dominant, reliable tag naming order. Per-object "
                "conformance cannot be judged against an inferred default without imposing "
                "a policy that the container does not prove."
            ),
            (
                "Confirm the intended naming convention once, then generate the complete "
                "rename set after behavior, canonical objects, remaps, and deletions are settled."
            ),
            extra={
                "source_lens": "inferred_policy_candidate",
                "policy_confirmation_required": True,
                "selected_naming_policy": selected,
                "target_naming_pattern": "Unresolved until owner confirmation",
            },
        )
        return
    blocking_trigger_ids = {
        str(trigger_id) for tag in tags for trigger_id in as_list(tag.get("blockingTriggerId"))
    }
    candidate_counts = naming_candidate_counts(
        tags,
        triggers,
        variables,
        folders,
        tag_order,
        selected,
        blocking_trigger_ids,
    )
    add_tag_naming_findings(
        builder, tags, module_name, tag_order, selected, candidate_counts
    )
    add_trigger_naming_findings(
        builder,
        triggers,
        module_name,
        selected,
        blocking_trigger_ids,
        candidate_counts,
    )
    add_variable_naming_findings(
        builder, variables, module_name, selected, candidate_counts
    )
    add_folder_naming_findings(
        builder, folders, module_name, selected, candidate_counts
    )


def audit_export(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    builder = BaselineBuilder()
    integrity_findings = add_source_integrity_findings(builder, data)
    blocking_integrity = [
        finding for finding in integrity_findings if finding.get("blocking")
    ]
    if blocking_integrity:
        return {
            **source_descriptor(path),
            "kind": "gtm_operational_sanitation_scan",
            "schema_version": 3,
            "run_status": "blocked_source_integrity",
            "blocking_source_findings": blocking_integrity,
            "modules": list(builder.modules.values()),
            "findings": builder.findings,
        }

    cv = container_version(data)
    root_path = container_root_path(data)
    tags = as_list(cv.get("tag"))
    triggers = as_list(cv.get("trigger"))
    variables = as_list(cv.get("variable"))
    folders = as_list(cv.get("folder"))
    templates = as_list(cv.get("customTemplate"))
    builtins = as_list(cv.get("builtInVariable"))
    zones = as_list(cv.get("zone"))
    clients = as_list(cv.get("client"))
    gtag_configs = as_list(cv.get("gtagConfig"))
    transformations = as_list(cv.get("transformation"))

    variable_consumers, trigger_consumers, tag_consumers = build_consumers(cv)
    system_refs = recognized_system_references(variable_consumers, trigger_consumers)
    naming_policy = infer_tag_order(tags)
    reachability = build_execution_reachability(cv)
    lifecycle = build_lifecycle_matrix(
        cv,
        variable_consumers,
        trigger_consumers,
        tag_consumers,
        reachability,
    )
    folder_topology = build_folder_topology(cv)
    destination_matrix = build_destination_matrix(cv)

    builder.add_module(
        "inventory",
        len(tags)
        + len(triggers)
        + len(variables)
        + len(folders)
        + len(templates)
        + len(builtins)
        + len(zones)
        + len(clients)
        + len(gtag_configs)
        + len(transformations),
    )
    builder.add_module("destination_inventory", len(destination_matrix))
    builder.add_module(
        "recognized_system_references",
        sum(len(values) for values in system_refs.values()),
    )
    add_missing_reference_findings(
        builder,
        cv,
        variable_consumers,
        trigger_consumers,
        root_path,
    )
    add_duplicate_name_findings(builder, "duplicate_tag_names", "tag", tags)
    add_duplicate_name_findings(builder, "duplicate_trigger_names", "trigger", triggers)
    add_duplicate_name_findings(builder, "duplicate_variable_names", "variable", variables)
    add_duplicate_name_findings(builder, "duplicate_folder_names", "folder", folders)
    add_duplicate_name_findings(builder, "duplicate_zone_names", "zone", zones)
    add_duplicate_name_findings(
        builder,
        "duplicate_custom_template_names",
        "customTemplate",
        templates,
    )
    add_duplicate_name_findings(builder, "duplicate_client_names", "client", clients)
    add_duplicate_name_findings(
        builder,
        "duplicate_transformation_names",
        "transformation",
        transformations,
    )
    add_signature_findings(
        builder,
        "duplicate_tag_configurations",
        "duplicate_configuration",
        "tag",
        tags,
        TAG_ID_IGNORED,
        "Review duplicate tag configurations; consolidate or document why each copy has a distinct purpose.",
    )
    add_signature_findings(
        builder,
        "normalized_duplicate_tag_signatures",
        "normalized_duplicate_tag_signature",
        "tag",
        tags,
        TAG_NORMALIZED_IGNORED,
        "Compare trigger and route differences; consolidate only if business intent and route behavior are equivalent.",
    )
    add_signature_findings(
        builder,
        "duplicate_trigger_logic",
        "duplicate_configuration",
        "trigger",
        triggers,
        TRIGGER_ID_IGNORED,
        "Consolidate duplicate trigger logic after consumer and route QA.",
    )
    add_signature_findings(
        builder,
        "duplicate_variable_logic",
        "duplicate_configuration",
        "variable",
        variables,
        VARIABLE_ID_IGNORED,
        "Consolidate duplicate variable logic after consumer value QA.",
    )
    add_signature_findings(
        builder,
        "duplicate_zone_configurations",
        "duplicate_configuration",
        "zone",
        zones,
        COMMON_IGNORED | {"zoneId", "name"},
        "Compare child-container scope, boundary logic, and type restrictions before consolidation.",
    )
    add_signature_findings(
        builder,
        "duplicate_google_tag_configurations",
        "duplicate_configuration",
        "gtagConfig",
        gtag_configs,
        COMMON_IGNORED | {"gtagConfigId"},
        "Compare destination, transport, consent, and inherited event behavior before consolidation.",
    )
    add_signature_findings(
        builder,
        "duplicate_client_configurations",
        "duplicate_configuration",
        "client",
        clients,
        COMMON_IGNORED | {"clientId", "name"},
        "Consolidate duplicate server clients only after request-claiming and event-output QA.",
    )
    add_signature_findings(
        builder,
        "duplicate_transformation_configurations",
        "duplicate_configuration",
        "transformation",
        transformations,
        COMMON_IGNORED | {"transformationId", "name"},
        "Consolidate duplicate transformations only after affected-tag and event-data QA.",
    )
    add_signature_findings(
        builder,
        "duplicate_custom_template_configurations",
        "duplicate_configuration",
        "customTemplate",
        templates,
        COMMON_IGNORED | {"templateId", "name"},
        "Consolidate identical custom templates only after every consuming object is remapped.",
    )

    builder.add_module("duplicate_variable_paths", len(variables))
    path_groups = group_by(
        [variable for variable in variables if param_value(variable, "name")],
        lambda variable: param_value(variable, "name"),
    )
    for path_value, group in sorted(path_groups.items()):
        if len(group) < 2:
            continue
        builder.add_finding(
            "duplicate_variable_paths",
            "duplicate_variable_path",
            "variable",
            [object_summary(variable, "variable") for variable in group],
            f"path:{path_value}",
            f"{len(group)} variables read the same source path {path_value!r}.",
            "Pick a canonical variable or document why separate variables are required.",
        )

    add_ua_styled_setup_findings(
        builder,
        tags,
        triggers,
        variables,
        variable_consumers,
        trigger_consumers,
        root_path,
    )
    add_unused_findings(builder, cv, lifecycle)
    add_lifecycle_findings(builder, lifecycle)
    add_tag_sequence_findings(builder, tags)
    execution_control_matrix = add_tag_execution_control_findings(builder, tags)
    add_trigger_group_findings(builder, triggers, trigger_consumers)
    add_zone_structure_findings(builder, zones)
    add_duplicate_code_findings(builder, tags, variables)
    add_builtin_mirror_findings(builder, variables, builtins)
    add_custom_formula_findings(builder, variables)
    add_consent_logic_findings(builder, tags, variables, root_path)
    trigger_lint_summary = add_trigger_lint_findings(
        builder, tags, triggers, zones, trigger_consumers, root_path
    )
    add_folder_topology_findings(builder, folder_topology)
    add_name_hygiene_findings(builder, cv, root_path)
    add_naming_architecture_findings(builder, cv, naming_policy)
    builder.close_zero_modules()

    return {
        **source_descriptor(path),
        "kind": "gtm_operational_sanitation_scan",
        "schema_version": 3,
        "run_status": "complete",
        "counts": {
            "tags": len(tags),
            "triggers": len(triggers),
            "variables": len(variables),
            "folders": len(folders),
            "customTemplates": len(templates),
            "builtInVariables": len(builtins),
            "zones": len(zones),
            "clients": len(clients),
            "gtagConfigs": len(gtag_configs),
            "transformations": len(transformations),
        },
        "recognized_system_references": system_refs,
        "naming_policy": naming_policy,
        "execution_reachability": reachability,
        "lifecycle_matrix": lifecycle,
        "execution_control_matrix": execution_control_matrix,
        "folder_topology": folder_topology,
        "destination_matrix": destination_matrix,
        "trigger_lint_summary": trigger_lint_summary,
        "modules": list(builder.modules.values()),
        "findings": builder.findings,
    }
