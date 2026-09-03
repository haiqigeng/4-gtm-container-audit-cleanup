#!/usr/bin/env python3
"""Source-bound facts used by the independent configuration review."""

from __future__ import annotations

import re
import unicodedata
from collections import defaultdict
from typing import Any

from gtm_lib import (
    ID_KEYS,
    SEMANTIC_LAYERS,
    as_list,
    comparable,
    custom_template_executable_code,
    custom_template_ids,
    custom_template_type_index,
    is_system_variable_reference,
    object_id,
    refs,
    safe_scalar_preview,
    stable_hash,
    trigger_group_members,
    walk_json_fields,
)


def layer_objects(cv: dict[str, Any]) -> list[tuple[str, int, dict[str, Any]]]:
    return [
        (layer, index, obj)
        for layer in SEMANTIC_LAYERS
        for index, obj in enumerate(as_list(cv.get(layer)))
    ]


def object_key(layer: str, obj: dict[str, Any]) -> str:
    return f"{layer}:{object_id(obj, ID_KEYS[layer])}"


def object_type(layer: str, obj: dict[str, Any]) -> str:
    fallback = layer if layer in {"customTemplate", "zone", "gtagConfig"} else ""
    return str(obj.get("type") or fallback)


def normalized_reference_name(value: Any) -> str:
    """Normalize invisible compatibility differences without guessing semantics."""

    normalized = unicodedata.normalize("NFKC", str(value or ""))
    normalized = "".join(
        " " if character.isspace() else character for character in normalized
    )
    return re.sub(r" +", " ", normalized).strip()


def object_hash(obj: dict[str, Any]) -> str:
    return stable_hash(comparable(obj, {"path", "fingerprint", "accountId", "containerId"}))


def build_consumers(
    cv: dict[str, Any], root_path: str = "$.containerVersion"
) -> dict[str, list[dict[str, str]]]:
    consumers: dict[str, list[dict[str, str]]] = defaultdict(list)
    template_type_index = custom_template_type_index(
        as_list(cv.get("customTemplate"))
    )
    for layer, index, obj in layer_objects(cv):
        key = object_key(layer, obj)
        name = str(obj.get("name") or "")
        for fact in walk_json_fields(obj, f"{root_path}.{layer}[{index}]"):
            for reference in fact["referenced_variables"]:
                consumers[f"variable-name:{reference}"].append(
                    {
                        "consumer_key": key,
                        "consumer_name": name,
                        "relation": "variable_reference",
                        "source_json_path": fact["json_path"],
                    }
                )

    for tag_index, tag in enumerate(as_list(cv.get("tag"))):
        tag_key = object_key("tag", tag)
        tag_name = str(tag.get("name") or "")
        for relation in ("firingTriggerId", "blockingTriggerId"):
            for trigger_id in as_list(tag.get(relation)):
                consumers[f"trigger-id:{trigger_id}"].append(
                    {
                        "consumer_key": tag_key,
                        "consumer_name": tag_name,
                        "relation": relation,
                        "source_json_path": f"{root_path}.tag[{tag_index}].{relation}",
                    }
                )
        for relation in ("setupTag", "teardownTag"):
            for reference_index, reference in enumerate(as_list(tag.get(relation))):
                if not isinstance(reference, dict):
                    continue
                referenced_name = str(reference.get("tagName") or "")
                if referenced_name:
                    consumers[f"tag-name:{referenced_name}"].append(
                        {
                            "consumer_key": tag_key,
                            "consumer_name": tag_name,
                            "relation": relation,
                            "source_json_path": (
                                f"{root_path}.tag[{tag_index}].{relation}"
                                f"[{reference_index}].tagName"
                            ),
                        }
                    )

    trigger_indexes = {
        str(trigger.get("triggerId") or ""): index
        for index, trigger in enumerate(as_list(cv.get("trigger")))
    }
    for trigger_index, trigger in enumerate(as_list(cv.get("trigger"))):
        group_key = object_key("trigger", trigger)
        for member_id in trigger_group_members(trigger):
            if str(member_id) not in trigger_indexes:
                continue
            consumers[f"trigger-id:{member_id}"].append(
                {
                    "consumer_key": group_key,
                    "consumer_name": str(trigger.get("name") or ""),
                    "relation": "trigger_group_member",
                    "source_json_path": (f"{root_path}.trigger[{trigger_index}].parameter"),
                }
            )

    for zone_index, zone in enumerate(as_list(cv.get("zone"))):
        boundary = zone.get("boundary") if isinstance(zone.get("boundary"), dict) else {}
        zone_key = object_key("zone", zone)
        for trigger_id in as_list(boundary.get("customEvaluationTriggerId")):
            consumers[f"trigger-id:{trigger_id}"].append(
                {
                    "consumer_key": zone_key,
                    "consumer_name": str(zone.get("name") or ""),
                    "relation": "zone_boundary_trigger",
                    "source_json_path": (
                        f"{root_path}.zone[{zone_index}].boundary.customEvaluationTriggerId"
                    ),
                }
            )

    for layer, index, obj in layer_objects(cv):
        folder_id = str(obj.get("parentFolderId") or "")
        if folder_id:
            consumers[f"folder-id:{folder_id}"].append(
                {
                    "consumer_key": object_key(layer, obj),
                    "consumer_name": str(obj.get("name") or ""),
                    "relation": "parent_folder",
                    "source_json_path": (f"{root_path}.{layer}[{index}].parentFolderId"),
                }
            )

    for layer in ("tag", "variable", "gtagConfig"):
        for index, obj in enumerate(as_list(cv.get(layer))):
            for template_id in custom_template_ids(obj, template_type_index):
                consumers[f"template-id:{template_id}"].append(
                    {
                        "consumer_key": object_key(layer, obj),
                        "consumer_name": str(obj.get("name") or ""),
                        "relation": "custom_template",
                        "source_json_path": f"{root_path}.{layer}[{index}].type",
                    }
                )
    return dict(consumers)


def object_consumers(
    layer: str, obj: dict[str, Any], consumers: dict[str, list[dict[str, str]]]
) -> list[dict[str, str]]:
    keys = {
        "variable": f"variable-name:{obj.get('name') or ''}",
        "trigger": f"trigger-id:{obj.get('triggerId') or ''}",
        "customTemplate": f"template-id:{obj.get('templateId') or ''}",
        "tag": f"tag-name:{obj.get('name') or ''}",
        "folder": f"folder-id:{obj.get('folderId') or ''}",
    }
    return consumers.get(keys.get(layer, ""), [])


def specific_tokens(obj: dict[str, Any]) -> list[str]:
    tokens: set[str] = {
        token.lower() for token in re.findall(r"[A-Za-z0-9_.-]{4,}", str(obj.get("name") or ""))
    }
    for parameter in as_list(obj.get("parameter")):
        if not isinstance(parameter, dict):
            continue
        key = str(parameter.get("key") or "")
        if len(key) >= 4:
            tokens.add(key.lower())
    tokens.update(reference.lower() for reference in refs(obj) if len(reference) >= 4)
    for trigger_id in as_list(obj.get("firingTriggerId")) + as_list(obj.get("blockingTriggerId")):
        tokens.add(str(trigger_id).lower())
    for fact in walk_json_fields(obj):
        for token in re.findall(
            r"(?:ecommerce|eventModel|items?|products?|consent|storage)"
            r"[A-Za-z0-9_.\[\]-]*",
            str(fact.get("value_preview") or ""),
            re.I,
        ):
            if len(token) >= 4:
                tokens.add(token.lower())
    return sorted(tokens)[:80]


def logic_anchors(facts: list[dict[str, Any]]) -> list[str]:
    ignored_suffixes = (
        ".accountId",
        ".containerId",
        ".workspaceId",
        ".fingerprint",
        ".path",
        ".tagManagerUrl",
        ".notes",
        ".parentFolderId",
        ".tagId",
        ".triggerId",
        ".variableId",
        ".templateId",
        ".zoneId",
        ".gtagConfigId",
        ".name",
    )
    return [fact["json_path"] for fact in facts if not fact["json_path"].endswith(ignored_suffixes)]


def parameter_value(obj: dict[str, Any], key: str) -> str:
    for parameter in as_list(obj.get("parameter")):
        if not isinstance(parameter, dict):
            continue
        if parameter.get("key") == key and parameter.get("value") is not None:
            return str(parameter["value"])
    return ""


def static_reference_values(
    cv: dict[str, Any],
    reference: str,
    active: tuple[str, ...] = (),
) -> list[str]:
    """Resolve source-visible scalar outcomes without inventing runtime values."""
    if reference in active:
        return []
    matches = [
        item
        for item in as_list(cv.get("variable"))
        if str(item.get("name") or "") == reference
    ]
    if len(matches) != 1:
        return []
    variable = matches[0]
    variable_type = str(variable.get("type") or "")
    if variable_type == "c":
        value = parameter_value(variable, "value").strip()
        return [value] if value else []
    if variable_type == "jsm":
        code = parameter_value(variable, "javascript")
        match = re.fullmatch(
            r"\s*function\s*\(\s*\)\s*\{\s*return\s+(['\"])(.*?)\1\s*;?\s*\}\s*",
            code,
            re.S,
        )
        return [match.group(2)] if match else []
    values: list[str] = []
    for parameter in as_list(variable.get("parameter")):
        if not isinstance(parameter, dict):
            continue
        key = str(parameter.get("key") or "").lower()
        if key not in {"defaultvalue", "output", "value"}:
            continue
        raw = parameter.get("value")
        if not isinstance(raw, str):
            continue
        values.extend(static_scalar_values(cv, raw, (*active, reference)))
    return list(dict.fromkeys(value for value in values if value))


def static_scalar_values(
    cv: dict[str, Any],
    raw_value: str,
    active: tuple[str, ...] = (),
) -> list[str]:
    """Return only literal or recursively source-resolved scalar outcomes."""
    value = str(raw_value or "").strip()
    references = re.findall(r"\{\{([^{}]+)\}\}", value)
    if not references:
        return [value] if value else []
    if value != f"{{{{{references[0]}}}}}" or len(references) != 1:
        return []
    return static_reference_values(cv, references[0], active)


def parameter_static_values(
    cv: dict[str, Any], obj: dict[str, Any], key: str
) -> list[str]:
    return static_scalar_values(cv, parameter_value(obj, key))


def code_body(layer: str, obj: dict[str, Any]) -> str:
    if layer == "tag":
        return parameter_value(obj, "html")
    if layer == "variable":
        return parameter_value(obj, "javascript")
    if layer == "customTemplate":
        return custom_template_executable_code(obj.get("templateData"))
    return ""


def code_segment_behavior_signals(segment: str) -> list[dict[str, Any]]:
    """Return conservative source-visible behavior that segment prose must preserve."""
    lowered = segment.lower()
    signals: list[dict[str, Any]] = []

    def add(signal: str, *term_groups: tuple[str, ...]) -> None:
        signals.append(
            {
                "signal": signal,
                "required_term_groups": [list(group) for group in term_groups],
            }
        )

    if re.search(r"createelement\s*\(\s*['\"]script", lowered):
        add("dynamic_script_creation", ("create", "creates", "createelement"), ("script",))
    if re.search(r"(?:\.src\s*=|setattribute\s*\(\s*['\"]src)", lowered):
        add(
            "script_source_assignment",
            ("assign", "set", "load", "source", "src"),
            ("script", "url", "endpoint", "src"),
        )
    if re.search(r"(?:appendchild|\.append\s*\(|insertbefore)", lowered):
        add(
            "dom_append",
            ("append", "appendchild", "insert", "add"),
            ("dom", "document", "head", "body", "element", "script"),
        )
    if re.search(r"\b(?:fetch|xmlhttprequest|sendbeacon)\b", lowered):
        add(
            "network_request",
            ("request", "network", "fetch", "send", "beacon", "xmlhttprequest"),
        )
    if re.search(r"\bdatalayer\s*\.\s*push\s*\(", lowered):
        add("data_layer_write", ("datalayer",), ("push", "write", "send"))
    vendor_patterns = (
        ("meta", r"\bfbq\s*\(\s*['\"](?:track|trackcustom)['\"]\s*,\s*['\"]([^'\"]+)", ("fbq", "meta")),
        ("tiktok", r"\bttq\s*\.\s*track\s*\(\s*['\"]([^'\"]+)", ("ttq", "tiktok")),
        ("snapchat", r"\bsnaptr\s*\(\s*['\"]track['\"]\s*,\s*['\"]([^'\"]+)", ("snaptr", "snapchat")),
        ("pinterest", r"\bpintrk\s*\(\s*['\"]track['\"]\s*,\s*['\"]([^'\"]+)", ("pintrk", "pinterest")),
    )
    for vendor, pattern, vendor_terms in vendor_patterns:
        match = re.search(pattern, segment, re.I)
        if match:
            add(
                f"{vendor}_event_send",
                vendor_terms,
                ("track", "send", "emit", "output", "event"),
                (match.group(1).lower(),),
            )
    if re.search(r"\b(?:localstorage|sessionstorage|document\.cookie)\b", lowered):
        add(
            "browser_storage_access",
            ("storage", "cookie", "localstorage", "sessionstorage"),
            ("read", "write", "set", "get", "access", "remove"),
        )
    if re.search(r"\baddeventlistener\s*\(", lowered):
        add(
            "event_listener_registration",
            ("listener", "event", "addeventlistener"),
            ("register", "add", "listen", "attach", "addeventlistener"),
        )
    if re.search(r"\b(?:queryselector|getelementbyid|getelementsby)", lowered):
        add(
            "dom_read",
            ("dom", "document", "element", "selector"),
            ("read", "query", "select", "get", "find"),
        )
    if re.search(r"\breturn\b", lowered):
        add("return_value", ("return", "returns", "output", "produce"))
    return signals


def code_line_facts(layer: str, obj: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(code_body(layer, obj).splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        segments = [
            stripped[position : position + 120]
            for position in range(0, len(stripped), 120)
        ]
        for segment_index, segment in enumerate(segments, start=1):
            rows.append(
                {
                    "line_number": line_number,
                    "segment_index": segment_index,
                    "segment_count": len(segments),
                    "line_hash": stable_hash(
                        {
                            "line_number": line_number,
                            "segment_index": segment_index,
                            "segment": segment,
                        }
                    ),
                    "line_preview": safe_scalar_preview(segment, 120),
                    "required_behavior_signals": code_segment_behavior_signals(segment),
                }
            )
    return rows


def reference_trace_requirements(
    cv: dict[str, Any],
    obj: dict[str, Any],
    root_path: str = "$.containerVersion",
    *,
    variables_by_name: dict[str, list[tuple[int, dict[str, Any]]]] | None = None,
    builtin_names: set[str] | None = None,
    source_path: str | None = None,
    source_reference_facts: list[dict[str, Any]] | None = None,
    variable_facts_by_key: dict[str, list[dict[str, Any]]] | None = None,
) -> list[dict[str, Any]]:
    if variables_by_name is None:
        variables_by_name = defaultdict(list)
        for index, variable in enumerate(as_list(cv.get("variable"))):
            if variable.get("name"):
                variables_by_name[str(variable.get("name") or "")].append(
                    (index, variable)
                )
    if builtin_names is None:
        builtin_names = {
            str(variable.get("name") or "")
            for variable in as_list(cv.get("builtInVariable"))
            if variable.get("name")
        }
    variable_facts_by_key = variable_facts_by_key or {}
    all_reference_names = sorted({*variables_by_name, *builtin_names})
    if source_path is None:
        source_path = "$"
        for layer, index, candidate in layer_objects(cv):
            if candidate is obj:
                source_path = f"{root_path}.{layer}[{index}]"
                break
    source_reference_facts = (
        source_reference_facts
        if source_reference_facts is not None
        else walk_json_fields(obj, source_path)
    )

    def normalization_candidates(reference: str) -> list[str]:
        normalized = normalized_reference_name(reference)
        return [
            candidate
            for candidate in all_reference_names
            if candidate != reference
            and normalized_reference_name(candidate) == normalized
        ]

    def visit(
        reference: str,
        active: tuple[str, ...],
        parent_key: str,
        object_keys: set[str],
        anchors: set[str],
        terminal_states: set[str],
        nodes: dict[str, dict[str, Any]],
        edges: set[tuple[str, str, str]],
        terminals: dict[str, dict[str, str]],
    ) -> None:
        if is_system_variable_reference(reference):
            terminal_states.add("system")
            terminal_key = f"system:{reference}"
            terminals[terminal_key] = {
                "terminal_key": terminal_key,
                "state": "system",
                "reference": reference,
                "source_object_key": "",
                "configured_source": f"GTM system variable {reference}",
            }
            return
        targets = variables_by_name.get(reference, [])
        builtin_match = reference in builtin_names
        if len(targets) + int(builtin_match) > 1:
            candidate_keys: list[str] = []
            for index, variable in targets:
                current_key = object_key("variable", variable)
                candidate_keys.append(current_key)
                object_keys.add(current_key)
                facts = variable_facts_by_key.get(current_key) or walk_json_fields(
                    variable, f"{root_path}.variable[{index}]"
                )
                variable_anchors = logic_anchors(facts)
                anchors.update(variable_anchors)
                children = sorted(
                    child
                    for child in refs(variable)
                    if not is_system_variable_reference(child)
                )
                nodes[current_key] = {
                    "object_key": current_key,
                    "object_name": str(variable.get("name") or ""),
                    "object_type": object_type("variable", variable),
                    "config_hash": object_hash(variable),
                    "source_json_path": f"{root_path}.variable[{index}]",
                    "required_evidence_anchors": variable_anchors,
                    "referenced_variables": children,
                    "specificity_tokens": specific_tokens(variable),
                    "configured_parameters": [
                        {
                            "key": str(parameter.get("key") or ""),
                            "type": str(parameter.get("type") or ""),
                            "value_preview": safe_scalar_preview(
                                parameter.get("value"),
                                160,
                                field_name=str(parameter.get("key") or ""),
                                object_name=str(variable.get("name") or ""),
                            ),
                        }
                        for parameter in as_list(variable.get("parameter"))
                        if isinstance(parameter, dict)
                    ],
                    "semantic_role": {
                        "v": "data_layer_read",
                        "c": "constant_value",
                        "jsm": "custom_javascript_computation",
                        "smm": "lookup_or_mapping",
                    }.get(
                        object_type("variable", variable),
                        "configured_variable_transformation",
                    ),
                }
                if parent_key:
                    edges.add((parent_key, current_key, reference))
            if builtin_match:
                candidate_keys.append(f"builtInVariable:{reference}")
            terminal_states.add("ambiguous")
            terminal_key = f"ambiguous:{reference}"
            terminals[terminal_key] = {
                "terminal_key": terminal_key,
                "state": "ambiguous",
                "reference": reference,
                "source_object_key": parent_key,
                "configured_source": (
                    f"Variable name {reference} resolves to "
                    + ", ".join(sorted(candidate_keys))
                ),
            }
            return
        if builtin_match:
            terminal_states.add("built_in")
            terminal_key = f"built_in:{reference}"
            terminals[terminal_key] = {
                "terminal_key": terminal_key,
                "state": "built_in",
                "reference": reference,
                "source_object_key": "",
                "configured_source": f"Enabled GTM built-in variable {reference}",
            }
            return
        if reference in active:
            terminal_states.add("cycle")
            terminal_key = f"cycle:{reference}"
            terminals[terminal_key] = {
                "terminal_key": terminal_key,
                "state": "cycle",
                "reference": reference,
                "source_object_key": parent_key,
                "configured_source": " -> ".join((*active, reference)),
            }
            return
        if not targets:
            candidates = normalization_candidates(reference)
            terminal_states.add("missing")
            terminal_key = f"missing:{reference}"
            terminals[terminal_key] = {
                "terminal_key": terminal_key,
                "state": "missing",
                "reference": reference,
                "source_object_key": parent_key,
                "configured_source": f"Missing GTM variable named {reference}",
                "normalized_reference": normalized_reference_name(reference),
                "normalization_candidate_names": candidates,
                "normalization_resolution": (
                    "unique"
                    if len(candidates) == 1
                    else "ambiguous"
                    if candidates
                    else "none"
                ),
            }
            return
        index, variable = targets[0]
        current_key = object_key("variable", variable)
        object_keys.add(current_key)
        facts = variable_facts_by_key.get(current_key) or walk_json_fields(
            variable, f"{root_path}.variable[{index}]"
        )
        variable_anchors = logic_anchors(facts)
        anchors.update(variable_anchors)
        children = sorted(
            child for child in refs(variable) if not is_system_variable_reference(child)
        )
        nodes[current_key] = {
            "object_key": current_key,
            "object_name": str(variable.get("name") or ""),
            "object_type": object_type("variable", variable),
            "config_hash": object_hash(variable),
            "source_json_path": f"{root_path}.variable[{index}]",
            "required_evidence_anchors": variable_anchors,
            "referenced_variables": children,
            "specificity_tokens": specific_tokens(variable),
            "configured_parameters": [
                {
                    "key": str(parameter.get("key") or ""),
                    "type": str(parameter.get("type") or ""),
                    "value_preview": safe_scalar_preview(
                        parameter.get("value"),
                        160,
                        field_name=str(parameter.get("key") or ""),
                        object_name=str(variable.get("name") or ""),
                    ),
                }
                for parameter in as_list(variable.get("parameter"))
                if isinstance(parameter, dict)
            ],
            "semantic_role": {
                "v": "data_layer_read",
                "c": "constant_value",
                "jsm": "custom_javascript_computation",
                "smm": "lookup_or_mapping",
            }.get(object_type("variable", variable), "configured_variable_transformation"),
        }
        if parent_key:
            edges.add((parent_key, current_key, reference))
        if not children:
            terminal_states.add("resolved")
            terminal_key = f"resolved:{current_key}"
            configured_source = "; ".join(
                "{}={}".format(
                    parameter.get("key"),
                    safe_scalar_preview(
                        parameter.get("value"),
                        80,
                        field_name=str(parameter.get("key") or ""),
                        object_name=str(variable.get("name") or ""),
                    ),
                )
                for parameter in as_list(variable.get("parameter"))
                if isinstance(parameter, dict)
                and parameter.get("key")
                and parameter.get("value") is not None
            )
            terminals[terminal_key] = {
                "terminal_key": terminal_key,
                "state": "resolved",
                "reference": reference,
                "source_object_key": current_key,
                "configured_source": configured_source
                or f"Terminal GTM variable type {object_type('variable', variable)}",
            }
            return
        for child in children:
            visit(
                child,
                (*active, reference),
                current_key,
                object_keys,
                anchors,
                terminal_states,
                nodes,
                edges,
                terminals,
            )

    requirements = []
    for reference in sorted(refs(obj)):
        if is_system_variable_reference(reference):
            continue
        object_keys: set[str] = set()
        anchors: set[str] = set()
        terminal_states: set[str] = set()
        nodes: dict[str, dict[str, Any]] = {}
        edges: set[tuple[str, str, str]] = set()
        terminals: dict[str, dict[str, str]] = {}
        visit(
            reference,
            (),
            "",
            object_keys,
            anchors,
            terminal_states,
            nodes,
            edges,
            terminals,
        )
        requirements.append(
            {
                "reference": reference,
                "source_reference_paths": sorted(
                    str(fact.get("json_path") or "")
                    for fact in source_reference_facts
                    if reference in as_list(fact.get("referenced_variables"))
                ),
                "required_object_keys": sorted(object_keys),
                "required_evidence_anchors": sorted(anchors),
                "terminal_states": sorted(terminal_states),
                "required_nodes": [nodes[key] for key in sorted(nodes)],
                "required_edges": [
                    {
                        "from_object_key": source,
                        "to_object_key": target,
                        "reference": child_reference,
                    }
                    for source, target, child_reference in sorted(edges)
                ],
                "terminal_requirements": [terminals[key] for key in sorted(terminals)],
            }
        )
    return requirements
