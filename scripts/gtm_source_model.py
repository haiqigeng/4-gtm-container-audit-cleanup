#!/usr/bin/env python3
"""Build a GTM source-model navigation map from an export.

The source model is not a replacement for the raw GTM export/API evidence. It is
the cross-reference map used by cleanup lenses to navigate back to object
configuration, fields, variables, triggers, custom code, and unresolved edges.
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
from pathlib import Path
from typing import Any

from gtm_lib import (
    ID_KEYS,
    OBJECT_LAYERS,
    SEMANTIC_LAYERS,
    as_list,
    code_identity_text,
    container_identity,
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
    system_reference_description,
    trigger_group_members,
    walk_json_fields,
)


def code_hash(text: str) -> str:
    identity = code_identity_text(text)
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16] if identity.strip() else ""


def object_id(obj: dict[str, Any], layer: str) -> str:
    value = obj.get(ID_KEYS[layer]) or obj.get("name")
    return "" if value is None else str(value)


def object_summary(obj: dict[str, Any], layer: str) -> dict[str, str]:
    return {
        "layer": layer,
        "object_id": object_id(obj, layer),
        "object_name": str(obj.get("name") or ""),
        "type": str(obj.get("type") or ("customTemplate" if layer == "customTemplate" else "")),
    }


def parameter_edges(
    layer: str,
    obj: dict[str, Any],
    object_index: int,
    root_path: str,
) -> list[dict[str, Any]]:
    edges = []
    for parameter_index, param in enumerate(as_list(obj.get("parameter"))):
        base_path = f"{root_path}.{layer}[{object_index}].parameter[{parameter_index}]"
        for fact in walk_json_fields(
            param,
            base_path,
            object_name=str(obj.get("name") or ""),
        ):
            edges.append(
                {
                    "source_layer": layer,
                    "source_id": object_id(obj, layer),
                    "source_name": str(obj.get("name") or ""),
                    "field_key": str(param.get("key") or ""),
                    "field_type": str(param.get("type") or ""),
                    **fact,
                }
            )
    return edges


def build_variable_consumers(cv: dict[str, Any]) -> dict[str, list[dict[str, str]]]:
    consumers: dict[str, list[dict[str, str]]] = collections.defaultdict(list)
    for layer in SEMANTIC_LAYERS:
        if layer == "customTemplate":
            continue
        for obj in as_list(cv.get(layer)):
            for ref in sorted(refs(obj)):
                if layer == "variable" and ref == obj.get("name"):
                    continue
                consumers[ref].append(object_summary(obj, layer))
    return dict(consumers)


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


def custom_code_body(layer: str, obj: dict[str, Any]) -> str:
    if layer == "tag":
        return str(param_value(obj, "html") or "")
    if layer == "variable":
        return str(param_value(obj, "javascript") or "")
    return str(obj.get("templateData") or "")


def trigger_relationships(
    tags: list[dict[str, Any]],
    triggers: list[dict[str, Any]],
    zones: list[dict[str, Any]],
) -> tuple[list[dict[str, str]], dict[str, list[dict[str, str]]]]:
    edges: list[dict[str, str]] = []
    consumers: dict[str, list[dict[str, str]]] = collections.defaultdict(list)
    for tag in tags:
        for relation in ("firingTriggerId", "blockingTriggerId"):
            for trigger_id in as_list(tag.get(relation)):
                target = str(trigger_id)
                edges.append(
                    {
                        "source_layer": "tag",
                        "source_id": object_id(tag, "tag"),
                        "source_name": str(tag.get("name") or ""),
                        "relation": relation,
                        "target_trigger_id": target,
                    }
                )
                consumers[target].append(object_summary(tag, "tag"))
    for trigger in triggers:
        for member_id in trigger_group_members(trigger):
            target = str(member_id)
            edges.append(
                {
                    "source_layer": "trigger",
                    "source_id": object_id(trigger, "trigger"),
                    "source_name": str(trigger.get("name") or ""),
                    "relation": "trigger_group_member",
                    "target_trigger_id": target,
                }
            )
            consumers[target].append(object_summary(trigger, "trigger"))
    for zone in zones:
        boundary = zone.get("boundary") if isinstance(zone.get("boundary"), dict) else {}
        for trigger_id in as_list(boundary.get("customEvaluationTriggerId")):
            target = str(trigger_id)
            edges.append(
                {
                    "source_layer": "zone",
                    "source_id": object_id(zone, "zone"),
                    "source_name": str(zone.get("name") or ""),
                    "relation": "zone_boundary_trigger",
                    "target_trigger_id": target,
                }
            )
            consumers[target].append(object_summary(zone, "zone"))
    return edges, dict(consumers)


def all_parameter_edges(
    layer_items: dict[str, list[dict[str, Any]]], root_path: str
) -> list[dict[str, Any]]:
    edges = []
    for layer in SEMANTIC_LAYERS:
        for index, obj in enumerate(layer_items[layer]):
            edges.extend(parameter_edges(layer, obj, index, root_path))
    return edges


def variable_source_rows(
    variables: list[dict[str, Any]],
    variable_consumers: dict[str, list[dict[str, str]]],
) -> list[dict[str, Any]]:
    return [
        {
            **object_summary(variable, "variable"),
            "data_layer_path": param_value(variable, "name"),
            "javascript_hash": code_hash(str(param_value(variable, "javascript") or "")),
            "referenced_variables": sorted(refs(variable)),
            "consumers": variable_consumers.get(variable.get("name"), []),
        }
        for variable in variables
    ]


def is_custom_code_object(layer: str, obj: dict[str, Any], body: str) -> bool:
    return bool(body) and (
        layer == "customTemplate"
        or str(obj.get("type") or "").lower() in {"html", "jsm"}
        or bool(param_value(obj, "html"))
        or bool(param_value(obj, "javascript"))
    )


def custom_code_rows(
    layer_items: dict[str, list[dict[str, Any]]],
    variable_consumers: dict[str, list[dict[str, str]]],
) -> list[dict[str, Any]]:
    rows = []
    for layer in ("tag", "variable", "customTemplate"):
        for obj in layer_items[layer]:
            body = custom_code_body(layer, obj)
            if not is_custom_code_object(layer, obj, body):
                continue
            rows.append(
                {
                    **object_summary(obj, layer),
                    "code_hash": code_hash(body),
                    "code_length": len(body),
                    "referenced_variables": sorted(refs(obj)),
                    "consumers": variable_consumers.get(obj.get("name"), [])
                    if layer == "variable"
                    else [],
                }
            )
    return rows


def unresolved_model_edges(
    layer_items: dict[str, list[dict[str, Any]]],
    variable_consumers: dict[str, list[dict[str, str]]],
    trigger_consumers: dict[str, list[dict[str, str]]],
) -> dict[str, list[str]]:
    tags = layer_items["tag"]
    variables = layer_items["variable"]
    builtins = layer_items["builtInVariable"]
    triggers = layer_items["trigger"]
    folders = layer_items["folder"]
    templates = layer_items["customTemplate"]
    referenced_objects = [obj for layer in SEMANTIC_LAYERS for obj in layer_items[layer]]
    variable_names = {obj.get("name") for obj in variables + builtins}
    trigger_ids = {str(obj.get("triggerId")) for obj in triggers}
    folder_ids = {str(obj.get("folderId")) for obj in folders}
    template_ids = {str(obj.get("templateId")) for obj in templates}
    template_type_index = custom_template_type_index(templates)
    tag_names = {obj.get("name") for obj in tags}
    return {
        "undefined_variable_references": sorted(
            ref
            for ref in variable_consumers
            if ref not in variable_names and not is_system_variable_reference(ref)
        ),
        "missing_trigger_references": sorted(
            ref
            for ref in trigger_consumers
            if ref not in trigger_ids and not is_system_trigger_reference(ref)
        ),
        "missing_folder_references": sorted(
            {
                str(obj.get("parentFolderId"))
                for obj in referenced_objects
                if obj.get("parentFolderId")
                and str(obj.get("parentFolderId")) not in folder_ids
            }
        ),
        "missing_custom_template_references": sorted(
            {
                template_id
                for obj in referenced_objects
                for template_id in custom_template_ids(obj, template_type_index)
                if template_id and template_id not in template_ids
            }
        ),
        "missing_setup_teardown_references": sorted(
            {
                ref.get("tagName")
                for tag in tags
                for relation in ("setupTag", "teardownTag")
                for ref in as_list(tag.get(relation))
                if isinstance(ref, dict)
                and ref.get("tagName")
                and ref.get("tagName") not in tag_names
            }
        ),
    }


def source_model_counts(
    layer_items: dict[str, list[dict[str, Any]]],
    field_edges: list[dict[str, Any]],
    trigger_edges: list[dict[str, str]],
    code_rows: list[dict[str, Any]],
    unresolved_count: int,
    system_refs: dict[str, list[dict[str, Any]]],
) -> dict[str, int]:
    return {
        "tags": len(layer_items["tag"]),
        "triggers": len(layer_items["trigger"]),
        "variables": len(layer_items["variable"]),
        "folders": len(layer_items["folder"]),
        "customTemplates": len(layer_items["customTemplate"]),
        "zones": len(layer_items["zone"]),
        "gtagConfigs": len(layer_items["gtagConfig"]),
        "builtInVariables": len(layer_items["builtInVariable"]),
        "field_edges": len(field_edges),
        "trigger_edges": len(trigger_edges),
        "custom_code_objects": len(code_rows),
        "unresolved_edges": unresolved_count,
        "recognized_system_references": sum(len(values) for values in system_refs.values()),
    }


def build_model(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    source_findings = source_integrity_findings(data)
    try:
        cv = container_version(data)
    except ValueError:
        cv = {}
    root_path = container_root_path(data) if isinstance(data, dict) else "$"
    layer_items = {
        layer: [obj for obj in as_list(cv.get(layer)) if isinstance(obj, dict)]
        for layer in OBJECT_LAYERS
    }
    variable_consumers = build_variable_consumers(layer_items)
    trigger_edges, trigger_consumers = trigger_relationships(
        layer_items["tag"], layer_items["trigger"], layer_items["zone"]
    )
    field_edges = all_parameter_edges(layer_items, root_path)
    variable_sources = variable_source_rows(layer_items["variable"], variable_consumers)
    custom_code_objects = custom_code_rows(layer_items, variable_consumers)
    system_refs = recognized_system_references(variable_consumers, trigger_consumers)
    unresolved_edges = unresolved_model_edges(
        layer_items, variable_consumers, trigger_consumers
    )
    unresolved_count = sum(len(values) for values in unresolved_edges.values())
    source_blocked = any(bool(row.get("blocking")) for row in source_findings)
    coverage_gate = (
        "blocked_source_integrity"
        if source_blocked
        else "pass_with_integrity_findings"
        if unresolved_count or source_findings
        else "pass"
    )
    counts = source_model_counts(
        layer_items,
        field_edges,
        trigger_edges,
        custom_code_objects,
        unresolved_count,
        system_refs,
    )
    counts["source_integrity_findings"] = len(source_findings)

    return {
        **source_descriptor(path),
        "kind": "gtm_source_model_navigation_map",
        "source_model_role": "navigation_map_not_evidence_source",
        "raw_evidence_must_be_rechecked_for_findings": True,
        "container_identity": container_identity(data) if isinstance(data, dict) else {},
        "counts": counts,
        "objects": {
            "tags": [object_summary(obj, "tag") for obj in layer_items["tag"]],
            "triggers": [object_summary(obj, "trigger") for obj in layer_items["trigger"]],
            "variables": [object_summary(obj, "variable") for obj in layer_items["variable"]],
            "customTemplates": [
                object_summary(obj, "customTemplate")
                for obj in layer_items["customTemplate"]
            ],
            "zones": [object_summary(obj, "zone") for obj in layer_items["zone"]],
            "gtagConfigs": [
                object_summary(obj, "gtagConfig") for obj in layer_items["gtagConfig"]
            ],
        },
        "field_edges": field_edges,
        "trigger_edges": trigger_edges,
        "variable_sources": variable_sources,
        "custom_code_objects": custom_code_objects,
        "trigger_consumers": dict(trigger_consumers),
        "variable_consumers": variable_consumers,
        "recognized_system_references": system_refs,
        "source_integrity_findings": source_findings,
        "unresolved_edges": unresolved_edges,
        "coverage_gate": coverage_gate,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("export", type=Path, help="Path to a GTM container export JSON")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output")
    args = parser.parse_args()

    result = build_model(args.export)
    print(json.dumps(result, ensure_ascii=False, indent=2 if args.pretty else None))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
