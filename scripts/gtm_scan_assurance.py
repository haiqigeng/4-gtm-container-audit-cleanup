#!/usr/bin/env python3
"""Independently assure critical invariants in a canonical GTM scan.

The checks reread raw JSON and deliberately avoid the canonical scanner's graph,
normalisation, settings, relationship, and candidate-generation functions.
"""

from __future__ import annotations

import argparse
import json
import re
import tomllib
from collections import defaultdict
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from gtm_audit_contract import AUDIT_AREAS
from gtm_lib import (
    ID_KEYS,
    as_list,
    container_root_path,
    container_version,
    file_sha256,
    stable_hash,
    write_json,
)

REF_RE = re.compile(r"\{\{([^{}]+)\}\}")
URL_RE = re.compile(r"https?://[^\s\"'<>\\)]+", re.I)
HOST_FIELD_RE = re.compile(r"server_container_url|transport_url|endpoint|url", re.I)
CONSENT_FIELD_RE = re.compile(
    r"consent|didomi|onetrust|optanon|cookiebot|analytics_storage|ad_storage|"
    r"ad_user_data|ad_personalization",
    re.I,
)
EVENT_FIELD_RE = re.compile(r"event(?:name)?$", re.I)
CODE_PARAMETER_KEYS = {"html", "javascript"}
CUSTOM_TEMPLATE_SECTION_RE = re.compile(r"(?m)^___([A-Z0-9_]+)___\s*$")
CUSTOM_TEMPLATE_EXECUTABLE_SECTIONS = (
    "SANDBOXED_JS_FOR_WEB_TEMPLATE",
    "SANDBOXED_JS_FOR_SERVER_TEMPLATE",
)
GOOGLE_TAG_TYPES = {"googtag", "gaawe", "gaawc", "gclidw", "flc", "fls"}
GOOGLE_CONFIGURATION_TYPES = {"googtag", "gaawc"}
GOOGLE_EVENT_TYPES = {"gaawe", "googtag"}
SETTINGS_VARIABLE_TYPES = {"gtcs": "configuration", "gtes": "event"}
SETTINGS_REFERENCE_KEYS = {
    "configuration": ("configSettingsVariable", "configurationSettingsVariable"),
    "event": ("eventSettingsVariable",),
}
SETTINGS_TABLE_KEYS = {
    "configuration": ("configSettingsTable", "configurationSettingsTable"),
    "event": ("eventSettingsTable",),
}
ROUTE_PARAMETER_NAMES = {
    "transporturl",
    "servercontainerurl",
    "taggingserverurl",
    "firstpartyurl",
    "serverurl",
}
DESTINATION_PARAMETER_RE = re.compile(
    r"(?:measurement|property|pixel|advertiser|conversion|destination|tag|account).*id$",
    re.I,
)


def _raw_data(path: Path) -> tuple[dict[str, Any], dict[str, Any], str]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return data, container_version(data), container_root_path(data)


def _object_rows(cv: dict[str, Any], root_path: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for layer, id_key in ID_KEYS.items():
        for index, obj in enumerate(as_list(cv.get(layer))):
            if not isinstance(obj, dict):
                continue
            identity = str(obj.get(id_key) or "")
            rows.append(
                {
                    "object_key": f"{layer}:{identity}",
                    "layer": layer,
                    "object_id": identity,
                    "object_name": str(obj.get("name") or ""),
                    "object_type": str(obj.get("type") or layer),
                    "source_json_path": f"{root_path}.{layer}[{index}]",
                    "object": obj,
                }
            )
    return rows


def _walk(value: Any, path: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}"
            if isinstance(child, (dict, list)):
                if child:
                    rows.extend(_walk(child, child_path))
                else:
                    rows.append(
                        {
                            "json_path": child_path,
                            "field": key,
                            "value_sha256": stable_hash(child, 32),
                            "references": [],
                        }
                    )
            else:
                rendered = "" if child is None else str(child)
                rows.append(
                    {
                        "json_path": child_path,
                        "field": key,
                        "value_sha256": stable_hash(child, 32),
                        "references": sorted(set(REF_RE.findall(rendered))),
                    }
                )
    elif isinstance(value, list):
        for index, child in enumerate(value):
            child_path = f"{path}[{index}]"
            if isinstance(child, (dict, list)):
                if child:
                    rows.extend(_walk(child, child_path))
                else:
                    rows.append(
                        {
                            "json_path": child_path,
                            "field": "",
                            "value_sha256": stable_hash(child, 32),
                            "references": [],
                        }
                    )
            else:
                rendered = "" if child is None else str(child)
                rows.append(
                    {
                        "json_path": child_path,
                        "field": "",
                        "value_sha256": stable_hash(child, 32),
                        "references": sorted(set(REF_RE.findall(rendered))),
                    }
                )
    return rows


def _reference_edges(objects: list[dict[str, Any]]) -> list[dict[str, str]]:
    variables_by_name = defaultdict(list)
    triggers_by_id = defaultdict(list)
    tags_by_name = defaultdict(list)
    folders_by_id = defaultdict(list)
    for row in objects:
        if row["layer"] == "variable":
            variables_by_name[row["object_name"]].append(row["object_key"])
        elif row["layer"] == "trigger":
            triggers_by_id[row["object_id"]].append(row["object_key"])
        elif row["layer"] == "tag":
            tags_by_name[row["object_name"]].append(row["object_key"])
        elif row["layer"] == "folder":
            folders_by_id[row["object_id"]].append(row["object_key"])

    edges: list[dict[str, str]] = []
    for row in objects:
        obj = row["object"]
        for leaf in _walk(obj, row["source_json_path"]):
            for reference in leaf["references"]:
                targets = variables_by_name.get(reference, [])
                edges.append(
                    {
                        "from": row["object_key"],
                        "relation": "variable_reference",
                        "reference": reference,
                        "source_json_path": leaf["json_path"],
                        "targets": ",".join(sorted(targets)),
                    }
                )
        if row["layer"] == "tag":
            for field in ("firingTriggerId", "blockingTriggerId"):
                for trigger_id in as_list(obj.get(field)):
                    edges.append(
                        {
                            "from": row["object_key"],
                            "relation": field,
                            "reference": str(trigger_id),
                            "source_json_path": f"{row['source_json_path']}.{field}",
                            "targets": ",".join(sorted(triggers_by_id.get(str(trigger_id), []))),
                        }
                    )
            for field in ("setupTag", "teardownTag"):
                for item in as_list(obj.get(field)):
                    if not isinstance(item, dict):
                        continue
                    tag_name = str(item.get("tagName") or "")
                    if tag_name:
                        edges.append(
                            {
                                "from": row["object_key"],
                                "relation": field,
                                "reference": tag_name,
                                "source_json_path": f"{row['source_json_path']}.{field}",
                                "targets": ",".join(sorted(tags_by_name.get(tag_name, []))),
                            }
                        )
        folder_id = str(obj.get("parentFolderId") or "")
        if folder_id:
            edges.append(
                {
                    "from": row["object_key"],
                    "relation": "parentFolderId",
                    "reference": folder_id,
                    "source_json_path": f"{row['source_json_path']}.parentFolderId",
                    "targets": ",".join(sorted(folders_by_id.get(folder_id, []))),
                }
            )
    return sorted(
        edges,
        key=lambda row: (
            row["from"],
            row["relation"],
            row["source_json_path"],
            row["reference"],
        ),
    )


def _scan_reference_edges(scan: dict[str, Any]) -> list[dict[str, str]]:
    objects = [row for row in as_list(scan.get("objects")) if isinstance(row, dict)]
    variables_by_name = defaultdict(list)
    triggers_by_id = defaultdict(list)
    tags_by_name = defaultdict(list)
    folders_by_id = defaultdict(list)
    for row in objects:
        if row.get("layer") == "variable":
            variables_by_name[str(row.get("object_name") or "")].append(
                str(row.get("object_key") or "")
            )
        elif row.get("layer") == "trigger":
            triggers_by_id[str(row.get("object_id") or "")].append(
                str(row.get("object_key") or "")
            )
        elif row.get("layer") == "tag":
            tags_by_name[str(row.get("object_name") or "")].append(
                str(row.get("object_key") or "")
            )
        elif row.get("layer") == "folder":
            folders_by_id[str(row.get("object_id") or "")].append(
                str(row.get("object_key") or "")
            )

    edges: list[dict[str, str]] = []
    for row in objects:
        object_key = str(row.get("object_key") or "")
        source_path = str(row.get("source_json_path") or "")
        for leaf in as_list(row.get("source_leaf_facts")):
            if not isinstance(leaf, dict):
                continue
            for reference in as_list(leaf.get("referenced_variables")):
                name = str(reference)
                edges.append(
                    {
                        "from": object_key,
                        "relation": "variable_reference",
                        "reference": name,
                        "source_json_path": str(leaf.get("json_path") or ""),
                        "targets": ",".join(sorted(variables_by_name.get(name, []))),
                    }
                )
        if row.get("layer") == "tag":
            for field, values in (
                ("firingTriggerId", row.get("firing_trigger_ids")),
                ("blockingTriggerId", row.get("blocking_trigger_ids")),
            ):
                for trigger_id in as_list(values):
                    identity = str(trigger_id)
                    edges.append(
                        {
                            "from": object_key,
                            "relation": field,
                            "reference": identity,
                            "source_json_path": f"{source_path}.{field}",
                            "targets": ",".join(
                                sorted(triggers_by_id.get(identity, []))
                            ),
                        }
                    )
            for field, values in (
                ("setupTag", row.get("setup_tags")),
                ("teardownTag", row.get("teardown_tags")),
            ):
                for item in as_list(values):
                    if not isinstance(item, dict):
                        continue
                    name = str(item.get("tagName") or "")
                    if name:
                        edges.append(
                            {
                                "from": object_key,
                                "relation": field,
                                "reference": name,
                                "source_json_path": f"{source_path}.{field}",
                                "targets": ",".join(sorted(tags_by_name.get(name, []))),
                            }
                        )
        for leaf in as_list(row.get("source_leaf_facts")):
            if not isinstance(leaf, dict):
                continue
            path = str(leaf.get("json_path") or "")
            if not path.endswith(".parentFolderId"):
                continue
            folder_id = str(leaf.get("value_preview") or "")
            if folder_id:
                edges.append(
                    {
                        "from": object_key,
                        "relation": "parentFolderId",
                        "reference": folder_id,
                        "source_json_path": path,
                        "targets": ",".join(sorted(folders_by_id.get(folder_id, []))),
                    }
                )
    return sorted(
        edges,
        key=lambda row: (
            row["from"],
            row["relation"],
            row["source_json_path"],
            row["reference"],
        ),
    )


def _terminal_sources(objects: list[dict[str, Any]]) -> list[dict[str, Any]]:
    variables_by_name = {
        row["object_name"]: row
        for row in objects
        if row["layer"] == "variable" and row["object_name"]
    }

    def visit(name: str, active: tuple[str, ...]) -> dict[str, Any]:
        if name in active:
            return {"name": name, "state": "cycle", "terminals": []}
        row = variables_by_name.get(name)
        if not row:
            return {"name": name, "state": "builtin_or_missing", "terminals": [name]}
        nested = sorted(set(REF_RE.findall(json.dumps(row["object"], ensure_ascii=False))))
        if not nested:
            return {
                "name": name,
                "state": "terminal_variable",
                "terminals": [row["object_key"]],
            }
        children = [visit(child, (*active, name)) for child in nested]
        return {
            "name": name,
            "state": "resolved",
            "terminals": sorted(
                {
                    terminal
                    for child in children
                    for terminal in child["terminals"]
                }
            ),
            "children": children,
        }

    referenced = sorted(
        {
            reference
            for row in objects
            for reference in REF_RE.findall(json.dumps(row["object"], ensure_ascii=False))
        }
    )
    return [visit(name, ()) for name in referenced]


def _scan_terminal_sources(scan: dict[str, Any]) -> list[dict[str, Any]]:
    objects = [row for row in as_list(scan.get("objects")) if isinstance(row, dict)]
    variables_by_name = {
        str(row.get("object_name") or ""): row
        for row in objects
        if row.get("layer") == "variable" and str(row.get("object_name") or "")
    }

    def visit(name: str, active: tuple[str, ...]) -> dict[str, Any]:
        if name in active:
            return {"name": name, "state": "cycle", "terminals": []}
        row = variables_by_name.get(name)
        if not row:
            return {"name": name, "state": "builtin_or_missing", "terminals": [name]}
        nested = sorted(str(value) for value in as_list(row.get("referenced_variables")))
        if not nested:
            return {
                "name": name,
                "state": "terminal_variable",
                "terminals": [str(row.get("object_key") or "")],
            }
        children = [visit(child, (*active, name)) for child in nested]
        return {
            "name": name,
            "state": "resolved",
            "terminals": sorted(
                {
                    terminal
                    for child in children
                    for terminal in child["terminals"]
                }
            ),
            "children": children,
        }

    referenced = sorted(
        {
            str(value)
            for row in objects
            for value in as_list(row.get("referenced_variables"))
        }
    )
    return [visit(name, ()) for name in referenced]


def _trigger_and_control_facts(objects: list[dict[str, Any]]) -> dict[str, Any]:
    triggers = {
        row["object_id"]: row for row in objects if row["layer"] == "trigger"
    }
    trigger_rows = []
    for trigger_id, row in sorted(triggers.items()):
        event_values = []
        for leaf in _walk(row["object"], row["source_json_path"]):
            field = str(leaf.get("field") or "")
            if EVENT_FIELD_RE.search(field):
                # The assurance record needs identity, not a human preview. The
                # value hash keeps literals and protected values source-bound.
                event_values.append(leaf["value_sha256"])
        serialized = json.dumps(row["object"], ensure_ascii=False)
        trigger_rows.append(
            {
                "trigger_id": trigger_id,
                "source_json_path": row["source_json_path"],
                "event_value_hashes": sorted(set(event_values)),
                "contains_consent_term": bool(CONSENT_FIELD_RE.search(serialized)),
            }
        )
    attachments = []
    for row in objects:
        if row["layer"] != "tag":
            continue
        attachments.append(
            {
                "object_key": row["object_key"],
                "firing": sorted(str(value) for value in as_list(row["object"].get("firingTriggerId"))),
                "blocking": sorted(str(value) for value in as_list(row["object"].get("blockingTriggerId"))),
            }
        )
    return {"triggers": trigger_rows, "attachments": attachments}


def _scan_trigger_and_control_facts(scan: dict[str, Any]) -> dict[str, Any]:
    objects = [row for row in as_list(scan.get("objects")) if isinstance(row, dict)]
    trigger_rows = []
    for row in sorted(
        (item for item in objects if item.get("layer") == "trigger"),
        key=lambda item: str(item.get("object_id") or ""),
    ):
        event_hashes = []
        contains_consent = False
        for leaf in as_list(row.get("source_leaf_facts")):
            if not isinstance(leaf, dict):
                continue
            path = str(leaf.get("json_path") or "")
            field_match = re.search(r"\.([^.[\]]+)$", path)
            field = field_match.group(1) if field_match else ""
            if EVENT_FIELD_RE.search(field):
                event_hashes.append(str(leaf.get("value_hash") or ""))
            if CONSENT_FIELD_RE.search(
                f"{path} {leaf.get('value_preview') or ''}"
            ):
                contains_consent = True
        trigger_rows.append(
            {
                "trigger_id": str(row.get("object_id") or ""),
                "source_json_path": str(row.get("source_json_path") or ""),
                "event_value_hashes": sorted(set(event_hashes)),
                "contains_consent_term": contains_consent,
            }
        )
    attachments = [
        {
            "object_key": str(row.get("object_key") or ""),
            "firing": sorted(str(value) for value in as_list(row.get("firing_trigger_ids"))),
            "blocking": sorted(
                str(value) for value in as_list(row.get("blocking_trigger_ids"))
            ),
        }
        for row in objects
        if row.get("layer") == "tag"
    ]
    return {"triggers": trigger_rows, "attachments": attachments}


def _parameter_rows(obj: dict[str, Any], path: str) -> list[dict[str, Any]]:
    rows = []
    for index, parameter in enumerate(as_list(obj.get("parameter"))):
        if not isinstance(parameter, dict):
            continue
        key = str(parameter.get("key") or "")
        rows.append(
            {
                "key": key,
                "value_sha256": stable_hash(
                    {
                        field: parameter.get(field)
                        for field in ("value", "list", "map")
                        if field in parameter
                    },
                    32,
                ),
                "references": sorted(set(REF_RE.findall(json.dumps(parameter, ensure_ascii=False)))),
                "source_json_path": f"{path}.parameter[{index}]",
            }
        )
    return rows


def _google_setting_ownership(objects: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for row in objects:
        if row["layer"] not in {"tag", "variable", "gtagConfig"}:
            continue
        parameters = _parameter_rows(row["object"], row["source_json_path"])
        relevant = [
            item
            for item in parameters
            if item["key"]
            in {
                "configSettingsVariable",
                "configurationSettingsVariable",
                "eventSettingsVariable",
                "configSettingsTable",
                "configurationSettingsTable",
                "eventSettingsTable",
            }
            or str(row["object_type"]) in {"gtcs", "gtes"}
        ]
        if relevant:
            rows.append(
                {
                    "object_key": row["object_key"],
                    "object_type": row["object_type"],
                    "setting_surfaces": relevant,
                }
            )
    return rows


def _normalized_setting_ownership(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        [
            {
                "object_key": str(row.get("object_key") or ""),
                "object_type": str(row.get("object_type") or ""),
                "setting_surfaces": sorted(
                    [
                        {
                            "key": str(item.get("key") or ""),
                            "references": sorted(
                                str(value)
                                for value in as_list(item.get("references"))
                            ),
                            "source_json_path": str(
                                item.get("source_json_path") or ""
                            ),
                        }
                        for item in as_list(row.get("setting_surfaces"))
                        if isinstance(item, dict)
                    ],
                    key=lambda item: (item["source_json_path"], item["key"]),
                ),
            }
            for row in rows
        ],
        key=lambda row: row["object_key"],
    )


def _scan_google_setting_ownership(scan: dict[str, Any]) -> list[dict[str, Any]]:
    result = []
    relevant_keys = {
        *SETTINGS_REFERENCE_KEYS["configuration"],
        *SETTINGS_REFERENCE_KEYS["event"],
        *SETTINGS_TABLE_KEYS["configuration"],
        *SETTINGS_TABLE_KEYS["event"],
    }
    for obj in as_list(scan.get("objects")):
        if not isinstance(obj, dict) or obj.get("layer") not in {
            "tag",
            "variable",
            "gtagConfig",
        }:
            continue
        grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for leaf in as_list(obj.get("source_leaf_facts")):
            if not isinstance(leaf, dict):
                continue
            path = str(leaf.get("json_path") or "")
            match = re.search(r"^(.*\.parameter\[\d+\])(?:\.|\[)", path)
            if match:
                grouped[match.group(1)].append(leaf)
        surfaces = []
        object_type = str(obj.get("object_type") or "")
        for parameter_path, leaves in sorted(grouped.items()):
            key = next(
                (
                    str(leaf.get("value_preview") or "")
                    for leaf in leaves
                    if str(leaf.get("json_path") or "")
                    == f"{parameter_path}.key"
                ),
                "",
            )
            if key not in relevant_keys and object_type not in SETTINGS_VARIABLE_TYPES:
                continue
            surfaces.append(
                {
                    "key": key,
                    "references": sorted(
                        {
                            str(reference)
                            for leaf in leaves
                            for reference in as_list(
                                leaf.get("referenced_variables")
                            )
                        }
                    ),
                    "source_json_path": parameter_path,
                }
            )
        if surfaces:
            result.append(
                {
                    "object_key": str(obj.get("object_key") or ""),
                    "object_type": object_type,
                    "setting_surfaces": surfaces,
                }
            )
    return _normalized_setting_ownership(result)


def _raw_parameters(obj: dict[str, Any]) -> list[dict[str, Any]]:
    return [row for row in as_list(obj.get("parameter")) if isinstance(row, dict)]


def _raw_parameter_index(obj: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    result: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in _raw_parameters(obj):
        key = str(row.get("key") or "")
        if key:
            result[key].append(row)
    return dict(result)


def _raw_scalar(parameter: dict[str, Any]) -> str:
    value = parameter.get("value")
    return "" if value is None or isinstance(value, (dict, list)) else str(value)


def _raw_map_values(row: dict[str, Any]) -> dict[str, Any]:
    values: dict[str, Any] = {}
    for item in as_list(row.get("map")):
        if not isinstance(item, dict) or not str(item.get("key") or ""):
            continue
        key = str(item["key"])
        for field in ("value", "list", "map"):
            if field in item:
                values[key] = item.get(field)
                break
    return values


def _raw_setting_table_rows(
    obj: dict[str, Any], table_keys: tuple[str, ...], source_path: str
) -> list[dict[str, Any]]:
    rows = []
    parameters = _raw_parameters(obj)
    indexes = _raw_parameter_index(obj)
    for table_key in table_keys:
        for parameter in indexes.get(table_key, []):
            parameter_index = parameters.index(parameter)
            for row_index, item in enumerate(as_list(parameter.get("list"))):
                if not isinstance(item, dict):
                    continue
                values = _raw_map_values(item)
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
                    name = "__unresolved_row__:" + stable_hash(values, 12)
                rows.append(
                    {
                        "parameter_name": name,
                        "value_sha256": stable_hash(value, 32),
                        "_configured_value": value,
                        "source_json_path": (
                            f"{source_path}.parameter[{parameter_index}].list[{row_index}]"
                        ),
                    }
                )
    return rows


def _raw_setting_reference(
    obj: dict[str, Any], scope: str, source_path: str
) -> dict[str, Any]:
    parameters = _raw_parameters(obj)
    indexes = _raw_parameter_index(obj)
    for key in SETTINGS_REFERENCE_KEYS[scope]:
        for parameter in indexes.get(key, []):
            raw = _raw_scalar(parameter)
            if raw:
                return {
                    "parameter_key": key,
                    "referenced_variable_names": sorted(set(REF_RE.findall(raw))),
                    "source_json_path": (
                        f"{source_path}.parameter[{parameters.index(parameter)}].value"
                    ),
                }
    return {}


def _independent_effective_google_settings(
    objects: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    variables_by_name: dict[str, dict[str, Any]] = {}
    for row in objects:
        scope = SETTINGS_VARIABLE_TYPES.get(str(row.get("object_type") or ""))
        if row.get("layer") != "variable" or not scope:
            continue
        variables_by_name[str(row.get("object_name") or "")] = {
            "object_key": row["object_key"],
            "scope": scope,
            "settings": _raw_setting_table_rows(
                row["object"], SETTINGS_TABLE_KEYS[scope], row["source_json_path"]
            ),
        }

    surfaces = []
    for row in objects:
        if row.get("layer") != "tag" or str(row.get("object_type") or "") not in GOOGLE_TAG_TYPES:
            continue
        obj = row["object"]
        tag_type = str(row.get("object_type") or "")
        indexes = _raw_parameter_index(obj)
        scopes = []
        if tag_type in GOOGLE_CONFIGURATION_TYPES or any(
            key in indexes
            for key in (
                *SETTINGS_REFERENCE_KEYS["configuration"],
                *SETTINGS_TABLE_KEYS["configuration"],
            )
        ):
            scopes.append("configuration")
        if tag_type in GOOGLE_EVENT_TYPES or any(
            key in indexes
            for key in (
                *SETTINGS_REFERENCE_KEYS["event"],
                *SETTINGS_TABLE_KEYS["event"],
            )
        ):
            scopes.append("event")
        for scope in dict.fromkeys(scopes):
            reference = _raw_setting_reference(obj, scope, row["source_json_path"])
            inherited = []
            resolved = []
            unresolved = []
            for name in reference.get("referenced_variable_names", []):
                variable = variables_by_name.get(name)
                if not variable or variable["scope"] != scope:
                    unresolved.append(name)
                    continue
                resolved.append(str(variable["object_key"]))
                inherited.extend(variable["settings"])
            local = _raw_setting_table_rows(
                obj, SETTINGS_TABLE_KEYS[scope], row["source_json_path"]
            )
            inherited_by_name = {
                str(item["parameter_name"]): item for item in inherited
            }
            local_by_name = {str(item["parameter_name"]): item for item in local}
            effective = []
            for name in sorted(set(inherited_by_name) | set(local_by_name)):
                inherited_row = inherited_by_name.get(name)
                local_row = local_by_name.get(name)
                selected = local_row or inherited_row or {}
                effective.append(
                    {
                        "parameter_name": name,
                        "value_sha256": selected.get("value_sha256"),
                        "origin": (
                            "local_override"
                            if inherited_row and local_row
                            else "local"
                            if local_row
                            else "inherited"
                        ),
                        "source_json_paths": sorted(
                            path
                            for path in (
                                inherited_row.get("source_json_path")
                                if inherited_row
                                else "",
                                local_row.get("source_json_path") if local_row else "",
                            )
                            if path
                        ),
                        "is_consent_setting": bool(
                            CONSENT_FIELD_RE.search(name)
                            or CONSENT_FIELD_RE.search(
                                str(selected.get("_configured_value") or "")
                            )
                        ),
                        "route_hosts": sorted(
                            {
                                (urlparse(url).hostname or "").casefold()
                                for url in URL_RE.findall(
                                    str(selected.get("_configured_value") or "")
                                )
                                if (urlparse(url).hostname or "")
                            }
                        )
                        if re.sub(r"[^a-z0-9]", "", name.casefold())
                        in ROUTE_PARAMETER_NAMES
                        else [],
                    }
                )
            surfaces.append(
                {
                    "object_key": row["object_key"],
                    "settings_scope": scope,
                    "settings_reference": reference,
                    "resolved_settings_variable_keys": sorted(resolved),
                    "unresolved_settings_variable_names": sorted(unresolved),
                    "effective_settings": effective,
                }
            )
    return sorted(surfaces, key=lambda item: (item["object_key"], item["settings_scope"]))


def _scan_effective_google_settings(scan: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for surface in as_list(
        (scan.get("optimization_facts") or {}).get("effective_google_settings")
    ):
        if not isinstance(surface, dict):
            continue
        reference = surface.get("settings_reference") or {}
        rows.append(
            {
                "object_key": str(surface.get("object_key") or ""),
                "settings_scope": str(surface.get("settings_scope") or ""),
                "settings_reference": {
                    "parameter_key": str(reference.get("parameter_key") or ""),
                    "referenced_variable_names": sorted(
                        str(value)
                        for value in as_list(reference.get("referenced_variable_names"))
                    ),
                    "source_json_path": str(reference.get("source_json_path") or ""),
                }
                if reference
                else {},
                "resolved_settings_variable_keys": sorted(
                    str(value)
                    for value in as_list(surface.get("resolved_settings_variable_keys"))
                ),
                "unresolved_settings_variable_names": sorted(
                    str(value)
                    for value in as_list(
                        surface.get("unresolved_settings_variable_names")
                    )
                ),
                "effective_settings": [
                    {
                        "parameter_name": str(item.get("parameter_name") or ""),
                        "value_sha256": str(item.get("value_sha256") or ""),
                        "origin": str(item.get("origin") or ""),
                        "source_json_paths": sorted(
                            str(path)
                            for path in as_list(item.get("source_json_paths"))
                        ),
                        "is_consent_setting": bool(
                            CONSENT_FIELD_RE.search(
                                str(item.get("parameter_name") or "")
                            )
                            or CONSENT_FIELD_RE.search(
                                str(item.get("configured_value") or "")
                            )
                        ),
                        "route_hosts": sorted(
                            {
                                (urlparse(url).hostname or "").casefold()
                                for url in URL_RE.findall(
                                    str(item.get("configured_value") or "")
                                )
                                if (urlparse(url).hostname or "")
                            }
                        )
                        if re.sub(
                            r"[^a-z0-9]",
                            "",
                            str(item.get("parameter_name") or "").casefold(),
                        )
                        in ROUTE_PARAMETER_NAMES
                        else [],
                    }
                    for item in as_list(surface.get("effective_settings"))
                    if isinstance(item, dict)
                ],
            }
        )
    return sorted(rows, key=lambda item: (item["object_key"], item["settings_scope"]))


def _route_and_consent_fields(objects: list[dict[str, Any]]) -> dict[str, Any]:
    consent_rows = []
    route_rows = []
    hostnames: set[str] = set()
    for row in objects:
        for leaf in _walk(row["object"], row["source_json_path"]):
            field = str(leaf.get("field") or "")
            if CONSENT_FIELD_RE.search(field) or CONSENT_FIELD_RE.search(leaf["json_path"]):
                consent_rows.append(
                    {
                        "object_key": row["object_key"],
                        "source_json_path": leaf["json_path"],
                        "value_sha256": leaf["value_sha256"],
                    }
                )
            if HOST_FIELD_RE.search(field):
                route_rows.append(
                    {
                        "object_key": row["object_key"],
                        "source_json_path": leaf["json_path"],
                        "value_sha256": leaf["value_sha256"],
                    }
                )
        serialized = json.dumps(row["object"], ensure_ascii=False)
        for raw_url in URL_RE.findall(serialized):
            hostname = (urlparse(raw_url).hostname or "").casefold()
            if hostname:
                hostnames.add(hostname)
    return {
        "consent_fields": sorted(
            consent_rows, key=lambda item: (item["object_key"], item["source_json_path"])
        ),
        "route_fields": sorted(
            route_rows, key=lambda item: (item["object_key"], item["source_json_path"])
        ),
        "route_hosts": sorted(hostnames),
    }


def _scan_route_and_consent_fields(scan: dict[str, Any]) -> dict[str, Any]:
    consent_rows = []
    route_rows = []
    for row in as_list(scan.get("objects")):
        if not isinstance(row, dict):
            continue
        object_key = str(row.get("object_key") or "")
        for leaf in as_list(row.get("source_leaf_facts")):
            if not isinstance(leaf, dict):
                continue
            path = str(leaf.get("json_path") or "")
            match = re.search(r"\.([^.[\]]+)$", path)
            field = match.group(1) if match else ""
            identity = {
                "object_key": object_key,
                "source_json_path": path,
                "value_sha256": str(leaf.get("value_hash") or ""),
            }
            if CONSENT_FIELD_RE.search(field) or CONSENT_FIELD_RE.search(path):
                consent_rows.append(identity)
            if HOST_FIELD_RE.search(field):
                route_rows.append(identity)
    return {
        "consent_fields": sorted(
            consent_rows, key=lambda item: (item["object_key"], item["source_json_path"])
        ),
        "route_fields": sorted(
            route_rows, key=lambda item: (item["object_key"], item["source_json_path"])
        ),
    }


def _normalized_field_rows(
    rows: list[dict[str, Any]], hash_length: int
) -> list[dict[str, Any]]:
    return [
        {
            "object_key": str(row.get("object_key") or ""),
            "source_json_path": str(row.get("source_json_path") or ""),
            "value_sha256": str(row.get("value_sha256") or "")[:hash_length],
        }
        for row in rows
    ]


def _normalized_key(value: Any) -> str:
    return re.sub(r"[^a-z0-9]", "", str(value or "").casefold())


def _independent_parameter_pairs(value: Any) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    if isinstance(value, dict):
        key = str(value.get("key") or "")
        scalar = value.get("value")
        if key and scalar is not None and not isinstance(scalar, (dict, list)):
            pairs.append((key, str(scalar)))
        for child in value.values():
            pairs.extend(_independent_parameter_pairs(child))
    elif isinstance(value, list):
        for child in value:
            pairs.extend(_independent_parameter_pairs(child))
    return pairs


def _independent_destinations(obj: dict[str, Any]) -> set[str]:
    return {
        re.sub(r"\s+", " ", value.strip().casefold())
        for key, value in _independent_parameter_pairs(obj.get("parameter", []))
        if (
            DESTINATION_PARAMETER_RE.search(_normalized_key(key))
            or _normalized_key(key) == "conversionlabel"
        )
        and value.strip()
    }


def _independent_route_hosts_from_object(obj: dict[str, Any]) -> set[str]:
    route_values: list[Any] = []

    def visit(value: Any) -> None:
        if isinstance(value, dict):
            parameter_key = _normalized_key(value.get("key"))
            if parameter_key in ROUTE_PARAMETER_NAMES:
                route_values.extend(
                    value[field]
                    for field in ("value", "list", "map")
                    if field in value
                )
            for key, child in value.items():
                if _normalized_key(key) in ROUTE_PARAMETER_NAMES:
                    route_values.append(child)
                elif key != "key":
                    visit(child)
        elif isinstance(value, list):
            pairs = {
                _normalized_key(item.get("key")): item.get("value")
                for item in value
                if isinstance(item, dict) and "key" in item and "value" in item
            }
            route_name = pairs.get("parameter") or pairs.get("parametername")
            if _normalized_key(route_name) in ROUTE_PARAMETER_NAMES:
                route_values.extend(
                    pairs[key]
                    for key in ("parametervalue", "configuredvalue")
                    if key in pairs
                )
            for child in value:
                visit(child)

    visit(obj)
    return {
        (urlparse(url).hostname or "").casefold()
        for url in URL_RE.findall(json.dumps(route_values, ensure_ascii=False))
        if (urlparse(url).hostname or "")
    }


def _independent_effective_object_route_hosts(
    obj: dict[str, Any],
    variables_by_name: dict[str, dict[str, Any]],
) -> set[str]:
    hosts = set(_independent_route_hosts_from_object(obj))
    queue = sorted(
        set(REF_RE.findall(json.dumps(obj.get("parameter", []), ensure_ascii=False)))
    )
    visited: set[str] = set()
    while queue:
        name = queue.pop(0)
        if name in visited:
            continue
        visited.add(name)
        variable = variables_by_name.get(name)
        if variable is None:
            continue
        hosts.update(_independent_route_hosts_from_object(variable))
        queue.extend(
            sorted(
                set(
                    REF_RE.findall(
                        json.dumps(variable.get("parameter", []), ensure_ascii=False)
                    )
                )
                - visited
            )
        )
    return hosts


def _effective_route_consent_topology(
    objects: list[dict[str, Any]], effective_settings: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    settings_by_tag: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in effective_settings:
        settings_by_tag[str(row.get("object_key") or "")].extend(
            item
            for item in as_list(row.get("effective_settings"))
            if isinstance(item, dict)
        )
    variables_by_name = {
        str(row.get("object_name") or ""): row["object"]
        for row in objects
        if row.get("layer") == "variable" and str(row.get("object_name") or "")
    }
    base_hosts_by_key: dict[str, set[str]] = {}
    destinations_by_key: dict[str, set[str]] = {}
    for obj in objects:
        if obj.get("layer") not in {"tag", "gtagConfig"}:
            continue
        key = str(obj["object_key"])
        base_hosts_by_key[key] = _independent_effective_object_route_hosts(
            obj["object"],
            variables_by_name,
        )
        destinations_by_key[key] = _independent_destinations(obj["object"])

    for key, effective in settings_by_tag.items():
        base_hosts_by_key.setdefault(key, set()).update(
            host
            for item in effective
            for host in as_list(item.get("route_hosts"))
        )

    route_owners = [
        obj
        for obj in objects
        if obj.get("layer") in {"tag", "gtagConfig"}
        and base_hosts_by_key.get(str(obj["object_key"]))
        and destinations_by_key.get(str(obj["object_key"]))
        and (
            obj.get("layer") == "gtagConfig"
            or str(obj.get("object_type") or "") in GOOGLE_CONFIGURATION_TYPES
        )
    ]
    rows = []
    for obj in objects:
        if obj.get("layer") != "tag":
            continue
        object_key = str(obj["object_key"])
        route_hosts = set(base_hosts_by_key.get(object_key, set()))
        destinations = destinations_by_key.get(object_key, set())
        for owner in route_owners:
            owner_key = str(owner["object_key"])
            if destinations & destinations_by_key.get(owner_key, set()):
                route_hosts.update(base_hosts_by_key.get(owner_key, set()))
        effective = settings_by_tag.get(str(obj["object_key"]), [])
        consent = [
            {
                "parameter_name": str(item.get("parameter_name") or ""),
                "value_sha256": str(item.get("value_sha256") or ""),
                "origin": str(item.get("origin") or ""),
                "source_json_paths": sorted(
                    str(path) for path in as_list(item.get("source_json_paths"))
                ),
            }
            for item in effective
            if item.get("is_consent_setting")
        ]
        rows.append(
            {
                "object_key": object_key,
                "server_route_hosts": sorted(route_hosts),
                "consent_forwarding_settings": consent,
            }
        )
    return sorted(rows, key=lambda item: item["object_key"])


def _scan_effective_route_consent_topology(scan: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for item in as_list(
        (scan.get("optimization_facts") or {}).get("tag_control_topology")
    ):
        if not isinstance(item, dict):
            continue
        rows.append(
            {
                "object_key": str(item.get("object_key") or ""),
                "server_route_hosts": sorted(
                    str(host) for host in as_list(item.get("server_route_hosts"))
                ),
                "consent_forwarding_settings": [
                    {
                        "parameter_name": str(setting.get("parameter_name") or ""),
                        "value_sha256": stable_hash(
                            setting.get("configured_value"), 32
                        ),
                        "origin": str(setting.get("origin") or ""),
                        "source_json_paths": sorted(
                            str(path)
                            for path in as_list(setting.get("source_json_paths"))
                        ),
                    }
                    for setting in as_list(item.get("consent_forwarding_settings"))
                    if isinstance(setting, dict)
                ],
            }
        )
    return sorted(rows, key=lambda item: item["object_key"])


def _strip_nonbehavior_comments(text: str) -> str:
    text = re.sub(r"<!--.*?-->", "", text, flags=re.S)
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    text = re.sub(r"(?m)^\s*//.*$", "", text)
    return text.strip()


def _independent_template_code(template_data: Any) -> str:
    text = str(template_data or "")
    matches = list(CUSTOM_TEMPLATE_SECTION_RE.finditer(text))
    if matches:
        sections = {}
        for index, match in enumerate(matches):
            end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
            sections[match.group(1)] = text[match.end() : end].strip()
        return _strip_nonbehavior_comments(
            "\n\n".join(
                sections[name]
                for name in CUSTOM_TEMPLATE_EXECUTABLE_SECTIONS
                if sections.get(name)
            )
        )
    raw = text.strip()
    try:
        payload = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return _strip_nonbehavior_comments(raw)
    if not isinstance(payload, dict):
        return _strip_nonbehavior_comments(raw)
    return _strip_nonbehavior_comments(
        "\n\n".join(
            str(value)
            for key, value in payload.items()
            if re.search(r"sandbox|code|script|execute|templateSource", str(key), re.I)
            and str(value).strip()
        )
    )


def _code_segments(objects: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for row in objects:
        code = ""
        source_path = str(row["source_json_path"])
        if row["layer"] in {"tag", "variable"}:
            expected_key = "html" if row["layer"] == "tag" else "javascript"
            for index, parameter in enumerate(as_list(row["object"].get("parameter"))):
                if not isinstance(parameter, dict) or str(parameter.get("key") or "") != expected_key:
                    continue
                code = str(parameter.get("value") or "")
                source_path = f"{row['source_json_path']}.parameter[{index}].value"
                break
        elif row["layer"] == "customTemplate":
            code = _independent_template_code(row["object"].get("templateData"))
            source_path = f"{row['source_json_path']}.templateData"
        for line_number, line in enumerate(code.splitlines(), start=1):
            stripped = line.strip()
            if not stripped:
                continue
            parts = [
                stripped[position : position + 120]
                for position in range(0, len(stripped), 120)
            ]
            for segment_index, segment in enumerate(parts, start=1):
                rows.append(
                    {
                        "object_key": row["object_key"],
                        "object_source_json_path": row["source_json_path"],
                        "code_source_json_path": source_path,
                        "line_number": line_number,
                        "segment_index": segment_index,
                        "segment_count": len(parts),
                        "line_hash": stable_hash(
                            {
                                "line_number": line_number,
                                "segment_index": segment_index,
                                "segment": segment,
                            }
                        ),
                    }
                )
    return rows


def _scan_code_segments(scan: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for obj in as_list(
        (scan.get("configuration_evidence") or {}).get("objects")
    ):
        if not isinstance(obj, dict):
            continue
        for segment in as_list(obj.get("code_line_facts")):
            if not isinstance(segment, dict):
                continue
            rows.append(
                {
                    "object_key": str(obj.get("object_key") or ""),
                    "object_source_json_path": str(obj.get("source_json_path") or ""),
                    "line_number": segment.get("line_number"),
                    "segment_index": segment.get("segment_index"),
                    "segment_count": segment.get("segment_count"),
                    "line_hash": str(segment.get("line_hash") or ""),
                }
            )
    return rows


def _scan_code_parser_coverage(scan: dict[str, Any]) -> list[dict[str, str]]:
    rows = []
    for obj in as_list(
        (scan.get("configuration_evidence") or {}).get("objects")
    ):
        if not isinstance(obj, dict) or not as_list(obj.get("code_line_facts")):
            continue
        technical = obj.get("technical_code_facts") or {}
        rows.append(
            {
                "object_key": str(obj.get("object_key") or ""),
                "parser_status": str(technical.get("javascript_parser") or ""),
            }
        )
    return rows


def _vendor_patterns(registry_path: Path) -> list[dict[str, Any]]:
    if not registry_path.is_file():
        return []
    payload = tomllib.loads(registry_path.read_text(encoding="utf-8"))
    return [row for row in as_list(payload.get("vendors")) if isinstance(row, dict)]


def _vendor_and_unknown_ownership(
    objects: list[dict[str, Any]], registry_path: Path
) -> dict[str, Any]:
    vendors = _vendor_patterns(registry_path)
    matched = []
    unmatched_hosts: dict[str, list[str]] = defaultdict(list)
    variables_by_name = {
        str(row.get("object_name") or ""): row["object"]
        for row in objects
        if row.get("layer") == "variable" and str(row.get("object_name") or "")
    }
    for row in objects:
        serialized = json.dumps(row["object"], ensure_ascii=False)
        route_hosts = _independent_effective_object_route_hosts(
            row["object"],
            variables_by_name,
        )
        identities = []
        for vendor in vendors:
            if any(
                re.search(str(pattern), serialized, re.I)
                for pattern in as_list(vendor.get("patterns"))
                if str(pattern)
            ):
                identities.append(str(vendor.get("name") or ""))
        if identities:
            matched.append(
                {"object_key": row["object_key"], "vendor_names": sorted(set(identities))}
            )
        for raw_url in URL_RE.findall(serialized):
            host = (urlparse(raw_url).hostname or "").casefold()
            if not host or host in route_hosts:
                continue
            known = any(
                re.search(str(pattern), host, re.I)
                for vendor in vendors
                for pattern in as_list(vendor.get("patterns"))
                if str(pattern)
            )
            if not known:
                unmatched_hosts[host].append(row["object_key"])
    unknown = [
        {
            "identity": host,
            "candidate_object_keys": sorted(set(keys)),
            "canonical_research_owner": sorted(set(keys))[0],
        }
        for host, keys in sorted(unmatched_hosts.items())
    ]
    return {"matched": matched, "unknown": unknown}


def _scan_vendor_and_unknown_ownership(scan: dict[str, Any]) -> dict[str, Any]:
    matched = set()
    unknown_by_identity: dict[str, dict[str, Any]] = {}
    for obj in as_list(
        (scan.get("configuration_evidence") or {}).get("objects")
    ):
        if not isinstance(obj, dict):
            continue
        object_key = str(obj.get("object_key") or "")
        for context in as_list(obj.get("vendor_contexts")):
            if not isinstance(context, dict):
                continue
            category = str(context.get("category") or "")
            vendor = str(context.get("vendor") or "")
            if category != "unknown_vendor" and vendor:
                matched.add((object_key, vendor))
                continue
            owner = str(context.get("research_owner_object_key") or "")
            for cue in as_list(context.get("detection_evidence")):
                cue_text = str(cue or "")
                host = (urlparse(cue_text).hostname or cue_text).casefold()
                if not host or "." not in host:
                    continue
                current = unknown_by_identity.setdefault(
                    host,
                    {
                        "identity": host,
                        "candidate_object_keys": set(),
                        "canonical_research_owner": owner,
                    },
                )
                current["candidate_object_keys"].add(object_key)
                if owner and current["canonical_research_owner"] != owner:
                    current["canonical_research_owner"] = "<conflict>"
    return {
        "matched_pairs": sorted(matched),
        "unknown": [
            {
                "identity": identity,
                "candidate_object_keys": sorted(row["candidate_object_keys"]),
                "canonical_research_owner": row["canonical_research_owner"],
            }
            for identity, row in sorted(unknown_by_identity.items())
        ],
    }


def _vendor_coverage_check(
    raw: dict[str, Any], observed: dict[str, Any]
) -> dict[str, Any]:
    expected_pairs = {
        (str(row.get("object_key") or ""), str(vendor))
        for row in as_list(raw.get("matched"))
        if isinstance(row, dict)
        for vendor in as_list(row.get("vendor_names"))
    }
    observed_pairs = {
        (str(pair[0]), str(pair[1]))
        for pair in as_list(observed.get("matched_pairs"))
        if isinstance(pair, (list, tuple)) and len(pair) == 2
    }
    raw_unknown = {
        str(row.get("identity") or ""): str(row.get("canonical_research_owner") or "")
        for row in as_list(raw.get("unknown"))
        if isinstance(row, dict)
    }
    observed_unknown = {
        str(row.get("identity") or ""): str(row.get("canonical_research_owner") or "")
        for row in as_list(observed.get("unknown"))
        if isinstance(row, dict)
    }
    missing_pairs = sorted(expected_pairs - observed_pairs)
    owner_mismatches = sorted(
        identity
        for identity, owner in raw_unknown.items()
        if observed_unknown.get(identity) != owner
    )
    return {
        "check_id": "vendor_classification_and_research_ownership",
        "status": "pass" if not missing_pairs and not owner_mismatches else "mismatch",
        "expected_matched_count": len(expected_pairs),
        "observed_matched_count": len(observed_pairs),
        "expected_unknown_count": len(raw_unknown),
        "observed_unknown_count": len(observed_unknown),
        "missing_matched_pairs": missing_pairs,
        "unknown_owner_mismatches": owner_mismatches,
    }


def _candidate_identities(
    scan: dict[str, Any], valid_keys: set[str], valid_paths: set[str]
) -> dict[str, Any]:
    def path_exists(path: str) -> bool:
        return path in valid_paths or any(
            candidate.startswith(path + ".") or candidate.startswith(path + "[")
            for candidate in valid_paths
        )

    relationships = []
    errors = []
    seen = set()
    for row in as_list((scan.get("architecture_evidence") or {}).get("relationships")):
        comparison_id = str(row.get("comparison_id") or "")
        members = sorted(str(value) for value in as_list(row.get("candidate_object_keys")))
        if not comparison_id or comparison_id in seen:
            errors.append("relationship candidate IDs are blank or duplicated")
        seen.add(comparison_id)
        unknown = sorted(set(members) - valid_keys)
        if unknown:
            errors.append(f"{comparison_id} contains unknown members: {', '.join(unknown)}")
        expected_id = f"REL-{stable_hash(tuple(members), 12).upper()}"
        if comparison_id != expected_id:
            errors.append(
                f"relationship candidate {comparison_id or '<blank>'} has invalid member-bound identity"
            )
        source_map = row.get("candidate_source_paths")
        if not isinstance(source_map, dict) or set(source_map) != set(members):
            errors.append(
                f"relationship candidate {comparison_id or '<blank>'} has incomplete source ownership"
            )
            source_map = {}
        missing_paths = sorted(
            str(value) for value in source_map.values() if not path_exists(str(value))
        )
        if missing_paths:
            errors.append(
                f"relationship candidate {comparison_id or '<blank>'} has unknown source coordinates"
            )
        relationships.append(
            {
                "comparison_id": comparison_id,
                "members": members,
                "comparison_types": sorted(
                    str(value) for value in as_list(row.get("comparison_types"))
                ),
                "source_coordinates": sorted(
                    str(value) for value in source_map.values()
                ),
                "candidate_owner": comparison_id,
                "identity_sha256": stable_hash(
                    {
                        "members": members,
                        "comparison_types": sorted(
                            str(value) for value in as_list(row.get("comparison_types"))
                        ),
                    },
                    32,
                ),
            }
        )
    optimization = []
    for row in as_list((scan.get("optimization_facts") or {}).get("optimization_candidates")):
        candidate_id = str(row.get("candidate_id") or "")
        if not candidate_id or candidate_id in seen:
            errors.append("candidate IDs are blank or duplicated across candidate classes")
        seen.add(candidate_id)
        candidate_type = str(row.get("candidate_type") or "")
        prefix = "OPT-PRI-" if candidate_type == "explicit_firing_priority" else "OPT-SET-"
        expected_id = prefix + stable_hash(
            {key: value for key, value in row.items() if key != "candidate_id"}, 16
        ).upper()
        if candidate_id != expected_id:
            errors.append(
                f"optimization candidate {candidate_id or '<blank>'} has invalid fact-bound identity"
            )
        candidate_paths = sorted(
            {
                str(path)
                for field in ("source_json_path", "source_json_paths")
                for path in (
                    [row.get(field)]
                    if field == "source_json_path"
                    else as_list(row.get(field))
                )
                if str(path or "")
            }
        )
        if any(not path_exists(path) for path in candidate_paths):
            errors.append(
                f"optimization candidate {candidate_id or '<blank>'} has unknown source coordinates"
            )
        optimization.append(
            {
                "candidate_id": candidate_id,
                "candidate_type": candidate_type,
                "members": sorted(
                    {
                        str(value)
                        for field in ("object_key", "consumer_object_keys")
                        for value in (
                            [row.get(field)]
                            if field == "object_key"
                            else as_list(row.get(field))
                        )
                        if str(value or "")
                    }
                ),
                "candidate_owner": candidate_id,
                "source_coordinates": candidate_paths,
            }
        )
    return {
        "relationships": relationships,
        "optimization_candidates": optimization,
        "errors": errors,
    }


def _branch_identities(
    scan: dict[str, Any], raw_leaf_index: dict[str, str]
) -> dict[str, Any]:
    branches = []
    obligations = []
    errors = []
    for obj in as_list(
        (scan.get("configuration_evidence") or {}).get("objects")
    ):
        if not isinstance(obj, dict):
            continue
        object_key = str(obj.get("object_key") or "")
        object_source = str(obj.get("source_json_path") or "")
        verified_absence_paths = {
            str(row.get("json_path") or "")
            for row in as_list(obj.get("source_absence_facts"))
            if isinstance(row, dict)
            and str(row.get("json_path") or "").startswith(object_source + ".")
            and str(row.get("json_path") or "") not in raw_leaf_index
        }
        invalid_absence = [
            str(row.get("json_path") or "")
            for row in as_list(obj.get("source_absence_facts"))
            if isinstance(row, dict)
            and str(row.get("json_path") or "") in raw_leaf_index
        ]
        if invalid_absence:
            errors.append(f"{object_key}: source-absence identity exists in raw source")
        seen_keys = set()
        for branch in as_list(obj.get("required_branch_reviews")):
            if not isinstance(branch, dict):
                continue
            path = str(branch.get("json_path") or "")
            value_hash = str(branch.get("value_hash") or "")
            raw_hash = raw_leaf_index.get(path, "")
            if not path or not raw_hash:
                errors.append(f"{object_key}: required branch has no raw-source identity")
            elif value_hash and raw_hash[: len(value_hash)] != value_hash:
                errors.append(f"{object_key}: required branch hash differs at {path}")
            branches.append(
                {
                    "object_key": object_key,
                    "source_json_path": path,
                    "value_hash": value_hash,
                    "branch_owner": object_key,
                }
            )
        for obligation in as_list(obj.get("required_configuration_obligations")):
            if not isinstance(obligation, dict):
                continue
            key = str(obligation.get("obligation_key") or "")
            if not key or key in seen_keys:
                errors.append(f"{object_key}: configuration branch owner is blank or duplicated")
            seen_keys.add(key)
            anchors = sorted(
                str(value) for value in as_list(obligation.get("evidence_anchors"))
            )
            missing = [
                path
                for path in anchors
                if path not in raw_leaf_index and path not in verified_absence_paths
            ]
            if not anchors or missing:
                errors.append(
                    f"{object_key}:{key or '<blank>'} has missing raw-source branch anchors"
                )
            obligations.append(
                {
                    "object_key": object_key,
                    "obligation_key": key,
                    "source_coordinates": anchors,
                    "branch_owner": object_key,
                    "identity_sha256": stable_hash(
                        {"object_key": object_key, "obligation_key": key, "anchors": anchors},
                        32,
                    ),
                }
            )
    return {
        "required_branches": branches,
        "configuration_branch_owners": obligations,
        "errors": errors,
    }


def _check(check_id: str, expected: Any, observed: Any) -> dict[str, Any]:
    return {
        "check_id": check_id,
        "status": "pass" if expected == observed else "mismatch",
        "expected_sha256": stable_hash(expected, 64),
        "observed_sha256": stable_hash(observed, 64),
        "expected_count": len(expected) if isinstance(expected, (list, dict)) else None,
        "observed_count": len(observed) if isinstance(observed, (list, dict)) else None,
    }


def assure_scan(
    export_path: Path,
    scan: dict[str, Any],
    *,
    vendor_registry_path: Path,
) -> dict[str, Any]:
    _data, cv, root_path = _raw_data(export_path)
    objects = _object_rows(cv, root_path)
    raw_counts = {
        layer: len(as_list(cv.get(layer))) for layer in ID_KEYS
    }
    raw_identities = sorted(
        (row["object_key"], row["source_json_path"]) for row in objects
    )
    scan_identities = sorted(
        (
            str(row.get("object_key") or ""),
            str(row.get("source_json_path") or ""),
        )
        for row in as_list(scan.get("objects"))
    )
    raw_leaf_rows = [
        {
            "object_key": row["object_key"],
            **leaf,
        }
        for row in objects
        for leaf in _walk(row["object"], row["source_json_path"])
    ]
    raw_leaf_index = {
        str(row["json_path"]): str(row["value_sha256"]) for row in raw_leaf_rows
    }
    valid_paths = {
        *raw_leaf_index,
        *(str(row["source_json_path"]) for row in objects),
    }
    raw_leaves = sorted(
        (
            row["object_key"],
            row["json_path"],
            row["value_sha256"],
        )
        for row in raw_leaf_rows
    )
    scan_leaves = sorted(
        (
            str(row.get("object_key") or ""),
            str(leaf.get("json_path") or ""),
            str(leaf.get("value_hash") or leaf.get("value_sha256") or ""),
        )
        for row in as_list(scan.get("objects"))
        for leaf in as_list(row.get("source_leaf_facts"))
    )
    # Existing shared facts use value_hash; normalize raw hashes to their first
    # 16 characters when that is the source format.
    if scan_leaves and any(len(value) == 16 for _, _, value in scan_leaves):
        raw_leaves = [(key, path, value[:16]) for key, path, value in raw_leaves]

    reference_edges = _reference_edges(objects)
    scan_reference_edges = _scan_reference_edges(scan)
    terminals = _terminal_sources(objects)
    scan_terminals = _scan_terminal_sources(scan)
    trigger_control = _trigger_and_control_facts(objects)
    scan_trigger_control = _scan_trigger_and_control_facts(scan)
    trigger_hash_length = next(
        (
            len(value)
            for row in scan_trigger_control["triggers"]
            for value in row["event_value_hashes"]
            if value
        ),
        16,
    )
    normalized_trigger_control = {
        **trigger_control,
        "triggers": [
            {
                **row,
                "event_value_hashes": [
                    value[:trigger_hash_length] for value in row["event_value_hashes"]
                ],
            }
            for row in trigger_control["triggers"]
        ],
    }
    settings = _google_setting_ownership(objects)
    scan_settings = _scan_google_setting_ownership(scan)
    normalized_settings = _normalized_setting_ownership(settings)
    effective_settings = _independent_effective_google_settings(objects)
    scan_effective_settings = _scan_effective_google_settings(scan)
    routes = _route_and_consent_fields(objects)
    scan_routes = _scan_route_and_consent_fields(scan)
    route_hash_length = next(
        (
            len(str(row.get("value_sha256") or ""))
            for field in ("consent_fields", "route_fields")
            for row in scan_routes[field]
            if row.get("value_sha256")
        ),
        16,
    )
    normalized_routes = {
        field: _normalized_field_rows(routes[field], route_hash_length)
        for field in ("consent_fields", "route_fields")
    }
    effective_topology = _effective_route_consent_topology(
        objects, effective_settings
    )
    scan_effective_topology = _scan_effective_route_consent_topology(scan)
    code_segments = _code_segments(objects)
    scan_code_segments = _scan_code_segments(scan)
    normalized_code_segments = [
        {
            key: value
            for key, value in row.items()
            if key != "code_source_json_path"
        }
        for row in code_segments
    ]
    parser_coverage = _scan_code_parser_coverage(scan)
    raw_code_keys = sorted({row["object_key"] for row in code_segments})
    parser_keys = sorted(
        row["object_key"] for row in parser_coverage if row["parser_status"]
    )
    vendor_ownership = _vendor_and_unknown_ownership(objects, vendor_registry_path)
    scan_vendor_ownership = _scan_vendor_and_unknown_ownership(scan)
    candidates = _candidate_identities(
        scan, {row["object_key"] for row in objects}, valid_paths
    )
    branches = _branch_identities(scan, raw_leaf_index)
    coverage_ids = sorted(str(row.get("area_id") or "") for row in as_list(scan.get("coverage_ledger")))
    expected_coverage_ids = sorted(str(row["area_id"]) for row in AUDIT_AREAS)

    checks = [
        _check("source_sha256", file_sha256(export_path), scan.get("source_sha256")),
        _check("entity_layer_counts", raw_counts, scan.get("source_layer_counts")),
        _check("object_identities", raw_identities, scan_identities),
        _check("source_leaf_identities", raw_leaves, scan_leaves),
        _check("reference_endpoints_and_consumers", reference_edges, scan_reference_edges),
        _check("recursive_terminal_sources", terminals, scan_terminals),
        _check(
            "trigger_event_and_blocker_identities",
            normalized_trigger_control,
            scan_trigger_control,
        ),
        _check(
            "google_setting_ownership_surfaces", normalized_settings, scan_settings
        ),
        _check(
            "effective_google_settings",
            effective_settings,
            scan_effective_settings,
        ),
        _check("consent_and_route_field_identities", normalized_routes, scan_routes),
        _check(
            "effective_route_and_consent_forwarding",
            effective_topology,
            scan_effective_topology,
        ),
        _check(
            "custom_code_segment_identities",
            normalized_code_segments,
            scan_code_segments,
        ),
        _check("custom_code_parser_coverage", raw_code_keys, parser_keys),
        _vendor_coverage_check(vendor_ownership, scan_vendor_ownership),
        _check("coverage_ledger_membership", expected_coverage_ids, coverage_ids),
    ]
    if candidates["errors"]:
        checks.append(
            {
                "check_id": "candidate_identity_integrity",
                "status": "mismatch",
                "errors": candidates["errors"],
            }
        )
    else:
        checks.append(
            {
                "check_id": "candidate_identity_integrity",
                "status": "pass",
                "relationship_count": len(candidates["relationships"]),
                "optimization_candidate_count": len(candidates["optimization_candidates"]),
            }
        )
    checks.append(
        {
            "check_id": "branch_identity_and_ownership",
            "status": "mismatch" if branches["errors"] else "pass",
            "required_branch_count": len(branches["required_branches"]),
            "configuration_branch_owner_count": len(
                branches["configuration_branch_owners"]
            ),
            "errors": branches["errors"],
        }
    )
    status = "pass" if all(row["status"] == "pass" for row in checks) else "blocked"
    payload = {
        "kind": "gtm_independent_scan_assurance",
        "schema_version": 1,
        "status": status,
        "source_sha256": file_sha256(export_path),
        "canonical_scan_sha256": scan.get("canonical_scan_sha256"),
        "checks": checks,
        "recomputed_invariants": {
            "reference_edges": reference_edges,
            "recursive_terminal_sources": terminals,
            "trigger_and_blocker_topology": trigger_control,
            "effective_google_setting_ownership_surfaces": settings,
            "independent_effective_google_settings": effective_settings,
            "consent_and_route_fields": routes,
            "effective_route_and_consent_forwarding": effective_topology,
            "custom_code_segments": code_segments,
            "custom_code_parser_coverage": parser_coverage,
            "vendor_and_unknown_research_ownership": vendor_ownership,
            "candidate_identities": candidates,
            "branch_identities_and_owners": branches,
        },
        "assurance_boundary": (
            "Critical identities and source mechanisms are recomputed directly from raw "
            "JSON. This is not a second full scanner and does not author semantic verdicts."
        ),
    }
    payload["scan_assurance_sha256"] = stable_hash(payload, 64)
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("export", type=Path)
    parser.add_argument("scan", type=Path)
    parser.add_argument("--vendor-registry", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    scan = json.loads(args.scan.read_text(encoding="utf-8"))
    result = assure_scan(
        args.export,
        scan,
        vendor_registry_path=args.vendor_registry,
    )
    write_json(args.out, result)
    print(json.dumps({"status": result["status"], "checks": result["checks"]}))
    return 0 if result["status"] == "pass" else 2


if __name__ == "__main__":
    raise SystemExit(main())
