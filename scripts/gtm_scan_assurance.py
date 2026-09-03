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
CODE_PARAMETER_KEYS = {"html", "javascript"}
CUSTOM_TEMPLATE_SECTION_RE = re.compile(r"(?m)^___([A-Z0-9_]+)___\s*$")
CUSTOM_TEMPLATE_EXECUTABLE_SECTIONS = ("SANDBOXED_JS_FOR_WEB_TEMPLATE",)
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
DIRECT_SETTING_IDENTITY_KEYS = {
    "accountid",
    "activitygroupid",
    "activitytagid",
    "advertiserid",
    "conversionid",
    "conversionlabel",
    "containerid",
    "destinationid",
    "event",
    "eventid",
    "eventname",
    "measurementid",
    "pixelid",
    "propertyid",
    "tagid",
    "trackingid",
}
ROUTE_PARAMETER_NAMES = {
    "transporturl",
    "servercontainerurl",
    "taggingserverurl",
    "firstpartyurl",
    "serverurl",
}
ROUTE_SETTINGS_REFERENCE_NAMES = {
    "configsettingsvariable",
    "configurationsettingsvariable",
    "eventsettingsvariable",
}
DESTINATION_PARAMETER_RE = re.compile(
    r"(?:measurement|property|pixel|advertiser|conversion|destination|tag|account).*id$",
    re.I,
)
RAW_APPLICABILITY_LAYERS = {
    "tag",
    "trigger",
    "variable",
    "customTemplate",
    "gtagConfig",
}
RAW_ECOMMERCE_SIGNAL_RE = re.compile(
    r"\becommerce\b|\bpurchase\b|\brefund\b|\bitems\b|\btransaction[_ .-]?id\b",
    re.I,
)
RAW_SENSITIVE_DATA_SIGNAL_RE = re.compile(
    r"\bemail\b|\bphone\b|\buser[_ .-]?id\b|\buser[_ .-]?data\b|\baddress\b",
    re.I,
)
INDEPENDENT_BEHAVIOR_NEUTRAL_FIELDS = frozenset(
    {
        "accountId",
        "containerId",
        "workspaceId",
        "fingerprint",
        "path",
        "tagManagerUrl",
        "notes",
        "parentFolderId",
    }
)
INDEPENDENT_VENDOR_NEUTRAL_FIELDS = frozenset(
    {
        *INDEPENDENT_BEHAVIOR_NEUTRAL_FIELDS,
        "name",
        "monitoringMetadata",
        "monitoringMetadataTagNameKey",
    }
)
INDEPENDENT_SEMANTIC_LAYERS = frozenset(
    {"tag", "trigger", "variable", "zone", "customTemplate", "gtagConfig"}
)
INDEPENDENT_VENDOR_RESEARCH_OWNER_LAYERS = frozenset(
    {"tag", "variable", "zone", "customTemplate", "gtagConfig"}
)
INDEPENDENT_CMP_TIMING_EVENTS = (
    "didomi-consent",
    "didomi-ready",
    "didomi-consent-changed",
    "OneTrustLoaded",
    "OneTrustGroupsUpdated",
    "OTConsentApplied",
)
INDEPENDENT_CONSENT_CONTROL_RE = re.compile(
    r"consent|didomi|onetrust|optanon|cookiebot|analytics_storage|ad_storage|"
    r"ad_user_data|ad_personalization|enabled[_ -]?vendors|active[_ -]?groups|"
    r"purpose(?:s)?[_ -]?(?:enabled|consent|status)",
    re.I,
)
INDEPENDENT_COMMENT_OR_LITERAL_RE = re.compile(
    r"(?P<literal>'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\"|`(?:\\.|[^`\\])*`)"
    r"|(?P<comment>/\*.*?\*/|//[^\r\n]*|<!--.*?-->)",
    re.S,
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


def _raw_applicability_text(row: dict[str, Any]) -> str:
    obj = row.get("object") or {}
    if row.get("layer") == "customTemplate" and isinstance(obj, dict):
        return _independent_template_code(obj.get("templateData"))
    return json.dumps(obj, ensure_ascii=False)


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


def _independent_behavior_references(obj: Any) -> set[str]:
    """Extract root behavior references without using the canonical helper."""

    references: set[str] = set()

    def visit(value: Any, *, root: bool = False) -> None:
        if isinstance(value, str):
            references.update(REF_RE.findall(value))
            return
        if isinstance(value, list):
            for item in value:
                visit(item)
            return
        if not isinstance(value, dict):
            return

        is_custom_template = root and "templateId" in value and "templateData" in value
        for key, item in value.items():
            if root and key in {
                *INDEPENDENT_BEHAVIOR_NEUTRAL_FIELDS,
                *ID_KEYS.values(),
                "name",
            }:
                continue
            if is_custom_template and key == "templateData":
                visit(_independent_template_code(item))
            else:
                visit(item)

    visit(obj, root=isinstance(obj, dict))
    return references


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
        nested = sorted(_independent_behavior_references(row["object"]))
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
            for reference in _independent_behavior_references(row["object"])
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


def _independent_trigger_event_values(value: Any) -> list[str]:
    values: list[str] = []

    def visit(node: Any) -> None:
        if isinstance(node, dict):
            parameters = {
                str(parameter.get("key") or ""): parameter.get("value")
                for parameter in as_list(node.get("parameter"))
                if isinstance(parameter, dict)
                and str(parameter.get("key") or "")
                and parameter.get("value") is not None
                and not isinstance(parameter.get("value"), (dict, list))
            }
            left = str(parameters.get("arg0") or "").strip()
            reference_match = REF_RE.fullmatch(left)
            normalized_left = (
                reference_match.group(1).strip().casefold()
                if reference_match
                else left.casefold()
            )
            right = str(parameters.get("arg1") or "").strip()
            if normalized_left in {"_event", "event"} and right:
                values.append(right)
            for key, configured in parameters.items():
                if re.sub(r"[^a-z0-9]", "", key.casefold()) in {
                    "eventname",
                    "customeventname",
                }:
                    rendered = str(configured or "").strip()
                    if rendered:
                        values.append(rendered)
            for child in node.values():
                visit(child)
        elif isinstance(node, list):
            for child in node:
                visit(child)

    visit(value)
    return sorted(
        {
            configured
            for configured in values
            if configured.casefold() not in {"_event", "event"}
        }
    )


def _independent_trigger_has_consent_condition(value: Any) -> bool:
    """Detect consent control while excluding known CMP timing event literals."""

    pending: list[Any] = [value]
    while pending:
        node = pending.pop()
        if isinstance(node, list):
            pending.extend(node)
            continue
        if not isinstance(node, dict):
            continue
        parameters = {
            str(parameter.get("key") or ""): parameter.get("value")
            for parameter in as_list(node.get("parameter"))
            if isinstance(parameter, dict)
            and str(parameter.get("key") or "")
            and parameter.get("value") is not None
            and not isinstance(parameter.get("value"), (dict, list))
        }
        if "arg0" in parameters and "arg1" in parameters:
            rendered = json.dumps(node, ensure_ascii=False)
            for event in INDEPENDENT_CMP_TIMING_EVENTS:
                rendered = re.sub(re.escape(event), "", rendered, flags=re.I)
            rendered = re.sub(r"\b_event\b", "", rendered, flags=re.I)
            if INDEPENDENT_CONSENT_CONTROL_RE.search(rendered):
                return True
        pending.extend(node.values())
    return False


def _trigger_and_control_facts(objects: list[dict[str, Any]]) -> dict[str, Any]:
    triggers = {
        row["object_id"]: row for row in objects if row["layer"] == "trigger"
    }
    trigger_rows = []
    for trigger_id, row in sorted(triggers.items()):
        event_values = _independent_trigger_event_values(row["object"])
        trigger_rows.append(
            {
                "trigger_id": trigger_id,
                "source_json_path": row["source_json_path"],
                "event_value_hashes": [
                    stable_hash(configured, 32) for configured in event_values
                ],
                "contains_consent_condition": _independent_trigger_has_consent_condition(
                    row["object"]
                ),
            }
        )
    attachments = sorted(
        (
            {
                "object_key": row["object_key"],
                "firing": sorted(str(value) for value in as_list(row["object"].get("firingTriggerId"))),
                "blocking": sorted(str(value) for value in as_list(row["object"].get("blockingTriggerId"))),
            }
            for row in objects
            if row["layer"] == "tag"
        ),
        key=lambda item: item["object_key"],
    )
    return {"triggers": trigger_rows, "attachments": attachments}


def _scan_trigger_and_control_facts(scan: dict[str, Any]) -> dict[str, Any]:
    objects = [row for row in as_list(scan.get("objects")) if isinstance(row, dict)]
    parsed_trigger_facts = {
        str(row.get("trigger_id") or ""): row
        for row in as_list(
            (scan.get("optimization_facts") or {}).get("trigger_control_facts")
        )
        if isinstance(row, dict)
    }
    trigger_rows = []
    for row in sorted(
        (item for item in objects if item.get("layer") == "trigger"),
        key=lambda item: str(item.get("object_id") or ""),
    ):
        parsed = parsed_trigger_facts.get(str(row.get("object_id") or ""), {})
        event_hashes = [
            stable_hash(str(value), 32)
            for value in as_list(parsed.get("event_names"))
            if str(value).strip()
        ]
        trigger_rows.append(
            {
                "trigger_id": str(row.get("object_id") or ""),
                "source_json_path": str(row.get("source_json_path") or ""),
                "event_value_hashes": sorted(set(event_hashes)),
                "contains_consent_condition": bool(
                    parsed.get("contains_consent_condition")
                ),
            }
        )
    attachments = sorted(
        (
            {
                "object_key": str(row.get("object_key") or ""),
                "firing": sorted(
                    str(value) for value in as_list(row.get("firing_trigger_ids"))
                ),
                "blocking": sorted(
                    str(value) for value in as_list(row.get("blocking_trigger_ids"))
                ),
            }
            for row in objects
            if row.get("layer") == "tag"
        ),
        key=lambda item: item["object_key"],
    )
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


def _raw_direct_setting_rows(
    obj: dict[str, Any], scope: str, source_path: str
) -> list[dict[str, Any]]:
    excluded = {
        *DIRECT_SETTING_IDENTITY_KEYS,
        *(
            re.sub(r"[^a-z0-9]", "", key.casefold())
            for key in (
                *SETTINGS_REFERENCE_KEYS[scope],
                *SETTINGS_TABLE_KEYS[scope],
            )
        ),
    }
    rows = []
    for index, parameter in enumerate(_raw_parameters(obj)):
        name = str(parameter.get("key") or "")
        normalized_name = re.sub(r"[^a-z0-9]", "", name.casefold())
        if not name or normalized_name in excluded:
            continue
        configured_fields = [
            field for field in ("value", "list", "map") if field in parameter
        ]
        if not configured_fields:
            continue
        configured_value = (
            parameter.get(configured_fields[0])
            if len(configured_fields) == 1
            else {field: parameter.get(field) for field in configured_fields}
        )
        rows.append(
            {
                "parameter_name": name,
                "value_sha256": stable_hash(configured_value, 32),
                "_configured_value": configured_value,
                "source_json_path": f"{source_path}.parameter[{index}]",
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
    variables_by_name: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in objects:
        scope = SETTINGS_VARIABLE_TYPES.get(str(row.get("object_type") or ""))
        if row.get("layer") != "variable" or not scope:
            continue
        name = str(row.get("object_name") or "")
        if name:
            variables_by_name[name].append(
                {
                    "object_key": row["object_key"],
                    "scope": scope,
                    "source_json_path": row["source_json_path"],
                    "settings": _raw_setting_table_rows(
                        row["object"],
                        SETTINGS_TABLE_KEYS[scope],
                        row["source_json_path"],
                    ),
                }
            )

    surfaces = []
    for row in objects:
        layer = str(row.get("layer") or "")
        object_type = str(row.get("object_type") or "").lower()
        if layer not in {"tag", "gtagConfig"}:
            continue
        if layer == "tag" and object_type not in GOOGLE_TAG_TYPES:
            continue
        obj = row["object"]
        indexes = _raw_parameter_index(obj)
        scopes = []
        if layer == "gtagConfig" or object_type in GOOGLE_CONFIGURATION_TYPES or any(
            key in indexes
            for key in (
                *SETTINGS_REFERENCE_KEYS["configuration"],
                *SETTINGS_TABLE_KEYS["configuration"],
            )
        ):
            scopes.append("configuration")
        if layer == "tag" and (
            object_type in GOOGLE_EVENT_TYPES
            or any(
                key in indexes
                for key in (
                    *SETTINGS_REFERENCE_KEYS["event"],
                    *SETTINGS_TABLE_KEYS["event"],
                )
            )
        ):
            scopes.append("event")
        for scope in dict.fromkeys(scopes):
            reference = _raw_setting_reference(obj, scope, row["source_json_path"])
            inherited = []
            resolved = []
            unresolved = []
            ambiguous = []
            candidate_inherited = []
            for name in reference.get("referenced_variable_names", []):
                candidates = variables_by_name.get(name, [])
                if len(candidates) > 1:
                    ambiguous.append(
                        {
                            "variable_name": name,
                            "candidate_object_keys": sorted(
                                str(candidate["object_key"])
                                for candidate in candidates
                            ),
                            "candidate_settings_scopes": sorted(
                                {str(candidate["scope"]) for candidate in candidates}
                            ),
                            "candidate_source_json_paths": sorted(
                                str(candidate["source_json_path"])
                                for candidate in candidates
                            ),
                        }
                    )
                    for candidate in candidates:
                        candidate_inherited.extend(
                            {
                                **setting,
                                "referenced_variable_name": name,
                                "candidate_object_key": candidate["object_key"],
                                "candidate_settings_scope": candidate["scope"],
                                "origin": "ambiguous_inherited_candidate",
                            }
                            for setting in candidate["settings"]
                        )
                    continue
                variable = candidates[0] if candidates else None
                if not variable or variable["scope"] != scope:
                    unresolved.append(name)
                    continue
                resolved.append(str(variable["object_key"]))
                inherited.extend(variable["settings"])
            local = _raw_setting_table_rows(
                obj, SETTINGS_TABLE_KEYS[scope], row["source_json_path"]
            )
            if layer == "gtagConfig":
                local.extend(
                    _raw_direct_setting_rows(obj, scope, row["source_json_path"])
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
                    "ambiguous_settings_variable_references": sorted(
                        ambiguous,
                        key=lambda item: item["variable_name"],
                    ),
                    "candidate_inherited_settings": [
                        {
                            "referenced_variable_name": str(
                                item.get("referenced_variable_name") or ""
                            ),
                            "candidate_object_key": str(
                                item.get("candidate_object_key") or ""
                            ),
                            "candidate_settings_scope": str(
                                item.get("candidate_settings_scope") or ""
                            ),
                            "parameter_name": str(item.get("parameter_name") or ""),
                            "value_sha256": str(item.get("value_sha256") or ""),
                            "origin": str(item.get("origin") or ""),
                            "source_json_paths": [
                                str(item.get("source_json_path") or "")
                            ],
                            "is_consent_setting": bool(
                                CONSENT_FIELD_RE.search(
                                    str(item.get("parameter_name") or "")
                                )
                                or CONSENT_FIELD_RE.search(
                                    str(item.get("_configured_value") or "")
                                )
                            ),
                            "route_hosts": sorted(
                                {
                                    (urlparse(url).hostname or "").casefold()
                                    for url in URL_RE.findall(
                                        str(item.get("_configured_value") or "")
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
                        for item in sorted(
                            candidate_inherited,
                            key=lambda candidate: (
                                str(candidate.get("referenced_variable_name") or ""),
                                str(candidate.get("candidate_object_key") or ""),
                                str(candidate.get("parameter_name") or ""),
                                str(candidate.get("source_json_path") or ""),
                            ),
                        )
                    ],
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
                "ambiguous_settings_variable_references": sorted(
                    (
                        {
                            "variable_name": str(item.get("variable_name") or ""),
                            "candidate_object_keys": sorted(
                                str(value)
                                for value in as_list(
                                    item.get("candidate_object_keys")
                                )
                            ),
                            "candidate_settings_scopes": sorted(
                                str(value)
                                for value in as_list(
                                    item.get("candidate_settings_scopes")
                                )
                            ),
                            "candidate_source_json_paths": sorted(
                                str(value)
                                for value in as_list(
                                    item.get("candidate_source_json_paths")
                                )
                            ),
                        }
                        for item in as_list(
                            surface.get("ambiguous_settings_variable_references")
                        )
                        if isinstance(item, dict)
                    ),
                    key=lambda item: item["variable_name"],
                ),
                "candidate_inherited_settings": [
                    {
                        "referenced_variable_name": str(
                            item.get("referenced_variable_name") or ""
                        ),
                        "candidate_object_key": str(
                            item.get("candidate_object_key") or ""
                        ),
                        "candidate_settings_scope": str(
                            item.get("candidate_settings_scope") or ""
                        ),
                        "parameter_name": str(item.get("parameter_name") or ""),
                        "value_sha256": str(item.get("value_sha256") or ""),
                        "origin": str(item.get("origin") or ""),
                        "source_json_paths": [
                            str(item.get("source_json_path") or "")
                        ],
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
                    for item in as_list(surface.get("candidate_inherited_settings"))
                    if isinstance(item, dict)
                ],
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


def _destination_setting_comparisons(
    effective_rows: list[dict[str, Any]], objects: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    destinations_by_key = {
        str(row.get("object_key") or ""): sorted(
            _independent_destinations(row.get("object") or {})
        )
        for row in objects
        if row.get("layer") in {"tag", "gtagConfig"}
    }
    groups: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for surface in effective_rows:
        object_key = str(surface.get("object_key") or "")
        for destination in destinations_by_key.get(object_key, []):
            for setting in as_list(surface.get("effective_settings")):
                if not isinstance(setting, dict) or not str(
                    setting.get("value_sha256") or ""
                ):
                    continue
                groups[
                    (
                        str(surface.get("settings_scope") or ""),
                        destination,
                        str(setting.get("parameter_name") or ""),
                    )
                ].append(
                    {
                        "object_key": object_key,
                        "value_sha256": str(setting.get("value_sha256") or ""),
                        "origin": str(setting.get("origin") or ""),
                        "source_json_paths": sorted(
                            str(path)
                            for path in as_list(setting.get("source_json_paths"))
                            if str(path)
                        ),
                    }
                )

    rows = []
    for (scope, destination, parameter_name), members in sorted(groups.items()):
        owners = sorted({member["object_key"] for member in members})
        if len(owners) < 2:
            continue
        owner_settings = sorted(
            members,
            key=lambda row: (
                row["object_key"],
                row["value_sha256"],
                row["origin"],
                row["source_json_paths"],
            ),
        )
        value_hashes = sorted({member["value_sha256"] for member in members})
        payload = {
            "candidate_type": "destination_setting_comparison",
            "settings_scope": scope,
            "destination": destination,
            "parameter_name": parameter_name,
            "consumer_object_keys": owners,
            "visible_value_sha256s": value_hashes,
            "visible_value_relation": (
                "same_visible_value"
                if len(value_hashes) == 1
                else "different_visible_values"
            ),
            "owner_settings": owner_settings,
            "source_json_paths": sorted(
                {
                    path
                    for member in members
                    for path in member["source_json_paths"]
                }
            ),
            "candidate_status": "neutral_candidate_not_a_verdict",
        }
        payload["candidate_id"] = "OPT-SET-" + stable_hash(payload, 16).upper()
        rows.append(payload)
    return sorted(rows, key=lambda row: row["candidate_id"])


def _scan_destination_setting_comparisons(scan: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for candidate in as_list(
        (scan.get("optimization_facts") or {}).get("optimization_candidates")
    ):
        if not isinstance(candidate, dict) or candidate.get(
            "candidate_type"
        ) != "destination_setting_comparison":
            continue
        rows.append(
            {
                "candidate_type": "destination_setting_comparison",
                "settings_scope": str(candidate.get("settings_scope") or ""),
                "destination": str(candidate.get("destination") or ""),
                "parameter_name": str(candidate.get("parameter_name") or ""),
                "consumer_object_keys": sorted(
                    str(value)
                    for value in as_list(candidate.get("consumer_object_keys"))
                ),
                "visible_value_sha256s": sorted(
                    str(value)
                    for value in as_list(candidate.get("visible_value_sha256s"))
                ),
                "visible_value_relation": str(
                    candidate.get("visible_value_relation") or ""
                ),
                "owner_settings": sorted(
                    (
                        {
                            "object_key": str(item.get("object_key") or ""),
                            "value_sha256": str(item.get("value_sha256") or ""),
                            "origin": str(item.get("origin") or ""),
                            "source_json_paths": sorted(
                                str(path)
                                for path in as_list(item.get("source_json_paths"))
                            ),
                        }
                        for item in as_list(candidate.get("owner_settings"))
                        if isinstance(item, dict)
                    ),
                    key=lambda row: (
                        row["object_key"],
                        row["value_sha256"],
                        row["origin"],
                        row["source_json_paths"],
                    ),
                ),
                "source_json_paths": sorted(
                    str(path)
                    for path in as_list(candidate.get("source_json_paths"))
                ),
                "candidate_status": str(candidate.get("candidate_status") or ""),
                "candidate_id": str(candidate.get("candidate_id") or ""),
            }
        )
    return sorted(rows, key=lambda row: row["candidate_id"])


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


def _independent_route_values_from_object(obj: dict[str, Any]) -> list[Any]:
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
    return route_values


def _independent_route_settings_reference_values(obj: dict[str, Any]) -> list[Any]:
    return [
        parameter[field]
        for parameter in as_list(obj.get("parameter"))
        if isinstance(parameter, dict)
        and _normalized_key(parameter.get("key")) in ROUTE_SETTINGS_REFERENCE_NAMES
        for field in ("value", "list", "map")
        if field in parameter
    ]


def _independent_hosts_from_values(values: Any) -> set[str]:
    return {
        (urlparse(url).hostname or "").casefold()
        for url in URL_RE.findall(json.dumps(values, ensure_ascii=False))
        if (urlparse(url).hostname or "")
    }


def _independent_route_hosts_from_object(obj: dict[str, Any]) -> set[str]:
    return _independent_hosts_from_values(_independent_route_values_from_object(obj))


def _independent_effective_object_route_hosts(
    obj: dict[str, Any],
    variables_by_name: dict[str, list[dict[str, Any]]],
) -> set[str]:
    route_values = _independent_route_values_from_object(obj)
    hosts = _independent_hosts_from_values(route_values)
    queue = [
        *(
            (name, "route_value")
            for name in sorted(
                set(REF_RE.findall(json.dumps(route_values, ensure_ascii=False)))
            )
        ),
        *(
            (name, "settings_owner")
            for name in sorted(
                set(
                    REF_RE.findall(
                        json.dumps(
                            _independent_route_settings_reference_values(obj),
                            ensure_ascii=False,
                        )
                    )
                )
            )
        ),
    ]
    visited_names: set[tuple[str, str]] = set()
    visited_candidates: set[str] = set()
    while queue:
        name, relation = queue.pop(0)
        identity = (name, relation)
        if identity in visited_names:
            continue
        visited_names.add(identity)
        for variable in variables_by_name.get(name, []):
            candidate_id = stable_hash({"relation": relation, "variable": variable}, 32)
            if candidate_id in visited_candidates:
                continue
            visited_candidates.add(candidate_id)
            if relation == "route_value":
                parameter_values = variable.get("parameter", [])
                hosts.update(_independent_hosts_from_values(parameter_values))
                queue.extend(
                    (reference, "route_value")
                    for reference in sorted(
                        set(
                            REF_RE.findall(
                                json.dumps(parameter_values, ensure_ascii=False)
                            )
                        )
                    )
                )
                continue
            nested_route_values = _independent_route_values_from_object(variable)
            hosts.update(_independent_hosts_from_values(nested_route_values))
            queue.extend(
                (reference, "route_value")
                for reference in sorted(
                    set(
                        REF_RE.findall(
                            json.dumps(nested_route_values, ensure_ascii=False)
                        )
                    )
                )
            )
            queue.extend(
                (reference, "settings_owner")
                for reference in sorted(
                    set(
                        REF_RE.findall(
                            json.dumps(
                                _independent_route_settings_reference_values(variable),
                                ensure_ascii=False,
                            )
                        )
                    )
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
            for field in ("effective_settings", "candidate_inherited_settings")
            for item in as_list(row.get(field))
            if isinstance(item, dict)
        )
    variables_by_name: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in objects:
        name = str(row.get("object_name") or "")
        if row.get("layer") == "variable" and name:
            variables_by_name[name].append(row["object"])
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
    return text


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


def _independent_strip_code_comments(value: str) -> str:
    return INDEPENDENT_COMMENT_OR_LITERAL_RE.sub(
        lambda match: match.group("literal") or " ",
        value,
    )


def _independent_vendor_behavior_text(row: dict[str, Any]) -> str:
    obj = row["object"]
    layer = str(row.get("layer") or "")
    payload: Any = obj
    if layer == "customTemplate":
        payload = {
            "type": obj.get("type"),
            "templateId": obj.get("templateId"),
            "executable_code": _independent_template_code(obj.get("templateData")),
        }

    def project(value: Any) -> Any:
        if isinstance(value, dict):
            parameter_key = str(value.get("key") or "").casefold()
            projected = {}
            for key, child in value.items():
                if key in INDEPENDENT_VENDOR_NEUTRAL_FIELDS:
                    continue
                is_parameter_code = (
                    key == "value"
                    and parameter_key in {"html", "javascript"}
                    and isinstance(child, str)
                )
                if is_parameter_code or (
                    key in {"html", "javascript", "executable_code"}
                    and isinstance(child, str)
                ):
                    projected[key] = _independent_strip_code_comments(child)
                else:
                    projected[key] = project(child)
            return projected
        if isinstance(value, list):
            return [project(child) for child in value]
        return value

    return json.dumps(project(payload), ensure_ascii=False, sort_keys=True)


def _independent_vendor_names(
    text: str, vendors: list[dict[str, Any]]
) -> set[str]:
    by_name = {
        str(vendor.get("name") or ""): vendor
        for vendor in vendors
        if str(vendor.get("name") or "")
    }
    matched: set[str] = set()
    if re.search(r"\bUA-\d|universal analytics|\"type\"\s*:\s*\"ua\"", text, re.I):
        if "Universal Analytics (legacy)" in by_name:
            matched.add("Universal Analytics (legacy)")
    elif "Google Ads" in by_name and re.search(
        r"\bAW-[A-Z0-9-]+|google ads|adwords|conversion linker", text, re.I
    ):
        matched.add("Google Ads")
    for name, vendor in by_name.items():
        if any(
            re.search(str(pattern), text, re.I)
            for pattern in as_list(vendor.get("patterns"))
            if str(pattern)
        ):
            matched.add(name)
    return matched


def _independent_vendor_consumers(
    objects: list[dict[str, Any]],
) -> dict[str, set[str]]:
    semantic_rows = [
        row for row in objects if row.get("layer") in INDEPENDENT_SEMANTIC_LAYERS
    ]
    variables_by_name: dict[str, list[str]] = defaultdict(list)
    templates_by_id: dict[str, str] = {}
    template_types: dict[str, set[str]] = defaultdict(set)
    for row in semantic_rows:
        if row.get("layer") == "variable" and row.get("object_name"):
            variables_by_name[str(row["object_name"])].append(str(row["object_key"]))
        if row.get("layer") != "customTemplate":
            continue
        obj = row["object"]
        template_id = str(obj.get("templateId") or "").strip()
        if not template_id:
            continue
        templates_by_id[template_id] = str(row["object_key"])
        account_id = str(obj.get("accountId") or "").strip()
        if account_id:
            template_types[f"cvt_{account_id}_{template_id}"].add(template_id)
        gallery = obj.get("galleryReference")
        gallery_id = (
            str(gallery.get("galleryTemplateId") or "").strip()
            if isinstance(gallery, dict)
            else ""
        )
        if gallery_id:
            template_types[f"cvt_{gallery_id}"].add(template_id)

    consumers: dict[str, set[str]] = defaultdict(set)
    for row in semantic_rows:
        consumer_key = str(row["object_key"])
        for leaf in _walk(row["object"], str(row["source_json_path"])):
            for reference in leaf["references"]:
                for variable_key in variables_by_name.get(reference, []):
                    consumers[variable_key].add(consumer_key)

        if row.get("layer") not in {"tag", "variable", "gtagConfig"}:
            continue
        type_token = str(row["object"].get("type") or "")
        legacy = re.fullmatch(r"cvt_\d+_(\d+)", type_token)
        template_ids = (
            {legacy.group(1)} if legacy else set(template_types.get(type_token, set()))
        )
        for template_id in template_ids:
            template_key = templates_by_id.get(template_id)
            if template_key:
                consumers[template_key].add(consumer_key)
    return dict(consumers)


def _vendor_and_unknown_ownership(
    objects: list[dict[str, Any]], registry_path: Path
) -> dict[str, Any]:
    vendors = _vendor_patterns(registry_path)
    semantic_rows = [
        row for row in objects if row.get("layer") in INDEPENDENT_SEMANTIC_LAYERS
    ]
    direct_consumers = _independent_vendor_consumers(semantic_rows)
    own_known: dict[str, set[str]] = {}
    own_unknown: dict[str, set[str]] = {}
    layers_by_key = {
        str(row["object_key"]): str(row.get("layer") or "") for row in semantic_rows
    }

    for row in semantic_rows:
        object_key = str(row["object_key"])
        serialized = _independent_vendor_behavior_text(row)
        known_names = _independent_vendor_names(serialized, vendors)
        route_hosts = _independent_route_hosts_from_object(row["object"])
        unknown_names: set[str] = set()
        for raw_url in URL_RE.findall(serialized):
            host = (urlparse(raw_url).hostname or "").casefold()
            if not host or host in route_hosts:
                continue
            if not _independent_vendor_names(host, vendors):
                unknown_names.add(f"Unclassified external integration ({host})")
        if not known_names and not unknown_names and row.get("layer") == "customTemplate":
            cue = str(
                row["object"].get("name")
                or row["object"].get("type")
                or object_key
            )
            unknown_names.add(f"Unclassified external integration ({cue})")
        own_known[object_key] = known_names
        own_unknown[object_key] = unknown_names

    research_owners: dict[str, str] = {}
    for object_key in sorted(own_unknown):
        if layers_by_key.get(object_key) not in INDEPENDENT_VENDOR_RESEARCH_OWNER_LAYERS:
            continue
        for identity in sorted(own_unknown[object_key]):
            research_owners.setdefault(identity, object_key)

    matched_pairs: set[tuple[str, str]] = set()
    for source_key in sorted(layers_by_key):
        pending = [source_key]
        seen: set[str] = set()
        while pending:
            current = pending.pop(0)
            if current in seen:
                continue
            seen.add(current)
            matched_pairs.update((source_key, name) for name in own_known.get(current, set()))
            pending.extend(sorted(direct_consumers.get(current, set()) - seen))

    unknown_candidates: dict[str, set[str]] = defaultdict(set)
    for object_key, identities in own_unknown.items():
        for identity in identities:
            unknown_candidates[identity].add(object_key)
    return {
        "matched_pairs": [list(pair) for pair in sorted(matched_pairs)],
        "unknown": [
            {
                "identity": identity,
                "candidate_object_keys": sorted(candidate_keys),
                "canonical_research_owner": research_owners.get(identity, ""),
            }
            for identity, candidate_keys in sorted(unknown_candidates.items())
        ],
    }


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
            if not vendor:
                continue
            owner = str(context.get("research_owner_object_key") or "")
            current = unknown_by_identity.setdefault(
                vendor,
                {
                    "identity": vendor,
                    "candidate_object_keys": set(),
                    "canonical_research_owner": owner,
                },
            )
            current["candidate_object_keys"].add(object_key)
            if current["canonical_research_owner"] != owner:
                current["canonical_research_owner"] = "<conflict>"
    return {
        "matched_pairs": [list(pair) for pair in sorted(matched)],
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
        (str(pair[0]), str(pair[1]))
        for pair in as_list(raw.get("matched_pairs"))
        if isinstance(pair, (list, tuple)) and len(pair) == 2
    }
    observed_pairs = {
        (str(pair[0]), str(pair[1]))
        for pair in as_list(observed.get("matched_pairs"))
        if isinstance(pair, (list, tuple)) and len(pair) == 2
    }
    expected_unknown = {
        str(row.get("identity") or ""): (
            tuple(sorted(str(key) for key in as_list(row.get("candidate_object_keys")))),
            str(row.get("canonical_research_owner") or ""),
        )
        for row in as_list(raw.get("unknown"))
        if isinstance(row, dict)
    }
    observed_unknown = {
        str(row.get("identity") or ""): (
            tuple(sorted(str(key) for key in as_list(row.get("candidate_object_keys")))),
            str(row.get("canonical_research_owner") or ""),
        )
        for row in as_list(observed.get("unknown"))
        if isinstance(row, dict)
    }
    missing_pairs = sorted(expected_pairs - observed_pairs)
    unexpected_pairs = sorted(observed_pairs - expected_pairs)
    missing_unknown = sorted(set(expected_unknown) - set(observed_unknown))
    unexpected_unknown = sorted(set(observed_unknown) - set(expected_unknown))
    unknown_detail_mismatches = sorted(
        identity
        for identity in set(expected_unknown) & set(observed_unknown)
        if expected_unknown[identity] != observed_unknown[identity]
    )
    mismatches = [
        *missing_pairs,
        *unexpected_pairs,
        *missing_unknown,
        *unexpected_unknown,
        *unknown_detail_mismatches,
    ]
    return {
        "check_id": "vendor_classification_and_research_ownership",
        "status": "pass" if not mismatches else "mismatch",
        "expected_matched_count": len(expected_pairs),
        "observed_matched_count": len(observed_pairs),
        "expected_unknown_count": len(expected_unknown),
        "observed_unknown_count": len(observed_unknown),
        "missing_matched_pairs": missing_pairs,
        "unexpected_matched_pairs": unexpected_pairs,
        "missing_unknown_identities": missing_unknown,
        "unexpected_unknown_identities": unexpected_unknown,
        "unknown_owner_or_candidate_mismatches": unknown_detail_mismatches,
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


def _priority_identity_errors(
    cv: dict[str, Any], root_path: str, scan: dict[str, Any]
) -> list[str]:
    """Check priority candidate completeness directly against native Tag fields."""
    expected = []
    expected_topology = []
    for index, tag in enumerate(as_list(cv.get("tag"))):
        key = f"tag:{tag.get('tagId')}"
        present = "priority" in tag
        parameter = tag.get("priority")
        raw = parameter.get("value") if isinstance(parameter, dict) else parameter
        raw_text = str(raw) if present else ""
        parsed = None
        if (
            isinstance(parameter, dict)
            and str(parameter.get("type", "")).upper() == "INTEGER"
            and re.fullmatch(r"[+-]?[0-9]+", raw_text.strip())
        ):
            parsed = int(raw_text)
        expected_topology.append((key, present, parsed, raw_text))
        if present:
            expected.append((key, f"{root_path}.tag[{index}].priority", raw_text, parsed))
    facts = scan.get("optimization_facts") or {}
    observed = [
        (row.get("object_key"), row.get("source_json_path"), row.get("configured_value"),
         row.get("parsed_value"))
        for row in as_list(facts.get("optimization_candidates"))
        if row.get("candidate_type") == "explicit_firing_priority"
    ]
    observed_topology = [
        (row.get("object_key"), row.get("explicit_firing_priority"), row.get("firing_priority"),
         row.get("firing_priority_raw"))
        for row in as_list(facts.get("tag_control_topology"))
    ]
    errors = []
    if sorted(expected, key=str) != sorted(observed, key=str):
        errors.append("priority candidates differ from native raw Tag.priority fields")
    if sorted(expected_topology, key=str) != sorted(observed_topology, key=str):
        errors.append("priority topology differs from native raw Tag.priority fields")
    return errors


def assure_scan(
    export_path: Path,
    scan: dict[str, Any],
    *,
    vendor_registry_path: Path,
    independent_agent_id: str | None = None,
    independent_context_id: str | None = None,
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
    destination_setting_comparisons = _destination_setting_comparisons(
        effective_settings, objects
    )
    scan_destination_setting_comparisons = _scan_destination_setting_comparisons(
        scan
    )
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
    candidates["errors"].extend(_priority_identity_errors(cv, root_path, scan))
    branches = _branch_identities(scan, raw_leaf_index)
    coverage_rows = [
        row
        for row in as_list(scan.get("coverage_ledger"))
        if isinstance(row, dict)
    ]
    coverage_ids = sorted(str(row.get("area_id") or "") for row in coverage_rows)
    expected_coverage_ids = sorted(str(row["area_id"]) for row in AUDIT_AREAS)
    raw_signal_counts = {
        "AREA-18": sum(
            1
            for row in objects
            if row.get("layer") in RAW_APPLICABILITY_LAYERS
            and RAW_ECOMMERCE_SIGNAL_RE.search(_raw_applicability_text(row))
        ),
        "AREA-21": sum(
            1
            for row in objects
            if row.get("layer") in RAW_APPLICABILITY_LAYERS
            and RAW_SENSITIVE_DATA_SIGNAL_RE.search(_raw_applicability_text(row))
        ),
    }
    expected_raw_scope_coverage = [
        {
            "area_id": area_id,
            "source_count": source_count,
        }
        for area_id, source_count in sorted(raw_signal_counts.items())
    ] + [
        {
            "area_id": "AREA-20",
            "source_count": (
                raw_counts.get("tag", 0)
                + raw_counts.get("variable", 0)
                + raw_counts.get("gtagConfig", 0)
                + raw_counts.get("customTemplate", 0)
                + len(raw_code_keys)
            ),
        },
        {
            "area_id": "AREA-23",
            "source_count": sum(raw_counts.values()),
        },
    ]
    for row in expected_raw_scope_coverage:
        row["applicability"] = (
            "applicable" if row["source_count"] else "source_counted_zero"
        )
    expected_raw_scope_coverage.sort(key=lambda row: row["area_id"])
    observed_raw_scope_coverage = sorted(
        (
            {
                "area_id": str(row.get("area_id") or ""),
                "source_count": row.get("source_count"),
                "applicability": row.get("applicability"),
            }
            for row in coverage_rows
            if str(row.get("area_id") or "")
            in {item["area_id"] for item in expected_raw_scope_coverage}
        ),
        key=lambda row: row["area_id"],
    )

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
        _check(
            "destination_setting_comparisons",
            destination_setting_comparisons,
            scan_destination_setting_comparisons,
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
        _check(
            "raw_scope_area_applicability",
            expected_raw_scope_coverage,
            observed_raw_scope_coverage,
        ),
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
        "independent_agent_id": str(independent_agent_id or ""),
        "independent_context_id": str(independent_context_id or ""),
        "input_manifest_sha256": stable_hash(
            {
                "source_sha256": file_sha256(export_path),
                "canonical_scan_sha256": scan.get("canonical_scan_sha256"),
                "vendor_registry_sha256": file_sha256(vendor_registry_path),
            },
            64,
        ),
        "checks": checks,
        "recomputed_invariants": {
            "reference_edges": reference_edges,
            "recursive_terminal_sources": terminals,
            "trigger_and_blocker_topology": trigger_control,
            "effective_google_setting_ownership_surfaces": settings,
            "independent_effective_google_settings": effective_settings,
            "destination_setting_comparisons": destination_setting_comparisons,
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
    parser.add_argument("--agent-id", required=True)
    parser.add_argument("--context-id", required=True)
    args = parser.parse_args()
    scan = json.loads(args.scan.read_text(encoding="utf-8"))
    result = assure_scan(
        args.export,
        scan,
        vendor_registry_path=args.vendor_registry,
        independent_agent_id=args.agent_id,
        independent_context_id=args.context_id,
    )
    write_json(args.out, result)
    print(json.dumps({"status": result["status"], "checks": result["checks"]}))
    return 0 if result["status"] == "pass" else 2


if __name__ == "__main__":
    raise SystemExit(main())
