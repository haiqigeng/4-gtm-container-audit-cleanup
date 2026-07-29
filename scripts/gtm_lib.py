#!/usr/bin/env python3
"""Shared dependency-free helpers for GTM cleanup scripts."""

from __future__ import annotations

import copy
import hashlib
import json
import re
from pathlib import Path
from typing import Any

ID_KEYS = {
    "tag": "tagId",
    "trigger": "triggerId",
    "variable": "variableId",
    "folder": "folderId",
    "builtInVariable": "name",
    "zone": "zoneId",
    "customTemplate": "templateId",
    "client": "clientId",
    "gtagConfig": "gtagConfigId",
    "transformation": "transformationId",
}

OBJECT_LAYERS = tuple(ID_KEYS)

SEMANTIC_LAYERS = (
    "tag",
    "trigger",
    "variable",
    "zone",
    "customTemplate",
    "client",
    "gtagConfig",
    "transformation",
)

IGNORED_FIELDS = {"path", "fingerprint"}
BEHAVIOR_NEUTRAL_FIELDS = frozenset(
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
REF_RE = re.compile(r"\{\{([^{}]+)\}\}")
CUSTOM_TEMPLATE_RE = re.compile(r"^cvt_\d+_(\d+)$")
SYSTEM_TRIGGER_RE = re.compile(r"^2147479\d{3}$")
CUSTOM_TEMPLATE_SECTION_RE = re.compile(r"(?m)^___([A-Z0-9_]+)___\s*$")
CUSTOM_TEMPLATE_EXECUTABLE_SECTIONS = (
    "SANDBOXED_JS_FOR_WEB_TEMPLATE",
    "SANDBOXED_JS_FOR_SERVER_TEMPLATE",
)
CUSTOM_TEMPLATE_BEHAVIOR_SECTIONS = CUSTOM_TEMPLATE_EXECUTABLE_SECTIONS + (
    "WEB_PERMISSIONS",
    "SERVER_PERMISSIONS",
)

SYSTEM_VARIABLE_REFERENCES = {
    "_event": "GTM internal current event name used by Custom Event trigger filters",
}

KNOWN_SYSTEM_TRIGGER_REFERENCES = {
    "2147479553": "GTM system trigger reference, commonly exported for all-pages/pageview routes",
    "2147479573": "GTM system trigger reference, commonly exported for initialization or Google tag routes",
    "2147479593": "GTM system trigger reference exported for Consent Initialization - All Pages",
}


def as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def param_value(obj: dict[str, Any], key: str) -> Any:
    for param in as_list(obj.get("parameter")):
        if param.get("key") != key:
            continue
        for value_field in ("value", "list", "map"):
            if value_field in param:
                return param.get(value_field)
    return None


def container_version(data: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise ValueError("GTM source must be a JSON object")
    value = data.get("containerVersion", data)
    if not isinstance(value, dict):
        raise ValueError("containerVersion must be a JSON object")
    return value


def container_root_path(data: dict[str, Any]) -> str:
    return "$.containerVersion" if "containerVersion" in data else "$"


def custom_template_sections(template_data: Any) -> dict[str, str]:
    """Split GTM community-template data without treating documentation as code."""
    text = str(template_data or "")
    matches = list(CUSTOM_TEMPLATE_SECTION_RE.finditer(text))
    sections: dict[str, str] = {}
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        sections[match.group(1)] = text[match.end() : end].strip()
    return sections


def custom_template_executable_code(template_data: Any) -> str:
    sections = custom_template_sections(template_data)
    if not sections:
        raw = str(template_data or "").strip()
        try:
            payload = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return strip_nonbehavior_comments(raw)
        if not isinstance(payload, dict):
            return strip_nonbehavior_comments(raw)
        behavior_values = [
            value
            for key, value in payload.items()
            if re.search(r"sandbox|code|script|execute|templateSource", str(key), re.I)
        ]
        return strip_nonbehavior_comments(
            "\n\n".join(str(value) for value in behavior_values if str(value).strip())
        )
    return strip_nonbehavior_comments(
        "\n\n".join(
            sections[name]
            for name in CUSTOM_TEMPLATE_EXECUTABLE_SECTIONS
            if sections.get(name)
        )
    )


def custom_template_behavior_text(template_data: Any) -> str:
    sections = custom_template_sections(template_data)
    if not sections:
        return strip_nonbehavior_comments(custom_template_executable_code(template_data))
    return strip_nonbehavior_comments(
        "\n\n".join(
            sections[name]
            for name in CUSTOM_TEMPLATE_BEHAVIOR_SECTIONS
            if sections.get(name)
        )
    )


def strip_nonbehavior_comments(text: str) -> str:
    """Remove comment-only documentation while retaining executable statements."""
    text = re.sub(r"<!--.*?-->", "", text, flags=re.S)
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"(?m)^\s*//.*$", "", text)


def behavior_projection(value: Any) -> Any:
    """Remove export/UI metadata before behavior, vendor, or host inference."""
    if isinstance(value, dict):
        projected = {}
        is_custom_template = "templateId" in value and "templateData" in value
        parameter_code_key = str(value.get("key") or "").lower() in {
            "html",
            "javascript",
        }
        for key, item in value.items():
            if key in BEHAVIOR_NEUTRAL_FIELDS:
                continue
            if is_custom_template and key == "templateData":
                projected[key] = custom_template_behavior_text(item)
            elif (
                parameter_code_key and key == "value" and isinstance(item, str)
            ) or (key in {"html", "javascript"} and isinstance(item, str)):
                projected[key] = strip_nonbehavior_comments(item)
            else:
                projected[key] = behavior_projection(item)
        return projected
    if isinstance(value, list):
        return [behavior_projection(item) for item in value]
    return value


def source_integrity_findings(data: dict[str, Any]) -> list[dict[str, Any]]:
    """Return deterministic identity/shape findings before semantic analysis."""
    if not isinstance(data, dict):
        return [
            {
                "finding_type": "invalid_source_root",
                "source_path": "$",
                "details": "GTM source must be a JSON object.",
                "blocking": True,
            }
        ]

    findings: list[dict[str, Any]] = []
    root_path = container_root_path(data)
    raw_cv = data.get("containerVersion", data)
    if not isinstance(raw_cv, dict):
        return [
            {
                "finding_type": "invalid_container_version_shape",
                "source_path": root_path,
                "details": "containerVersion must be a JSON object.",
                "blocking": True,
            }
        ]
    cv = raw_cv
    nested_container = cv.get("container")
    has_nested_container_identity = isinstance(nested_container, dict) and any(
        str(nested_container.get(key) or "").strip()
        for key in ("containerId", "publicId", "path", "accountId")
    )
    has_version_identity = bool(str(cv.get("containerVersionId") or "").strip())
    has_entity_layer = any(layer in cv for layer in OBJECT_LAYERS)
    if not (has_version_identity or has_nested_container_identity or has_entity_layer):
        findings.append(
            {
                "finding_type": "invalid_container_version_shape",
                "source_path": root_path,
                "details": (
                    "The source has no ContainerVersion identity, identified nested container, "
                    "or recognized GTM entity layer."
                ),
                "blocking": True,
            }
        )

    for key, value in sorted(cv.items()):
        if key in ID_KEYS:
            continue
        if isinstance(value, list):
            findings.append(
                {
                    "finding_type": "unmodelled_entity_layer",
                    "source_path": f"{root_path}.{key}",
                    "layer": key,
                    "details": (
                        f"Top-level entity-like layer {key!r} is not in the locked GTM "
                        "entity registry and cannot be silently skipped."
                    ),
                    "blocking": True,
                }
            )

    for layer, id_key in ID_KEYS.items():
        if layer not in cv:
            continue
        items = cv.get(layer)
        if not isinstance(items, list):
            findings.append(
                {
                    "finding_type": "invalid_entity_layer_shape",
                    "source_path": f"{root_path}.{layer}",
                    "layer": layer,
                    "details": f"GTM layer {layer!r} must be a JSON array.",
                    "blocking": True,
                }
            )
            continue

        indexes_by_id: dict[str, list[int]] = {}
        for index, item in enumerate(items):
            item_path = f"{root_path}.{layer}[{index}]"
            if not isinstance(item, dict):
                findings.append(
                    {
                        "finding_type": "invalid_entity_shape",
                        "source_path": item_path,
                        "layer": layer,
                        "object_index": index,
                        "details": f"Every {layer} entry must be a JSON object.",
                        "blocking": True,
                    }
                )
                continue
            raw_id = item.get(id_key)
            entity_id = "" if raw_id is None else str(raw_id).strip()
            if not entity_id:
                findings.append(
                    {
                        "finding_type": "missing_entity_id",
                        "source_path": item_path,
                        "layer": layer,
                        "object_index": index,
                        "id_field": id_key,
                        "details": f"{layer} entry is missing required identity field {id_key}.",
                        "blocking": True,
                    }
                )
                continue
            indexes_by_id.setdefault(entity_id, []).append(index)

        for entity_id, indexes in sorted(indexes_by_id.items()):
            if len(indexes) < 2:
                continue
            findings.append(
                {
                    "finding_type": "duplicate_entity_id",
                    "source_path": f"{root_path}.{layer}",
                    "layer": layer,
                    "object_id": entity_id,
                    "object_indexes": indexes,
                    "id_field": id_key,
                    "details": (
                        f"{layer} ID {entity_id!r} occurs at indexes {indexes}; object "
                        "identity and mutation targeting are ambiguous."
                    ),
                    "blocking": True,
                }
            )
    return findings


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, payload: Any, pretty: bool = True) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2 if pretty else None) + "\n",
        encoding="utf-8",
    )


def load_container_version(path: Path) -> dict[str, Any]:
    return container_version(load_json(path))


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def source_descriptor(path: Path) -> dict[str, str]:
    return {
        "source_file": path.name,
        "source_sha256": file_sha256(path),
    }


def object_id(obj: dict[str, Any], id_key: str) -> str:
    value = obj.get(id_key) or obj.get("name")
    return "" if value is None else str(value)


def comparable(obj: dict[str, Any], ignored: set[str] | None = None) -> dict[str, Any]:
    ignored = IGNORED_FIELDS if ignored is None else ignored
    return {key: value for key, value in obj.items() if key not in ignored}


def stable_payload(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def stable_hash(value: Any, length: int = 16) -> str:
    return hashlib.sha256(stable_payload(value).encode("utf-8")).hexdigest()[:length]


SECRET_FIELD_CONTEXT_RE = re.compile(
    r"\b(?:client|api)[ _-]?secret\b|\b(?:access|refresh)[ _-]?token\b|"
    r"\bauthorization\b|\bpassword\b|\bprivate[ _-]?key\b|"
    r"\b(?:api|subscription)[ _-]?key\b",
    re.I,
)
SECRET_OBJECT_NAME_RE = re.compile(
    r"\b(?:client|api)[ _-]?secret\b|\b(?:access|refresh)[ _-]?token\b|"
    r"\bpassword\b|\bprivate[ _-]?key\b|\b(?:api|subscription)[ _-]?key\b",
    re.I,
)
SECRET_VALUE_SHAPE_RE = re.compile(
    r"^eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}$|"
    r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
    re.I,
)


def safe_scalar_preview(
    value: Any,
    limit: int = 160,
    *,
    field_name: str = "",
    object_name: str = "",
) -> str:
    if value is None or isinstance(value, (bool, int, float)):
        return json.dumps(value, ensure_ascii=False)
    text = str(value)
    if (
        text.strip()
        and not REF_RE.search(text)
        and (
            SECRET_FIELD_CONTEXT_RE.search(field_name)
            or SECRET_OBJECT_NAME_RE.search(object_name)
            or SECRET_VALUE_SHAPE_RE.search(text.strip())
        )
    ):
        return "<redacted secret-like container value>"
    text = re.sub(
        r"(?i)(api[_-]?key|access[_-]?token|refresh[_-]?token|secret|password)"
        r"\s*[:=]\s*[^&\s,;]+",
        r"\1=<redacted>",
        text,
    )
    text = re.sub(r"(?i)(https?://[^/@\s]+):[^/@\s]+@", r"\1:<redacted>@", text)
    return text if len(text) <= limit else text[: limit - 1] + "..."


def walk_json_fields(
    value: Any,
    path: str = "$",
    *,
    object_name: str = "",
    field_name: str = "",
) -> list[dict[str, Any]]:
    """Return stable leaf facts with exact JSON paths and variable references."""
    rows: list[dict[str, Any]] = []
    if isinstance(value, dict):
        current_object_name = str(value.get("name") or object_name)
        parameter_name = str(value.get("key") or "")
        for key in sorted(value):
            child_path = f"{path}.{key}"
            rows.extend(
                walk_json_fields(
                    value[key],
                    child_path,
                    object_name=current_object_name,
                    field_name=(
                        parameter_name
                        if parameter_name and key in {"value", "list", "map"}
                        else key
                    ),
                )
            )
        if not value:
            rows.append(
                {
                    "json_path": path,
                    "value_type": "dict",
                    "value_preview": "{}",
                    "value_hash": stable_hash(value),
                    "referenced_variables": [],
                }
            )
        return rows
    if isinstance(value, list):
        for index, item in enumerate(value):
            rows.extend(
                walk_json_fields(
                    item,
                    f"{path}[{index}]",
                    object_name=object_name,
                    field_name=field_name,
                )
            )
        if not value:
            rows.append(
                {
                    "json_path": path,
                    "value_type": "list",
                    "value_preview": "[]",
                    "value_hash": stable_hash(value),
                    "referenced_variables": [],
                }
            )
        return rows

    rows.append(
        {
            "json_path": path,
            "value_type": type(value).__name__,
            "value_preview": safe_scalar_preview(
                value,
                field_name=field_name,
                object_name=object_name,
            ),
            "value_hash": stable_hash(value),
            "referenced_variables": sorted(refs(value)),
        }
    )
    return rows


def apply_patch(original_cv: dict[str, Any], patch_cv: dict[str, Any]) -> dict[str, Any]:
    merged = copy.deepcopy(original_cv)
    for layer, id_key in ID_KEYS.items():
        replacements = patch_cv.get(layer)
        if not replacements:
            continue
        by_id = {object_id(obj, id_key): obj for obj in replacements if object_id(obj, id_key)}
        seen: set[str] = set()
        next_objects = []
        for obj in merged.get(layer, []) or []:
            oid = object_id(obj, id_key)
            if oid in by_id:
                next_objects.append(by_id[oid])
                seen.add(oid)
            else:
                next_objects.append(obj)
        for oid, obj in by_id.items():
            if oid not in seen:
                next_objects.append(obj)
        merged[layer] = next_objects
    return merged


def refs(obj: Any) -> set[str]:
    if isinstance(obj, dict) and "templateId" in obj and "templateData" in obj:
        obj = {
            **obj,
            "templateData": custom_template_executable_code(obj.get("templateData")),
        }
    return set(REF_RE.findall(json.dumps(obj, ensure_ascii=False)))


def custom_template_id(obj: dict[str, Any]) -> str | None:
    """Return the locally-addressed template ID embedded in a legacy type.

    Older/custom container exports encode a local template reference as
    ``cvt_<accountId>_<templateId>``.  Gallery-installed templates instead use
    ``cvt_<galleryTemplateId>``; resolving those requires the container's
    custom-template registry, so callers should use ``custom_template_ids``
    when that registry is available.
    """
    match = CUSTOM_TEMPLATE_RE.match(str(obj.get("type", "")))
    return match.group(1) if match else None


def custom_template_type_index(
    templates: list[dict[str, Any]],
) -> dict[str, list[str]]:
    """Map exported custom-tag type tokens to every local template ID.

    A Community Template Gallery installation stores its local ``templateId``
    separately from ``galleryReference.galleryTemplateId``.  GTM tag types use
    the latter (for example ``cvt_5RM3Q``), whereas older templates use the
    account/template form.  Preserve all matching local IDs so a malformed
    duplicate gallery mapping remains visible rather than being silently
    resolved to the first template.
    """
    index: dict[str, list[str]] = {}
    for template in templates:
        if not isinstance(template, dict):
            continue
        template_id = str(template.get("templateId") or "").strip()
        if not template_id:
            continue
        tokens: set[str] = set()
        account_id = str(template.get("accountId") or "").strip()
        if account_id:
            tokens.add(f"cvt_{account_id}_{template_id}")
        gallery = template.get("galleryReference")
        gallery_id = (
            str(gallery.get("galleryTemplateId") or "").strip()
            if isinstance(gallery, dict)
            else ""
        )
        if gallery_id:
            tokens.add(f"cvt_{gallery_id}")
        for token in tokens:
            index.setdefault(token, []).append(template_id)
    return {token: sorted(set(ids)) for token, ids in index.items()}


def custom_template_ids(
    obj: dict[str, Any], template_type_index: dict[str, list[str]] | None = None
) -> list[str]:
    """Return all locally exported custom templates referenced by ``obj``.

    The list form is intentional: if two local templates advertise the same
    gallery ID, consumers must retain the ambiguity for review instead of
    choosing one arbitrarily.
    """
    legacy_id = custom_template_id(obj)
    if legacy_id:
        return [legacy_id]
    type_token = str(obj.get("type") or "")
    return list((template_type_index or {}).get(type_token, []))


def trigger_group_members(trigger: dict[str, Any]) -> list[str]:
    members = []
    parameters = trigger.get("parameter")
    if not isinstance(parameters, list):
        return members
    for parameter in parameters:
        if not isinstance(parameter, dict) or parameter.get("key") != "triggerIds":
            continue
        items = parameter.get("list")
        if not isinstance(items, list):
            continue
        members.extend(
            str(item.get("value"))
            for item in items
            if isinstance(item, dict) and str(item.get("value") or "").strip()
        )
    return members


def is_system_variable_reference(name: str) -> bool:
    return name in SYSTEM_VARIABLE_REFERENCES


def is_system_trigger_reference(trigger_id: str) -> bool:
    return trigger_id in KNOWN_SYSTEM_TRIGGER_REFERENCES or bool(
        SYSTEM_TRIGGER_RE.match(trigger_id)
    )


def system_reference_description(kind: str, value: str) -> str:
    if kind == "variable":
        return SYSTEM_VARIABLE_REFERENCES.get(value, "GTM internal/system variable reference")
    if kind == "trigger":
        return KNOWN_SYSTEM_TRIGGER_REFERENCES.get(value, "GTM internal/system trigger reference")
    return "GTM internal/system reference"


def sort_ids(values: set[str]) -> list[str]:
    return sorted(values, key=lambda value: (not value.isdigit(), value))
