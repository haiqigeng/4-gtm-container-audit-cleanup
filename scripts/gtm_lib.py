#!/usr/bin/env python3
"""Shared dependency-free helpers for GTM optimization scripts."""

from __future__ import annotations

import copy
import hashlib
import json
import re
import stat
import sys
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
    "gtagConfig": "gtagConfigId",
}

OBJECT_LAYERS = tuple(ID_KEYS)

SEMANTIC_LAYERS = (
    "tag",
    "trigger",
    "variable",
    "zone",
    "customTemplate",
    "gtagConfig",
)

IGNORED_FIELDS = {"path", "fingerprint"}
READBACK_VOLATILE_FIELDS = frozenset(
    {
        "accountId",
        "containerId",
        "fingerprint",
        "path",
        "tagManagerUrl",
        "workspaceId",
    }
)
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
CUSTOM_TEMPLATE_EXECUTABLE_SECTIONS = ("SANDBOXED_JS_FOR_WEB_TEMPLATE",)
CUSTOM_TEMPLATE_BEHAVIOR_SECTIONS = CUSTOM_TEMPLATE_EXECUTABLE_SECTIONS + (
    "WEB_PERMISSIONS",
)
UNSUPPORTED_SERVER_TEMPLATE_SECTIONS = frozenset(
    {"SANDBOXED_JS_FOR_SERVER_TEMPLATE", "SERVER_PERMISSIONS"}
)

SYSTEM_VARIABLE_REFERENCES = {
    "_event": "GTM internal current event name used by Custom Event trigger filters",
}

# GTM serializes a small number of built-in variables with a user-facing name
# while referring to them through an internal token elsewhere in the export.
# Keep those aliases in one registry so dependency and deletion checks resolve
# the same object instead of treating the display name and token as unrelated.
BUILTIN_REFERENCE_ALIASES_BY_TYPE = {
    "EVENT": frozenset({"_event"}),
}

KNOWN_SYSTEM_TRIGGER_REFERENCES = {
    "2147479553": "GTM system trigger reference, commonly exported for all-pages/pageview routes",
    "2147479573": "GTM system trigger reference, commonly exported for initialization or Google tag routes",
    "2147479593": "GTM system trigger reference exported for Consent Initialization - All Pages",
}


def as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def locked_evidence_coordinates(
    source_coordinates: Any,
    evidence: Any,
) -> list[str]:
    """Return exact JSON paths already present in one locked evidence bundle."""

    coordinates = {
        value
        for value in as_list(source_coordinates)
        if isinstance(value, str) and value.startswith("$.")
    }
    pending = [evidence]
    while pending:
        value = pending.pop()
        if isinstance(value, dict):
            pending.extend(value.values())
        elif isinstance(value, list):
            pending.extend(value)
        elif isinstance(value, str) and value.startswith("$."):
            coordinates.add(value)
    return sorted(coordinates)


def path_is_link_or_reparse(path: Path) -> bool:
    """Reject symlinks and Windows reparse points, including NTFS junctions."""

    try:
        if path.is_symlink():
            return True
        attributes = int(getattr(path.lstat(), "st_file_attributes", 0))
    except OSError:
        return False
    return bool(
        attributes & int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))
    )


def package_root_errors(package_dir: Path) -> list[str]:
    """Reject a workflow root whose directory entry redirects elsewhere."""

    return (
        ["audit package root is a link or reparse point"]
        if path_is_link_or_reparse(package_dir)
        else []
    )


def package_tree_errors(package_dir: Path) -> list[str]:
    """Return every redirected boundary visible in one package tree."""

    errors = package_root_errors(package_dir)
    if errors:
        return errors
    if not package_dir.exists():
        return []
    pending = [package_dir]
    while pending:
        directory = pending.pop()
        try:
            entries = list(directory.iterdir())
        except OSError as exc:
            return [f"cannot enumerate protected audit package path {directory}: {exc}"]
        for entry in entries:
            if path_is_link_or_reparse(entry):
                errors.append(
                    f"audit package path is a link or reparse point: {entry}"
                )
                continue
            if entry.is_dir():
                pending.append(entry)
    return errors


def require_safe_package_root(package_dir: Path) -> None:
    """Fail before workflow I/O crosses a redirected package-tree boundary."""

    errors = package_tree_errors(package_dir)
    if errors:
        raise ValueError("; ".join(errors))


def contained_relative_path(root: Path, value: Any, label: str) -> Path:
    """Return one canonical package-owned path without normalizing traversal.

    Workflow manifests are integrity-protected, but an attacker can rehash a
    modified manifest.  Every path carried by such a manifest therefore needs
    an independent lexical containment check before any read or write.
    """

    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(f"{label} must be a non-blank canonical relative path")
    if "\\" in value or "\x00" in value:
        raise ValueError(f"{label} must use canonical forward-slash path syntax")
    parts = value.split("/")
    if any(part in {"", ".", ".."} or ":" in part for part in parts):
        raise ValueError(f"{label} must remain inside its owning package directory")
    relative = Path(*parts)
    if relative.is_absolute() or relative.anchor:
        raise ValueError(f"{label} must remain inside its owning package directory")
    absolute_root = root.absolute()
    target = absolute_root.joinpath(relative)
    if not target.is_relative_to(absolute_root):
        raise ValueError(f"{label} must remain inside its owning package directory")
    return target


def param_value(obj: dict[str, Any], key: str) -> Any:
    for param in as_list(obj.get("parameter")):
        if not isinstance(param, dict):
            continue
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
    identity = container_identity(data)
    missing_identity_parts = []
    if not identity.get("account_id"):
        missing_identity_parts.append("account")
    if not (identity.get("container_id") or identity.get("public_id")):
        missing_identity_parts.append("container")
    if not (identity.get("version_id") or identity.get("workspace_id")):
        missing_identity_parts.append("version/workspace")
    if not identity.get("container_type"):
        missing_identity_parts.append("container type")
    if missing_identity_parts:
        findings.append(
            {
                "finding_type": "incomplete_container_identity",
                "source_path": root_path,
                "details": (
                    "The source does not resolve the required GTM identity parts: "
                    + ", ".join(missing_identity_parts)
                    + "."
                ),
                "blocking": True,
            }
        )
    container_types = {
        value.strip().upper()
        for value in str(identity.get("container_type") or "").split(",")
        if value.strip()
    }
    if container_types and container_types != {"WEB"}:
        findings.append(
            {
                "finding_type": "unsupported_container_type",
                "source_path": root_path,
                "details": (
                    "This skill accepts one WEB container only; resolved usageContext is "
                    + ", ".join(sorted(container_types))
                    + "."
                ),
                "blocking": True,
            }
        )

    standard_export_envelope = bool(
        "containerVersion" in data
        and str(data.get("exportFormatVersion") or "").strip()
        and str(data.get("exportTime") or "").strip()
    )
    web_layers = {
        "tag",
        "trigger",
        "variable",
        "folder",
        "builtInVariable",
        "customTemplate",
        "zone",
        "gtagConfig",
    }
    missing_web_layers = sorted(web_layers - set(cv))
    if not standard_export_envelope and missing_web_layers:
        findings.append(
            {
                "finding_type": "partial_equivalent_source",
                "source_path": root_path,
                "missing_layers": missing_web_layers,
                "details": (
                    "Equivalent read-only evidence lacks a standard GTM export envelope and "
                    "does not enumerate every supported web layer."
                ),
                "blocking": True,
            }
        )

    for key, value in sorted(cv.items()):
        if key in ID_KEYS or key == "usageContext":
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
            findings.extend(nested_parameter_shape_findings(item, item_path, layer))
            if layer == "customTemplate":
                unsupported_sections = sorted(
                    set(custom_template_sections(item.get("templateData")))
                    & UNSUPPORTED_SERVER_TEMPLATE_SECTIONS
                )
                if unsupported_sections:
                    findings.append(
                        {
                            "finding_type": "unsupported_server_template_section",
                            "source_path": f"{item_path}.templateData",
                            "layer": layer,
                            "object_index": index,
                            "sections": unsupported_sections,
                            "details": (
                                "A WEB-container audit cannot model server-template "
                                "executable or permission sections."
                            ),
                            "blocking": True,
                        }
                    )
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


def nested_parameter_shape_findings(
    value: Any,
    source_path: str,
    layer: str,
) -> list[dict[str, Any]]:
    """Reject malformed GTM parameter collections before semantic traversal.

    GTM parameter, list, and map collections are arrays of parameter objects.
    Treating a scalar or arbitrary array member as a mapping otherwise causes
    inconsistent crashes in downstream scanners and makes exhaustive review
    impossible.
    """

    findings: list[dict[str, Any]] = []
    if not isinstance(value, (dict, list)):
        return findings
    if isinstance(value, list):
        for index, item in enumerate(value):
            findings.extend(
                nested_parameter_shape_findings(
                    item,
                    f"{source_path}[{index}]",
                    layer,
                )
            )
        return findings

    for collection_name in ("parameter", "list", "map"):
        if collection_name not in value:
            continue
        collection = value.get(collection_name)
        collection_path = f"{source_path}.{collection_name}"
        if not isinstance(collection, list):
            findings.append(
                {
                    "finding_type": "invalid_parameter_collection_shape",
                    "source_path": collection_path,
                    "layer": layer,
                    "details": (
                        f"GTM {collection_name!r} parameter collection must be a JSON "
                        "array; retain this as a malformed configuration finding while "
                        "scanning every other interpretable object."
                    ),
                    "blocking": False,
                }
            )
            continue
        for index, item in enumerate(collection):
            item_path = f"{collection_path}[{index}]"
            if not isinstance(item, dict):
                findings.append(
                    {
                        "finding_type": "invalid_parameter_entry_shape",
                        "source_path": item_path,
                        "layer": layer,
                        "details": (
                            f"Every GTM {collection_name!r} parameter entry must be a JSON "
                            "object; retain this as a malformed configuration finding while "
                            "scanning every other interpretable object."
                        ),
                        "blocking": False,
                    }
                )
                continue
            findings.extend(nested_parameter_shape_findings(item, item_path, layer))

    for key, child in value.items():
        if key in {"parameter", "list", "map", "templateData"}:
            continue
        if isinstance(child, (dict, list)):
            findings.extend(
                nested_parameter_shape_findings(
                    child,
                    f"{source_path}.{key}",
                    layer,
                )
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


def normalized_readback_value(value: Any) -> Any:
    """Remove transport/workspace metadata while preserving configured behavior."""

    if isinstance(value, dict):
        return {
            key: normalized_readback_value(item)
            for key, item in sorted(value.items())
            if key not in READBACK_VOLATILE_FIELDS
        }
    if isinstance(value, list):
        return [normalized_readback_value(item) for item in value]
    return value


def container_configuration_state(data: dict[str, Any]) -> dict[str, Any]:
    """Return an ID-stable, metadata-neutral snapshot of every modeled GTM object."""

    cv = container_version(data)
    state: dict[str, Any] = {}
    for layer, id_key in ID_KEYS.items():
        rows = []
        for obj in as_list(cv.get(layer)):
            object_id_value = str(obj.get(id_key) or obj.get("name") or "")
            if object_id_value:
                rows.append(
                    {
                        "object_key": f"{layer}:{object_id_value}",
                        "configuration": normalized_readback_value(obj),
                    }
                )
        state[layer] = sorted(rows, key=lambda row: row["object_key"])
    return state


def container_configuration_sha256(data: dict[str, Any]) -> str:
    """Hash the complete modeled configuration independently of export metadata."""

    return stable_hash(container_configuration_state(data), 64)


def container_configuration_differences(
    expected: dict[str, Any], actual: dict[str, Any]
) -> dict[str, list[str]]:
    """Summarize object-level drift between two complete GTM readbacks."""

    def by_key(data: dict[str, Any]) -> dict[str, Any]:
        return {
            str(row["object_key"]): row["configuration"]
            for rows in container_configuration_state(data).values()
            for row in rows
        }

    expected_by_key = by_key(expected)
    actual_by_key = by_key(actual)
    expected_keys = set(expected_by_key)
    actual_keys = set(actual_by_key)
    return {
        "missing_object_keys": sorted(expected_keys - actual_keys),
        "unexpected_object_keys": sorted(actual_keys - expected_keys),
        "changed_object_keys": sorted(
            key
            for key in expected_keys & actual_keys
            if expected_by_key[key] != actual_by_key[key]
        ),
    }


def container_identity(data: dict[str, Any]) -> dict[str, str]:
    """Return one canonical source identity for a GTM ContainerVersion."""

    cv = container_version(data)
    nested = cv.get("container") if isinstance(cv.get("container"), dict) else {}
    raw_usage = cv.get("usageContext") or nested.get("usageContext") or []
    usage_contexts = (
        [str(value).strip().upper() for value in raw_usage if str(value).strip()]
        if isinstance(raw_usage, list)
        else [str(raw_usage).strip().upper()]
        if str(raw_usage).strip()
        else []
    )
    values = {
        "account_id": cv.get("accountId") or nested.get("accountId"),
        "container_id": cv.get("containerId") or nested.get("containerId"),
        "public_id": cv.get("publicId") or nested.get("publicId"),
        "container_name": cv.get("name") or nested.get("name"),
        "version_id": cv.get("containerVersionId"),
        "workspace_id": cv.get("workspaceId"),
        "path": cv.get("path") or nested.get("path"),
        "container_type": ",".join(sorted(set(usage_contexts))),
    }
    return {key: str(value) for key, value in values.items() if str(value or "")}


def container_identity_binding(
    expected: dict[str, Any], actual: dict[str, Any]
) -> dict[str, Any]:
    """Compare two GTM identities without rejecting compatible extra evidence.

    ``public_id`` is globally meaningful.  The numeric ``container_id`` is scoped
    to an account, so it is strong only when ``account_id`` is also shared.  A
    readback may legitimately expose more identity fields than an older export;
    matching shared strong fields is therefore required instead of exact-dict
    equality.
    """

    expected_identity = container_identity(expected)
    actual_identity = container_identity(actual)
    shared_fields = sorted(set(expected_identity) & set(actual_identity))
    stable_fields = {"account_id", "container_id", "public_id", "container_type"}
    conflicting_fields = sorted(
        field
        for field in set(shared_fields) & stable_fields
        if expected_identity[field] != actual_identity[field]
    )
    strong_shared_fields: list[str] = []
    if "public_id" in shared_fields:
        strong_shared_fields.append("public_id")
    if {"account_id", "container_id"} <= set(shared_fields):
        strong_shared_fields.extend(["account_id", "container_id"])
    strong_shared_fields = sorted(set(strong_shared_fields))

    errors: list[str] = []
    if not expected_identity:
        errors.append("audited source has no strong GTM container identity")
    if not actual_identity:
        errors.append("readback has no strong GTM container identity")
    if conflicting_fields:
        errors.append(
            "readback conflicts with the audited container identity at: "
            + ", ".join(conflicting_fields)
        )
    if not conflicting_fields and not strong_shared_fields:
        errors.append(
            "audited source and readback share no comparable strong container identity"
        )
    return {
        "status": "pass" if not errors else "fail",
        "expected_identity": expected_identity,
        "actual_identity": actual_identity,
        "shared_identity_fields": shared_fields,
        "strong_shared_identity_fields": strong_shared_fields,
        "conflicting_identity_fields": conflicting_fields,
        "errors": errors,
    }


def code_identity_text(value: Any) -> str:
    """Normalize transport-only code differences without changing JS literals."""

    return str(value or "").removeprefix("\ufeff").replace("\r\n", "\n").replace(
        "\r", "\n"
    )


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
    """Return references from real behavior-bearing string leaves only.

    Serialized whole-object matching can invent references across adjacent JSON
    fields and treats UI metadata such as notes or URLs as executable logic.
    Walk each string leaf independently and exclude only root object metadata.
    """

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
                *BEHAVIOR_NEUTRAL_FIELDS,
                *ID_KEYS.values(),
                "name",
            }:
                continue
            if is_custom_template and key == "templateData":
                visit(custom_template_executable_code(item))
            else:
                visit(item)

    visit(obj, root=isinstance(obj, dict))
    return references


def configure_utf8_stdio() -> None:
    """Use stable UTF-8 CLI output where Python exposes reconfigurable streams."""

    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if not callable(reconfigure):
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (OSError, ValueError):
            continue


configure_utf8_stdio()


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


def builtin_reference_names(obj: dict[str, Any]) -> set[str]:
    """Return every exported reference token that can identify a built-in variable."""

    name = str(obj.get("name") or "").strip()
    variable_type = str(obj.get("type") or "").strip().upper()
    values = set(BUILTIN_REFERENCE_ALIASES_BY_TYPE.get(variable_type, ()))
    if name:
        values.add(name)
    return values


def is_system_trigger_reference(trigger_id: str) -> bool:
    # Mutation and reference validation must fail closed.  A value that merely
    # resembles Google's reserved range is not proof that GTM owns that exact
    # ID; add future IDs to the explicit registry only after source confirmation.
    return trigger_id in KNOWN_SYSTEM_TRIGGER_REFERENCES


def resembles_system_trigger_reference(trigger_id: str) -> bool:
    """Return whether an unregistered trigger ID resembles GTM's reserved range."""

    return bool(SYSTEM_TRIGGER_RE.fullmatch(trigger_id))


def system_reference_description(kind: str, value: str) -> str:
    if kind == "variable":
        return SYSTEM_VARIABLE_REFERENCES.get(value, "GTM internal/system variable reference")
    if kind == "trigger":
        return KNOWN_SYSTEM_TRIGGER_REFERENCES.get(value, "GTM internal/system trigger reference")
    return "GTM internal/system reference"


def sort_ids(values: set[str]) -> list[str]:
    return sorted(values, key=lambda value: (not value.isdigit(), value))
