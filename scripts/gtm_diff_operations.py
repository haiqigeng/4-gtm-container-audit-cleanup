#!/usr/bin/env python3
"""Diff two GTM exports and emit structured cleanup operations."""

from __future__ import annotations

import argparse
import copy
import csv
import json
from pathlib import Path
from typing import Any

from gtm_approval_response import (
    CLEANUP_PACKET_SCHEMA_VERSION,
    approval_packet_sha256,
    cleanup_packet_errors,
)
from gtm_future_state_check import apply_operations
from gtm_lib import (
    ID_KEYS,
    READBACK_VOLATILE_FIELDS,
    apply_patch,
    as_list,
    comparable,
    container_configuration_differences,
    container_configuration_sha256,
    container_identity_binding,
    load_container_version,
    object_id,
    sort_ids,
    source_descriptor,
    source_integrity_findings,
)
from gtm_privacy import redact_text, spreadsheet_safe_text

LAYER_LABELS = {
    "tag": "Tag",
    "trigger": "Trigger",
    "variable": "Variable",
    "folder": "Folder",
    "customTemplate": "Template",
    "builtInVariable": "Built-in variable",
    "zone": "Zone",
    "client": "Server client",
    "gtagConfig": "Google tag configuration",
    "transformation": "Server transformation",
}

CSV_COLUMNS = [
    "Change ID",
    "Area / object",
    "Change made",
    "Before",
    "After",
    "Reason / QA / status",
]

DIFF_IGNORED_FIELDS = set(READBACK_VOLATILE_FIELDS)

OPERATION_PHASE_FIELDS = (
    "creations",
    "additions",
    "changes",
    "remaps",
    "renames",
    "deletions",
)


def action_for(before: dict[str, Any] | None, after: dict[str, Any] | None) -> str:
    if before is None:
        return "Added"
    if after is None:
        return "Removed"
    renamed = before.get("name") != after.get("name")
    modified = comparable(before, DIFF_IGNORED_FIELDS) != comparable(
        after, DIFF_IGNORED_FIELDS
    )
    if renamed and modified:
        return "Renamed + Modified"
    if renamed:
        return "Renamed"
    if modified:
        return "Modified"
    return "No-op / Documented exception"


def compact_value(value: Any, limit: int = 500) -> str:
    if isinstance(value, (dict, list)):
        text = json.dumps(value, ensure_ascii=False, sort_keys=True)
    else:
        text = str(value if value is not None else "")
    text = redact_text(text)
    return text if len(text) <= limit else text[: limit - 1] + "..."


def field_diffs(before: Any, after: Any, path: str = "$") -> list[dict[str, Any]]:
    if before == after:
        return []
    if isinstance(before, dict) and isinstance(after, dict):
        rows = []
        for key in sorted(set(before) | set(after)):
            if key in DIFF_IGNORED_FIELDS:
                continue
            rows.extend(field_diffs(before.get(key), after.get(key), f"{path}.{key}"))
        return rows
    if isinstance(before, list) and isinstance(after, list):
        rows = []
        for index in range(max(len(before), len(after))):
            left = before[index] if index < len(before) else None
            right = after[index] if index < len(after) else None
            rows.extend(field_diffs(left, right, f"{path}[{index}]"))
        return rows
    return [{"field_path": path, "before": before, "after": after}]


def mutation_signature(
    layer: str,
    object_id_value: str,
    action: str,
    field_path: str,
    before: Any,
    after: Any,
) -> str:
    return json.dumps(
        [layer, object_id_value, action, field_path, before, after],
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def state_field_diffs(
    before_cv: dict[str, Any], after_cv: dict[str, Any]
) -> list[tuple[str, str, str, str, Any, Any]]:
    rows: list[tuple[str, str, str, str, Any, Any]] = []
    for layer, key in ID_KEYS.items():
        before_by_id = {
            object_id(obj, key): obj
            for obj in before_cv.get(layer, []) or []
            if object_id(obj, key)
        }
        after_by_id = {
            object_id(obj, key): obj
            for obj in after_cv.get(layer, []) or []
            if object_id(obj, key)
        }
        for oid in sort_ids(set(before_by_id) | set(after_by_id)):
            before = before_by_id.get(oid)
            after = after_by_id.get(oid)
            if before is None:
                rows.append(
                    (
                        layer,
                        oid,
                        "Created",
                        "$",
                        None,
                        comparable(after or {}, DIFF_IGNORED_FIELDS),
                    )
                )
                continue
            if after is None:
                rows.append(
                    (
                        layer,
                        oid,
                        "Deleted",
                        "$",
                        comparable(before, DIFF_IGNORED_FIELDS),
                        None,
                    )
                )
                continue
            for change in field_diffs(
                comparable(before, DIFF_IGNORED_FIELDS),
                comparable(after, DIFF_IGNORED_FIELDS),
            ):
                action = "Renamed" if change["field_path"].endswith(".name") else "Updated"
                rows.append(
                    (
                        layer,
                        oid,
                        action,
                        change["field_path"],
                        change["before"],
                        change["after"],
                    )
                )
    return rows


def approved_field_lookup(
    before_cv: dict[str, Any], payload: dict[str, Any] | None
) -> dict[str, dict[str, Any]]:
    if not payload:
        return {}

    operation_rows = as_list(payload.get("operations"))
    expected, expected_errors = apply_operations(
        {"containerVersion": copy.deepcopy(before_cv)},
        {"operations": operation_rows},
    )
    if expected_errors:
        return {}

    # Replay the approved plan by global execution phase so dependencies between
    # operations do not depend on their presentation order in the workbook.
    current = {"containerVersion": copy.deepcopy(before_cv)}
    trace: list[tuple[str, str, str, str, dict[str, Any]]] = []
    for phase in OPERATION_PHASE_FIELDS:
        for operation in operation_rows:
            if not as_list(operation.get(phase)):
                continue
            phase_operation = {
                key: copy.deepcopy(operation.get(key, [])) if key == phase else []
                for key in OPERATION_PHASE_FIELDS
            }
            previous_cv = copy.deepcopy(load_container_version_from_payload(current))
            updated, apply_errors = apply_operations(
                current,
                {"operations": [phase_operation]},
            )
            if apply_errors:
                continue
            updated_cv = load_container_version_from_payload(updated)
            for layer, oid, action, path, _before, _after in state_field_diffs(
                previous_cv, updated_cv
            ):
                trace.append((layer, oid, action, path, operation))
            current = updated

    lookup: dict[str, dict[str, Any]] = {}
    expected_cv = load_container_version_from_payload(expected)
    for layer, oid, action, path, before, after in state_field_diffs(before_cv, expected_cv):
        candidates: dict[int, dict[str, Any]] = {}
        for traced_layer, traced_oid, traced_action, traced_path, operation in trace:
            if traced_layer != layer or traced_oid != oid:
                continue
            if action == "Deleted":
                if traced_action != "Deleted":
                    continue
            elif action != "Created" and traced_path != path:
                continue
            candidates[id(operation)] = operation
        if len(candidates) == 1:
            lookup[mutation_signature(layer, oid, action, path, before, after)] = next(
                iter(candidates.values())
            )
    return lookup


def load_container_version_from_payload(payload: dict[str, Any]) -> dict[str, Any]:
    value = payload.get("containerVersion")
    return value if isinstance(value, dict) else payload


def category_for_path(layer: str, field_path: str, action: str) -> str:
    lowered = field_path.lower()
    if action == "Deleted":
        return "Deletion"
    if action == "Created":
        return "Creation"
    if lowered.endswith(".name"):
        return "Naming"
    if "firingtriggerid" in lowered or "blockingtriggerid" in lowered or "triggerids" in lowered:
        return "Trigger routing"
    if "setuptag" in lowered or "teardowntag" in lowered:
        return "Dependency remap"
    if "parentfolderid" in lowered:
        return "Folder move"
    if "consent" in lowered or "storage" in lowered:
        return "Consent configuration"
    if "parameter" in lowered:
        return "Configuration field"
    if layer == "builtInVariable":
        return "Built-in variable set"
    return "Configuration"


def objects_by_id(cv: dict[str, Any], layer: str, id_key: str) -> dict[str, dict[str, Any]]:
    return {
        object_id(obj, id_key): obj
        for obj in cv.get(layer, []) or []
        if object_id(obj, id_key)
    }


def object_field_changes(
    before: dict[str, Any] | None, after: dict[str, Any] | None
) -> list[dict[str, Any]]:
    if before is None or after is None:
        return [
            {
                "field_path": "$",
                "before": (
                    comparable(before, DIFF_IGNORED_FIELDS)
                    if before is not None
                    else None
                ),
                "after": (
                    comparable(after, DIFF_IGNORED_FIELDS)
                    if after is not None
                    else None
                ),
            }
        ]
    return field_diffs(
        comparable(before, DIFF_IGNORED_FIELDS),
        comparable(after, DIFF_IGNORED_FIELDS),
    )


def change_action(
    before: dict[str, Any] | None, after: dict[str, Any] | None, field_path: str
) -> str:
    if before is None:
        return "Created"
    if after is None:
        return "Deleted"
    return "Renamed" if field_path.endswith(".name") else "Updated"


def change_status(execution_mode: str, approved: dict[str, Any] | None) -> str:
    if execution_mode != "executed":
        return "Proposed"
    return "Applied" if approved else "Blocked: missing approved operation link"


def change_log_row(
    number: int,
    layer: str,
    oid: str,
    before: dict[str, Any] | None,
    after: dict[str, Any] | None,
    change: dict[str, Any],
    approved: dict[str, Any] | None,
    route: str,
    execution_mode: str,
) -> dict[str, Any]:
    field_path = str(change["field_path"])
    action = change_action(before, after, field_path)
    reason = str((approved or {}).get("why_it_matters") or "")
    if not reason:
        reason = (
            "Unlinked export difference; reconcile this field with an approved cleanup "
            "operation before treating it as executed."
        )
    return {
        "change_id": f"GTM-OP-{number:03d}",
        "route": route,
        "layer": LAYER_LABELS[layer],
        "action": action,
        "object_id": oid,
        "before_name": (before or {}).get("name", ""),
        "after_name": (after or {}).get("name", ""),
        "field_path": field_path,
        "before_value": compact_value(change["before"]),
        "after_value": compact_value(change["after"]),
        "operation_id": str((approved or {}).get("operation_id") or ""),
        "reason": reason,
        "functional_impact": str((approved or {}).get("why_it_matters") or ""),
        "qa_method": str(
            (approved or {}).get("qa_steps")
            or "Compare the field through GTM readback and verify the exported configuration."
        ),
        "rollback": "Restore from original export or reverse this operation.",
        "status": change_status(execution_mode, approved),
        "blocker": str((approved or {}).get("blocker") or ""),
        "change_category": category_for_path(layer, field_path, action),
        "qa_status": (
            "Not started"
            if execution_mode == "planned"
            else "Pending final readback certification"
        ),
    }


def operations(
    before_cv: dict[str, Any],
    after_cv: dict[str, Any],
    route: str,
    approved_operations: dict[str, Any] | None = None,
    execution_mode: str = "planned",
) -> list[dict[str, Any]]:
    for label, cv in (("before", before_cv), ("after", after_cv)):
        blocking_integrity = [
            row for row in source_integrity_findings(cv) if row.get("blocking")
        ]
        if blocking_integrity:
            raise ValueError(
                f"{label} change-log source fails integrity: "
                + ", ".join(
                    sorted(
                        str(row.get("finding_type") or "source_integrity_error")
                        for row in blocking_integrity
                    )
                )
            )
    rows: list[dict[str, Any]] = []
    change_number = 1
    approved_lookup = approved_field_lookup(before_cv, approved_operations)
    for layer, key in ID_KEYS.items():
        before_by_id = objects_by_id(before_cv, layer, key)
        after_by_id = objects_by_id(after_cv, layer, key)
        for oid in sort_ids(set(before_by_id) | set(after_by_id)):
            before = before_by_id.get(oid)
            after = after_by_id.get(oid)
            if action_for(before, after) == "No-op / Documented exception":
                continue
            for change in object_field_changes(before, after):
                action = change_action(before, after, str(change["field_path"]))
                approved = approved_lookup.get(
                    mutation_signature(
                        layer,
                        oid,
                        action,
                        str(change["field_path"]),
                        change["before"],
                        change["after"],
                    )
                )
                rows.append(
                    change_log_row(
                        change_number,
                        layer,
                        oid,
                        before,
                        after,
                        change,
                        approved,
                        route,
                        execution_mode,
                    )
                )
                change_number += 1
    return rows


def execution_verification(
    before_cv: dict[str, Any],
    after_cv: dict[str, Any],
    approved_operations: dict[str, Any],
    change_rows: list[dict[str, Any]],
) -> dict[str, Any]:
    packet_errors = cleanup_packet_errors(approved_operations)
    expected, apply_errors = apply_operations(
        {"containerVersion": copy.deepcopy(before_cv)},
        approved_operations,
    )
    expected_cv = load_container_version_from_payload(expected)
    state_differences = state_field_diffs(expected_cv, after_cv)
    configuration_differences = container_configuration_differences(
        expected_cv, after_cv
    )
    identity_binding = container_identity_binding(before_cv, after_cv)
    unlinked_changes = [
        str(row.get("change_id") or "")
        for row in change_rows
        if not row.get("operation_id")
    ]
    errors = [
        *[f"approved operation packet is invalid: {error}" for error in packet_errors],
        *[f"approved operation simulation failed: {error}" for error in apply_errors],
        *[
            f"final readback identity check failed: {error}"
            for error in identity_binding["errors"]
        ],
        *(
            [
                "readback differs from the approved simulated future state at "
                + ", ".join(
                    f"{layer}:{object_id_value}{field_path}"
                    for (
                        layer,
                        object_id_value,
                        _action,
                        field_path,
                        _before,
                        _after,
                    ) in state_differences[:20]
                )
            ]
            if state_differences
            else []
        ),
        *(
            [
                "readback contains field changes with no exact approved operation link: "
                + ", ".join(unlinked_changes)
            ]
            if unlinked_changes
            else []
        ),
    ]
    return {
        "status": "pass" if not errors else "fail",
        "authoritative_result": "final_complete_gtm_readback",
        "matches_approved_future_state": (
            not state_differences
            and not apply_errors
            and not packet_errors
            and identity_binding["status"] == "pass"
        ),
        "expected_configuration_sha256": container_configuration_sha256(expected_cv),
        "readback_configuration_sha256": container_configuration_sha256(after_cv),
        "configuration_differences": configuration_differences,
        "container_identity_binding": identity_binding,
        "operation_packet_binding": {
            "status": "pass" if not packet_errors else "fail",
            "kind": str(approved_operations.get("kind") or ""),
            "schema_version": approved_operations.get("schema_version"),
            "required_schema_version": CLEANUP_PACKET_SCHEMA_VERSION,
            "packet_sha256": approval_packet_sha256(approved_operations),
            "errors": packet_errors,
        },
        "unlinked_change_ids": unlinked_changes,
        "unexpected_or_missing_field_count": len(state_differences),
        "errors": errors,
    }


def csv_row(row: dict[str, Any]) -> dict[str, str]:
    rendered = {
        "Change ID": row["change_id"],
        "Area / object": f"{row['change_category']} / {row['layer']} {row['object_id']}",
        "Change made": f"{row['action']} {row['field_path']}",
        "Before": row["before_value"],
        "After": row["after_value"],
        "Reason / QA / status": (
            f"{row['reason']} Operation: {row['operation_id'] or 'unlinked'}. "
            f"QA: {row['qa_method']} Status: {row['status']}"
        ),
    }
    return {key: spreadsheet_safe_text(value) for key, value in rendered.items()}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("before", type=Path, help="Original GTM export JSON")
    parser.add_argument("after", type=Path, help="Cleanup draft or post-change export JSON")
    parser.add_argument(
        "--patch",
        action="store_true",
        help="Treat the after file as a same-container patch applied to the before export",
    )
    parser.add_argument("--route", default="Direct GTM/MCP/API", help="Execution route label")
    parser.add_argument("--operations", type=Path, help="Approved reconciled_operations.json")
    parser.add_argument("--execution-mode", choices=("planned", "executed"), default="planned")
    parser.add_argument("--json", type=Path, help="Optional JSON output file")
    parser.add_argument("--csv", type=Path, help="Optional change-log-shaped CSV output")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output")
    args = parser.parse_args()

    before_descriptor = source_descriptor(args.before)
    before_cv = load_container_version(args.before)
    after_cv = load_container_version(args.after)
    if args.patch:
        after_cv = apply_patch(before_cv, after_cv)
    approved = json.loads(args.operations.read_text(encoding="utf-8")) if args.operations else None
    if args.execution_mode == "executed" and not approved:
        raise SystemExit("--operations is required for an executed change log")
    if args.execution_mode == "executed" and args.patch:
        raise SystemExit(
            "--patch cannot certify execution; supply a final complete GTM readback"
        )
    source_hash_error = ""
    if (
        args.execution_mode == "executed"
        and approved
        and approved.get("source_sha256") != before_descriptor["source_sha256"]
    ):
        source_hash_error = (
            "approved operations source hash differs from the original readback source"
        )
    rows = operations(
        before_cv,
        after_cv,
        args.route,
        approved,
        args.execution_mode,
    )
    payload = {
        "kind": "gtm_field_level_change_log",
        "schema_version": 2,
        "execution_mode": args.execution_mode,
        "source_sha256": before_descriptor["source_sha256"],
        "changeCount": len(rows),
        "changes": rows,
    }
    if args.execution_mode == "executed" and approved:
        verification = execution_verification(before_cv, after_cv, approved, rows)
        if source_hash_error:
            verification["status"] = "fail"
            verification["errors"].insert(0, source_hash_error)
        payload["execution_verification"] = verification
        payload["final_readback"] = {
            **source_descriptor(args.after),
            "configuration_sha256": container_configuration_sha256(after_cv),
            "authoritative": verification.get("status") == "pass",
        }
        if verification.get("status") == "pass":
            for row in rows:
                row["qa_status"] = "Verified by final complete GTM readback"
                row["status"] = "Applied and verified"

    if args.csv:
        with args.csv.open("w", encoding="utf-8-sig", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=CSV_COLUMNS)
            writer.writeheader()
            for row in rows:
                writer.writerow(csv_row(row))

    rendered = json.dumps(payload, ensure_ascii=False, indent=2 if args.pretty else None)
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return (
        1
        if (payload.get("execution_verification") or {}).get("status") == "fail"
        else 0
    )


if __name__ == "__main__":
    raise SystemExit(main())
