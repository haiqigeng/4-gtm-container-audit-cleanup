#!/usr/bin/env python3
"""Compile three independently validated GTM reviews into cleanup operations."""

from __future__ import annotations

import argparse
import copy
import difflib
import json
import re
import sys
import unicodedata
from collections import defaultdict
from pathlib import Path
from typing import Any

from gtm_approval_response import approval_contract
from gtm_architecture_review import validate_review as validate_architecture_review
from gtm_baseline_audit import build_execution_reachability
from gtm_configuration_review import validate_review as validate_configuration_review
from gtm_consent_model import server_route_hosts
from gtm_lib import (
    ID_KEYS,
    REF_RE,
    container_version,
    load_json,
    source_integrity_findings,
    stable_hash,
)
from gtm_operational_review import validate_review as validate_operational_review
from gtm_review_common import (
    as_list,
    object_consumer_map,
    object_name_map,
    object_source_path_map,
    specific_text,
    validate_challenge,
    validate_operation_set,
    validate_review_provenance,
)

ACTION_FIELDS = (
    "creations",
    "additions",
    "changes",
    "remaps",
    "deletions",
    "renames",
)
TEXT_FIELDS = (
    "title",
    "area",
    "problem_type",
    "problem",
    "why_it_matters",
    "expected_clean_state",
    "exact_proposed_action",
    "preconditions",
    "qa_steps",
    "rollback",
    "priority",
    "confidence",
    "execution_readiness",
    "canonical_selection_rationale",
)


def source_object_catalog(export_path: Path) -> dict[str, dict[str, Any]]:
    data = load_json(export_path)
    blocking_integrity = [
        row for row in source_integrity_findings(data) if row.get("blocking")
    ]
    if blocking_integrity:
        raise ValueError(
            "source integrity gate blocked operation compilation: "
            + ", ".join(
                sorted(
                    str(row.get("finding_type") or "source_integrity_error")
                    for row in blocking_integrity
                )
            )
        )
    cv = container_version(data)
    reachability = build_execution_reachability(cv)
    active_keys = set(as_list(reachability.get("active_object_keys")))
    paused_only_keys = set(as_list(reachability.get("paused_only_object_keys")))
    catalog: dict[str, dict[str, Any]] = {}
    for layer, id_key in ID_KEYS.items():
        for obj in as_list(cv.get(layer)):
            object_id = str(obj.get(id_key) or obj.get("name") or "")
            if not object_id:
                continue
            key = f"{layer}:{object_id}"
            reachability_state = (
                "active"
                if key in active_keys
                else "paused_only"
                if key in paused_only_keys or (layer == "tag" and bool(obj.get("paused")))
                else "inactive_or_unreferenced"
            )
            catalog[key] = {
                "object_key": key,
                "layer": layer,
                "object_id": object_id,
                "object_name": str(obj.get("name") or ""),
                "parent_folder_id": str(obj.get("parentFolderId") or ""),
                "paused": bool(obj.get("paused")) if layer == "tag" else False,
                "reachability": reachability_state,
                "server_route_hosts": server_route_hosts(obj),
                "config_hash": stable_hash(
                    {
                        name: value
                        for name, value in obj.items()
                        if name not in {"path", "fingerprint", "accountId", "containerId"}
                    }
                ),
            }
    return catalog


def operational_object_keys(row: dict[str, Any]) -> list[str]:
    bound_keys = [
        str(value)
        for field in ("shared_fact_object_keys", "repair_affected_object_keys")
        for value in as_list(row.get(field))
        if str(value)
    ]
    if bound_keys:
        return sorted(set(bound_keys))
    layer = str(row.get("object_type") or "")
    return [f"{layer}:{value}" for value in as_list(row.get("object_ids")) if value]


def action_object_keys(operation: dict[str, Any]) -> set[str]:
    keys: set[str] = set()
    for creation in as_list(operation.get("creations")):
        layer = str(creation.get("layer") or "")
        obj = creation.get("object") or {}
        id_key = ID_KEYS.get(layer, "")
        object_id = str(obj.get(id_key) or obj.get("name") or "")
        if layer and object_id:
            keys.add(f"{layer}:{object_id}")
    for addition in as_list(operation.get("additions")):
        keys.add(str(addition.get("object_key") or ""))
    for change in as_list(operation.get("changes")):
        keys.add(str(change.get("object_key") or ""))
    for remap in as_list(operation.get("remaps")):
        keys.add(str(remap.get("from_object_key") or ""))
        keys.add(str(remap.get("to_object_key") or ""))
        keys.update(str(value) for value in as_list(remap.get("consumer_object_keys")))
    for field in ("deletions", "renames"):
        keys.update(str(item.get("object_key") or "") for item in as_list(operation.get(field)))
    canonical = str(operation.get("canonical_object_key") or "")
    if canonical:
        keys.add(canonical)
    return {key for key in keys if key}


def structural_action_item(field: str, item: Any) -> Any:
    """Return the mutation identity, excluding explanatory prose.

    A deletion reason and a declared canonical key make an operation easier for
    an analyst to read, but neither changes the JSON mutation.  The remap
    endpoint itself remains part of the structural identity, so two different
    canonical targets cannot be silently merged.
    """
    if not isinstance(item, dict):
        return copy.deepcopy(item)
    result = copy.deepcopy(item)
    if field in {"creations", "deletions"}:
        result.pop("reason", None)
    return result


def normalized_action_payload(operation: dict[str, Any]) -> dict[str, Any]:
    return {
        field: sorted(
            [
                structural_action_item(field, item)
                for item in as_list(operation.get(field))
            ],
            key=lambda item: json.dumps(item, sort_keys=True, ensure_ascii=False),
        )
        for field in ACTION_FIELDS
    }


def normalized_operation(
    operation: dict[str, Any],
    source_run: str,
    source_reference: str,
    source_keys: list[str],
) -> dict[str, Any]:
    row = {field: copy.deepcopy(operation.get(field)) for field in TEXT_FIELDS}
    row.update(normalized_action_payload(operation))
    row["canonical_object_key"] = str(operation.get("canonical_object_key") or "")
    row["operation_key"] = str(operation.get("operation_key") or "").strip()
    row["source_runs"] = [source_run]
    row["source_references"] = [source_reference]
    row["source_object_keys"] = sorted(set(source_keys))
    row["affected_object_keys"] = sorted(action_object_keys(operation))
    row["challenge_review"] = copy.deepcopy(operation.get("challenge_review") or {})
    return row


def collect_operations(
    operational: dict[str, Any],
    configuration: dict[str, Any],
    architecture: dict[str, Any],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for finding in as_list(operational.get("findings")):
        if finding.get("disposition") != "cleanup_operation":
            continue
        rows.append(
            normalized_operation(
                finding,
                "operational_sanitation",
                str(finding.get("finding_id") or ""),
                operational_object_keys(finding),
            )
        )
    for review in as_list(configuration.get("rows")):
        if review.get("disposition") != "cleanup_operation":
            continue
        rows.append(
            normalized_operation(
                review.get("operation") or {},
                "configuration_correctness",
                str(review.get("review_id") or review.get("object_key") or ""),
                [str(review.get("object_key") or "")],
            )
        )
    for family in as_list(architecture.get("families")):
        for index, operation in enumerate(as_list(family.get("operations")), start=1):
            rows.append(
                normalized_operation(
                    operation,
                    "business_architecture",
                    f"{family.get('family_id')}:operation:{index}",
                    [str(value) for value in as_list(family.get("chain_object_keys"))],
                )
            )
    for comparison in as_list(architecture.get("comparisons")):
        for index, operation in enumerate(as_list(comparison.get("operations")), start=1):
            rows.append(
                normalized_operation(
                    operation,
                    "business_architecture",
                    f"{comparison.get('comparison_id')}:operation:{index}",
                    [str(value) for value in as_list(comparison.get("candidate_object_keys"))],
                )
            )
    return rows


def _selected_text(rows: list[dict[str, Any]], field: str) -> Any:
    values = [row.get(field) for row in rows if row.get(field) not in {None, ""}]
    if not values:
        return ""
    if field == "priority":
        order = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
        return max(values, key=lambda value: order.get(str(value), 0))
    if field == "confidence":
        order = {"Low": 1, "Medium": 2, "High": 3}
        return min(values, key=lambda value: order.get(str(value), 0))
    if field == "execution_readiness":
        order = {"approval_required": 1, "owner_blocked": 2, "not_actionable": 3}
        return max(values, key=lambda value: order.get(str(value), 0))
    return max(values, key=lambda value: (len(str(value)), str(value)))


def _operation_group_key(operation: dict[str, Any]) -> str:
    return json.dumps(normalized_action_payload(operation), sort_keys=True, ensure_ascii=False)


def _deletion_targets(operation: dict[str, Any]) -> set[str]:
    return {
        str(item.get("object_key") or "")
        for item in as_list(operation.get("deletions"))
        if str(item.get("object_key") or "")
    }


def _is_deletion_only_operation(operation: dict[str, Any]) -> bool:
    return bool(_deletion_targets(operation)) and not any(
        as_list(operation.get(field))
        for field in ACTION_FIELDS
        if field != "deletions"
    )


def reconcile_redundant_deletion_operations(
    operations: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Fold a deletion-only subset into one compatible broader operation.

    Independent scans can prove that the same object should be deleted for
    different reasons. For example, Run 1 may mark an unused trigger for
    deletion while Run 3 includes that trigger in an exact-duplicate
    consolidation. When the deletion-only mutation is a strict subset of one
    unambiguous broader action payload, both evidence lenses should support one
    atomic operation rather than emit two competing deletes.

    Ambiguous carriers remain untouched so the normal mutation-conflict gate
    still blocks them.
    """

    snapshot = copy.deepcopy(operations)
    adjusted = copy.deepcopy(operations)
    for index, operation in enumerate(snapshot):
        if not _is_deletion_only_operation(operation):
            continue
        targets = _deletion_targets(operation)
        candidates = [
            candidate
            for candidate_index, candidate in enumerate(snapshot)
            if candidate_index != index
            and targets <= _deletion_targets(candidate)
            and (
                targets < _deletion_targets(candidate)
                or not _is_deletion_only_operation(candidate)
            )
        ]
        candidate_payloads = {
            _operation_group_key(candidate): candidate for candidate in candidates
        }
        if len(candidate_payloads) != 1:
            continue
        carrier = min(
            candidate_payloads.values(),
            key=lambda row: str(row.get("operation_key") or ""),
        )
        for field in ACTION_FIELDS:
            adjusted[index][field] = copy.deepcopy(carrier.get(field) or [])
        adjusted[index]["canonical_object_key"] = str(
            carrier.get("canonical_object_key") or ""
        )
        adjusted[index]["affected_object_keys"] = sorted(
            action_object_keys(adjusted[index])
        )
    return adjusted


def _compose_text_change(before: str, after_values: list[str]) -> str | None:
    """Compose disjoint replacements made against the same exported string.

    Independent sanitation findings can legitimately repair different Unicode
    references inside one Custom JavaScript field.  They must compile to one
    atomic field write, but overlapping or incompatible edits must remain an
    error.  This returns a composed value only when every edit has a disjoint
    span in the original value (or is an identical edit).
    """

    edits: list[tuple[int, int, str]] = []
    for after in after_values:
        if after == before:
            continue
        matcher = difflib.SequenceMatcher(a=before, b=after, autojunk=False)
        for tag, start, end, replacement_start, replacement_end in matcher.get_opcodes():
            if tag != "equal":
                edits.append((start, end, after[replacement_start:replacement_end]))
    deduplicated: list[tuple[int, int, str]] = []
    for edit in sorted(edits):
        if edit in deduplicated:
            continue
        deduplicated.append(edit)
    for index, left in enumerate(deduplicated):
        for right in deduplicated[index + 1 :]:
            left_start, left_end, left_value = left
            right_start, right_end, right_value = right
            if (
                left_start == left_end == right_start == right_end
                and left_value != right_value
            ):
                return None
            if left_end <= right_start or right_end <= left_start:
                continue
            if left_start == right_start and left_end == right_end and left_value == right_value:
                continue
            return None
    composed = before
    for start, end, replacement in sorted(deduplicated, reverse=True):
        composed = composed[:start] + replacement + composed[end:]
    return composed


def _compose_change_lists(change_lists: list[list[dict[str, Any]]]) -> list[dict[str, Any]] | None:
    by_target: dict[tuple[str, str], dict[str, Any]] = {}
    for changes in change_lists:
        for change in changes:
            object_key = str(change.get("object_key") or "")
            path = normalized_mutation_path(object_key, str(change.get("json_path") or ""))
            target = (object_key, path)
            previous = by_target.get(target)
            if previous is None:
                by_target[target] = copy.deepcopy(change)
                continue
            previous_before = previous.get("before")
            current_before = change.get("before")
            previous_after = previous.get("after")
            current_after = change.get("after")
            if previous_before != current_before:
                return None
            if previous_after == current_after:
                continue
            if not isinstance(previous_before, str) or not isinstance(previous_after, str) or not isinstance(current_after, str):
                return None
            composed = _compose_text_change(previous_before, [previous_after, current_after])
            if composed is None:
                return None
            previous["after"] = composed
    return sorted(
        by_target.values(),
        key=lambda item: (
            str(item.get("object_key") or ""),
            normalized_mutation_path(str(item.get("object_key") or ""), str(item.get("json_path") or "")),
        ),
    )


def _coalesce_compatible_change_writes(operations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Coalesce compatible same-field changes before exact-action merging."""

    def targets(changes: list[dict[str, Any]]) -> set[tuple[str, str]]:
        return {
            (
                str(change.get("object_key") or ""),
                normalized_mutation_path(
                    str(change.get("object_key") or ""),
                    str(change.get("json_path") or ""),
                ),
            )
            for change in changes
        }

    base_groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for operation in operations:
        payload = normalized_action_payload(operation)
        payload["changes"] = []
        base_groups[json.dumps(payload, sort_keys=True, ensure_ascii=False)].append(operation)
    adjusted: list[dict[str, Any]] = []
    for rows in base_groups.values():
        subgroups: list[dict[str, Any]] = []
        for operation in rows:
            operation_changes = [copy.deepcopy(item) for item in as_list(operation.get("changes"))]
            operation_targets = targets(operation_changes)
            for subgroup in subgroups:
                # Composition exists only to combine disjoint edits to the same
                # exported field (for example, two Unicode reference repairs in
                # one Custom JavaScript value). Unrelated field writes remain
                # separately approvable operations even when both are changes.
                if not operation_targets & subgroup["targets"]:
                    continue
                composed = _compose_change_lists(
                    [subgroup["changes"], operation_changes]
                )
                if composed is None:
                    continue
                subgroup["changes"] = composed
                subgroup["targets"].update(operation_targets)
                subgroup["rows"].append(operation)
                break
            else:
                subgroups.append(
                    {
                        "changes": operation_changes,
                        "targets": operation_targets,
                        "rows": [operation],
                    }
                )
        for subgroup in subgroups:
            for operation in subgroup["rows"]:
                adjusted_operation = copy.deepcopy(operation)
                adjusted_operation["changes"] = copy.deepcopy(subgroup["changes"])
                adjusted.append(adjusted_operation)
    return adjusted


def merge_compatible_operations(
    operations: list[dict[str, Any]], errors: list[str]
) -> list[dict[str, Any]]:
    operations = reconcile_redundant_deletion_operations(operations)
    operations = _coalesce_compatible_change_writes(operations)
    key_actions: dict[str, set[str]] = defaultdict(set)
    for operation in operations:
        key_actions[operation["operation_key"]].add(_operation_group_key(operation))
    for operation_key, signatures in sorted(key_actions.items()):
        if len(signatures) > 1:
            errors.append(
                f"operation_key {operation_key!r} is reused for different structured mutations"
            )

    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for operation in operations:
        groups[_operation_group_key(operation)].append(operation)
    merged: list[dict[str, Any]] = []
    for action_signature, rows in sorted(groups.items()):
        first = copy.deepcopy(rows[0])
        source_operation_keys = sorted({str(row.get("operation_key") or "") for row in rows})
        first["operation_key"] = (
            source_operation_keys[0]
            if len(source_operation_keys) == 1
            else f"reconciled-{stable_hash(action_signature, 12)}"
        )
        first["source_operation_keys"] = source_operation_keys
        for field in TEXT_FIELDS:
            first[field] = _selected_text(rows, field)
        challenge_rows = [
            row
            for row in rows
            if isinstance(row.get("challenge_review"), dict)
            and row.get("challenge_review")
        ]
        if challenge_rows:
            verdict_rank = {
                "confirmed": 0,
                "downgraded": 1,
                "rejected": 2,
                "blocked": 3,
            }
            selected_challenge = max(
                challenge_rows,
                key=lambda row: (
                    verdict_rank.get(
                        str(
                            (row.get("challenge_review") or {}).get(
                                "challenge_verdict"
                            )
                            or ""
                        ),
                        -1,
                    ),
                    {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}.get(
                        str(row.get("priority") or ""), -1
                    ),
                    len(json.dumps(row.get("challenge_review"), sort_keys=True)),
                    str(row.get("operation_key") or ""),
                ),
            )
            first["challenge_review"] = copy.deepcopy(
                selected_challenge["challenge_review"]
            )
        else:
            first["challenge_review"] = {}
        classification_rank = {
            "configuration_correctness": 0,
            "business_architecture": 1,
            "operational_sanitation": 2,
        }
        classification_source = min(
            rows,
            key=lambda row: (
                {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}.get(
                    str(row.get("priority") or ""), 4
                ),
                classification_rank.get(
                    str(as_list(row.get("source_runs"))[0])
                    if as_list(row.get("source_runs"))
                    else "",
                    9,
                ),
                str(row.get("operation_key") or ""),
            ),
        )
        first["area"] = str(classification_source.get("area") or "")
        first["problem_type"] = str(
            classification_source.get("problem_type") or ""
        )
        first["lens_classifications"] = [
            {
                "source_run": str(as_list(row.get("source_runs"))[0])
                if as_list(row.get("source_runs"))
                else "",
                "source_reference": str(as_list(row.get("source_references"))[0])
                if as_list(row.get("source_references"))
                else "",
                "area": str(row.get("area") or ""),
                "problem_type": str(row.get("problem_type") or ""),
            }
            for row in sorted(
                rows,
                key=lambda item: (
                    str(as_list(item.get("source_runs"))[0])
                    if as_list(item.get("source_runs"))
                    else "",
                    str(as_list(item.get("source_references"))[0])
                    if as_list(item.get("source_references"))
                    else "",
                ),
            )
        ]
        first["lens_rationales"] = [
            {
                "source_run": str(row.get("source_runs", ["unknown"])[0]),
                "source_reference": str(row.get("source_references", [""])[0]),
                "operation_key": row.get("operation_key"),
                "problem": row.get("problem"),
                "why_it_matters": row.get("why_it_matters"),
                "expected_clean_state": row.get("expected_clean_state"),
            }
            for row in sorted(
                rows,
                key=lambda item: (
                    str(item.get("source_runs", [""])[0]),
                    str(item.get("source_references", [""])[0]),
                ),
            )
        ]
        first["source_runs"] = sorted(
            {value for row in rows for value in as_list(row.get("source_runs"))}
        )
        first["source_references"] = sorted(
            {value for row in rows for value in as_list(row.get("source_references"))}
        )
        first["source_object_keys"] = sorted(
            {value for row in rows for value in as_list(row.get("source_object_keys"))}
        )
        first["affected_object_keys"] = sorted(
            {value for row in rows for value in as_list(row.get("affected_object_keys"))}
        )
        errors.extend(
            validate_challenge(
                first,
                f"compiled operation {first['operation_key']!r}",
            )
        )
        merged.append(first)
    return merged


def normalized_mutation_path(object_key: str, json_path: str) -> str:
    layer = object_key.split(":", 1)[0]
    match = re.match(
        rf"^\$\.(?:containerVersion\.)?{re.escape(layer)}\[\d+\](.*)$",
        json_path,
    )
    return "$" + match.group(1) if match else json_path


def paths_overlap(left: str, right: str) -> bool:
    if left == right:
        return True
    return left.startswith((right + ".", right + "[")) or right.startswith(
        (left + ".", left + "[")
    )


def mutation_state() -> dict[str, Any]:
    return {
        "field_targets": {},
        "rename_targets": {},
        "remap_targets": {},
        "deleted_by": {},
        "created_by": {},
        "addition_targets": defaultdict(list),
        "changed_by": defaultdict(set),
        "writes": [],
    }


def record_creation(
    creation: dict[str, Any], key: str, state: dict[str, Any]
) -> list[str]:
    layer = str(creation.get("layer") or "")
    obj = creation.get("object") or {}
    id_key = ID_KEYS.get(layer, "")
    object_id = str(obj.get(id_key) or obj.get("name") or "")
    target = f"{layer}:{object_id}" if layer and object_id else ""
    if not target:
        return []
    previous = state["created_by"].get(target)
    state["created_by"][target] = key
    state["changed_by"][target].add(key)
    if previous:
        return [f"{target} is created more than once in {previous!r} and {key!r}"]
    return []


def record_addition(
    addition: dict[str, Any], key: str, state: dict[str, Any]
) -> list[str]:
    object_key = str(addition.get("object_key") or "")
    path = normalized_mutation_path(object_key, str(addition.get("json_path") or ""))
    target = (object_key, path, str(addition.get("mode") or ""), addition.get("index"))
    value = json.dumps(addition.get("value"), sort_keys=True, ensure_ascii=False)
    previous_rows = state["addition_targets"][target]
    errors: list[str] = []
    if target[2] in {"set", "insert"} and previous_rows:
        errors.append(
            f"ambiguous {target[2]} additions for {object_key} {path} in "
            f"{previous_rows[0][1]!r} and {key!r}"
        )
    if any(previous_value == value for previous_value, _ in previous_rows):
        errors.append(f"duplicate addition for {object_key} {path} in {key!r}")
    previous_rows.append((value, key))
    state["writes"].append((object_key, path, "addition", value, key))
    state["changed_by"][object_key].add(key)
    return errors


def record_change(change: dict[str, Any], key: str, state: dict[str, Any]) -> list[str]:
    object_key = str(change.get("object_key") or "")
    path = normalized_mutation_path(object_key, str(change.get("json_path") or ""))
    target = (object_key, path)
    value = json.dumps(change.get("after"), sort_keys=True, ensure_ascii=False)
    previous = state["field_targets"].get(target)
    state["field_targets"][target] = (value, key)
    state["writes"].append((object_key, path, "change", value, key))
    state["changed_by"][object_key].add(key)
    if previous:
        return [
            f"duplicate or conflicting field changes for {object_key} {path} in "
            f"{previous[1]!r} and {key!r}"
        ]
    return []


def record_rename(rename: dict[str, Any], key: str, state: dict[str, Any]) -> list[str]:
    target = str(rename.get("object_key") or "")
    value = str(rename.get("after") or "")
    previous = state["rename_targets"].get(target)
    state["rename_targets"][target] = (value, key)
    state["writes"].append((target, "$.name", "rename", json.dumps(value), key))
    state["changed_by"][target].add(key)
    if previous:
        return [
            f"duplicate or conflicting rename targets for {target} in "
            f"{previous[1]!r} and {key!r}"
        ]
    return []


def record_remap(remap: dict[str, Any], key: str, state: dict[str, Any]) -> list[str]:
    source = str(remap.get("from_object_key") or "")
    target = str(remap.get("to_object_key") or "")
    previous = state["remap_targets"].get(source)
    state["remap_targets"][source] = (target, key)
    for consumer in as_list(remap.get("consumer_object_keys")):
        consumer_key = str(consumer or "")
        if consumer_key:
            state["changed_by"][consumer_key].add(key)
    if previous:
        return [
            f"duplicate or conflicting remap targets for {source} in "
            f"{previous[1]!r} and {key!r}"
        ]
    return []


def record_deletion(
    deletion: dict[str, Any], key: str, state: dict[str, Any]
) -> list[str]:
    target = str(deletion.get("object_key") or "")
    previous = state["deleted_by"].get(target)
    state["deleted_by"][target] = key
    if previous:
        return [f"{target} is deleted more than once in {previous!r} and {key!r}"]
    return []


def record_operation_mutations(
    operation: dict[str, Any], state: dict[str, Any]
) -> list[str]:
    errors: list[str] = []
    key = str(operation.get("operation_key") or "")
    handlers = (
        ("creations", record_creation),
        ("additions", record_addition),
        ("changes", record_change),
        ("renames", record_rename),
        ("remaps", record_remap),
        ("deletions", record_deletion),
    )
    for field, handler in handlers:
        for item in as_list(operation.get(field)):
            errors.extend(handler(item, key, state))
    return errors


def overlapping_write_errors(writes: list[tuple[str, str, str, str, str]]) -> list[str]:
    errors: list[str] = []
    for index, left in enumerate(writes):
        for right in writes[index + 1 :]:
            if left[0] != right[0] or not paths_overlap(left[1], right[1]):
                continue
            if left[2] == right[2] == "addition" and left[1] == right[1]:
                continue
            errors.append(
                f"overlapping writes for {left[0]} at {left[1]} and {right[1]} "
                f"in {left[4]!r} and {right[4]!r}"
            )
    return errors


def deletion_conflict_errors(state: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    for target, delete_key in sorted(state["deleted_by"].items()):
        for change_key in sorted(state["changed_by"].get(target, set()) - {delete_key}):
            errors.append(
                f"{target} is deleted by {delete_key!r} but also changed by {change_key!r}"
            )
        if target in state["created_by"]:
            errors.append(
                f"{target} is both created by {state['created_by'][target]!r} "
                f"and deleted by {delete_key!r}"
            )
    for source, (target, operation_key) in sorted(state["remap_targets"].items()):
        if target in state["deleted_by"]:
            errors.append(
                f"{operation_key!r} remaps {source} to {target}, but {target} is also deleted"
            )
    return errors


def validate_mutation_conflicts(operations: list[dict[str, Any]]) -> list[str]:
    state = mutation_state()
    errors: list[str] = []
    for operation in operations:
        errors.extend(record_operation_mutations(operation, state))
    errors.extend(overlapping_write_errors(state["writes"]))
    errors.extend(deletion_conflict_errors(state))
    return errors


def mutation_path_errors(
    operations: list[dict[str, Any]],
    source_paths_by_key: dict[str, str] | None,
) -> list[str]:
    """Bind each source-field mutation to the exact object array entry."""

    errors: list[str] = []
    for operation in operations:
        operation_key = str(operation.get("operation_key") or "")
        for field in ("changes", "additions"):
            for mutation in as_list(operation.get(field)):
                if not isinstance(mutation, dict):
                    continue
                object_key = str(mutation.get("object_key") or "")
                json_path = str(mutation.get("json_path") or "")
                expected_path = (source_paths_by_key or {}).get(object_key)
                if expected_path and not (
                    json_path == expected_path
                    or json_path.startswith((expected_path + ".", expected_path + "["))
                ):
                    errors.append(
                        f"{operation_key!r} {field[:-1]} pairs {object_key!r} with "
                        "another object's source json_path"
                    )
                    continue
                path_match = re.match(
                    r"^\$\.(?:containerVersion\.)?([A-Za-z][A-Za-z0-9]*)\[\d+\]",
                    json_path,
                )
                object_layer = object_key.partition(":")[0]
                if path_match and object_layer and path_match.group(1) != object_layer:
                    errors.append(
                        f"{operation_key!r} {field[:-1]} path layer "
                        f"{path_match.group(1)!r} does not match {object_key!r}"
                    )
    return errors


def destructive_object_keys(operation: dict[str, Any]) -> set[str]:
    return {
        str(item.get("object_key") or "")
        for item in as_list(operation.get("deletions"))
    } | {
        str(item.get("from_object_key") or "")
        for item in as_list(operation.get("remaps"))
    }


NON_BEHAVIOR_PATHS = {
    "$.accountId",
    "$.containerId",
    "$.workspaceId",
    "$.fingerprint",
    "$.path",
    "$.tagManagerUrl",
    "$.name",
    "$.notes",
    "$.parentFolderId",
}


def behavior_impact_keys(operation: dict[str, Any]) -> set[str]:
    """Return existing objects whose execution, data, or routing can change."""
    # Folder removal is organizational metadata. Folder-member moves are
    # represented separately through parentFolderId changes and remain visible
    # exact mutations without pretending that an empty folder has runtime
    # behavior.
    keys = {
        key
        for key in destructive_object_keys(operation)
        if not key.startswith("folder:")
    }
    for field in ("additions", "changes"):
        for item in as_list(operation.get(field)):
            object_key = str(item.get("object_key") or "")
            path = normalized_mutation_path(
                object_key,
                str(item.get("json_path") or ""),
            )
            if object_key and path not in NON_BEHAVIOR_PATHS:
                keys.add(object_key)
    for remap in as_list(operation.get("remaps")):
        # Architecture must prove the equivalence/consolidation of the remap
        # endpoints. The exact consumer list remains mutation evidence and is
        # revalidated in the projected graph, but those consumers should not
        # be recast as architecture conflicts when their dependency is merely
        # switched to the approved canonical equivalent. Folder remaps only
        # update parentFolderId metadata and do not change runtime behavior.
        keys.update(
            str(value)
            for value in [
                remap.get("from_object_key"),
                remap.get("to_object_key"),
            ]
            if value and not str(value).startswith("folder:")
        )
    return keys


def architecture_family_support(
    behavior_keys: set[str], families: list[dict[str, Any]]
) -> set[str]:
    """Return completed architecture families that cover each edited object.

    Source-bound field repairs preserve object identity and do not resolve or
    remove a cross-object relationship.  They still need architecture evidence,
    but duplicating the exact same operation into a family adds no safety.  A
    completed family that includes the object supplies that evidence.
    """
    support_by_key: dict[str, set[str]] = defaultdict(set)
    for family in families:
        if family.get("review_status") != "complete":
            continue
        family_id = str(family.get("family_id") or "")
        if not family_id:
            continue
        family_keys = {
            str(value)
            for value in [
                *as_list(family.get("member_object_keys")),
                *as_list(family.get("chain_object_keys")),
            ]
            if str(value)
        }
        for key in behavior_keys & family_keys:
            support_by_key[key].add(family_id)
    if not behavior_keys <= set(support_by_key):
        return set()
    return set().union(*(support_by_key[key] for key in behavior_keys))


def architecture_cleanup_action_signatures(
    comparisons: list[dict[str, Any]], families: list[dict[str, Any]]
) -> set[str]:
    """Return exact mutation signatures declared by Run 3 cleanup decisions.

    A generic candidate relationship cannot veto the architecture decision that
    explicitly removes or remaps the same member.  The exemption is deliberately
    tied to the complete structured mutation, rather than merely to object
    overlap, so an unrelated deletion cannot borrow another decision's cover.
    """
    signatures: set[str] = set()
    for row in [*comparisons, *families]:
        if row.get("disposition") != "cleanup_operation":
            continue
        for operation in as_list(row.get("operations")):
            signatures.add(_operation_group_key(operation))
    return signatures


RUNTIME_NEUTRAL_LIFECYCLE_FINDINGS = {
    "paused_objects_for_lifecycle_review",
    "unused_built_in_variable",
    "unused_object",
    "used_only_by_paused_tags",
}


def runtime_neutral_operational_deletions(
    operation: dict[str, Any], operational_by_id: dict[str, dict[str, Any]]
) -> set[str]:
    """Return deletions proven outside the active execution graph by Run 1.

    These removals do not alter current execution and therefore do not need a
    fabricated Run 3 relationship. Reference/remap validation and future-state
    simulation remain mandatory.
    """
    if (
        operation.get("problem_type") == "Exact duplicate"
        and "business_architecture" in as_list(operation.get("source_runs"))
        and str(operation.get("canonical_object_key") or "")
        and not any(
            as_list(operation.get(field))
            for field in ("creations", "additions", "changes")
        )
    ):
        remapped_sources = {
            str(remap.get("from_object_key") or "")
            for remap in as_list(operation.get("remaps"))
            if str(remap.get("from_object_key") or "")
        }
        canonical = str(operation.get("canonical_object_key") or "")
        return {
            str(deletion.get("object_key") or "")
            for deletion in as_list(operation.get("deletions"))
            if str(deletion.get("object_key") or "") in remapped_sources
            and str(deletion.get("object_key") or "") != canonical
        }
    ineffective_repair_keys: set[str] = set()
    for reference in as_list(operation.get("source_references")):
        finding = operational_by_id.get(str(reference))
        repair = (finding or {}).get("deterministic_repair") or {}
        if (
            (finding or {}).get("finding_type") == "ineffective_blocking_trigger"
            and str(repair.get("status") or "").startswith("unique_")
        ):
            ineffective_repair_keys.update(
                str(item.get("object_key") or "")
                for item in as_list(repair.get("deletions"))
                if str(item.get("object_key") or "")
            )
    if ineffective_repair_keys:
        return {
            str(item.get("object_key") or "")
            for item in as_list(operation.get("deletions"))
            if str(item.get("object_key") or "") in ineffective_repair_keys
        }

    if any(
        as_list(operation.get(field))
        for field in ("creations", "additions", "changes", "remaps")
    ):
        return set()
    lifecycle_keys: set[str] = set()
    # A paused tag has no active execution path in this export regardless of
    # which review first proposes its retirement. This implements the explicit
    # lifecycle exception without requiring a duplicate Run 3 relationship.
    paused_tag_keys = {
        key
        for finding in operational_by_id.values()
        if finding.get("finding_type") == "paused_objects_for_lifecycle_review"
        for key in operational_object_keys(finding)
    }
    for reference in as_list(operation.get("source_references")):
        finding = operational_by_id.get(str(reference))
        if not finding or finding.get("finding_type") not in RUNTIME_NEUTRAL_LIFECYCLE_FINDINGS:
            continue
        lifecycle_keys.update(operational_object_keys(finding))
    return {
        str(item.get("object_key") or "")
        for item in as_list(operation.get("deletions"))
        if str(item.get("object_key") or "") in lifecycle_keys | paused_tag_keys
    }


def runtime_neutral_operational_behavior_keys(
    operation: dict[str, Any], operational_by_id: dict[str, dict[str, Any]]
) -> set[str]:
    """Return exact Run-1 repair keys proven not to change reachable behavior."""

    keys = runtime_neutral_operational_deletions(operation, operational_by_id)
    for reference in as_list(operation.get("source_references")):
        finding = operational_by_id.get(str(reference))
        repair = (finding or {}).get("deterministic_repair") or {}
        if (
            (finding or {}).get("finding_type") == "ineffective_blocking_trigger"
            and str(repair.get("status") or "").startswith("unique_")
        ):
            keys.update(
                str(value)
                for value in as_list(
                    (finding or {}).get("repair_affected_object_keys")
                )
                if str(value)
            )
    return keys


def operational_source_bound_repair(
    operation: dict[str, Any], operational_by_id: dict[str, dict[str, Any]]
) -> bool:
    """Whether Run 1 supplies a deterministic, exact repair rationale."""
    for reference in as_list(operation.get("source_references")):
        finding = operational_by_id.get(str(reference))
        if not finding:
            continue
        if (
            finding.get("finding_class") == "deterministic_defect"
            and finding.get("disposition") == "cleanup_operation"
        ):
            return True
    return False


def creation_keys(operation: dict[str, Any]) -> set[str]:
    keys: set[str] = set()
    for creation in as_list(operation.get("creations")):
        layer = str(creation.get("layer") or "")
        obj = creation.get("object") or {}
        id_key = ID_KEYS.get(layer, "")
        object_id = str(obj.get(id_key) or obj.get("name") or "")
        if layer and object_id:
            keys.add(f"{layer}:{object_id}")
    return keys


def consolidation_alignment_errors(
    operation: dict[str, Any], operational_by_id: dict[str, dict[str, Any]]
) -> list[str]:
    references = set(as_list(operation.get("source_references")))
    findings = [operational_by_id[key] for key in references if key in operational_by_id]
    requires_architecture = any(
        finding.get("deterministic_action_candidate") == "consolidate_candidate"
        for finding in findings
    )
    if requires_architecture and "business_architecture" not in as_list(
        operation.get("source_runs")
    ):
        return [
            f"{operation.get('operation_key')!r}: deterministic consolidation lacks an "
            "aligned business-architecture operation"
        ]
    return []


def comparison_reconciliation_errors(
    operation_key: str,
    destructive_keys: set[str],
    behavior_keys: set[str],
    comparisons: list[dict[str, Any]],
    architecture_cleanup: bool = False,
) -> list[str]:
    errors: list[str] = []
    for comparison in comparisons:
        candidate_keys = {
            str(value) for value in as_list(comparison.get("candidate_object_keys"))
        }
        destructive = sorted(candidate_keys & destructive_keys)
        behavior = sorted(candidate_keys & behavior_keys)
        # Non-destructive corrections (consent, regex, references, blockers)
        # can preserve a cross-object relationship. Only removal/remap of a
        # candidate contradicts a decision that retains or leaves that exact
        # candidate relationship unresolved.
        if not destructive:
            continue
        # This exact mutation is itself a validated Run 3 cleanup decision.
        # It resolves lower-strength candidate rows involving the member;
        # requiring the same deletion/remap to be copied into every such row
        # creates contradictory duplicate operations without extra safety.
        if architecture_cleanup:
            continue
        disposition = comparison.get("disposition")
        verdict = comparison.get("relationship_verdict")
        comparison_id = comparison.get("comparison_id")
        if destructive and disposition == "keep" and verdict in {
            "Intentional variant",
            "Complementary",
            "Unrelated",
        }:
            errors.append(
                f"{operation_key!r} removes or remaps {destructive!r}, but architecture "
                f"comparison {comparison_id} says to keep them"
            )
        if disposition in {"owner_decision_needed", "container_evidence_limit"}:
            errors.append(
                f"{operation_key!r} changes {behavior!r} while architecture "
                f"comparison {comparison_id} is unresolved"
            )
    return errors


def family_reconciliation_errors(
    operation_key: str,
    destructive_keys: set[str],
    behavior_keys: set[str],
    families: list[dict[str, Any]],
    architecture_cleanup: bool = False,
) -> list[str]:
    errors: list[str] = []
    for family in families:
        # Dependency consolidation is governed by its own relationship. It
        # should not force every consuming business family to become a fake
        # conflict. A family contradiction exists when a root member that the
        # family retains is itself removed or remapped.
        family_keys = {str(value) for value in as_list(family.get("member_object_keys"))}
        destructive = sorted(destructive_keys & family_keys)
        behavior = sorted(behavior_keys & family_keys)
        if not destructive:
            continue
        if architecture_cleanup:
            continue
        disposition = family.get("disposition")
        verdict = family.get("relationship_verdict")
        family_id = family.get("family_id")
        if disposition in {"owner_decision_needed", "container_evidence_limit"}:
            errors.append(
                f"{operation_key!r} changes {behavior!r} while architecture "
                f"family {family_id} remains unresolved"
            )
        elif destructive and disposition == "keep" and verdict in {
            "Intentional variant",
            "Complementary",
            "Unrelated",
        }:
            errors.append(
                f"{operation_key!r} removes or remaps {destructive!r} but architecture "
                f"family {family_id} says to keep the chain"
            )
    return errors


def validate_cross_run_reconciliation(
    operational: dict[str, Any],
    architecture: dict[str, Any],
    operations: list[dict[str, Any]],
) -> list[str]:
    errors: list[str] = []
    operational_by_id = {
        str(row.get("finding_id") or ""): row for row in as_list(operational.get("findings"))
    }
    comparison_rows = as_list(architecture.get("comparisons"))
    family_rows = as_list(architecture.get("families"))
    architecture_cleanup_actions = architecture_cleanup_action_signatures(
        comparison_rows, family_rows
    )
    for operation in operations:
        operation_key = str(operation.get("operation_key") or "")
        destructive_keys = destructive_object_keys(operation)
        behavior_keys = behavior_impact_keys(operation)
        runtime_neutral_keys = runtime_neutral_operational_deletions(
            operation, operational_by_id
        )
        runtime_neutral_behavior_keys = runtime_neutral_operational_behavior_keys(
            operation, operational_by_id
        )
        if runtime_neutral_keys:
            operation["runtime_neutral_deletion_keys"] = sorted(
                runtime_neutral_keys
            )
        behavior_keys -= runtime_neutral_behavior_keys
        reconciliation_destructive_keys = destructive_keys - runtime_neutral_keys
        created_keys = {
            key for key in creation_keys(operation) if not key.startswith("folder:")
        }
        architecture_cleanup = (
            bool(reconciliation_destructive_keys)
            and "business_architecture" in as_list(operation.get("source_runs"))
            and _operation_group_key(operation) in architecture_cleanup_actions
        )
        # A merged mutation can be runtime-neutral from one sanitation finding
        # (for example, "unused variable") while the same deletion also resolves
        # a consolidation candidate.  The latter still needs an independent
        # architecture decision, so never let the runtime-neutral classification
        # suppress consolidation alignment.
        errors.extend(consolidation_alignment_errors(operation, operational_by_id))
        if behavior_keys and "business_architecture" not in as_list(
            operation.get("source_runs")
        ):
            supporting_family_ids = architecture_family_support(behavior_keys, family_rows)
            source_bound_direct_repair = (
                not destructive_keys
                and not created_keys
                and (
                    "configuration_correctness" in as_list(operation.get("source_runs"))
                    or operational_source_bound_repair(operation, operational_by_id)
                )
                and bool(supporting_family_ids)
            )
            if source_bound_direct_repair:
                operation["architecture_supporting_family_ids"] = sorted(
                    supporting_family_ids
                )
            else:
                errors.append(
                    f"{operation_key!r} changes behavior of {sorted(behavior_keys)!r} "
                    "without an aligned business-architecture operation"
                )
        if created_keys and "business_architecture" not in as_list(
            operation.get("source_runs")
        ):
            errors.append(
                f"{operation_key!r} creates {sorted(created_keys)!r} without an aligned "
                "business-architecture operation"
            )
        errors.extend(
            comparison_reconciliation_errors(
                operation_key,
                reconciliation_destructive_keys,
                behavior_keys,
                comparison_rows,
                architecture_cleanup,
            )
        )
        errors.extend(
            family_reconciliation_errors(
                operation_key,
                reconciliation_destructive_keys,
                behavior_keys,
                family_rows,
                architecture_cleanup,
            )
        )
    return errors


def affected_objects(operation: dict[str, Any], catalog: dict[str, dict[str, str]]) -> str:
    labels = []
    for key in as_list(operation.get("affected_object_keys")):
        item = catalog.get(str(key))
        labels.append(
            f"{key} — {item['object_name']}" if item and item["object_name"] else str(key)
        )
    return "; ".join(labels)


def operational_taxonomy(finding: dict[str, Any]) -> tuple[str, str]:
    text = (
        f"{finding.get('finding_type') or ''} "
        f"{finding.get('module_name') or ''}"
    ).lower()
    if "missing" in text or "undefined" in text or "reference" in text:
        return "Event firing logic", "Broken reference"
    if "ineffective_blocking_trigger" in text:
        return "Event firing logic", "Over-firing"
    if "consent" in text or "blocking" in text:
        return "Consent & compliance", "Consent mismatch"
    if "duplicate" in text:
        return "GTM hygiene", "Exact duplicate"
    if "unused" in text or "paused" in text:
        return "GTM hygiene", "Unused object"
    if "folder" in text or "unfiled" in text:
        return "GTM hygiene", "Folder organization"
    if "name" in text or "unicode" in text or "confusable" in text:
        return "GTM hygiene", "Naming inconsistency"
    if "legacy" in text or "universal" in text or "ua_" in text:
        return "GTM hygiene", "Obsolete or legacy setup"
    if "formula" in text or "fixed" in text:
        return "Ecommerce payload quality", "Wrong value or formula logic"
    if "trigger" in text or "sequence" in text or "schedule" in text:
        return "Event firing logic", "Wrong trigger timing"
    if "custom_code" in text or "template" in text:
        return "Custom code & templates", "Custom code risk"
    return "GTM hygiene", "Unnecessary complexity"


def configuration_taxonomy(review: dict[str, Any]) -> tuple[str, str]:
    layer = str(review.get("layer") or "")
    defect_text = json.dumps(review.get("defects") or [], ensure_ascii=False).lower()
    technical_text = json.dumps(
        {
            "required": review.get("required_technical_findings") or [],
            "completed": review.get("technical_finding_reviews") or [],
            "assessment": review.get("technical_facts_assessment") or "",
        },
        ensure_ascii=False,
    ).lower()
    decision_text = " ".join(
        str(review.get(field) or "")
        for field in ("correctness_basis", "owner_question")
    ).lower()
    issue_text = " ".join((defect_text, technical_text, decision_text))

    # Classify the actual defect/decision, not the generic consent facts that
    # every tag row carries. This keeps code, reference, and formula work out
    # of the consent queue merely because the object also has consent settings.
    if re.search(
        r"missing (?:reference|dependency|setup|teardown)|"
        r"resolves as missing|undefined .*reference|missing or cyclic|ambiguous reference",
        defect_text,
    ):
        return "Event firing logic", "Broken reference"
    if (
        layer == "customTemplate"
        or bool(review.get("required_code_line_hashes"))
        or bool(review.get("required_technical_findings"))
    ):
        return "Custom code & templates", "Custom code risk"
    if re.search(
        r"purchase|refund|ecommerce|items|currency|quantity|transaction|"
        r"revenue|fixed numbered|formula",
        issue_text,
    ):
        return "Ecommerce payload quality", "Wrong value or formula logic"
    if re.search(
        r"consent (?:mismatch|route|purpose|status|timing|control)|"
        r"cmp (?:mapping|category|purpose)|ad_user_data|ad_personalization|"
        r"analytics_storage|ad_storage",
        issue_text,
    ):
        return "Consent & compliance", "Consent mismatch"
    if re.search(r"server|transport_url|first.party|routing", issue_text):
        return "Server-side tracking", "Server-side routing unclear"
    if str(review.get("vendor_category") or "") in {"media", "affiliate"}:
        return "Media platform tracking", "Incomplete payload"
    if layer == "trigger":
        return "Event firing logic", "Wrong trigger timing"
    return "Tracking plan / dataLayer", "Unclear business purpose"


def architecture_taxonomy(row: dict[str, Any]) -> tuple[str, str]:
    comparison_types = set(as_list(row.get("comparison_types")))
    text = json.dumps(row.get("candidate_basis") or [], ensure_ascii=False).lower()
    if "different_consent_purposes_same_logic" in comparison_types or "consent" in text:
        return "Consent & compliance", "Consent mismatch"
    if "exact_configuration" in comparison_types:
        return "GTM hygiene", "Exact duplicate"
    if comparison_types & {
        "equivalent_trigger_conditions",
        "near_equivalent_trigger_conditions",
        "trigger_condition_subset",
        "shared_business_scope",
        "multi_firing_route_consolidation_review",
    }:
        return "Event firing logic", "Functional overlap"
    if comparison_types & {
        "same_vendor_destination_event",
        "same_vendor_event_family",
        "cross_vendor_event_family",
    }:
        return "Data quality / reporting", "Duplicate firing"
    if "server" in text:
        return "Server-side tracking", "Server-side routing unclear"
    return "Stack & architecture", "Functional overlap"


def context_taxonomy(question: str) -> tuple[str, str]:
    lowered = question.lower()
    if "cmp" in lowered or "consent" in lowered:
        return "Consent & compliance", "Consent mismatch"
    if "server" in lowered or "route" in lowered:
        return "Server-side tracking", "Server-side routing unclear"
    return "Governance / ownership", "Unclear business purpose"


def context_recommendation(question: str) -> str:
    lowered = question.lower()
    if "cmp" in lowered or "consent" in lowered:
        return (
            "Confirm the CMP and consent owner, preserve the current route until the "
            "intended purpose mapping is documented, then apply that approved mapping; "
            "do not choose a route from relative strictness alone."
        )
    if "server" in lowered or "route" in lowered:
        return (
            "Confirm the browser-to-server route owner and inspect the receiving container "
            "before approving any cleanup that depends on unseen server behavior."
        )
    return (
        "Provide the named business or scope decision, then use it to choose the simplest "
        "configuration that preserves the required measurement outcome."
    )


def context_decisions(operational: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for index, question_value in enumerate(
        as_list(operational.get("unresolved_context_questions")), start=1
    ):
        question = str(question_value)
        area, problem_type = context_taxonomy(question)
        rows.append(
            {
                "decision_id": f"CONTEXT-{index:03d}",
                "source_run": "audit_context",
                "source_object_keys": [],
                "verdict": "Context required",
                "disposition": "owner_decision_needed",
                "title": "Audit context confirmation",
                "area": area,
                "problem_type": problem_type,
                "affected_objects": "Container scope",
                "summary": question,
                "owner_question": question,
                "recommended_action": context_recommendation(question),
                "confidence": "High",
                "operation_keys": [],
            }
        )
    return rows


def operational_decisions(operational: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for finding in as_list(operational.get("findings")):
        area, problem_type = operational_taxonomy(finding)
        layer = str(finding.get("object_type") or "object")
        affected = "; ".join(
            f"{layer}:{object_id} — {name}" if name else f"{layer}:{object_id}"
            for object_id, name in zip(
                as_list(finding.get("object_ids")),
                as_list(finding.get("object_names")),
                strict=False,
            )
            if str(object_id)
        )
        rows.append(
            {
                "decision_id": str(finding.get("finding_id") or ""),
                "source_run": "operational_sanitation",
                "source_object_keys": operational_object_keys(finding),
                "verdict": str(finding.get("finding_type") or ""),
                "disposition": str(finding.get("disposition") or ""),
                "finding_class": str(finding.get("finding_class") or ""),
                "deterministic_action_candidate": str(
                    finding.get("deterministic_action_candidate") or ""
                ),
                "deterministic_repair_status": str(
                    (finding.get("deterministic_repair") or {}).get("status") or ""
                ),
                "rename_candidate_unique": bool(
                    finding.get("rename_candidate_unique")
                ),
                "policy_confirmation_required": bool(
                    finding.get("policy_confirmation_required")
                ),
                "proposed_final_name": str(
                    finding.get("proposed_final_name") or ""
                ),
                "rename_blocker": str(finding.get("rename_blocker") or ""),
                "title": str(
                    finding.get("title")
                    or str(finding.get("finding_type") or "").replace("_", " ").title()
                ),
                "area": str(finding.get("area") or area),
                "problem_type": str(finding.get("problem_type") or problem_type),
                "affected_objects": affected
                or "Container-wide operational policy",
                "summary": str(
                    finding.get("problem")
                    or (
                        finding.get("deterministic_evidence")
                        if finding.get("finding_type")
                        == "naming_policy_confirmation_required"
                        else ""
                    )
                    or finding.get("rationale")
                    or finding.get("deterministic_evidence")
                    or ""
                ),
                "owner_question": str(finding.get("owner_question") or ""),
                "recommended_action": str(finding.get("recommended_action") or ""),
                "confidence": str(finding.get("confidence") or ""),
                "operation_keys": [str(finding.get("operation_key") or "")]
                if finding.get("disposition") == "cleanup_operation"
                else [],
            }
        )
    return rows


def configuration_decisions(configuration: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for review in as_list(configuration.get("rows")):
        operation = review.get("operation") or {}
        area, problem_type = configuration_taxonomy(review)
        missing_reference_terminals = [
            {
                "reference": str(terminal.get("reference") or ""),
                "source_object_key": str(
                    terminal.get("source_object_key") or review.get("object_key") or ""
                ),
                "normalization_candidate_names": [
                    str(value)
                    for value in as_list(
                        terminal.get("normalization_candidate_names")
                    )
                    if str(value)
                ],
                "normalization_resolution": str(
                    terminal.get("normalization_resolution") or ""
                ),
            }
            for trace in as_list(review.get("reference_trace_requirements"))
            for terminal in as_list(trace.get("terminal_requirements"))
            if terminal.get("state") == "missing"
        ]
        technical_findings = [
            {
                "finding_key": str(source.get("finding_key") or ""),
                "decision_class": str(source.get("decision_class") or ""),
                "statement": str(source.get("statement") or ""),
                "verdict": str(
                    next(
                        (
                            item.get("verdict")
                            for item in as_list(
                                review.get("technical_finding_reviews")
                            )
                            if item.get("finding_key") == source.get("finding_key")
                        ),
                        "",
                    )
                    or ""
                ),
            }
            for source in as_list(review.get("required_technical_findings"))
        ]
        rows.append(
            {
                "decision_id": str(review.get("review_id") or review.get("object_key") or ""),
                "source_run": "configuration_correctness",
                "source_object_keys": [str(review.get("object_key") or "")],
                "source_layer": str(review.get("layer") or ""),
                "consumer_object_keys": sorted(
                    {
                        str(item.get("consumer_key") or "")
                        for item in as_list(review.get("export_consumers"))
                        if isinstance(item, dict) and str(item.get("consumer_key") or "")
                    }
                ),
                "defect_evidence_anchors": sorted(
                    {
                        str(anchor)
                        for defect in as_list(review.get("defects"))
                        if isinstance(defect, dict)
                        for anchor in as_list(defect.get("evidence_anchors"))
                        if str(anchor)
                    }
                ),
                "verdict": str(review.get("correctness_verdict") or ""),
                "disposition": str(review.get("disposition") or ""),
                "title": str(
                    review.get("object_name")
                    or review.get("object_key")
                    or "Configuration decision"
                ),
                "area": area,
                "problem_type": problem_type,
                "affected_objects": (
                    f"{review.get('object_key')} — {review.get('object_name')}"
                ),
                "summary": str(
                    review.get("correctness_basis")
                    or review.get("configured_output_or_side_effect")
                    or ""
                ),
                "missing_reference_terminals": missing_reference_terminals,
                "technical_findings": technical_findings,
                "technical_summary": str(
                    review.get("technical_facts_assessment")
                    or (review.get("technical_code_facts") or {}).get(
                        "technical_plain_language_summary"
                    )
                    or ""
                ),
                "owner_question": str(review.get("owner_question") or ""),
                "recommended_action": str(review.get("recommended_action") or ""),
                "confidence": str(review.get("confidence") or ""),
                "external_evidence_status": str(
                    review.get("external_evidence_status") or ""
                ),
                "external_evidence_summary": str(
                    review.get("external_evidence_summary") or ""
                ),
                "external_evidence_next_action": str(
                    review.get("external_evidence_next_action") or ""
                ),
                "detected_vendor": str(review.get("detected_vendor") or ""),
                "server_routing_hosts": [
                    str(value)
                    for value in as_list(
                        (review.get("effective_consent_route_facts") or {}).get(
                            "server_routing_hosts"
                        )
                    )
                    if str(value)
                ],
                "configured_event_values": sorted(
                    {
                        str(value)
                        for topic in as_list(review.get("required_contract_topics"))
                        for value in as_list(topic.get("configured_event_values"))
                        if str(value)
                    }
                ),
                "operation_keys": [str(operation.get("operation_key") or "")]
                if review.get("disposition") == "cleanup_operation"
                else [],
            }
        )
    return rows


def architecture_decision_row(
    row: dict[str, Any], id_field: str, key_field: str
) -> dict[str, Any]:
    area, problem_type = architecture_taxonomy(row)
    keys = [str(value) for value in as_list(row.get(key_field))]
    if key_field == "candidate_object_keys":
        names = [str(value) for value in as_list(row.get("candidate_object_names"))]
        affected = "; ".join(
            f"{key} — {name}" if name else key
            for key, name in zip(keys, names, strict=False)
        )
    else:
        names_by_key = row.get("chain_object_names") or {}
        affected = "; ".join(
            (
                f"{key} — {names_by_key.get(key)}"
                if isinstance(names_by_key, dict) and names_by_key.get(key)
                else key
            )
            for key in keys
        )
    return {
        "decision_id": str(row.get(id_field) or ""),
        "source_run": "business_architecture",
        "source_object_keys": keys,
        "verdict": str(row.get("relationship_verdict") or ""),
        "disposition": str(row.get("disposition") or ""),
        "title": str(
            row.get("family_label")
            or row.get("comparison_id")
            or row.get(id_field)
            or "Architecture decision"
        ),
        "area": area,
        "problem_type": problem_type,
        "affected_objects": affected or "Container-wide target architecture",
        "summary": str(
            row.get("analyst_rationale")
            or row.get("architecture_effect")
            or row.get("family_purpose")
            or ""
        ),
        "owner_question": str(row.get("owner_question") or ""),
        "recommended_action": str(row.get("recommended_action") or ""),
        "comparison_types": [
            str(value) for value in as_list(row.get("comparison_types")) if str(value)
        ],
        "recommended_canonical_object_key": str(
            row.get("recommended_canonical_object_key") or ""
        ),
        "recommended_canonical_basis": str(
            row.get("recommended_canonical_basis")
            or row.get("canonical_selection_rationale")
            or ""
        ),
        "confidence": str(row.get("confidence") or ""),
        "operation_keys": [
            str(operation.get("operation_key") or "")
            for operation in as_list(row.get("operations"))
        ],
    }


def architecture_decisions(architecture: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for collection, id_field, key_field in (
        (as_list(architecture.get("families")), "family_id", "chain_object_keys"),
        (
            as_list(architecture.get("comparisons")),
            "comparison_id",
            "candidate_object_keys",
        ),
    ):
        rows.extend(
            architecture_decision_row(row, id_field, key_field) for row in collection
        )
    return rows


def decision_ledger(
    operational: dict[str, Any],
    configuration: dict[str, Any],
    architecture: dict[str, Any],
) -> list[dict[str, Any]]:
    rows = [
        *context_decisions(operational),
        *operational_decisions(operational),
        *configuration_decisions(configuration),
        *architecture_decisions(architecture),
    ]
    return sorted(rows, key=lambda row: (row["source_run"], row["decision_id"]))


def projected_object_counts(
    catalog: dict[str, dict[str, str]], operations: list[dict[str, Any]]
) -> dict[str, dict[str, int]]:
    layers = sorted({item.get("layer", "") for item in catalog.values() if item.get("layer")})
    deleted = {
        str(item.get("object_key") or "")
        for operation in operations
        for item in as_list(operation.get("deletions"))
    }
    created: set[str] = set()
    for operation in operations:
        for creation in as_list(operation.get("creations")):
            layer = str(creation.get("layer") or "")
            obj = creation.get("object")
            if layer not in ID_KEYS or not isinstance(obj, dict):
                continue
            object_id = str(obj.get(ID_KEYS[layer]) or obj.get("name") or "")
            if object_id:
                created.add(f"{layer}:{object_id}")
    layers = sorted(
        set(layers)
        | {key.split(":", 1)[0] for key in created if ":" in key}
    )
    rows: dict[str, dict[str, int]] = {}
    for layer in layers:
        before = sum(1 for item in catalog.values() if item.get("layer") == layer)
        deletion_count = sum(
            1
            for key in deleted
            if key in catalog and catalog[key].get("layer") == layer
        )
        creation_count = sum(1 for key in created if key.startswith(layer + ":"))
        rows[layer] = {
            "before": before,
            "after": before - deletion_count + creation_count,
            "delta": creation_count - deletion_count,
        }
    return rows


def measurement_preservation_summary(
    architecture: dict[str, Any],
    operations: list[dict[str, Any]],
) -> dict[str, Any]:
    """Project how the cleanup plan treats every source-confirmed business family."""
    families: list[dict[str, Any]] = []
    for family in as_list(architecture.get("families")):
        family_id = str(family.get("family_id") or "")
        family_keys = {
            str(value)
            for value in [
                *as_list(family.get("member_object_keys")),
                *as_list(family.get("chain_object_keys")),
            ]
            if str(value)
        }
        related = [
            operation
            for operation in operations
            if (
                family_keys
                & {
                    str(value)
                    for value in [
                        *as_list(operation.get("affected_object_keys")),
                        *as_list(operation.get("source_object_keys")),
                    ]
                    if str(value)
                }
            )
            or any(
                str(reference).startswith(f"{family_id}:operation:")
                for reference in as_list(operation.get("source_references"))
            )
        ]
        disposition = str(family.get("disposition") or "")
        if disposition == "owner_decision_needed":
            status = "owner_confirmation_required"
        elif disposition == "container_evidence_limit":
            status = "container_evidence_boundary"
        elif related:
            status = "planned_change"
        elif disposition == "keep":
            status = "retained_unchanged"
        else:
            status = "reviewed_no_operation"
        families.append(
            {
                "family_id": family_id,
                "family_label": str(
                    family.get("family_label")
                    or family.get("family_key")
                    or family.get("family_id")
                    or ""
                ),
                "preservation_status": status,
                "source_object_keys": sorted(family_keys),
                "related_operation_ids": sorted(
                    {
                        str(operation.get("operation_id") or "")
                        for operation in related
                        if operation.get("operation_id")
                    }
                ),
                "required_business_behavior": str(
                    family.get("business_action")
                    or family.get("family_purpose")
                    or family.get("analyst_rationale")
                    or ""
                ),
                "execution_path": str(family.get("execution_path_summary") or ""),
                "consent_and_routing": str(
                    family.get("consent_and_sequence_coherence") or ""
                ),
                "target_state": str(
                    family.get("target_architecture")
                    or family.get("recommended_action")
                    or ""
                ),
                "owner_question": str(family.get("owner_question") or ""),
            }
        )
    counts = {
        status: sum(
            1 for family in families if family.get("preservation_status") == status
        )
        for status in (
            "retained_unchanged",
            "planned_change",
            "owner_confirmation_required",
            "container_evidence_boundary",
            "reviewed_no_operation",
        )
    }
    unresolved = counts["owner_confirmation_required"] + counts[
        "container_evidence_boundary"
    ]
    return {
        "status": "owner_confirmation_required" if unresolved else "complete",
        "scope": (
            "Container-visible preservation of configured measurement families, "
            "dependencies, consent controls, and routing. Live delivery, dataLayer values, "
            "CMP behavior, vendor acceptance, and unseen server behavior remain outside "
            "this container-only projection."
        ),
        "counts": counts,
        "families": families,
    }


def annotate_operation_preservation(
    operations: list[dict[str, Any]],
    preservation: dict[str, Any],
) -> None:
    for operation in operations:
        relevant_keys = {
            str(value)
            for value in [
                *as_list(operation.get("affected_object_keys")),
                *as_list(operation.get("source_object_keys")),
            ]
            if str(value)
        }
        source_references = {
            str(value)
            for value in as_list(operation.get("source_references"))
            if str(value)
        }
        families = [
            family
            for family in as_list(preservation.get("families"))
            if (
                relevant_keys
                & {
                    str(value)
                    for value in as_list(family.get("source_object_keys"))
                    if str(value)
                }
            )
            or any(
                reference.startswith(f"{family.get('family_id')}:operation:")
                for reference in source_references
            )
        ]
        operation["affected_measurement_family_ids"] = sorted(
            {
                str(family.get("family_id") or "")
                for family in families
                if family.get("family_id")
            }
        )
        operation["retained_behavior"] = " ".join(
            dict.fromkeys(
                str(family.get("required_business_behavior") or "")
                for family in families
                if specific_text(family.get("required_business_behavior"), 5)
            )
        )


def validate_review_bundle(
    operational: dict[str, Any],
    configuration: dict[str, Any],
    architecture: dict[str, Any],
    route: str,
) -> tuple[list[str], set[str], set[str], set[str]]:
    errors: list[str] = []
    if not route.strip():
        errors.append("execution route must not be blank")
    expected_kinds = {
        "operational": "gtm_operational_sanitation_review",
        "configuration": "gtm_configuration_correctness_review",
        "architecture": "gtm_business_architecture_review",
    }
    expected_runs = {
        "operational": "operational_sanitation",
        "configuration": "configuration_correctness",
        "architecture": "business_architecture",
    }
    supplied = {
        "operational": operational,
        "configuration": configuration,
        "architecture": architecture,
    }
    hashes: set[str] = set()
    fact_hashes: set[str] = set()
    context_hashes: set[str] = set()
    hash_targets = (
        ("source_sha256", hashes),
        ("shared_facts_sha256", fact_hashes),
        ("context_sha256", context_hashes),
    )
    for label, payload in supplied.items():
        if payload.get("kind") != expected_kinds[label]:
            errors.append(f"{label} review kind is invalid")
        if payload.get("run_status") != "complete":
            errors.append(f"{label} review is not complete")
        if (payload.get("input_contract") or {}).get("review_run") != expected_runs[label]:
            errors.append(f"{label} review input contract is invalid")
        errors.extend(validate_review_provenance(payload, payload, f"{label} review"))
        for field, target in hash_targets:
            if payload.get(field):
                target.add(str(payload.get(field)))
    for values, message in (
        (hashes, "the three reviews do not share one source export hash"),
        (fact_hashes, "the three reviews do not share one canonical fact hash"),
        (context_hashes, "the three reviews do not share one audit context hash"),
    ):
        if len(values) != 1:
            errors.append(message)
    return errors, hashes, fact_hashes, context_hashes


def ledger_link_errors(
    ledger: list[dict[str, Any]], operations: list[dict[str, Any]]
) -> list[str]:
    compiled_keys = {
        key
        for row in operations
        for key in [
            str(row.get("operation_key") or ""),
            *[str(value) for value in as_list(row.get("source_operation_keys"))],
        ]
        if key
    }
    errors: list[str] = []
    for decision in ledger:
        if decision.get("disposition") != "cleanup_operation":
            continue
        operation_keys = {key for key in as_list(decision.get("operation_keys")) if key}
        if not operation_keys:
            errors.append(
                f"decision {decision.get('decision_id')!r} is marked cleanup_operation "
                "without an operation key"
            )
            continue
        missing_keys = sorted(operation_keys - compiled_keys)
        if missing_keys:
            errors.append(
                f"decision {decision.get('decision_id')!r} is missing from compiled "
                "operations: " + ", ".join(missing_keys)
            )
    return errors


EXECUTION_PHASES = (
    ("create", "creations"),
    ("add", "additions"),
    ("change", "changes"),
    ("remap", "remaps"),
    ("rename", "renames"),
    ("delete", "deletions"),
)


def operation_priority_basis(
    operation: dict[str, Any],
    catalog: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Explain priority from source reach, impact, evidence, and rollback facts."""
    object_keys = {
        str(value)
        for value in [
            *as_list(operation.get("affected_object_keys")),
            *as_list(operation.get("source_object_keys")),
        ]
        if str(value)
    }
    known_states = {
        str(catalog[key].get("reachability") or "")
        for key in object_keys
        if key in catalog
    }
    known_layers = {
        str(catalog[key].get("layer") or "")
        for key in object_keys
        if key in catalog
    }
    if known_layers and known_layers <= {"folder"}:
        reachability = "metadata_only"
    elif "active" in known_states:
        reachability = "active"
    elif known_states and known_states <= {"paused_only"}:
        reachability = "paused_only"
    elif known_states:
        reachability = "inactive_or_unreferenced"
    else:
        reachability = "unknown"

    text = json.dumps(
        {
            field: operation.get(field)
            for field in (
                "area",
                "problem_type",
                "problem",
                "why_it_matters",
                "exact_proposed_action",
            )
        },
        ensure_ascii=False,
    ).lower()
    impact_patterns = (
        (
            "consent_privacy",
            r"consent|privacy|cookie|samesite|personalization|ad_user_data|storage",
        ),
        (
            "security",
            r"security|unsafe|eval|origin|injection|unencrypted|http://|google_tag_manager",
        ),
        (
            "measurement_loss_or_corruption",
            r"measurement|missing|broken|invalid|wrong|formula|value|currency|"
            r"transaction|revenue|payload|data loss",
        ),
        (
            "duplicate_delivery_or_attribution",
            r"duplicate|deduplic|double|overlap|consolidat|attribution",
        ),
        (
            "routing_or_integration",
            r"server|routing|route|destination|vendor|endpoint|transport",
        ),
        (
            "maintainability",
            r"naming|folder|unused|paused|complex|legacy|hygiene|organisation|organization",
        ),
    )
    impact_classes = [
        name for name, pattern in impact_patterns if re.search(pattern, text)
    ] or ["architecture_or_configuration"]

    if as_list(operation.get("deletions")) or as_list(operation.get("remaps")):
        reversibility = "source_restorable_behavior_change"
    elif as_list(operation.get("creations")):
        reversibility = "additive_with_explicit_rollback"
    elif as_list(operation.get("changes")) or as_list(operation.get("additions")):
        reversibility = "field_level_rollback"
    elif as_list(operation.get("renames")):
        reversibility = "name_and_reference_rollback"
    else:
        reversibility = "no_mutation"

    readiness = str(operation.get("execution_readiness") or "")
    owner_dependency = (
        "blocking_owner_dependency"
        if readiness in {"owner_blocked", "not_actionable"}
        else "approval_only"
    )
    confidence = str(operation.get("confidence") or "Low")
    if (
        reachability == "active"
        and {"consent_privacy", "security", "measurement_loss_or_corruption"}
        & set(impact_classes)
    ):
        calibrated_floor = "High"
    elif reachability == "active" or {
        "duplicate_delivery_or_attribution",
        "routing_or_integration",
    } & set(impact_classes):
        calibrated_floor = "Medium"
    else:
        calibrated_floor = "Low"
    assigned = str(operation.get("priority") or "")
    rank = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
    alignment = (
        "at_or_above_evidence_floor"
        if rank.get(assigned, 0) >= rank[calibrated_floor]
        else "below_evidence_floor_review_recommended"
    )
    return {
        "assigned_priority": assigned,
        "active_reachability": reachability,
        "impact_classes": impact_classes,
        "evidence_confidence": confidence,
        "reversibility": reversibility,
        "owner_dependency": owner_dependency,
        "calibrated_floor": calibrated_floor,
        "alignment": alignment,
        "rationale": (
            f"{reachability} source reach; impact={','.join(impact_classes)}; "
            f"confidence={confidence}; rollback={reversibility}; "
            f"owner={owner_dependency}."
        ),
    }


SERVER_ROUTE_PATH_RE = re.compile(
    r"transport[_-]?url|server(?:container|tagging)?[_-]?url|first[_-]?party[_-]?url",
    re.I,
)
ACTIVATION_PATH_RE = re.compile(
    r"firingTriggerId|blockingTriggerId|setupTag|teardownTag|paused|"
    r"scheduleStartMs|scheduleEndMs",
    re.I,
)


def operation_server_route_hosts(
    operation: dict[str, Any],
    catalog: dict[str, dict[str, Any]],
) -> list[str]:
    """Return server hosts from exact behavior-bearing source or mutation fields."""
    hosts = {
        str(host)
        for key in {
            *[str(value) for value in as_list(operation.get("affected_object_keys"))],
            *[str(value) for value in as_list(operation.get("source_object_keys"))],
        }
        for host in as_list(catalog.get(key, {}).get("server_route_hosts"))
        if str(host)
    }
    for creation in as_list(operation.get("creations")):
        if isinstance(creation, dict):
            hosts.update(server_route_hosts(creation.get("object") or {}))
    for field in ("changes", "additions"):
        for mutation in as_list(operation.get(field)):
            if not isinstance(mutation, dict):
                continue
            path = str(mutation.get("json_path") or "")
            value = mutation.get("after") if field == "changes" else mutation.get("value")
            structured_probe = (
                {"parameter": value if isinstance(value, list) else [value]}
                if isinstance(value, (dict, list))
                else {}
            )
            hosts.update(server_route_hosts(structured_probe))
            if not SERVER_ROUTE_PATH_RE.search(path):
                continue
            probe = {
                "parameter": [
                    {
                        "key": "transport_url",
                        "value": value,
                    }
                ]
            }
            hosts.update(server_route_hosts(probe))
    return sorted(hosts)


def operation_has_configured_activation_risk(operation: dict[str, Any]) -> bool:
    """Flag mutations that can change configured reachability, never live firing."""
    creation_risk = any(
        str(creation.get("layer") or "") == "tag"
        and bool(as_list((creation.get("object") or {}).get("firingTriggerId")))
        and not bool((creation.get("object") or {}).get("paused"))
        for creation in as_list(operation.get("creations"))
        if isinstance(creation, dict)
    )
    remap_risk = any(
        str(remap.get("from_object_key") or "").startswith(("tag:", "trigger:"))
        or str(remap.get("to_object_key") or "").startswith(("tag:", "trigger:"))
        or any(
            str(key).startswith(("tag:", "trigger:"))
            for key in as_list(remap.get("consumer_object_keys"))
        )
        for remap in as_list(operation.get("remaps"))
        if isinstance(remap, dict)
    )
    mutation_risk = False
    for field in ("changes", "additions"):
        for mutation in as_list(operation.get(field)):
            if not isinstance(mutation, dict):
                continue
            if ACTIVATION_PATH_RE.search(str(mutation.get("json_path") or "")):
                mutation_risk = True
    return creation_risk or remap_risk or mutation_risk


def operation_safety_metadata(
    operation: dict[str, Any],
    catalog: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Derive compact execution safeguards from exact source and mutation facts."""
    priority_basis = operation.get("priority_basis") or {}
    reachability = str(priority_basis.get("active_reachability") or "unknown")
    impact_classes = {
        str(value) for value in as_list(priority_basis.get("impact_classes"))
    }
    priority = str(operation.get("priority") or "")
    route_hosts = operation_server_route_hosts(operation, catalog)
    server_coupled = bool(route_hosts)
    activation_risk = operation_has_configured_activation_risk(operation)
    sensitive = bool({"consent_privacy", "security"} & impact_classes)
    individual_reasons = [
        reason
        for condition, reason in (
            (priority in {"High", "Critical"}, f"{priority or 'unknown'} priority"),
            (reachability == "active", "active configured reachability"),
            (sensitive, "consent/privacy or security impact"),
            (server_coupled, "server-coupled route"),
            (activation_risk, "configured activation scope may change"),
        )
        if condition
    ]
    bulk_eligible = (
        priority == "Low"
        and reachability in {"inactive_or_unreferenced", "metadata_only"}
        and str(priority_basis.get("alignment") or "")
        != "below_evidence_floor_review_recommended"
        and not individual_reasons
    )
    if not bulk_eligible and not individual_reasons:
        individual_reasons.append(
            "only evidence-calibrated Low, non-active operations are bulk-eligible"
        )

    deletions = as_list(operation.get("deletions"))
    decommission: dict[str, Any] = {
        "required": False,
        "strategy": "not_applicable",
        "basis": "operation contains no deletion",
    }
    if deletions:
        deletion_states = {
            str(catalog.get(str(item.get("object_key") or ""), {}).get("reachability") or "unknown")
            for item in deletions
            if isinstance(item, dict)
        }
        quarantine = (
            bool(deletion_states & {"active", "paused_only", "unknown"})
            or priority in {"High", "Critical"}
            or sensitive
            or server_coupled
            or activation_risk
        )
        decommission = {
            "required": quarantine,
            "strategy": (
                "quarantine_then_delete_after_approved_observation"
                if quarantine
                else "direct_delete_after_exact_readback"
            ),
            "basis": (
                "active, paused, uncertain, sensitive, server-coupled, or "
                "activation-relevant deletion requires a reversible observation stage"
                if quarantine
                else "all deleted source objects are proven inactive/unreferenced and low risk"
            ),
            "observation_window": (
                "analyst_defined_from_traffic_cycle_and_business_risk"
                if quarantine
                else "not_required"
            ),
            "delete_gate": (
                "separate explicit deletion approval after observation evidence"
                if quarantine
                else "included in the exact approved operation"
            ),
        }

    return {
        "server_coupled": server_coupled,
        "server_route_hosts": route_hosts,
        "configured_activation_risk": {
            "flag": activation_risk,
            "meaning": (
                "structured mutation may change configured tag reachability; "
                "this is not evidence of live firing"
                if activation_risk
                else "no structured activation-scope mutation detected"
            ),
            "future_state_confirmation_required": activation_risk,
        },
        "approval": {
            "scope": (
                "bulk_eligible_exact_low_risk_bundle"
                if bulk_eligible
                else "individual_operation"
            ),
            "reasons": individual_reasons
            or ["evidence-calibrated low-risk, non-active exact mutation"],
        },
        "decommission": decommission,
    }


def packetize_operations(
    rows: list[dict[str, Any]],
    route: str,
    catalog: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    packets: list[dict[str, Any]] = []
    for number, operation in enumerate(rows, start=1):
        packet = copy.deepcopy(operation)
        readiness = str(operation.get("execution_readiness") or "")
        blocked = readiness in {"owner_blocked", "not_actionable"}
        packet.update(
            {
                "operation_id": f"OP-{number:04d}",
                "affected_objects": affected_objects(operation, catalog),
                "object_identity": "; ".join(
                    f"{key}|{catalog.get(key, {}).get('config_hash', '')}"
                    for key in as_list(operation.get("affected_object_keys"))
                ),
                "source_lenses": ", ".join(as_list(operation.get("source_runs"))),
                "resolution_status": "proposed",
                "approval_status": (
                    "pending_owner_decision" if blocked else "pending_approval"
                ),
                "risk_class": operation.get("priority"),
                "blocker": operation.get("preconditions") if blocked else "",
                "route": route,
                "execution_order": number,
                "execution_phases": [
                    phase for phase, field in EXECUTION_PHASES if as_list(operation.get(field))
                ],
                "priority_basis": operation_priority_basis(operation, catalog),
            }
        )
        packet["execution_safety"] = operation_safety_metadata(packet, catalog)
        packets.append(packet)
    return packets


def action_completeness_report(
    ledger: list[dict[str, Any]],
) -> dict[str, Any]:
    """Judge whether the audit has become a usable cleanup plan.

    Review validators prove coverage. This compact outcome check prevents a
    completed audit from substituting owner questions for source-visible fixes.
    """

    errors: list[str] = []
    for decision in ledger:
        decision_id = str(decision.get("decision_id") or "<missing>")
        source_run = str(decision.get("source_run") or "")
        disposition = str(decision.get("disposition") or "")
        linked = [str(value) for value in as_list(decision.get("compiled_operation_ids"))]

        if disposition == "cleanup_operation" and not linked:
            errors.append(f"{decision_id}: cleanup decision has no compiled operation")
        finding_class = str(decision.get("finding_class") or "deterministic_defect")
        exact_action_available = (
            (
                not str(decision.get("deterministic_action_candidate") or "")
                and not str(decision.get("deterministic_repair_status") or "")
            )
            or str(decision.get("deterministic_repair_status") or "").startswith(
                "unique_"
            )
            or decision.get("deterministic_action_candidate") == "delete_candidate"
            or (
                decision.get("deterministic_action_candidate") == "rename_candidate"
                and not bool(decision.get("policy_confirmation_required"))
                and bool(decision.get("rename_candidate_unique"))
                and bool(str(decision.get("proposed_final_name") or "").strip())
                and not str(decision.get("rename_blocker") or "").strip()
            )
        )
        if (
            source_run == "operational_sanitation"
            and disposition == "owner_decision_needed"
            and finding_class not in {"review_candidate", "business_decision"}
            and exact_action_available
        ):
            errors.append(
                f"{decision_id}: deterministic operational finding with a "
                "source-proven safe action must become an exact cleanup operation or "
                "an intake-locked documented exception"
            )
        if (
            source_run == "operational_sanitation"
            and disposition == "keep"
            and finding_class != "review_candidate"
        ):
            errors.append(
                f"{decision_id}: only a source-locked review candidate may be retained "
                "without a cleanup operation"
            )
        if (
            source_run == "configuration_correctness"
            and str(decision.get("verdict") or "") == "Issue"
            and disposition == "owner_decision_needed"
        ):
            recommendation = str(decision.get("recommended_action") or "")
            lowered = recommendation.lower()
            source_object_key = next(
                (
                    str(value)
                    for value in as_list(decision.get("source_object_keys"))
                    if str(value)
                ),
                "",
            )
            evidence_terms = [
                str(value)
                for value in as_list(decision.get("defect_evidence_anchors"))
                if str(value)
            ]
            if (
                not source_object_key
                or source_object_key.lower() not in lowered
                or (
                    evidence_terms
                    and not any(term.lower() in lowered for term in evidence_terms)
                )
                or not re.search(
                    r"\b(?:correct|delete|disable|fix|remap|remove|repair|replace|"
                    r"reconfigure|restore|split)\b",
                    lowered,
                )
            ):
                errors.append(
                    f"{decision_id}: unresolved configuration Issue lacks a "
                    "source-specific, decision-ready remediation"
                )
        if disposition in {"owner_decision_needed", "container_evidence_limit"} and not specific_text(
            decision.get("recommended_action"), 6
        ):
            errors.append(
                f"{decision_id}: unresolved decision lacks a concrete recommended action"
            )

    counts = {
        disposition: sum(
            1 for decision in ledger if decision.get("disposition") == disposition
        )
        for disposition in (
            "cleanup_operation",
            "keep",
            "documented_exception",
            "owner_decision_needed",
            "container_evidence_limit",
            "not_applicable",
        )
    }
    return {
        "status": "pass" if not errors else "incomplete",
        "counts": counts,
        "errors": errors,
    }


def packet_index(packets: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    index: dict[str, dict[str, Any]] = {}
    for packet in packets:
        keys = {
            str(packet.get("operation_key") or ""),
            *{
                str(value)
                for value in as_list(packet.get("source_operation_keys"))
                if str(value)
            },
        }
        for key in keys - {""}:
            index[key] = packet
    return index


def link_ledger_packets(
    ledger: list[dict[str, Any]], packets: list[dict[str, Any]]
) -> None:
    by_key = packet_index(packets)
    for decision in ledger:
        linked = [
            by_key[key]
            for key in as_list(decision.get("operation_keys"))
            if key in by_key
        ]
        decision["compiled_operation_ids"] = sorted(
            {str(packet.get("operation_id") or "") for packet in linked}
        )
        decision["execution_selection"] = sorted(
            {str(packet.get("resolution_status") or "") for packet in linked}
        )


def normalized_reference_name(value: Any) -> str:
    normalized = unicodedata.normalize("NFKC", str(value or ""))
    normalized = "".join(
        " " if character.isspace() else character for character in normalized
    )
    return re.sub(r" +", " ", normalized).strip()


def reference_repairs_by_source(
    packets: list[dict[str, Any]],
) -> dict[tuple[str, str], set[str]]:
    """Index exact Unicode/whitespace-only reference repairs by source object."""

    repairs: dict[tuple[str, str], set[str]] = defaultdict(set)
    for packet in packets:
        operation_id = str(packet.get("operation_id") or "")
        if not operation_id:
            continue
        for change in as_list(packet.get("changes")):
            object_key = str(change.get("object_key") or "")
            before_references = REF_RE.findall(
                str(change.get("before") or "")
            )
            after_references = REF_RE.findall(
                str(change.get("after") or "")
            )
            for before in before_references:
                if before in after_references:
                    continue
                normalized = normalized_reference_name(before)
                if any(
                    candidate != before
                    and normalized_reference_name(candidate) == normalized
                    for candidate in after_references
                ):
                    repairs[(object_key, before)].add(operation_id)
    return repairs


def reconcile_duplicate_owner_authority(
    rows: list[dict[str, Any]],
    packet_by_id: dict[str, dict[str, Any]],
) -> None:
    """Represent one exact cross-object decision once in the final ledger."""

    architecture_by_scope: dict[frozenset[str], list[dict[str, Any]]] = defaultdict(list)
    for decision in rows:
        keys = frozenset(
            str(value)
            for value in as_list(decision.get("source_object_keys"))
            if str(value)
        )
        if (
            keys
            and decision.get("source_run") == "business_architecture"
            and as_list(decision.get("comparison_types"))
            and decision.get("disposition")
            in {"owner_decision_needed", "cleanup_operation"}
        ):
            architecture_by_scope[keys].append(decision)

    for decision in rows:
        keys = frozenset(
            str(value)
            for value in as_list(decision.get("source_object_keys"))
            if str(value)
        )
        if (
            not keys
            or decision.get("source_run") != "operational_sanitation"
            or decision.get("disposition") != "owner_decision_needed"
        ):
            continue
        authorities = architecture_by_scope.get(keys, [])
        if len(authorities) != 1:
            continue
        authority = authorities[0]
        source_disposition = str(decision.get("disposition") or "")
        decision["source_disposition"] = source_disposition
        decision["source_owner_question"] = str(
            decision.get("owner_question") or ""
        )
        decision["delegated_to_decision_id"] = str(
            authority.get("decision_id") or ""
        )
        decision["owner_question"] = ""
        decision["recommended_action"] = ""
        if authority.get("disposition") == "cleanup_operation":
            operation_ids = [
                str(value)
                for value in as_list(authority.get("compiled_operation_ids"))
                if str(value)
            ]
            decision["disposition"] = "cleanup_operation"
            decision["reconciliation_status"] = (
                "resolved_by_architecture_authority"
            )
            decision["reconciliation_basis"] = (
                "The exact same object set is resolved by the authoritative "
                f"architecture comparison {authority.get('decision_id')}; Run 1's "
                "weaker candidate is retained as evidence without creating a second "
                "action or approval."
            )
            decision["compiled_operation_ids"] = operation_ids
            decision["operation_keys"] = sorted(
                {
                    str(packet_by_id[operation_id].get("operation_key") or "")
                    for operation_id in operation_ids
                    if operation_id in packet_by_id
                    and str(packet_by_id[operation_id].get("operation_key") or "")
                }
            )
            decision["execution_selection"] = (
                ["proposed"] if operation_ids else []
            )
        else:
            decision["disposition"] = "documented_exception"
            decision["reconciliation_status"] = (
                "delegated_to_architecture_decision"
            )
            decision["reconciliation_basis"] = (
                "The exact same cross-object owner choice is already represented by "
                f"architecture comparison {authority.get('decision_id')}; Run 1's "
                "independent signal remains in the ledger without duplicating the "
                "human decision."
            )


def reconcile_ledger_resolutions(
    ledger: list[dict[str, Any]], packets: list[dict[str, Any]]
) -> tuple[list[dict[str, Any]], list[str]]:
    """Resolve decisions made obsolete by the exact final operation set.

    Independent runs must retain their original judgments until reconciliation.
    Once the full plan removes every object in a decision, an owner question
    about retaining, hardening, or selecting one of those objects is no longer a
    final-state decision. Preserve its source disposition, but link the final
    ledger row to the deletion operations instead of showing a stale question.
    """

    rows = copy.deepcopy(ledger)
    errors: list[str] = []
    deleted_by_key: dict[str, set[str]] = defaultdict(set)
    packet_by_id = {
        str(packet.get("operation_id") or ""): packet for packet in packets
    }
    reference_repairs = reference_repairs_by_source(packets)
    runtime_neutral_deleted_keys = {
        str(value)
        for packet in packets
        for value in as_list(packet.get("runtime_neutral_deletion_keys"))
        if str(value)
    }
    for packet in packets:
        operation_id = str(packet.get("operation_id") or "")
        for deletion in as_list(packet.get("deletions")):
            key = str(deletion.get("object_key") or "")
            if key and operation_id:
                deleted_by_key[key].add(operation_id)

    for decision in rows:
        source_keys = {
            str(value)
            for value in as_list(decision.get("source_object_keys"))
            if str(value)
        }
        if not source_keys:
            continue
        deleted_keys = source_keys & set(deleted_by_key)
        all_deleted = deleted_keys == source_keys
        disposition = str(decision.get("disposition") or "")
        source_run = str(decision.get("source_run") or "")
        recommended = str(
            decision.get("recommended_canonical_object_key") or ""
        )
        if (
            source_run == "business_architecture"
            and recommended
            and recommended in deleted_keys
            and not (
                all_deleted and recommended in runtime_neutral_deleted_keys
            )
        ):
            errors.append(
                f"{decision.get('decision_id')}: recommended canonical object "
                f"{recommended!r} is deleted by the proposed operation set"
            )
            continue
        if (
            source_run == "business_architecture"
            and disposition == "keep"
            and deleted_keys
        ):
            operation_ids = sorted(
                {
                    operation_id
                    for key in deleted_keys
                    for operation_id in deleted_by_key[key]
                }
            )
            architecture_backed = bool(operation_ids) and all(
                "business_architecture"
                in as_list(packet_by_id[operation_id].get("source_runs"))
                for operation_id in operation_ids
                if operation_id in packet_by_id
            )
            # A retained comparison or family can be superseded by the very
            # architecture cleanup that removes one of its source members.
            # Preserve its source verdict, but project its scope to the live
            # target state instead of manufacturing a contradictory owner
            # question for every secondary relationship that shared the object.
            if all_deleted:
                decision["source_disposition"] = disposition
                decision["disposition"] = "cleanup_operation"
                decision["reconciliation_status"] = "resolved_by_complete_object_deletion"
                decision["reconciliation_basis"] = (
                    "Every object in this retained source relationship is removed by the "
                    "final approved cleanup plan, so no retained relationship survives."
                )
                decision["compiled_operation_ids"] = operation_ids
                decision["operation_keys"] = sorted(
                    {
                        str(packet_by_id[operation_id].get("operation_key") or "")
                        for operation_id in operation_ids
                        if operation_id in packet_by_id
                        and str(packet_by_id[operation_id].get("operation_key") or "")
                    }
                )
                decision["execution_selection"] = ["proposed"] if operation_ids else []
                continue
            if architecture_backed:
                surviving_keys = source_keys - deleted_keys
                decision["source_scope_object_keys"] = sorted(source_keys)
                decision["source_object_keys"] = sorted(surviving_keys)
                decision["affected_objects"] = "; ".join(sorted(surviving_keys))
                decision["reconciliation_status"] = "narrowed_by_architecture_cleanup"
                decision["reconciliation_basis"] = (
                    f"A source-proven architecture cleanup removes {sorted(deleted_keys)!r}; "
                    f"the retained relationship now covers only {sorted(surviving_keys)!r}."
                )
                decision["compiled_operation_ids"] = sorted(
                    {
                        *as_list(decision.get("compiled_operation_ids")),
                        *operation_ids,
                    }
                )
                continue
            nonneutral_deleted_keys = deleted_keys - runtime_neutral_deleted_keys
            if nonneutral_deleted_keys:
                errors.append(
                    f"{decision.get('decision_id')}: retained architecture relationship "
                    f"loses planned object(s) {sorted(nonneutral_deleted_keys)!r}"
                )
                continue
            surviving_keys = source_keys - deleted_keys
            operation_ids = sorted(
                {
                    operation_id
                    for key in deleted_keys
                    for operation_id in deleted_by_key[key]
                }
            )
            decision["source_scope_object_keys"] = sorted(source_keys)
            decision["source_object_keys"] = sorted(surviving_keys)
            decision["affected_objects"] = "; ".join(sorted(surviving_keys))
            decision["reconciliation_status"] = (
                "narrowed_by_runtime_neutral_cleanup"
            )
            decision["reconciliation_basis"] = (
                f"Source-proven behavior-neutral cleanup removes "
                f"{sorted(deleted_keys)!r}; the retained architecture now covers "
                f"{sorted(surviving_keys)!r}."
            )
            decision["compiled_operation_ids"] = sorted(
                {
                    *as_list(decision.get("compiled_operation_ids")),
                    *operation_ids,
                }
            )
            if not surviving_keys:
                decision["source_disposition"] = disposition
                decision["disposition"] = "cleanup_operation"
                decision["reconciliation_status"] = (
                    "resolved_by_runtime_neutral_cleanup"
                )
                decision["operation_keys"] = sorted(
                    {
                        str(packet_by_id[operation_id].get("operation_key") or "")
                        for operation_id in operation_ids
                        if operation_id in packet_by_id
                        and str(
                            packet_by_id[operation_id].get("operation_key") or ""
                        )
                    }
                )
                decision["execution_selection"] = (
                    ["proposed"] if operation_ids else []
                )
            continue
        can_resolve_by_deletion = disposition in {
            "owner_decision_needed",
            "container_evidence_limit",
        }
        if all_deleted and can_resolve_by_deletion:
            operation_ids = sorted(
                {
                    operation_id
                    for key in source_keys
                    for operation_id in deleted_by_key[key]
                }
            )
            decision["source_disposition"] = disposition
            decision["disposition"] = "cleanup_operation"
            decision["reconciliation_status"] = "resolved_by_complete_object_deletion"
            decision["reconciliation_basis"] = (
                "Every object in this source decision is removed by the final "
                "source-proven inactive-lifecycle operation set, so its retention "
                "or hardening question does not survive into the target container."
            )
            decision["compiled_operation_ids"] = operation_ids
            decision["operation_keys"] = sorted(
                {
                    str(packet_by_id[operation_id].get("operation_key") or "")
                    for operation_id in operation_ids
                    if operation_id in packet_by_id
                    and str(packet_by_id[operation_id].get("operation_key") or "")
                }
            )
            decision["execution_selection"] = ["proposed"] if operation_ids else []
            continue

        if source_run != "business_architecture" or not deleted_keys:
            continue
        if disposition != "owner_decision_needed":
            continue

        surviving_keys = source_keys - deleted_keys
        operation_ids = sorted(
            {
                operation_id
                for key in deleted_keys
                for operation_id in deleted_by_key[key]
            }
        )
        if len(surviving_keys) == 1 and (
            not recommended or recommended in surviving_keys
        ):
            decision["source_disposition"] = disposition
            decision["disposition"] = "cleanup_operation"
            decision["reconciliation_status"] = (
                "resolved_by_surviving_canonical_object"
            )
            decision["reconciliation_basis"] = (
                f"The approved operation set removes {sorted(deleted_keys)!r} and "
                f"leaves the sole surviving relationship member "
                f"{next(iter(surviving_keys))!r}."
            )
            decision["compiled_operation_ids"] = operation_ids
            decision["operation_keys"] = sorted(
                {
                    str(packet_by_id[operation_id].get("operation_key") or "")
                    for operation_id in operation_ids
                    if operation_id in packet_by_id
                    and str(packet_by_id[operation_id].get("operation_key") or "")
                }
            )
            decision["execution_selection"] = ["proposed"] if operation_ids else []
            continue

        decision["source_scope_object_keys"] = sorted(source_keys)
        decision["source_object_keys"] = sorted(surviving_keys)
        decision["affected_objects"] = "; ".join(sorted(surviving_keys))
        decision["reconciliation_status"] = "narrowed_to_surviving_objects"
        decision["reconciliation_basis"] = (
            f"Planned deletion removes {sorted(deleted_keys)!r}; the owner decision "
            f"now applies only to surviving objects {sorted(surviving_keys)!r}."
        )

    for decision in rows:
        if (
            decision.get("source_run") != "configuration_correctness"
            or decision.get("disposition")
            not in {"owner_decision_needed", "container_evidence_limit"}
        ):
            continue
        terminals = [
            terminal
            for terminal in as_list(
                decision.get("missing_reference_terminals")
            )
            if terminal.get("normalization_resolution") == "unique"
            and len(as_list(terminal.get("normalization_candidate_names"))) == 1
        ]
        all_missing = as_list(decision.get("missing_reference_terminals"))
        if not terminals or len(terminals) != len(all_missing):
            continue
        operation_ids_by_terminal = [
            reference_repairs.get(
                (
                    str(
                        terminal.get("source_object_key")
                        or next(
                            iter(as_list(decision.get("source_object_keys"))),
                            "",
                        )
                    ),
                    str(terminal.get("reference") or ""),
                ),
                set(),
            )
            for terminal in terminals
        ]
        if not all(operation_ids_by_terminal):
            continue
        operation_ids = sorted(set().union(*operation_ids_by_terminal))
        decision["source_disposition"] = str(decision.get("disposition") or "")
        decision["source_owner_question"] = str(
            decision.get("owner_question") or ""
        )
        decision["disposition"] = "cleanup_operation"
        decision["owner_question"] = ""
        decision["recommended_action"] = ""
        decision["reconciliation_status"] = (
            "resolved_by_upstream_reference_repair"
        )
        decision["reconciliation_basis"] = (
            "Every missing terminal reference in this decision is repaired by an "
            "exact Unicode/whitespace-only change at its source object. This "
            "consumer receives no independent mutation and therefore needs no "
            "second owner choice."
        )
        decision["compiled_operation_ids"] = operation_ids
        decision["operation_keys"] = sorted(
            {
                str(packet_by_id[operation_id].get("operation_key") or "")
                for operation_id in operation_ids
                if operation_id in packet_by_id
                and str(packet_by_id[operation_id].get("operation_key") or "")
            }
        )
        decision["execution_selection"] = ["proposed"]

    reconcile_duplicate_owner_authority(rows, packet_by_id)
    return rows, errors


def target_organization_summary(
    operational: dict[str, Any],
    packets: list[dict[str, Any]],
    catalog: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Describe the actual proposed organization without inventing folder moves."""

    findings = as_list(operational.get("findings"))
    naming_findings = [
        row
        for row in findings
        if row.get("module_name") == "naming_architecture_standardization"
    ]
    naming_policies = sorted(
        {
            str(row.get("selected_naming_policy") or "")
            for row in naming_findings
            if str(row.get("selected_naming_policy") or "")
        }
    )
    naming_patterns = sorted(
        {
            str(row.get("target_naming_pattern") or "")
            for row in naming_findings
            if str(row.get("target_naming_pattern") or "")
            and "unresolved" not in str(row.get("target_naming_pattern") or "").lower()
        }
    )
    naming_confirmation_ids = sorted(
        {
            str(row.get("finding_id") or "")
            for row in naming_findings
            if row.get("finding_type") == "naming_policy_confirmation_required"
            or row.get("disposition") == "owner_decision_needed"
        }
    )

    exact_renames = []
    exact_folder_actions = []
    deleted_keys: set[str] = set()
    for packet in packets:
        operation_id = str(packet.get("operation_id") or "")
        for rename in as_list(packet.get("renames")):
            key = str(rename.get("object_key") or "")
            exact_renames.append(
                {
                    "operation_id": operation_id,
                    "object_key": key,
                    "before": str(rename.get("before") or ""),
                    "after": str(rename.get("after") or ""),
                }
            )
            if key.startswith("folder:"):
                exact_folder_actions.append(
                    {
                        "operation_id": operation_id,
                        "action": "rename_folder",
                        "object_key": key,
                        "before": str(rename.get("before") or ""),
                        "after": str(rename.get("after") or ""),
                    }
                )
        for deletion in as_list(packet.get("deletions")):
            key = str(deletion.get("object_key") or "")
            deleted_keys.add(key)
            if key.startswith("folder:"):
                exact_folder_actions.append(
                    {
                        "operation_id": operation_id,
                        "action": "delete_folder",
                        "object_key": key,
                        "reason": str(deletion.get("reason") or ""),
                    }
                )
        for change in as_list(packet.get("changes")):
            path = str(change.get("json_path") or "")
            if path.endswith(".parentFolderId"):
                exact_folder_actions.append(
                    {
                        "operation_id": operation_id,
                        "action": "move_object",
                        "object_key": str(change.get("object_key") or ""),
                        "before_folder_id": str(change.get("before") or ""),
                        "after_folder_id": str(change.get("after") or ""),
                    }
                )
        for remap in as_list(packet.get("remaps")):
            if str(remap.get("from_object_key") or "").startswith("folder:"):
                exact_folder_actions.append(
                    {
                        "operation_id": operation_id,
                        "action": "move_folder_members",
                        "from_folder_key": str(remap.get("from_object_key") or ""),
                        "to_folder_key": str(remap.get("to_object_key") or ""),
                        "object_keys": [
                            str(value)
                            for value in as_list(remap.get("consumer_object_keys"))
                            if str(value)
                        ],
                    }
                )

    folder_findings = [
        row
        for row in findings
        if row.get("module_name")
        in {
            "unfiled_objects",
            "unused_folders",
            "singleton_folders",
            "overloaded_folders",
            "folder_topology",
        }
    ]
    unresolved_folder_ids = sorted(
        {
            str(row.get("finding_id") or "")
            for row in folder_findings
            if row.get("disposition")
            in {"owner_decision_needed", "container_evidence_limit"}
        }
    )
    paused_keys = sorted(
        key
        for key, item in catalog.items()
        if key.startswith("tag:") and bool(item.get("paused"))
    )
    retired_paused_keys = sorted(set(paused_keys) & deleted_keys)
    retained_paused_keys = sorted(set(paused_keys) - deleted_keys)

    if naming_confirmation_ids or unresolved_folder_ids:
        status = "policy_confirmation_required_for_listed_metadata_only"
    elif exact_renames or exact_folder_actions or retired_paused_keys:
        status = "concrete_target_organization_proposed"
    else:
        status = "no_organization_change_justified"
    return {
        "status": status,
        "scope": (
            "Container-visible naming, folders, and paused-object lifecycle only. "
            "Every listed move or rename is an exact approved-operation candidate; "
            "no folder placement is invented from an arbitrary quota."
        ),
        "naming": {
            "selected_policy": ", ".join(naming_policies)
            or "No reliable container-local convention inferred",
            "target_patterns": naming_patterns,
            "exact_renames": exact_renames,
            "confirmation_decision_ids": naming_confirmation_ids,
        },
        "folders": {
            "exact_actions": exact_folder_actions,
            "unresolved_decision_ids": unresolved_folder_ids,
        },
        "paused_lifecycle": {
            "source_paused_tag_keys": paused_keys,
            "proposed_retirement_keys": retired_paused_keys,
            "retained_pending_or_necessary_keys": retained_paused_keys,
        },
    }


def compile_operations(
    operational: dict[str, Any],
    configuration: dict[str, Any],
    architecture: dict[str, Any],
    route: str,
    catalog: dict[str, dict[str, str]] | None = None,
    expected_consumers: dict[str, set[str]] | None = None,
    object_names: dict[str, str] | None = None,
    source_paths_by_key: dict[str, str] | None = None,
) -> tuple[dict[str, Any], list[str]]:
    errors, hashes, fact_hashes, context_hashes = validate_review_bundle(
        operational, configuration, architecture, route
    )
    collected = collect_operations(operational, configuration, architecture)
    merged = merge_compatible_operations(collected, errors)
    ledger = decision_ledger(operational, configuration, architecture)
    errors.extend(ledger_link_errors(ledger, merged))
    errors.extend(validate_cross_run_reconciliation(operational, architecture, merged))
    errors.extend(
        validate_operation_set(
            merged,
            expected_consumers=expected_consumers,
            object_names=object_names,
            label="compiled cross-run operation set",
        )
    )
    errors.extend(mutation_path_errors(merged, source_paths_by_key))
    errors.extend(validate_mutation_conflicts(merged))
    catalog = catalog or {}
    packets = packetize_operations(
        merged,
        route,
        catalog,
    )
    link_ledger_packets(ledger, packets)
    reconciled_ledger, reconciliation_errors = reconcile_ledger_resolutions(
        ledger, packets
    )
    errors.extend(reconciliation_errors)
    if errors:
        packets = []
        reconciled_ledger = decision_ledger(
            operational, configuration, architecture
        )
        link_ledger_packets(reconciled_ledger, packets)
    action_completeness = action_completeness_report(reconciled_ledger)
    if errors:
        action_completeness["status"] = "incomplete"
        action_completeness["errors"].append(
            "operation compilation has unresolved validation errors"
        )
    measurement_preservation = measurement_preservation_summary(
        architecture, packets
    )
    annotate_operation_preservation(packets, measurement_preservation)
    target_organization = target_organization_summary(
        operational, packets, catalog
    )
    payload = {
        "kind": "gtm_reconciled_operations",
        "schema_version": 4,
        "source_file": operational.get("source_file"),
        "source_sha256": next(iter(hashes), ""),
        "shared_facts_sha256": next(iter(fact_hashes), ""),
        "context_sha256": next(iter(context_hashes), ""),
        "run_statuses": {
            "operational_sanitation": operational.get("run_status"),
            "configuration_correctness": configuration.get("run_status"),
            "business_architecture": architecture.get("run_status"),
        },
        "route": route,
        "plan_status": (
            "complete" if action_completeness["status"] == "pass" else "incomplete_actions"
        ),
        "action_completeness": action_completeness,
        "object_catalog": {
            key: {
                "layer": str(value.get("layer") or ""),
                "object_name": str(value.get("object_name") or ""),
                "reachability": str(value.get("reachability") or ""),
            }
            for key, value in sorted(catalog.items())
        },
        "projected_object_counts": projected_object_counts(catalog, packets),
        "measurement_preservation": measurement_preservation,
        "target_organization": target_organization,
        "decision_ledger": reconciled_ledger,
        "operations": packets,
    }
    payload["approval_contract"] = approval_contract(payload)
    return payload, errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("export", type=Path)
    parser.add_argument("operational_review", type=Path)
    parser.add_argument("configuration_review", type=Path)
    parser.add_argument("architecture_review", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--route", default="Pending user selection")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    validators = (
        ("operational", validate_operational_review, args.operational_review),
        ("configuration", validate_configuration_review, args.configuration_review),
        ("architecture", validate_architecture_review, args.architecture_review),
    )
    failed = False
    for label, validator, path in validators:
        review_errors, review_warnings = validator(args.export, path)
        for warning in review_warnings:
            print(f"WARNING [{label}]: {warning}")
        for error in review_errors:
            print(f"ERROR [{label}]: {error}", file=sys.stderr)
            failed = True
    if failed:
        return 1

    operational = load_json(args.operational_review)
    configuration = load_json(args.configuration_review)
    architecture = load_json(args.architecture_review)
    payload, errors = compile_operations(
        operational,
        configuration,
        architecture,
        args.route,
        source_object_catalog(args.export),
        object_consumer_map(args.export),
        object_name_map(args.export),
        object_source_path_map(args.export),
    )
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2 if args.pretty else None) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({"output": str(args.output), "operations": len(payload["operations"])}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
