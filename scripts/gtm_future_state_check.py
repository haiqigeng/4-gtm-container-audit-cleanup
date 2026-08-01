#!/usr/bin/env python3
"""Simulate approved GTM cleanup operations and validate the future-state graph."""

from __future__ import annotations

import argparse
import copy
import json
import re
import sys
import tempfile
from pathlib import Path
from typing import Any

from gtm_architecture_review import scaffold_review as scaffold_architecture_review
from gtm_baseline_audit import audit_export, build_execution_reachability
from gtm_configuration_review import scaffold_review as scaffold_configuration_review
from gtm_custom_code_extract import extract_export
from gtm_lib import (
    ID_KEYS,
    as_list,
    container_version,
    load_json,
    source_descriptor,
    source_integrity_findings,
)
from gtm_shared_facts import build_shared_facts
from gtm_validate_artifact import duplicate_ids, missing_references

PATH_TOKEN_RE = re.compile(r"\.([^.[\]]+)|\[(\d+)\]")

# Deleting source members can shrink an already-reviewed architecture group.
# That is not a newly introduced relationship. It must not force a fictive
# Run-3 mutation simply because the deterministic detector emits the surviving
# subset under a new membership signature. This exemption is deliberately
# narrow: one retained source comparison must cover every current member and
# comparison type, every removed source member must be deleted by the approved
# plan, and no surviving member may be changed by a non-deletion operation.
# Any relationship introduced or altered by a route, consent, Zone, cycle,
# deduplication, creation, remap, or other configuration mutation still needs
# explicit architecture backing.
RETENTION_VERDICTS = {"Intentional variant", "Complementary", "Unrelated"}


def object_catalog(cv: dict[str, Any]) -> dict[str, dict[str, Any]]:
    catalog: dict[str, dict[str, Any]] = {}
    for layer, id_key in ID_KEYS.items():
        for obj in as_list(cv.get(layer)):
            object_id = str(obj.get(id_key) or obj.get("name") or "")
            if object_id:
                catalog[f"{layer}:{object_id}"] = obj
    return catalog


def layer_counts(cv: dict[str, Any]) -> dict[str, int]:
    return {
        layer: len(as_list(cv.get(layer)))
        for layer in ID_KEYS
        if as_list(cv.get(layer))
    }


def object_name(catalog: dict[str, dict[str, Any]], key: str) -> str:
    return str(catalog.get(key, {}).get("name") or "")


def deep_replace(value: Any, before: str, after: str) -> Any:
    if isinstance(value, dict):
        return {key: deep_replace(child, before, after) for key, child in value.items()}
    if isinstance(value, list):
        return [deep_replace(child, before, after) for child in value]
    if isinstance(value, str):
        return value.replace(before, after)
    return value


def replace_in_place(target: dict[str, Any], before: str, after: str) -> None:
    updated = deep_replace(target, before, after)
    target.clear()
    target.update(updated)


def relative_path(path: str, object_key: str) -> str:
    if not path.startswith("$"):
        raise ValueError("JSON path must start with $")
    layer = object_key.split(":", 1)[0]
    match = re.match(
        rf"^\$\.(?:containerVersion\.)?{re.escape(layer)}\[\d+\](.*)$",
        path,
    )
    if match:
        return "$" + match.group(1)
    return path


def set_json_path(target: Any, path: str, value: Any) -> None:
    tokens: list[str | int] = []
    for match in PATH_TOKEN_RE.finditer(path[1:]):
        tokens.append(match.group(1) if match.group(1) is not None else int(match.group(2)))
    if not tokens:
        if not isinstance(value, dict) or not isinstance(target, dict):
            raise ValueError("root replacement requires a mapping")
        target.clear()
        target.update(copy.deepcopy(value))
        return
    current = target
    for token in tokens[:-1]:
        current = current[token]
    current[tokens[-1]] = copy.deepcopy(value)


def get_json_path(target: Any, path: str) -> Any:
    tokens: list[str | int] = []
    for match in PATH_TOKEN_RE.finditer(path[1:]):
        tokens.append(match.group(1) if match.group(1) is not None else int(match.group(2)))
    current = target
    for token in tokens:
        current = current[token]
    return current


def add_json_value(
    target: Any,
    path: str,
    value: Any,
    mode: str,
    index: int | None = None,
) -> None:
    if mode in {"append", "insert"}:
        destination = get_json_path(target, path)
        if not isinstance(destination, list):
            raise TypeError(f"addition target {path} is not a list")
        if mode == "append":
            destination.append(copy.deepcopy(value))
        else:
            if index is None or index < 0 or index > len(destination):
                raise IndexError(f"addition index {index!r} is outside {path}")
            destination.insert(index, copy.deepcopy(value))
        return

    tokens: list[str | int] = []
    for match in PATH_TOKEN_RE.finditer(path[1:]):
        tokens.append(match.group(1) if match.group(1) is not None else int(match.group(2)))
    if not tokens:
        raise ValueError("set addition requires a non-root path")
    current = target
    for token in tokens[:-1]:
        current = current[token]
    final = tokens[-1]
    if isinstance(current, dict):
        if final in current:
            raise ValueError(f"addition target {path} already exists")
        current[final] = copy.deepcopy(value)
    else:
        raise TypeError(f"set addition parent for {path} is not an object")


def apply_creations(
    cv: dict[str, Any], operations: list[dict[str, Any]], errors: list[str]
) -> None:
    catalog = object_catalog(cv)
    for operation in operations:
        for creation in as_list(operation.get("creations")):
            layer = str(creation.get("layer") or "")
            obj = creation.get("object")
            id_key = ID_KEYS.get(layer)
            if not id_key or not isinstance(obj, dict):
                errors.append("creation requires a supported GTM layer and complete object")
                continue
            object_id = str(obj.get(id_key) or obj.get("name") or "")
            key = f"{layer}:{object_id}" if object_id else ""
            if not key:
                errors.append(f"creation in {layer!r} has no {id_key}")
                continue
            if key in catalog:
                errors.append(f"creation duplicates existing object {key!r}")
                continue
            cv.setdefault(layer, []).append(copy.deepcopy(obj))
            catalog[key] = cv[layer][-1]


def remap_trigger(source: str, target: str, consumer: dict[str, Any]) -> None:
    def replaced_unique(values: Any) -> list[Any]:
        result: list[Any] = []
        seen: set[str] = set()
        for value in as_list(values):
            replacement = target if str(value) == source else value
            identity = json.dumps(replacement, sort_keys=True, ensure_ascii=False)
            if identity in seen:
                continue
            seen.add(identity)
            result.append(replacement)
        return result

    for field in ("firingTriggerId", "blockingTriggerId"):
        consumer[field] = replaced_unique(consumer.get(field))
    for parameter in as_list(consumer.get("parameter")):
        if not isinstance(parameter, dict):
            continue
        if parameter.get("key") != "triggerIds":
            continue
        next_items: list[Any] = []
        seen_references: set[str] = set()
        for item in as_list(parameter.get("list")):
            if not isinstance(item, dict):
                next_items.append(item)
                continue
            if str(item.get("value") or "") == source:
                item["value"] = target
            reference = str(item.get("value") or "")
            if reference and reference in seen_references:
                continue
            if reference:
                seen_references.add(reference)
            next_items.append(item)
        parameter["list"] = next_items
    boundary = consumer.get("boundary")
    if isinstance(boundary, dict) and "customEvaluationTriggerId" in boundary:
        boundary["customEvaluationTriggerId"] = replaced_unique(
            boundary.get("customEvaluationTriggerId")
        )


def remap_folder(source: str, target: str, consumer: dict[str, Any]) -> None:
    if str(consumer.get("parentFolderId") or "") == source:
        consumer["parentFolderId"] = target


def apply_remap(
    remap: dict[str, Any], catalog: dict[str, dict[str, Any]], errors: list[str]
) -> None:
    source_key = str(remap.get("from_object_key") or "")
    target_key = str(remap.get("to_object_key") or "")
    source = catalog.get(source_key)
    target = catalog.get(target_key)
    if not source or not target:
        errors.append(f"cannot simulate remap {source_key!r} to {target_key!r}")
        return
    source_layer = source_key.split(":", 1)[0]
    target_layer = target_key.split(":", 1)[0]
    if source_layer != target_layer:
        errors.append(f"remap crosses GTM layers: {source_key!r} to {target_key!r}")
        return
    source_id = source_key.split(":", 1)[1]
    target_id = target_key.split(":", 1)[1]
    before_name = object_name(catalog, source_key)
    after_name = object_name(catalog, target_key)
    for consumer_key in as_list(remap.get("consumer_object_keys")):
        consumer = catalog.get(str(consumer_key))
        if not consumer:
            errors.append(f"remap references missing consumer {consumer_key!r}")
            continue
        if source_layer == "trigger":
            remap_trigger(source_id, target_id, consumer)
        elif source_layer == "variable":
            replace_in_place(consumer, "{{" + before_name + "}}", "{{" + after_name + "}}")
        elif source_layer == "tag":
            for field in ("setupTag", "teardownTag"):
                for ref in as_list(consumer.get(field)):
                    if not isinstance(ref, dict):
                        continue
                    if str(ref.get("tagName") or "") == before_name:
                        ref["tagName"] = after_name
        elif source_layer == "folder":
            remap_folder(source_id, target_id, consumer)
        else:
            errors.append(f"future-state remap is unsupported for layer {source_layer!r}")


def apply_additions(
    operation_rows: list[dict[str, Any]],
    catalog: dict[str, dict[str, Any]],
    errors: list[str],
) -> None:
    for operation in operation_rows:
        for addition in as_list(operation.get("additions")):
            key = str(addition.get("object_key") or "")
            target = catalog.get(key)
            if not target:
                errors.append(f"addition references missing object {key!r}")
                continue
            path = relative_path(str(addition.get("json_path") or ""), key)
            try:
                add_json_value(
                    target,
                    path,
                    addition.get("value"),
                    str(addition.get("mode") or ""),
                    addition.get("index"),
                )
            except (KeyError, IndexError, TypeError, ValueError) as exc:
                errors.append(f"cannot apply addition to {key} at {path}: {exc}")


def apply_changes(
    operation_rows: list[dict[str, Any]],
    catalog: dict[str, dict[str, Any]],
    errors: list[str],
) -> None:
    for operation in operation_rows:
        for change in as_list(operation.get("changes")):
            key = str(change.get("object_key") or "")
            target = catalog.get(key)
            if not target:
                errors.append(f"change references missing object {key!r}")
                continue
            path = relative_path(str(change.get("json_path") or ""), key)
            try:
                current_value = get_json_path(target, path)
                if current_value != change.get("before"):
                    errors.append(f"change before value does not match {key} at {path}")
                    continue
                set_json_path(target, path, change.get("after"))
            except (KeyError, IndexError, TypeError, ValueError) as exc:
                errors.append(f"cannot apply change to {key} at {path}: {exc}")


def apply_remaps(
    operation_rows: list[dict[str, Any]],
    catalog: dict[str, dict[str, Any]],
    errors: list[str],
) -> None:
    for operation in operation_rows:
        for remap in as_list(operation.get("remaps")):
            apply_remap(remap, catalog, errors)


def rename_references(
    layer: str,
    before: str,
    after: str,
    catalog: dict[str, dict[str, Any]],
) -> None:
    if layer == "variable":
        marker_before, marker_after = "{{" + before + "}}", "{{" + after + "}}"
        for consumer in catalog.values():
            replace_in_place(consumer, marker_before, marker_after)
    elif layer == "tag":
        for consumer in catalog.values():
            for field in ("setupTag", "teardownTag"):
                for ref in as_list(consumer.get(field)):
                    if not isinstance(ref, dict):
                        continue
                    if str(ref.get("tagName") or "") == before:
                        ref["tagName"] = after


def apply_renames(
    operation_rows: list[dict[str, Any]],
    catalog: dict[str, dict[str, Any]],
    errors: list[str],
) -> None:
    for operation in operation_rows:
        for rename in as_list(operation.get("renames")):
            key = str(rename.get("object_key") or "")
            target = catalog.get(key)
            if not target:
                errors.append(f"rename references missing object {key!r}")
                continue
            before = str(rename.get("before") or "")
            after = str(rename.get("after") or "")
            if str(target.get("name") or "") != before:
                errors.append(f"rename before value does not match {key!r}")
                continue
            target["name"] = after
            rename_references(key.split(":", 1)[0], before, after, catalog)


def apply_deletions(
    cv: dict[str, Any],
    operation_rows: list[dict[str, Any]],
    catalog: dict[str, dict[str, Any]],
    errors: list[str],
) -> None:
    deletions = {
        str(item.get("object_key") or "")
        for operation in operation_rows
        for item in as_list(operation.get("deletions"))
    }
    for key in sorted(deletions):
        if key not in catalog:
            errors.append(f"deletion references missing object {key!r}")
            continue
        layer, object_id = key.split(":", 1)
        id_key = ID_KEYS[layer]
        cv[layer] = [
            obj
            for obj in as_list(cv.get(layer))
            if str(obj.get(id_key) or obj.get("name") or "") != object_id
        ]


def apply_operations(
    source: dict[str, Any], operations: dict[str, Any]
) -> tuple[dict[str, Any], list[str]]:
    result = copy.deepcopy(source)
    cv = container_version(result)
    errors: list[str] = []
    operation_rows = as_list(operations.get("operations"))

    apply_creations(cv, operation_rows, errors)
    catalog = object_catalog(cv)
    apply_additions(operation_rows, catalog, errors)
    apply_changes(operation_rows, catalog, errors)
    apply_remaps(operation_rows, catalog, errors)
    apply_renames(operation_rows, catalog, errors)
    apply_deletions(cv, operation_rows, catalog, errors)
    return result, errors


def finding_signature(finding: dict[str, Any]) -> tuple[Any, ...]:
    return (
        finding.get("module_name"),
        finding.get("finding_type"),
        finding.get("signature_key"),
        tuple(sorted(str(value) for value in as_list(finding.get("object_ids")))),
        str(finding.get("deterministic_evidence") or ""),
    )


def evidence_shape(finding: dict[str, Any]) -> str:
    text = str(finding.get("deterministic_evidence") or "").lower()
    text = re.sub(r"\b[0-9a-f]{8,}\b", "<hash>", text)
    text = re.sub(r"\b\d+(?:\.\d+)?\b", "<number>", text)
    return " ".join(text.split())


def evidence_numbers(finding: dict[str, Any]) -> list[float]:
    text = str(finding.get("deterministic_evidence") or "").lower()
    text = re.sub(r"\b[0-9a-f]{8,}\b", "", text)
    return [float(value) for value in re.findall(r"\b\d+(?:\.\d+)?\b", text)]


def prior_finding_covers(
    before: dict[str, Any], after: dict[str, Any]
) -> bool:
    if (
        before.get("module_name") != after.get("module_name")
        or before.get("finding_type") != after.get("finding_type")
        or before.get("object_type") != after.get("object_type")
        or evidence_shape(before) != evidence_shape(after)
    ):
        return False
    before_ids = {str(value) for value in as_list(before.get("object_ids"))}
    after_ids = {str(value) for value in as_list(after.get("object_ids"))}
    if (before_ids or after_ids) and not after_ids <= before_ids:
        return False
    before_numbers = evidence_numbers(before)
    after_numbers = evidence_numbers(after)
    if len(before_numbers) != len(after_numbers):
        return not after_numbers
    return all(after <= prior for prior, after in zip(before_numbers, after_numbers, strict=True))


def nonzero_findings(scan: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        row for row in as_list(scan.get("findings")) if row.get("finding_type") != "zero_findings"
    ]


def missing_reference_values(report: dict[str, Any]) -> set[tuple[str, str]]:
    values: set[tuple[str, str]] = set()
    for category, items in report.items():
        if category == "referencedCustomTemplateIds":
            continue
        values.update((category, str(value)) for value in as_list(items))
    return values


def future_integrity_results(
    before_cv: dict[str, Any], future_cv: dict[str, Any]
) -> tuple[dict[str, Any], list[tuple[str, str]], list[str]]:
    before_missing = missing_reference_values(missing_references(before_cv))
    after_report = missing_references(future_cv)
    new_missing = sorted(missing_reference_values(after_report) - before_missing)
    errors = []
    if new_missing:
        errors.append("future state creates missing references: " + repr(new_missing))
    duplicates = duplicate_ids(future_cv)
    if duplicates:
        errors.append("future state contains duplicate IDs: " + repr(duplicates))
    return after_report, new_missing, errors


def scan_future_payload(
    export_path: Path, future: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, Any]]:
    before_scan = audit_export(export_path)
    with tempfile.TemporaryDirectory() as temporary_directory:
        temporary_path = Path(temporary_directory) / "future-state.json"
        temporary_path.write_text(json.dumps(future, ensure_ascii=False), encoding="utf-8")
        after_scan = audit_export(temporary_path)
    return before_scan, after_scan


def newly_created_findings(
    before_rows: list[dict[str, Any]], after_rows: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    return [
        row
        for row in after_rows
        if not any(prior_finding_covers(before, row) for before in before_rows)
    ]


def requested_operational_cleanup_ids(operations: dict[str, Any]) -> set[str]:
    return {
        str(reference)
        for operation in as_list(operations.get("operations"))
        if "operational_sanitation" in as_list(operation.get("source_runs"))
        for reference in as_list(operation.get("source_references"))
        if str(reference).startswith("BASE-")
    }


def finding_persists(
    before: dict[str, Any], after_rows: list[dict[str, Any]]
) -> bool:
    before_ids = {str(value) for value in as_list(before.get("object_ids"))}
    return any(
        after.get("module_name") == before.get("module_name")
        and after.get("finding_type") == before.get("finding_type")
        and (
            bool(before_ids & {str(value) for value in as_list(after.get("object_ids"))})
            or (
                not before_ids
                and evidence_shape(after) == evidence_shape(before)
            )
        )
        for after in after_rows
    )


def unresolved_cleanup_ids(
    before_rows: list[dict[str, Any]],
    after_rows: list[dict[str, Any]],
    cleanup_ids: set[str],
) -> list[str]:
    return sorted(
        str(row.get("finding_id") or "")
        for row in before_rows
        if str(row.get("finding_id") or "") in cleanup_ids
        and finding_persists(row, after_rows)
    )


def count_deltas(
    before_cv: dict[str, Any], future_cv: dict[str, Any]
) -> dict[str, dict[str, int]]:
    before_counts = layer_counts(before_cv)
    after_counts = layer_counts(future_cv)
    return {
        layer: {
            "before": before_counts.get(layer, 0),
            "after": after_counts.get(layer, 0),
            "delta": after_counts.get(layer, 0) - before_counts.get(layer, 0),
        }
        for layer in sorted(set(before_counts) | set(after_counts))
    }


def configured_activation_risk(
    before_cv: dict[str, Any],
    future_cv: dict[str, Any],
    operations: dict[str, Any],
) -> dict[str, Any]:
    """Report newly reachable configured tags without claiming live execution."""
    before_active = {
        str(value)
        for value in as_list(
            build_execution_reachability(before_cv).get("active_object_keys")
        )
        if str(value).startswith("tag:")
    }
    after_active = {
        str(value)
        for value in as_list(
            build_execution_reachability(future_cv).get("active_object_keys")
        )
        if str(value).startswith("tag:")
    }
    newly_active = sorted(after_active - before_active)
    heuristic_risk_operations = [
        {
            "operation_id": str(operation.get("operation_id") or ""),
            "operation_key": str(operation.get("operation_key") or ""),
        }
        for operation in as_list(operations.get("operations"))
        if bool(
            (
                (operation.get("execution_safety") or {}).get(
                    "configured_activation_risk"
                )
                or {}
            ).get("flag")
        )
    ]
    return {
        "flag": bool(newly_active),
        "scope": "configured graph reachability only; not evidence of live firing",
        "before_active_tag_count": len(before_active),
        "after_active_tag_count": len(after_active),
        "newly_active_tag_keys": newly_active,
        "candidate_operation_ids": [
            item["operation_id"]
            for item in heuristic_risk_operations
            if item["operation_id"] and newly_active
        ],
        "candidate_operations": heuristic_risk_operations if newly_active else [],
        "heuristic_candidate_operation_ids": [
            item["operation_id"]
            for item in heuristic_risk_operations
            if item["operation_id"]
        ],
        "simulation_overrides_heuristic": bool(
            heuristic_risk_operations and not newly_active
        ),
        "execution_requirement": (
            "individually review the newly reachable configured tags before approval; "
            "this container-only audit does not perform runtime acceptance"
            if newly_active
            else "none"
        ),
    }


def deterministic_quality_scaffolds(export_path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    """Regenerate the two semantic-lens fact queues for a projected container."""

    technical = extract_export(export_path)
    shared = build_shared_facts(export_path, technical=technical)
    return (
        scaffold_configuration_review(export_path, technical, shared),
        scaffold_architecture_review(export_path, shared),
    )


def configuration_signals(review: dict[str, Any], outcome: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for item in as_list(review.get("rows")):
        for obligation in as_list(item.get("required_configuration_obligations")):
            if obligation.get("required_outcome") != outcome:
                continue
            rows.append(
                {
                    "object_key": str(item.get("object_key") or ""),
                    "obligation_key": str(obligation.get("obligation_key") or ""),
                    "statement": str(obligation.get("statement") or ""),
                }
            )
    return sorted(rows, key=lambda row: (row["object_key"], row["obligation_key"]))


def configuration_signal_key(row: dict[str, Any]) -> tuple[str, str]:
    return str(row.get("object_key") or ""), str(row.get("obligation_key") or "")


def architecture_candidate_atoms(row: dict[str, Any]) -> set[tuple[tuple[str, ...], str]]:
    members = tuple(
        sorted(str(value) for value in as_list(row.get("candidate_object_keys")))
    )
    return {
        (members, str(comparison_type))
        for comparison_type in as_list(row.get("comparison_types"))
        if str(comparison_type)
    }


def architecture_candidate_summary(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "candidate_object_keys": sorted(
            str(value) for value in as_list(row.get("candidate_object_keys"))
        ),
        "comparison_types": sorted(
            str(value) for value in as_list(row.get("comparison_types"))
        ),
        "candidate_basis": as_list(row.get("candidate_basis")),
    }


def retained_architecture_comparisons(
    operations: dict[str, Any], source_architecture: dict[str, Any] | None = None
) -> list[dict[str, Any]]:
    """Return source-bound Run-3 comparison decisions that cover retained subsets.

    The compiled ledger removes deleted object keys from decision rows so that
    the final plan names only objects that still need attention. The future
    state check needs the original source membership to distinguish an actual
    new relationship from the surviving subset of one already reviewed in Run
    3, so it restores that membership from the deterministic source scaffold by
    comparison ID.
    """
    source_rows_by_id = {
        str(row.get("comparison_id") or ""): row
        for row in as_list((source_architecture or {}).get("comparisons"))
        if str(row.get("comparison_id") or "")
    }
    comparisons: list[dict[str, Any]] = []
    for decision in as_list(operations.get("decision_ledger")):
        if decision.get("source_run") != "business_architecture":
            continue
        if not as_list(decision.get("comparison_types")):
            continue
        disposition = str(decision.get("disposition") or "")
        verdict = str(decision.get("verdict") or "")
        if disposition == "keep" and verdict in RETENTION_VERDICTS:
            coverage = "source_bound_retention_comparison"
        elif disposition in {"owner_decision_needed", "container_evidence_limit"}:
            # The final ledger/workbook retains the unresolved source decision.
            # A deletion-only subset is therefore still explicitly owned rather
            # than silently treated as a new, unreviewed candidate.
            coverage = "source_bound_unresolved_decision"
        else:
            continue
        decision_id = str(decision.get("decision_id") or "")
        source_row = source_rows_by_id.get(decision_id, {})
        keys = sorted(
            {
                str(value)
                for value in as_list(
                    source_row.get("candidate_object_keys")
                    or decision.get("source_object_keys")
                )
                if str(value)
            }
        )
        comparison_types = sorted(
            {
                str(value)
                for value in as_list(
                    source_row.get("comparison_types")
                    or decision.get("comparison_types")
                )
                if str(value)
            }
        )
        if len(keys) < 2 or not comparison_types:
            continue
        comparisons.append(
            {
                "decision_id": decision_id,
                "source_object_keys": keys,
                "comparison_types": comparison_types,
                "coverage": coverage,
            }
        )
    return comparisons


def planned_deleted_keys(operations: dict[str, Any]) -> set[str]:
    """Return only exact object keys removed by the planned operation set."""
    return {
        str(deletion.get("object_key"))
        for operation in as_list(operations.get("operations"))
        for deletion in as_list(operation.get("deletions"))
        if isinstance(deletion, dict) and str(deletion.get("object_key") or "")
    }


def non_deletion_mutation_keys(operations: dict[str, Any]) -> set[str]:
    """Return object keys touched by a mutation other than a pure deletion."""
    keys: set[str] = set()
    mutation_fields = ("creations", "additions", "changes", "remaps", "renames")
    for operation in as_list(operations.get("operations")):
        if not any(as_list(operation.get(field)) for field in mutation_fields):
            continue
        for field in ("affected_object_keys", "source_object_keys"):
            keys.update(
                str(value)
                for value in as_list(operation.get(field))
                if str(value)
            )
    return keys


def retention_coverage_decision(
    row: dict[str, Any],
    retained_comparisons: list[dict[str, Any]],
    deleted_keys: set[str],
    non_deletion_keys: set[str],
) -> str:
    """Return the retained comparison ID that safely covers a shrunk group.

    The source comparison must be a strict superset of the projected candidate
    and all disappeared members must be exact planned deletions. This prevents
    a source-retained relationship from masking a configuration-created one.
    """
    comparison_types = {
        str(value) for value in as_list(row.get("comparison_types")) if str(value)
    }
    candidate_keys = {
        str(value) for value in as_list(row.get("candidate_object_keys")) if str(value)
    }
    if (
        len(candidate_keys) < 2
        or not comparison_types
        or candidate_keys & non_deletion_keys
    ):
        return ""
    for comparison in retained_comparisons:
        source_keys = set(comparison["source_object_keys"])
        source_types = set(comparison["comparison_types"])
        removed_members = source_keys - candidate_keys
        if (
            candidate_keys < source_keys
            and comparison_types <= source_types
            and removed_members <= deleted_keys
        ):
            return str(comparison["decision_id"])
    return ""


def source_comparison_coverage(
    row: dict[str, Any],
    retained_comparisons: list[dict[str, Any]],
    deleted_keys: set[str],
    non_deletion_keys: set[str],
) -> dict[str, str] | None:
    """Return the exact source-decision coverage for a deletion-only subset."""
    decision_id = retention_coverage_decision(
        row, retained_comparisons, deleted_keys, non_deletion_keys
    )
    if not decision_id:
        return None
    for comparison in retained_comparisons:
        if comparison["decision_id"] == decision_id:
            return {
                "decision_id": decision_id,
                "coverage": str(comparison["coverage"]),
            }
    return None


def projected_quality_review(
    export_path: Path,
    future: dict[str, Any],
    operations: dict[str, Any],
) -> tuple[dict[str, Any], list[str]]:
    """Check the projected state through configuration and architecture lenses.

    This reuses the deterministic obligation/candidate generators. It does not
    invent semantic verdicts: exact mutations retain their reviewed rationale,
    while new relationships must be attributable to an architecture-backed
    operation and every deterministic configuration Issue must be fixed or
    explicitly covered by a source-specific owner remediation decision.
    """

    with tempfile.TemporaryDirectory() as temporary_directory:
        future_path = Path(temporary_directory) / "future-quality-state.json"
        future_path.write_text(json.dumps(future, ensure_ascii=False), encoding="utf-8")
        before_configuration, before_architecture = deterministic_quality_scaffolds(
            export_path
        )
        after_configuration, after_architecture = deterministic_quality_scaffolds(future_path)

    before_issues = configuration_signals(before_configuration, "Issue")
    after_issues = configuration_signals(after_configuration, "Issue")
    before_issue_keys = {configuration_signal_key(row) for row in before_issues}
    new_configuration_issues = [
        row for row in after_issues if configuration_signal_key(row) not in before_issue_keys
    ]

    before_unclear = configuration_signals(before_configuration, "Unclear")
    after_unclear = configuration_signals(after_configuration, "Unclear")

    before_candidate_rows = as_list(before_architecture.get("comparisons"))
    before_candidate_atoms = {
        atom for row in before_candidate_rows for atom in architecture_candidate_atoms(row)
    }
    new_candidate_rows = []
    for row in as_list(after_architecture.get("comparisons")):
        new_types = sorted(
            comparison_type
            for members, comparison_type in architecture_candidate_atoms(row)
            if (members, comparison_type) not in before_candidate_atoms
        )
        if new_types:
            new_row = copy.deepcopy(row)
            new_row["comparison_types"] = new_types
            new_candidate_rows.append(new_row)
    architecture_backed_keys = {
        str(key)
        for operation in as_list(operations.get("operations"))
        if "business_architecture" in as_list(operation.get("source_runs"))
        for field in ("affected_object_keys", "source_object_keys")
        for key in as_list(operation.get(field))
        if str(key)
    }
    retention_comparisons = retained_architecture_comparisons(
        operations, before_architecture
    )
    deleted_keys = planned_deleted_keys(operations)
    non_deletion_keys = non_deletion_mutation_keys(operations)
    covered_new_candidates = []
    unexpected_new_candidates = []
    for row in new_candidate_rows:
        candidate_keys = {
            str(value) for value in as_list(row.get("candidate_object_keys")) if str(value)
        }
        summary = architecture_candidate_summary(row)
        if candidate_keys & architecture_backed_keys:
            summary["coverage"] = "architecture_operation"
            covered_new_candidates.append(summary)
        elif coverage := source_comparison_coverage(
            row,
            retention_comparisons,
            deleted_keys,
            non_deletion_keys,
        ):
            summary["coverage"] = coverage["coverage"]
            summary["retention_comparison_id"] = coverage["decision_id"]
            covered_new_candidates.append(summary)
        else:
            unexpected_new_candidates.append(summary)

    errors: list[str] = []
    owner_blocked_configuration_keys = {
        str(key)
        for decision in as_list(operations.get("decision_ledger"))
        if decision.get("source_run") == "configuration_correctness"
        and decision.get("verdict") == "Issue"
        and decision.get("disposition") == "owner_decision_needed"
        for key in as_list(decision.get("source_object_keys"))
        if str(key)
    }
    owner_blocked_issues = [
        row
        for row in after_issues
        if row["object_key"] in owner_blocked_configuration_keys
    ]
    unaccounted_after_issues = [
        row
        for row in after_issues
        if row["object_key"] not in owner_blocked_configuration_keys
    ]
    if operations.get("plan_status") == "complete" and unaccounted_after_issues:
        errors.append(
            "projected state retains unaccounted deterministic configuration Issues: "
            + ", ".join(
                f"{row['object_key']}:{row['obligation_key']}"
                for row in unaccounted_after_issues
            )
        )
    if operations.get("plan_status") == "complete" and unexpected_new_candidates:
        errors.append(
            "projected state creates architecture candidates outside architecture-backed "
            "operations: "
            + ", ".join(
                "/".join(row["candidate_object_keys"])
                for row in unexpected_new_candidates
            )
        )

    return {
        "status": "pass" if not errors else "fail",
        "configuration": {
            "before_issue_count": len(before_issues),
            "after_issue_count": len(after_issues),
            "new_issues": new_configuration_issues,
            "remaining_issues": after_issues,
            "owner_blocked_issues": owner_blocked_issues,
            "unaccounted_remaining_issues": unaccounted_after_issues,
            "before_unclear_count": len(before_unclear),
            "after_unclear_count": len(after_unclear),
        },
        "architecture": {
            "before_candidate_count": len(before_candidate_rows),
            "after_candidate_count": len(as_list(after_architecture.get("comparisons"))),
            "new_architecture_backed_candidates": covered_new_candidates,
            "unexpected_new_candidates": unexpected_new_candidates,
        },
        "errors": errors,
    }, errors


def blocking_new_operational_findings(
    rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Return projected findings that prove a defect rather than invite review."""
    return [
        row
        for row in rows
        if str(row.get("finding_class") or "deterministic_defect")
        not in {"review_candidate", "business_decision"}
    ]


def check_future_state(
    export_path: Path, operations: dict[str, Any]
) -> tuple[dict[str, Any], list[str]]:
    source = load_json(export_path)
    blocking_integrity = [
        row for row in source_integrity_findings(source) if row.get("blocking")
    ]
    if blocking_integrity:
        errors = [
            "source integrity gate blocked future-state simulation: "
            + ", ".join(
                sorted(
                    str(row.get("finding_type") or "source_integrity_error")
                    for row in blocking_integrity
                )
            )
        ]
        return (
            {
                **source_descriptor(export_path),
                "kind": "gtm_future_state_validation",
                "schema_version": 2,
                "status": "blocked_source_integrity",
                "operation_count": len(as_list(operations.get("operations"))),
                "source_integrity_findings": blocking_integrity,
                "errors": errors,
            },
            errors,
        )
    before_cv = container_version(source)
    future, errors = apply_operations(source, operations)
    apply_errors = list(errors)
    future_cv = container_version(future)
    after_missing_report, new_missing, integrity_errors = future_integrity_results(
        before_cv, future_cv
    )
    errors.extend(integrity_errors)
    before_scan, after_scan = scan_future_payload(export_path, future)
    before_rows = nonzero_findings(before_scan)
    before_signatures = {finding_signature(row) for row in before_rows}
    after_rows = nonzero_findings(after_scan)
    after_signatures = {finding_signature(row) for row in after_rows}
    new_findings = newly_created_findings(before_rows, after_rows)
    blocking_new_findings = blocking_new_operational_findings(new_findings)
    if blocking_new_findings:
        errors.append(
            "future state creates new operational findings: "
            + ", ".join(
                sorted(
                    str(row.get("finding_type") or "")
                    for row in blocking_new_findings
                )
            )
        )
    operational_cleanup_ids = requested_operational_cleanup_ids(operations)
    unresolved = unresolved_cleanup_ids(before_rows, after_rows, operational_cleanup_ids)
    if unresolved:
        errors.append(
            "future state does not resolve operational cleanup findings: "
            + ", ".join(sorted(unresolved))
        )
    if apply_errors:
        projected_quality = {
            "status": "not_run",
            "reason": "structured operations did not apply cleanly",
            "errors": [],
        }
    else:
        projected_quality, quality_errors = projected_quality_review(
            export_path, future, operations
        )
        errors.extend(quality_errors)
    report = {
        **source_descriptor(export_path),
        "kind": "gtm_future_state_validation",
        "schema_version": 2,
        "status": "pass" if not errors else "fail",
        "operation_count": len(as_list(operations.get("operations"))),
        "object_counts": count_deltas(before_cv, future_cv),
        "configured_activation_risk": configured_activation_risk(
            before_cv,
            future_cv,
            operations,
        ),
        "before_operational_findings": len(before_signatures),
        "after_operational_findings": len(after_signatures),
        "resolved_operational_cleanup_ids": sorted(operational_cleanup_ids - set(unresolved)),
        "unresolved_operational_cleanup_ids": sorted(unresolved),
        "new_operational_findings": new_findings,
        "new_blocking_operational_findings": blocking_new_findings,
        "new_review_candidates": [
            row for row in new_findings if row not in blocking_new_findings
        ],
        "projected_quality": projected_quality,
        "new_missing_references": new_missing,
        "after_missing_references": after_missing_report,
        "errors": errors,
    }
    return report, errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("export", type=Path)
    parser.add_argument("operations", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--future-export", type=Path)
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()
    operations = load_json(args.operations)
    report, errors = check_future_state(args.export, operations)
    if args.future_export and not errors:
        future, apply_errors = apply_operations(load_json(args.export), operations)
        errors.extend(apply_errors)
        args.future_export.parent.mkdir(parents=True, exist_ok=True)
        args.future_export.write_text(
            json.dumps(future, ensure_ascii=False, indent=2 if args.pretty else None) + "\n",
            encoding="utf-8",
        )
    rendered = json.dumps(report, ensure_ascii=False, indent=2 if args.pretty else None)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
