#!/usr/bin/env python3
"""Scaffold and validate the independent operational-sanitation review."""

from __future__ import annotations

import argparse
import difflib
import json
import re
import sys
from pathlib import Path
from typing import Any

from gtm_baseline_audit import audit_export
from gtm_lib import source_descriptor, write_json
from gtm_review_common import (
    VALID_CONFIDENCE,
    VALID_PRIORITIES,
    VALID_READINESS,
    as_list,
    canonical_review_facts,
    object_consumer_map,
    object_keys,
    object_name_map,
    object_source_path_map,
    pending_completion_attestation,
    precise_question,
    review_input_contract,
    specific_text,
    validate_challenge,
    validate_neutral_recheck_contexts,
    validate_operation_set,
    validate_review_provenance,
    validate_structured_actions,
)
from gtm_shared_facts import build_shared_facts
from gtm_taxonomy import taxonomy_errors

VALID_DISPOSITIONS = {
    "cleanup_operation",
    "documented_exception",
    "owner_decision_needed",
    "keep",
    "container_evidence_limit",
    "not_applicable",
}
DECISION_FIELDS = {
    "review_status",
    "disposition",
    "rationale",
    "operation_key",
    "title",
    "area",
    "problem_type",
    "problem",
    "why_it_matters",
    "expected_clean_state",
    "exact_proposed_action",
    "canonical_object_key",
    "canonical_selection_rationale",
    "creations",
    "additions",
    "changes",
    "remaps",
    "deletions",
    "renames",
    "preconditions",
    "qa_steps",
    "rollback",
    "priority",
    "confidence",
    "execution_readiness",
    "owner_question",
    "recommended_action",
    "challenge_review",
}

MANDATORY_OPERATIONAL_MODULES = (
    "source_integrity",
    "inventory",
    "destination_inventory",
    "recognized_system_references",
    "missing_references",
    "duplicate_tag_names",
    "duplicate_trigger_names",
    "duplicate_variable_names",
    "duplicate_folder_names",
    "duplicate_zone_names",
    "duplicate_custom_template_names",
    "duplicate_client_names",
    "duplicate_transformation_names",
    "duplicate_tag_configurations",
    "normalized_duplicate_tag_signatures",
    "duplicate_trigger_logic",
    "duplicate_variable_logic",
    "duplicate_zone_configurations",
    "duplicate_google_tag_configurations",
    "duplicate_client_configurations",
    "duplicate_transformation_configurations",
    "duplicate_custom_template_configurations",
    "duplicate_variable_paths",
    "outdated_ua_styled_setup_objects",
    "unused_variables",
    "unused_triggers",
    "tags_without_firing_triggers",
    "unused_custom_templates",
    "unused_folders",
    "paused_tags",
    "used_only_by_paused_tags",
    "tag_sequence_structure",
    "tag_execution_controls",
    "single_member_trigger_groups",
    "trigger_group_structure",
    "zone_structure",
    "duplicate_custom_code",
    "variables_mirroring_builtins",
    "custom_variable_formula_logic",
    "consent_variable_logic",
    "media_tag_consent_route",
    "trigger_condition_lint",
    "ineffective_blocking_triggers",
    "unfiled_objects",
    "singleton_folders",
    "overloaded_folders",
    "name_hygiene",
    "naming_architecture_standardization",
)


def mandatory_module_errors(scan: dict[str, Any]) -> list[str]:
    rows = as_list(scan.get("modules"))
    names = [str(row.get("module_name") or "") for row in rows]
    errors: list[str] = []
    missing = sorted(set(MANDATORY_OPERATIONAL_MODULES) - set(names))
    duplicate = sorted(name for name in set(names) if name and names.count(name) > 1)
    if missing:
        errors.append("mandatory operational modules missing: " + ", ".join(missing))
    if duplicate:
        errors.append("duplicate operational module results: " + ", ".join(duplicate))
    for row in rows:
        name = str(row.get("module_name") or "")
        if name not in MANDATORY_OPERATIONAL_MODULES:
            continue
        if row.get("module_status") not in {"findings", "zero_findings"}:
            errors.append(f"mandatory operational module {name} has no closed status")
        if not isinstance(row.get("objects_scanned"), int) or row.get("objects_scanned", -1) < 0:
            errors.append(f"mandatory operational module {name} has invalid source count")
    return errors


def matching_owner_exception(
    finding: dict[str, Any], audit_context: dict[str, Any]
) -> dict[str, Any] | None:
    """Return a source-locked owner exception that identifies this finding."""
    finding_id = str(finding.get("finding_id") or "")
    signature_key = str(finding.get("signature_key") or "")
    object_names = {str(value) for value in as_list(finding.get("object_names"))}
    object_ids = {str(value) for value in as_list(finding.get("object_ids"))}
    for exception in as_list(audit_context.get("known_owner_exceptions")):
        if not isinstance(exception, dict) or not specific_text(exception.get("reason"), 5):
            continue
        identifiers = {
            str(exception.get("finding_id") or ""),
            str(exception.get("signature_key") or ""),
        } - {""}
        exception_objects = {
            str(value) for value in as_list(exception.get("object_names"))
        } | {str(value) for value in as_list(exception.get("object_ids"))}
        if finding_id in identifiers or signature_key in identifiers:
            return exception
        finding_objects = object_names | object_ids
        if finding_objects and finding_objects <= exception_objects:
            return exception
    return None


def finding_evidence_terms(finding: dict[str, Any]) -> list[str]:
    values = [
        *as_list(finding.get("object_ids")),
        *as_list(finding.get("object_names")),
        finding.get("deterministic_evidence"),
    ]
    terms: list[str] = []
    ignored = {
        "configuration",
        "duplicate",
        "finding",
        "review",
        "object",
        "module",
        "trigger",
        "variable",
    }
    for value in values:
        rendered = json.dumps(value, ensure_ascii=False) if isinstance(value, (dict, list)) else str(value or "")
        candidates = [rendered, *re.findall(r"[A-Za-z0-9_.$:/{}-]{3,}", rendered)]
        for candidate in candidates:
            term = " ".join(candidate.split()).strip().lower()
            if len(term) < 2 or term in ignored or term in terms:
                continue
            terms.append(term[:160])
    return terms[:60]


def scaffold_review(
    export_path: Path,
    shared_facts: dict[str, Any] | None = None,
) -> dict[str, Any]:
    descriptor = source_descriptor(export_path)
    shared_facts = shared_facts or build_shared_facts(export_path)
    shared_by_key = {
        str(row.get("object_key") or ""): row
        for row in as_list(shared_facts.get("objects"))
    }
    scan = audit_export(export_path)
    if scan.get("run_status") != "complete":
        finding_types = sorted(
            str(row.get("finding_type") or "source_integrity_error")
            for row in as_list(scan.get("blocking_source_findings"))
        )
        raise ValueError(
            "source integrity gate blocked operational review"
            + (": " + ", ".join(finding_types) if finding_types else "")
        )
    findings = []
    for finding in as_list(scan.get("findings")):
        if finding.get("finding_type") == "zero_findings":
            continue
        layer = str(finding.get("object_type") or "")
        source_ids = {str(value) for value in as_list(finding.get("object_ids"))}
        shared_keys = sorted(
            key
            for key, fact in shared_by_key.items()
            if str(fact.get("object_id") or "") in source_ids
            and (
                (
                    layer not in {"", "custom_code", "module"}
                    and key.startswith(layer + ":")
                )
                or layer in {"custom_code", "module"}
            )
        )
        findings.append(
            {
                **finding,
                "shared_fact_object_keys": shared_keys,
                "shared_behavior_signatures": {
                    key: shared_by_key[key].get("behavior_signatures", {})
                    for key in shared_keys
                },
                "rationale_evidence_terms": finding_evidence_terms(finding),
                "review_status": "pending",
                "disposition": "",
                "rationale": "",
                "operation_key": "",
                "title": "",
                "area": "",
                "problem_type": "",
                "problem": "",
                "why_it_matters": "",
                "expected_clean_state": "",
                "exact_proposed_action": "",
                "canonical_object_key": "",
                "canonical_selection_rationale": "",
                "creations": [],
                "additions": [],
                "changes": [],
                "remaps": [],
                "deletions": [],
                "renames": [],
                "preconditions": "",
                "qa_steps": "",
                "rollback": "",
                "priority": "",
                "confidence": "",
                "execution_readiness": "",
                "owner_question": "",
                "recommended_action": "",
                "challenge_review": {},
            }
        )
    input_contract = review_input_contract(
        "operational_sanitation",
        descriptor["source_sha256"],
        shared_facts["context_sha256"],
        shared_facts["shared_facts_sha256"],
    )
    return {
        **descriptor,
        "kind": "gtm_operational_sanitation_review",
        "schema_version": 3,
        "shared_facts_sha256": shared_facts["shared_facts_sha256"],
        "context_sha256": shared_facts["context_sha256"],
        "input_contract": input_contract,
        "completion_attestation": pending_completion_attestation(input_contract),
        "audit_context": shared_facts.get("audit_context", {}),
        "inferred_context": shared_facts.get("inferred_context", {}),
        "provided_context": shared_facts.get("provided_context", {}),
        "provided_context_fields": shared_facts.get("provided_context_fields", []),
        "unresolved_context_questions": shared_facts.get(
            "unresolved_context_questions", []
        ),
        "run_status": "pending",
        "inventory_counts": scan.get("counts", {}),
        "lifecycle_matrix": scan.get("lifecycle_matrix", []),
        "folder_topology": scan.get("folder_topology", {}),
        "destination_matrix": scan.get("destination_matrix", []),
        "trigger_lint_summary": scan.get("trigger_lint_summary", {}),
        "module_results": scan.get("modules", []),
        "findings": findings,
    }


def validate_review_identity(
    supplied: dict[str, Any],
    expected: dict[str, Any],
    expected_context: dict[str, Any],
    source_sha256: str,
) -> list[str]:
    checks = (
        ("source_sha256", source_sha256, "source_sha256 does not match the export"),
        ("kind", "gtm_operational_sanitation_review", "kind is invalid"),
        ("schema_version", 3, "schema_version must be 3"),
        (
            "shared_facts_sha256",
            expected.get("shared_facts_sha256"),
            "does not use the canonical shared facts",
        ),
        (
            "context_sha256",
            expected.get("context_sha256"),
            "does not use the canonical audit context",
        ),
        (
            "audit_context",
            expected.get("audit_context"),
            "audit_context differs from the canonical context",
        ),
        (
            "inferred_context",
            expected_context.get("inferred_context"),
            "inferred_context differs from source inference",
        ),
        (
            "provided_context",
            expected_context.get("provided_context"),
            "provided_context differs from its locked provenance",
        ),
        (
            "provided_context_fields",
            expected_context.get("provided_fields"),
            "provided context fields changed",
        ),
        (
            "unresolved_context_questions",
            expected.get("unresolved_context_questions"),
            "unresolved context questions changed",
        ),
        (
            "module_results",
            expected.get("module_results"),
            "mandatory module results differ from the source scan",
        ),
        ("run_status", "complete", "run_status must be complete"),
    )
    return [
        f"operational review {message}"
        for field, expected_value, message in checks
        if supplied.get(field) != expected_value
    ]


def finding_sets(
    supplied: dict[str, Any], expected: dict[str, Any]
) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]], list[str]]:
    expected_by_id = {row["finding_id"]: row for row in expected["findings"]}
    raw_supplied_rows = as_list(supplied.get("findings"))
    supplied_rows = [row for row in raw_supplied_rows if isinstance(row, dict)]
    supplied_by_id = {
        str(row.get("finding_id") or ""): row
        for row in supplied_rows
    }
    errors: list[str] = []
    if len(supplied_rows) != len(raw_supplied_rows):
        errors.append("operational findings contain malformed rows")
    if len(supplied_by_id) != len(supplied_rows) or "" in supplied_by_id:
        errors.append("operational finding IDs must be unique and nonblank")
    missing = sorted(set(expected_by_id) - set(supplied_by_id))
    unknown = sorted(set(supplied_by_id) - set(expected_by_id))
    if missing:
        errors.append("missing operational findings: " + ", ".join(missing))
    if unknown:
        errors.append("unknown operational findings: " + ", ".join(unknown))
    return expected_by_id, supplied_by_id, errors


def validate_locked_finding(
    row: dict[str, Any], expected_row: dict[str, Any], label: str
) -> list[str]:
    return [
        f"{label}: generated field {field} differs from the source scan"
        for field, value in expected_row.items()
        if field not in DECISION_FIELDS and row.get(field) != value
    ]


def validate_exception(
    row: dict[str, Any], expected_row: dict[str, Any], audit_context: dict[str, Any], label: str
) -> list[str]:
    exception = matching_owner_exception(expected_row, audit_context)
    if not exception:
        return [
            f"{label}: documented_exception is not declared in intake "
            "known_owner_exceptions"
        ]
    reason = str(exception.get("reason") or "").lower()
    if reason not in str(row.get("rationale") or "").lower():
        return [f"{label}: rationale must quote the locked exception reason"]
    return []


def validate_disposition(
    row: dict[str, Any],
    expected_row: dict[str, Any],
    audit_context: dict[str, Any],
    label: str,
) -> list[str]:
    errors: list[str] = []
    disposition = str(row.get("disposition") or "")
    if disposition not in VALID_DISPOSITIONS:
        errors.append(f"{label}: disposition is invalid")
    allowed = {
        value.strip()
        for value in str(expected_row.get("required_resolution") or "").split("|")
        if value.strip()
    }
    if disposition and disposition not in allowed:
        errors.append(f"{label}: disposition is not allowed for this finding type")
    if disposition in {"not_applicable", "container_evidence_limit"}:
        errors.append(
            f"{label}: a deterministic nonzero finding must be resolved by cleanup, "
            "a visible owner decision, or a source-locked exception"
        )
    finding_class = str(expected_row.get("finding_class") or "deterministic_defect")
    repair = expected_row.get("deterministic_repair") or {}
    action_candidate = str(
        expected_row.get("deterministic_action_candidate") or ""
    )
    exact_action_available = (
        str(repair.get("status") or "").startswith("unique_")
        or action_candidate == "delete_candidate"
        or (
            action_candidate == "rename_candidate"
            and not bool(expected_row.get("policy_confirmation_required"))
            and bool(expected_row.get("rename_candidate_unique"))
            and bool(str(expected_row.get("proposed_final_name") or "").strip())
            and not str(expected_row.get("rename_blocker") or "").strip()
        )
    )
    if (
        finding_class == "deterministic_defect"
        and exact_action_available
        and disposition in {"owner_decision_needed", "keep"}
    ):
        errors.append(
            f"{label}: a unique safe operational action is already source-proven; use "
            "that exact cleanup operation or an intake-locked documented exception "
            "before Run 1 can pass"
        )
    if disposition == "documented_exception":
        errors.extend(validate_exception(row, expected_row, audit_context, label))
    return errors


def validate_rationale(
    row: dict[str, Any], expected_row: dict[str, Any], label: str
) -> list[str]:
    errors: list[str] = []
    if not specific_text(row.get("rationale"), 6):
        errors.append(f"{label}: rationale is not source-specific")
    rationale = str(row.get("rationale") or "").lower()
    evidence_terms = [
        str(value).lower()
        for value in as_list(expected_row.get("rationale_evidence_terms"))
        if str(value).strip()
    ]
    required_hits = min(2, len(evidence_terms))
    if required_hits and sum(term in rationale for term in evidence_terms) < required_hits:
        errors.append(f"{label}: rationale does not cite enough deterministic evidence")
    return errors


def register_operation_key(
    row: dict[str, Any],
    finding_id: str,
    operation_keys: dict[str, str],
    label: str,
) -> tuple[list[str], list[str]]:
    key = str(row.get("operation_key") or "").strip()
    if not key:
        return [f"{label}: cleanup operation requires operation_key"], []
    if key in operation_keys:
        return [], [
            f"{label}: operation_key also used by {operation_keys[key]}; "
            "the compiler may merge only when every action is compatible"
        ]
    operation_keys[key] = finding_id
    return [], []


def validate_cleanup_operation(
    row: dict[str, Any],
    expected_row: dict[str, Any],
    finding_id: str,
    operation_keys: dict[str, str],
    valid_keys: set[str],
    source_paths_by_key: dict[str, str],
    lifecycle_by_key: dict[str, dict[str, Any]],
    label: str,
) -> tuple[list[str], list[str]]:
    errors, warnings = register_operation_key(row, finding_id, operation_keys, label)
    for field in (
        "title",
        "area",
        "problem_type",
        "problem",
        "why_it_matters",
        "expected_clean_state",
        "exact_proposed_action",
        "qa_steps",
        "rollback",
    ):
        # Taxonomy membership already proves area/problem-type validity; some
        # supported labels (for example "Over-firing") are one lexical token.
        minimum = 1 if field in {"area", "problem_type"} else 3
        if not specific_text(row.get(field), minimum):
            errors.append(f"{label}: {field} is incomplete")
    if row.get("priority") not in VALID_PRIORITIES:
        errors.append(f"{label}: priority is invalid")
    if row.get("confidence") not in VALID_CONFIDENCE:
        errors.append(f"{label}: confidence is invalid")
    if row.get("execution_readiness") not in VALID_READINESS:
        errors.append(f"{label}: execution_readiness is invalid")
    errors.extend(taxonomy_errors(row.get("area"), row.get("problem_type"), label))
    errors.extend(
        validate_structured_actions(
            row,
            valid_keys,
            label,
            # Cross-finding cleanup is deliberately atomic.  Consumer coverage
            # is checked over the complete accepted operation set below, where
            # a consumer deleted by another finding is visible.
            None,
            source_paths_by_key,
        )
    )
    errors.extend(validate_challenge(row, label, source_paths_by_key))
    errors.extend(
        validate_deterministic_repair(row, expected_row, lifecycle_by_key, label)
    )
    return errors, warnings


def validate_deterministic_repair(
    row: dict[str, Any],
    expected_row: dict[str, Any],
    lifecycle_by_key: dict[str, dict[str, Any]],
    label: str,
) -> list[str]:
    repair = row.get("deterministic_repair")
    if not isinstance(repair, dict) or not str(repair.get("status") or "").startswith(
        "unique_"
    ):
        return []
    repair_targets = {
        str(value)
        for value in as_list(expected_row.get("repair_affected_object_keys"))
        if str(value)
    }
    deleted_targets = {
        str(item.get("object_key") or "")
        for item in as_list(row.get("deletions"))
        if isinstance(item, dict)
    }
    # A full deletion is cleaner than repairing a stale field on a tag that is
    # itself paused and has no active export-visible consumers.  This narrow
    # precedence avoids emitting both a repair and a deletion for the same
    # inactive object while preserving the fail-closed rule for every active
    # or referenced repair target.
    deletion_replaces_repair = bool(repair_targets) and repair_targets <= deleted_targets
    if deletion_replaces_repair:
        deletion_replaces_repair = all(
            bool((lifecycle_by_key.get(key) or {}).get("paused"))
            and int((lifecycle_by_key.get(key) or {}).get("active_consumer_count") or 0)
            == 0
            for key in repair_targets
        )
    errors: list[str] = []
    for field in ("changes", "renames", "deletions"):
        required = {
            json.dumps(item, sort_keys=True, ensure_ascii=False)
            for item in as_list(repair.get(field))
        }
        supplied = {
            json.dumps(item, sort_keys=True, ensure_ascii=False)
            for item in as_list(row.get(field))
        }
        missing = required - supplied
        if missing and deletion_replaces_repair:
            missing = set()
        if missing and field == "changes":
            composed_missing: set[str] = set()
            supplied_changes = as_list(row.get("changes"))
            for required_item in as_list(repair.get("changes")):
                if any(
                    json.dumps(required_item, sort_keys=True, ensure_ascii=False)
                    == json.dumps(item, sort_keys=True, ensure_ascii=False)
                    for item in supplied_changes
                ):
                    continue
                object_key = str(required_item.get("object_key") or "")
                path = str(required_item.get("json_path") or "")
                for supplied_item in supplied_changes:
                    if (
                        str(supplied_item.get("object_key") or "") != object_key
                        or str(supplied_item.get("json_path") or "") != path
                        or supplied_item.get("before") != required_item.get("before")
                        or not isinstance(required_item.get("before"), str)
                        or not isinstance(required_item.get("after"), str)
                        or not isinstance(supplied_item.get("after"), str)
                    ):
                        continue
                    edits_required = []
                    for tag, start, end, replacement_start, replacement_end in difflib.SequenceMatcher(
                        a=required_item["before"], b=required_item["after"], autojunk=False
                    ).get_opcodes():
                        if tag != "equal":
                            edits_required.append(
                                (start, end, required_item["after"][replacement_start:replacement_end])
                            )
                    if not edits_required or any(
                        replacement and replacement not in supplied_item["after"]
                        for _start, _end, replacement in edits_required
                    ):
                        continue
                    composed_missing.add(
                        json.dumps(required_item, sort_keys=True, ensure_ascii=False)
                    )
                    break
            missing -= composed_missing
        if missing:
            errors.append(
                f"{label}: cleanup operation omits the generated unique "
                f"{repair.get('repair_kind')} {field[:-1]} mutation"
            )
    if repair.get("repair_kind") in {"setupTag", "teardownTag"}:
        exact_paths = {
            str(item.get("json_path") or "")
            for item in as_list(repair.get("changes"))
        }
        for change in as_list(row.get("changes")):
            path = str(change.get("json_path") or "")
            if (
                any(
                    path == exact.rsplit("[", 1)[0]
                    or path == exact.rsplit(".", 1)[0]
                    for exact in exact_paths
                )
                and change.get("after") in ([], None, "")
            ):
                errors.append(
                    f"{label}: a peer-supported sequence target exists; clearing the "
                    "setup/teardown edge is not the generated safe repair"
                )
    return errors


def validate_non_operation(row: dict[str, Any], label: str) -> list[str]:
    errors: list[str] = []
    mutation_fields = (
        "creations",
        "additions",
        "changes",
        "remaps",
        "deletions",
        "renames",
    )
    if any(as_list(row.get(field)) for field in mutation_fields):
        errors.append(f"{label}: non-operation disposition cannot contain mutations")
    if row.get("disposition") == "owner_decision_needed" and not precise_question(
        row.get("owner_question"), 5
    ):
        errors.append(f"{label}: owner decision requires one precise owner question")
    if row.get("disposition") == "owner_decision_needed" and not specific_text(
        row.get("recommended_action"), 6
    ):
        errors.append(
            f"{label}: owner decision requires one concrete recommended_action"
        )
    if row.get("disposition") == "keep" and not specific_text(
        row.get("recommended_action"), 6
    ):
        errors.append(
            f"{label}: retained review candidate requires one concrete recommended_action"
        )
    return errors


def validate_finding_decision(
    row: dict[str, Any],
    expected_row: dict[str, Any],
    audit_context: dict[str, Any],
    operation_keys: dict[str, str],
    valid_keys: set[str],
    source_paths_by_key: dict[str, str],
    lifecycle_by_key: dict[str, dict[str, Any]],
) -> tuple[list[str], list[str]]:
    finding_id = str(expected_row.get("finding_id") or "")
    label = f"finding {finding_id}"
    errors = validate_locked_finding(row, expected_row, label)
    if row.get("review_status") != "complete":
        errors.append(f"{label}: review_status must be complete")
    errors.extend(validate_disposition(row, expected_row, audit_context, label))
    errors.extend(validate_rationale(row, expected_row, label))
    if row.get("disposition") == "cleanup_operation":
        operation_errors, warnings = validate_cleanup_operation(
            row,
            expected_row,
            finding_id,
            operation_keys,
            valid_keys,
            source_paths_by_key,
            lifecycle_by_key,
            label,
        )
        errors.extend(operation_errors)
        return errors, warnings
    errors.extend(validate_non_operation(row, label))
    return errors, []


def validate_review(export_path: Path, review_path: Path) -> tuple[list[str], list[str]]:
    supplied = json.loads(review_path.read_text(encoding="utf-8"))
    expected_context, expected_shared = canonical_review_facts(export_path, supplied)
    expected = scaffold_review(export_path, expected_shared)
    errors: list[str] = []
    warnings: list[str] = []
    errors.extend(mandatory_module_errors({"modules": expected.get("module_results", [])}))
    descriptor = source_descriptor(export_path)
    valid_keys = object_keys(export_path)
    expected_consumers = object_consumer_map(export_path)
    object_names = object_name_map(export_path)
    source_paths_by_key = object_source_path_map(export_path)
    lifecycle_by_key = {
        str(item.get("object_key") or ""): item
        for item in as_list(expected.get("lifecycle_matrix"))
        if isinstance(item, dict) and str(item.get("object_key") or "")
    }

    errors.extend(
        validate_review_identity(
            supplied, expected, expected_context, descriptor["source_sha256"]
        )
    )
    errors.extend(validate_review_provenance(supplied, expected, "operational review"))
    errors.extend(
        validate_neutral_recheck_contexts(
            supplied,
            str(
                (supplied.get("completion_attestation") or {}).get(
                    "independent_review_context_id"
                )
                or ""
            ),
            "operational review",
        )
    )
    expected_by_id, supplied_by_id, set_errors = finding_sets(supplied, expected)
    errors.extend(set_errors)
    operation_keys: dict[str, str] = {}
    for finding_id, expected_row in expected_by_id.items():
        row = supplied_by_id.get(finding_id)
        if not row:
            continue
        finding_errors, finding_warnings = validate_finding_decision(
            row,
            expected_row,
            supplied.get("audit_context") or {},
            operation_keys,
            valid_keys,
            source_paths_by_key,
            lifecycle_by_key,
        )
        errors.extend(finding_errors)
        warnings.extend(finding_warnings)
    cleanup_rows = [
        row
        for row in supplied_by_id.values()
        if row.get("disposition") == "cleanup_operation"
    ]
    errors.extend(
        validate_operation_set(
            cleanup_rows,
            expected_consumers=expected_consumers,
            object_names=object_names,
            label="operational review operation set",
        )
    )
    return errors, warnings


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    scaffold = subparsers.add_parser("scaffold")
    scaffold.add_argument("export", type=Path)
    scaffold.add_argument("output", type=Path)
    scaffold.add_argument("--pretty", action="store_true")

    validate = subparsers.add_parser("validate")
    validate.add_argument("export", type=Path)
    validate.add_argument("review", type=Path)

    args = parser.parse_args()
    if args.command == "scaffold":
        payload = scaffold_review(args.export)
        write_json(args.output, payload, args.pretty)
        print(json.dumps({"output": str(args.output), "findings": len(payload["findings"])}))
        return 0

    errors, warnings = validate_review(args.export, args.review)
    for warning in warnings:
        print(f"WARNING: {warning}")
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(json.dumps({"status": "pass", "review": str(args.review)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
