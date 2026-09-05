#!/usr/bin/env python3
"""Extract internal operational candidate evidence.

This module is an implementation component of the canonical v2.2 scan.  The
standalone v1 review command was deliberately removed.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from gtm_baseline_audit import audit_export
from gtm_lib import as_list, source_descriptor
from gtm_shared_facts import build_shared_facts

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


def specific_text(value: Any, minimum: int = 5) -> bool:
    text = " ".join(str(value or "").split()).strip().lower()
    return len(re.findall(r"\b[\w{}.-]+\b", text)) >= minimum and text not in {
        "review configuration",
        "check in gtm",
        "needs review",
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
    "duplicate_tag_configurations",
    "normalized_duplicate_tag_signatures",
    "duplicate_trigger_logic",
    "duplicate_variable_logic",
    "duplicate_zone_configurations",
    "duplicate_google_tag_configurations",
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


def candidate_source_scope(
    finding: dict[str, Any],
    shared_by_key: dict[str, dict[str, Any]],
) -> tuple[list[str], list[str]]:
    """Resolve one neutral candidate to existing source objects and exact JSON paths."""

    object_keys = {
        str(value)
        for value in as_list(finding.get("shared_fact_object_keys"))
        if str(value) in shared_by_key
    }
    object_keys.update(
        str(value)
        for value in as_list(finding.get("repair_affected_object_keys"))
        if str(value) in shared_by_key
    )
    for identity in as_list(finding.get("object_identities")):
        identity_text = str(identity or "")
        if identity_text in shared_by_key:
            object_keys.add(identity_text)
            continue
        parts = identity_text.split("|", 2)
        if len(parts) >= 2:
            key = f"{parts[0]}:{parts[1]}"
            if key in shared_by_key:
                object_keys.add(key)

    finding_layer = str(finding.get("object_type") or "").strip()
    if finding_layer:
        object_keys.update(
            key
            for value in as_list(finding.get("object_ids"))
            if (key := f"{finding_layer}:{value}") in shared_by_key
        )
        finding_names = {
            str(value) for value in as_list(finding.get("object_names")) if str(value)
        }
        object_keys.update(
            key for key, fact in shared_by_key.items()
            if key.startswith(f"{finding_layer}:")
            and str(fact.get("object_name") or "") in finding_names
        )

    def trace_target_keys(trace: dict[str, Any]) -> set[str]:
        targets: set[str] = set()
        for target in as_list(trace.get("targets")):
            if not isinstance(target, dict):
                continue
            target_key = str(target.get("object_key") or "")
            if target_key:
                targets.add(target_key)
            for child in as_list(target.get("member_traces")):
                if isinstance(child, dict):
                    targets.update(trace_target_keys(child))
        return targets

    source_paths: set[str] = set()
    finding_type = str(finding.get("finding_type") or "")
    referenced_identities = {
        str(value)
        for field in ("object_ids", "object_names")
        for value in as_list(finding.get(field))
        if str(value)
    }
    if finding_type == "undefined_variable_reference":
        for key, fact in shared_by_key.items():
            if referenced_identities & {
                str(value) for value in as_list(fact.get("referenced_variables"))
            }:
                object_keys.add(key)
                for leaf in as_list(fact.get("source_leaf_facts")):
                    if referenced_identities & {
                        str(value)
                        for value in as_list((leaf or {}).get("referenced_variables"))
                    }:
                        path = str((leaf or {}).get("json_path") or "")
                        if path.startswith("$."):
                            source_paths.add(path)
    elif finding_type == "missing_trigger_reference":
        for key, fact in shared_by_key.items():
            for trace in as_list(fact.get("execution_dependency_traces")):
                if (
                    isinstance(trace, dict)
                    and str(trace.get("reference") or "") in referenced_identities
                ):
                    object_keys.add(key)
                    source_paths.update(
                        path
                        for path in as_list(trace.get("source_reference_paths"))
                        if isinstance(path, str) and path.startswith("$.")
                    )
    elif finding_type in {"missing_setupTag_reference", "missing_teardownTag_reference"}:
        source_id = next(
            (str(value) for value in as_list(finding.get("object_ids"))
             if f"tag:{value}" in shared_by_key),
            "",
        )
        if source_id:
            object_keys.add(f"tag:{source_id}")

    changed = True
    while changed:
        changed = False
        variable_names = {
            str(shared_by_key[key].get("object_name") or "")
            for key in object_keys
            if key.startswith("variable:")
        }
        for key, fact in shared_by_key.items():
            matching_dependency_traces = [
                trace for trace in as_list(fact.get("execution_dependency_traces"))
                if isinstance(trace, dict) and trace_target_keys(trace) & object_keys
            ]
            referenced_here = variable_names & {
                str(value) for value in as_list(fact.get("referenced_variables"))
            }
            if matching_dependency_traces or referenced_here:
                if key not in object_keys:
                    object_keys.add(key)
                    changed = True
                for trace in matching_dependency_traces:
                    source_paths.update(
                        path
                        for path in as_list(trace.get("source_reference_paths"))
                        if isinstance(path, str) and path.startswith("$.")
                    )
                for leaf in as_list(fact.get("source_leaf_facts")):
                    if referenced_here & {
                        str(value)
                        for value in as_list((leaf or {}).get("referenced_variables"))
                    }:
                        path = str((leaf or {}).get("json_path") or "")
                        if path.startswith("$."):
                            source_paths.add(path)
    for key in object_keys:
        path = str(shared_by_key[key].get("source_json_path") or "")
        if path.startswith("$."):
            source_paths.add(path)
    return sorted(object_keys), sorted(source_paths)


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
        candidate_keys, candidate_paths = candidate_source_scope(
            {**finding, "shared_fact_object_keys": shared_keys}, shared_by_key
        )
        findings.append(
            {
                **finding,
                "shared_fact_object_keys": shared_keys,
                "candidate_object_keys": candidate_keys,
                "candidate_source_paths": candidate_paths,
                "shared_behavior_signatures": {
                    key: shared_by_key[key].get("behavior_signatures", {})
                    for key in candidate_keys
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
    return {
        **descriptor,
        "kind": "gtm_operational_sanitation_review",
        "schema_version": 3,
        "shared_facts_sha256": shared_facts["shared_facts_sha256"],
        "context_sha256": shared_facts["context_sha256"],
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
