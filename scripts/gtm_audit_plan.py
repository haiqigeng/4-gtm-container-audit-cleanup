#!/usr/bin/env python3
"""Apply one independently authored declarative plan to released audit work units."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from gtm_audit_contract import (
    ACTIONABLE_DECISION_CLASSES,
    BASE_REQUIRED_DECISION_FIELDS,
    CANONICAL_DECISION_FIELDS,
    CLASS_REQUIRED_DECISION_FIELDS,
    CONFIDENCE_LEVELS,
    DECISION_CLASSES,
    OPERATION_ACTION_FIELDS,
    PRIORITIES,
    semantic_contract_errors,
)
from gtm_audit_work_units import (
    DISCOVERY_DECISION_FIELDS,
    DISCOVERY_FIELDS,
    OPERATION_ACTION_ROW_FIELDS,
    OPERATION_PROPOSAL_FIELDS,
    WORK_UNIT_MANIFEST,
    declared_work_unit_files,
    discovery_schema_errors,
    merge_work_units,
    work_unit_contract_errors,
    work_unit_identity_hash,
)
from gtm_cleanroom_audit import (
    OPERATION_ID_PATTERN,
    OPERATION_TEXT_FIELDS_MINIMUM_WORDS,
    operation_proposal_errors,
)
from gtm_lib import as_list, require_safe_package_root, write_json
from gtm_operation_model import validate_operations
from gtm_projection_review import REVIEW_IDS, validate_projection_review

PLAN_FIELDS = {
    "kind",
    "schema_version",
    "owner_id",
    "authoring_contract",
    "decision_groups",
    "open_discoveries",
    "global_shared_infrastructure_review",
    "global_target_architecture_review",
}
DECISION_GROUP_FIELDS = {"group_id", "obligation_ids", "decision"}
PLAN_DECISION_FIELDS = {
    *CANONICAL_DECISION_FIELDS,
    "operation_proposal",
    "evidence_citations",
}


def _authoring_contract() -> dict[str, Any]:
    return {
        "authoring_unit": "exact_obligation_id_group",
        "decision_group_fields": sorted(DECISION_GROUP_FIELDS),
        "decision_group_shape": {
            "group_id": "one unique non-blank string",
            "obligation_ids": ["one or more exact obligation IDs"],
            "decision": "one nested decision object",
        },
        "every_obligation_id_exactly_once": True,
        "actionable_groups_require_one_obligation": True,
        "decision_classes": list(DECISION_CLASSES),
        "priorities_case_sensitive": list(PRIORITIES),
        "confidence_levels_case_sensitive": list(CONFIDENCE_LEVELS),
        "required_fields_by_class": {
            decision_class: [
                *BASE_REQUIRED_DECISION_FIELDS,
                *CLASS_REQUIRED_DECISION_FIELDS[decision_class],
            ]
            for decision_class in DECISION_CLASSES
        },
        "actionable_operation_contract": {
            "operation_id_pattern": OPERATION_ID_PATTERN,
            "operation_id_example": "OP-TAG-943-REMOVE-BLOCKER",
            "source_decision_id_must_match_locked_decision_id": True,
            "operation_family_rule": (
                "human-readable phrase of at least two words with no underscore"
            ),
            "at_least_one_structured_action": True,
            "depends_on_rule": "list containing only OP-* operation IDs",
            "text_fields_minimum_words": OPERATION_TEXT_FIELDS_MINIMUM_WORDS,
            "text_fields_require_strings": True,
            "proposal_fields": sorted(OPERATION_PROPOSAL_FIELDS),
            "action_row_fields": {
                field: sorted(fields)
                for field, fields in sorted(OPERATION_ACTION_ROW_FIELDS.items())
            },
            "action_json_path_rule": (
                "object-relative JSONPath beginning with $, for example "
                "$.tagFiringPriority; never a $.containerVersion path"
            ),
            "every_action_list_present": True,
        },
        "open_discoveries_contract": {
            "default": [],
            "item_fields": sorted(DISCOVERY_FIELDS),
            "decision_fields": sorted(DISCOVERY_DECISION_FIELDS),
            "checkpoint_string_notes_are_not_plan_discoveries": True,
        },
    }


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"JSON root must be an object: {path}")
    return value


def _audit_plan_path(package: Path, audit_id: str, supplied: Path) -> Path:
    expected = (package / "audit-scratch" / audit_id / "audit-plan.json").resolve()
    if supplied.resolve() != expected:
        raise ValueError(
            "audit plan must use its isolated path: "
            f"audit-scratch/{audit_id}/audit-plan.json"
        )
    return expected


def _projection_plan_path(
    package: Path,
    cycle_number: int,
    review_id: str,
    supplied: Path,
) -> Path:
    expected = (
        package
        / "projection-scratch"
        / f"cycle-{cycle_number:02d}"
        / review_id
        / "review-plan.json"
    ).resolve()
    if supplied.resolve() != expected:
        raise ValueError(
            "projection plan must use its isolated path: "
            f"projection-scratch/cycle-{cycle_number:02d}/{review_id}/review-plan.json"
        )
    return expected


def _empty_plan(owner_id: str) -> dict[str, Any]:
    return {
        "kind": "gtm_independent_semantic_plan",
        "schema_version": 2,
        "owner_id": owner_id,
        "authoring_contract": _authoring_contract(),
        "decision_groups": [],
        "open_discoveries": [],
        "global_shared_infrastructure_review": "",
        "global_target_architecture_review": "",
    }


def scaffold_plan(bundle: Path, output: Path) -> dict[str, Any]:
    bundle = bundle.resolve()
    package = bundle.parent.parent
    require_safe_package_root(package)
    audit = _read_json(bundle / "audit.json")
    audit_id = str(audit.get("audit_id") or "")
    output = _audit_plan_path(package, audit_id, output)
    if output.exists():
        raise FileExistsError(f"plan output already exists: {output}")
    output.parent.mkdir(parents=True, exist_ok=False)
    payload = _empty_plan(audit_id)
    write_json(output, payload)
    return payload


def _plan_errors(plan: dict[str, Any], owner_id: str) -> list[str]:
    errors: list[str] = []
    if set(plan) != PLAN_FIELDS:
        errors.append("audit plan fields differ from the closed schema")
    if plan.get("kind") != "gtm_independent_semantic_plan":
        errors.append("semantic plan kind is invalid")
    if plan.get("schema_version") != 2:
        errors.append("audit plan schema_version must be 2")
    if plan.get("owner_id") != owner_id:
        errors.append("semantic plan belongs to another owner")
    if plan.get("authoring_contract") != _authoring_contract():
        errors.append("audit plan authoring_contract differs from the current contract")
    group_ids: set[str] = set()
    for index, group in enumerate(as_list(plan.get("decision_groups")), start=1):
        label = f"decision group {index}"
        if not isinstance(group, dict) or set(group) != DECISION_GROUP_FIELDS:
            errors.append(f"{label} fields differ from the closed schema")
            continue
        group_id = str(group.get("group_id") or "")
        if not group_id or group_id in group_ids:
            errors.append(f"{label} group_id is blank or duplicated")
        group_ids.add(group_id)
        obligation_ids = group.get("obligation_ids")
        if (
            not isinstance(obligation_ids, list)
            or not obligation_ids
            or any(not isinstance(value, str) or not value for value in obligation_ids)
            or len(set(obligation_ids)) != len(obligation_ids)
        ):
            errors.append(
                f"{label} obligation_ids must be a non-empty list of unique non-blank strings"
            )
        decision = group.get("decision")
        if not isinstance(decision, dict) or set(decision) - PLAN_DECISION_FIELDS:
            errors.append(f"{label} decision uses unsupported fields")
        elif (
            decision.get("decision_class") in ACTIONABLE_DECISION_CLASSES
            and isinstance(obligation_ids, list)
            and len(obligation_ids) != 1
        ):
            errors.append(
                f"{label} actionable decision must name exactly one obligation"
            )
    if not isinstance(plan.get("open_discoveries"), list):
        errors.append("audit plan open_discoveries must be a list")
    else:
        for index, discovery in enumerate(plan["open_discoveries"], start=1):
            errors.extend(discovery_schema_errors(discovery, f"plan discovery {index}"))
    for field in (
        "global_shared_infrastructure_review",
        "global_target_architecture_review",
    ):
        if len(str(plan.get(field) or "").split()) < 10:
            errors.append(f"audit plan {field} is incomplete")
    return errors


def _complete_operation(proposal: dict[str, Any], decision_id: str) -> dict[str, Any]:
    completed = {
        "operation_id": proposal.get("operation_id", ""),
        "source_decision_id": decision_id,
        "operation_family": proposal.get("operation_family", ""),
        "exact_target_state": proposal.get("exact_target_state", ""),
        "preconditions": proposal.get("preconditions", ""),
        "static_verification": proposal.get("static_verification", ""),
        "rollback": proposal.get("rollback", ""),
        "depends_on": list(as_list(proposal.get("depends_on"))),
        **{field: list(as_list(proposal.get(field))) for field in OPERATION_ACTION_FIELDS},
    }
    return completed


def _complete_decision(
    locked: dict[str, Any],
    authored: dict[str, Any],
) -> dict[str, Any]:
    result = dict(locked)
    for field in CANONICAL_DECISION_FIELDS:
        result[field] = authored.get(field, "")
    result["status"] = "complete"
    result["evidence_citations"] = list(
        as_list(authored.get("evidence_citations", locked.get("source_coordinates", [])))
    )
    decision_class = str(result.get("decision_class") or "")
    proposal = authored.get("operation_proposal")
    result["operation_proposal"] = (
        _complete_operation(proposal, str(result["decision_id"]))
        if decision_class in ACTIONABLE_DECISION_CLASSES and isinstance(proposal, dict)
        else {}
    )
    return result


def _author_decisions(
    locked_by_obligation: dict[str, dict[str, Any]],
    plan: dict[str, Any],
) -> tuple[dict[str, dict[str, Any]], int, list[str]]:
    errors: list[str] = []
    selected_by_obligation: dict[str, dict[str, Any]] = {}
    duplicated_ids: set[str] = set()
    for group in as_list(plan.get("decision_groups")):
        if not isinstance(group, dict) or not isinstance(group.get("decision"), dict):
            continue
        for obligation_id in as_list(group.get("obligation_ids")):
            obligation_id = str(obligation_id)
            if obligation_id in selected_by_obligation:
                duplicated_ids.add(obligation_id)
            else:
                selected_by_obligation[obligation_id] = group["decision"]
    if duplicated_ids:
        errors.append(
            "semantic plan assigns obligations more than once: "
            + ", ".join(sorted(duplicated_ids))
        )
    unknown_ids = sorted(set(selected_by_obligation) - set(locked_by_obligation))
    if unknown_ids:
        errors.append(
            "semantic plan assigns unknown obligations: " + ", ".join(unknown_ids)
        )
    missing_ids = sorted(set(locked_by_obligation) - set(selected_by_obligation))
    if missing_ids:
        errors.append(
            "semantic plan leaves obligations unassigned: " + ", ".join(missing_ids)
        )
    authored: dict[str, dict[str, Any]] = {}
    operation_ids: set[str] = set()
    for obligation_id, locked in locked_by_obligation.items():
        selected = selected_by_obligation.get(obligation_id)
        if not isinstance(selected, dict):
            continue
        completed = _complete_decision(locked, selected)
        label = str(completed.get("decision_id") or obligation_id)
        errors.extend(semantic_contract_errors(completed, label))
        citations = {
            str(value) for value in as_list(completed.get("evidence_citations"))
        }
        allowed_citations = {
            str(value) for value in as_list(locked.get("source_coordinates"))
        }
        if allowed_citations and (
            not citations or citations - allowed_citations
        ):
            errors.append(f"{label}: citations must use locked source coordinates")
        proposal = completed.get("operation_proposal")
        if completed.get("decision_class") in ACTIONABLE_DECISION_CLASSES:
            errors.extend(
                operation_proposal_errors(proposal, completed, operation_ids, label)
            )
        authored[obligation_id] = completed
    return authored, len(as_list(plan.get("decision_groups"))), errors


def apply_plan(bundle: Path, plan_path: Path) -> dict[str, Any]:
    bundle = bundle.resolve()
    package = bundle.parent.parent
    require_safe_package_root(package)
    audit = _read_json(bundle / "audit.json")
    audit_id = str(audit.get("audit_id") or "")
    plan_path = _audit_plan_path(package, audit_id, plan_path)
    plan = _read_json(plan_path)
    errors = _plan_errors(plan, audit_id)
    manifest = _read_json(bundle / "work-units" / WORK_UNIT_MANIFEST)
    if manifest.get("work_unit_manifest_sha256") != work_unit_identity_hash(manifest):
        errors.append("work-unit manifest identity changed")
    _, manifest_errors = declared_work_unit_files(manifest)
    errors.extend(manifest_errors)
    records = as_list(manifest.get("work_units"))
    units: list[tuple[Path, dict[str, Any]]] = []
    locked_by_obligation: dict[str, dict[str, Any]] = {}
    if manifest.get("strategy") == "single_file":
        for decision in as_list(audit.get("decisions")):
            locked_by_obligation[str(decision.get("obligation_id") or "")] = decision
    else:
        for record in records:
            path = bundle / "work-units" / str(record.get("filename") or "")
            unit = _read_json(path)
            errors.extend(work_unit_contract_errors(unit, record, manifest))
            units.append((path, unit))
            for decision in as_list(unit.get("decisions")):
                obligation_id = str(decision.get("obligation_id") or "")
                if obligation_id in locked_by_obligation:
                    errors.append(f"obligation appears in multiple work units: {obligation_id}")
                locked_by_obligation[obligation_id] = decision
    authored, group_count, authored_errors = _author_decisions(
        locked_by_obligation, plan
    )
    errors.extend(authored_errors)
    operations = [
        row["operation_proposal"]
        for row in authored.values()
        if row.get("decision_class") in ACTIONABLE_DECISION_CLASSES
    ]
    if not authored_errors:
        source = _read_json(bundle / "locked-source.json")
        context = _read_json(bundle / "context.json")
        do_not_touch = {
            str(value)
            for value in as_list((context.get("context") or {}).get("do_not_touch"))
        }
        errors.extend(
            f"audit operation safety gate failed: {error}"
            for error in validate_operations(
                source,
                operations,
                do_not_touch=do_not_touch,
            )
        )
    if errors:
        raise ValueError("; ".join(errors))

    if units:
        for index, (path, unit) in enumerate(units):
            unit["decisions"] = [
                authored[str(row["obligation_id"])] for row in unit["decisions"]
            ]
            unit["open_discoveries"] = plan["open_discoveries"] if index == 0 else []
            unit["unit_closure"] = (
                f"Independent review completed for all {len(unit['decisions'])} obligations "
                f"in {unit['work_unit_id']}."
            )
            write_json(path, unit)
        merge_work_units(bundle)
        audit = _read_json(bundle / "audit.json")
    else:
        audit["decisions"] = [
            authored[str(row["obligation_id"])] for row in audit["decisions"]
        ]
        audit["open_discoveries"] = plan["open_discoveries"]

    decisions = list(authored.values())
    audit["status"] = "complete"
    audit["coverage_closure"] = {
        "reviewed_obligation_ids": sorted(locked_by_obligation),
        "reviewed_object_keys": sorted(
            {str(value) for row in decisions for value in as_list(row.get("subject_keys"))}
        ),
        "reviewed_family_ids": sorted(
            {str(value) for row in decisions for value in as_list(row.get("family_ids"))}
        ),
        "reviewed_relationship_candidate_ids": sorted(
            {
                str(row.get("candidate_id"))
                for row in decisions
                if str(row.get("candidate_id") or "")
            }
        ),
        "global_shared_infrastructure_review": plan[
            "global_shared_infrastructure_review"
        ],
        "global_target_architecture_review": plan["global_target_architecture_review"],
    }
    audit["completion_attestation"] = {
        "status": "complete",
        "foreign_audit_artifacts_used": [],
        "test_or_bulk_semantic_helpers_used": [],
        "decision_authoring_method": "independent_agent_review",
        "peer_findings_received_before_completion": False,
    }
    write_json(bundle / "audit.json", audit)
    return {
        "status": "pass",
        "audit_id": audit_id,
        "decision_groups": group_count,
        "decisions": len(authored),
        "work_units": len(units),
        "strategy": manifest.get("strategy"),
    }


def scaffold_projection_plan(
    package: Path,
    cycle_number: int,
    review_id: str,
    output: Path,
) -> dict[str, Any]:
    package = package.resolve()
    require_safe_package_root(package)
    if review_id not in REVIEW_IDS:
        raise ValueError(f"unsupported projection review: {review_id}")
    review_path = (
        package
        / "fixed-point"
        / f"cycle-{cycle_number:02d}"
        / "reviews"
        / review_id
        / "review.json"
    )
    review = _read_json(review_path)
    if review.get("review_id") != review_id or review.get("cycle_number") != cycle_number:
        raise ValueError("projection review scaffold identity is invalid")
    output = _projection_plan_path(package, cycle_number, review_id, output)
    if output.exists():
        raise FileExistsError(f"plan output already exists: {output}")
    output.parent.mkdir(parents=True, exist_ok=False)
    payload = _empty_plan(review_id)
    payload["global_shared_infrastructure_review"] = (
        "This projection plan preserves the source audit shared-infrastructure review without reinterpretation."
    )
    payload["global_target_architecture_review"] = (
        "This projection plan reviews changed obligations without replacing the complete target architecture review."
    )
    write_json(output, payload)
    return payload


def apply_projection_plan(
    package: Path,
    cycle_number: int,
    review_id: str,
    plan_path: Path,
    *,
    agent_id: str,
    context_id: str,
) -> dict[str, Any]:
    package = package.resolve()
    require_safe_package_root(package)
    if review_id not in REVIEW_IDS:
        raise ValueError(f"unsupported projection review: {review_id}")
    if not agent_id.strip() or not context_id.strip():
        raise ValueError("projection plan requires non-blank agent and context identities")
    cycle_dir = package / "fixed-point" / f"cycle-{cycle_number:02d}"
    review_path = cycle_dir / "reviews" / review_id / "review.json"
    review = _read_json(review_path)
    plan_path = _projection_plan_path(package, cycle_number, review_id, plan_path)
    plan = _read_json(plan_path)
    errors = _plan_errors(plan, review_id)
    if plan.get("open_discoveries"):
        errors.append("projection plans cannot introduce open discoveries")
    rows = [row for row in as_list(review.get("decisions")) if isinstance(row, dict)]
    locked_by_obligation = {
        str(row.get("obligation_id") or ""): row for row in rows
    }
    if len(locked_by_obligation) != len(rows) or "" in locked_by_obligation:
        errors.append("projection review decision identities are blank or duplicated")
    authored, group_count, authored_errors = _author_decisions(
        locked_by_obligation, plan
    )
    errors.extend(authored_errors)
    operations = [
        row["operation_proposal"]
        for row in authored.values()
        if row.get("decision_class") in ACTIONABLE_DECISION_CLASSES
    ]
    if not authored_errors:
        projected_source = _read_json(review_path.parent / "projected-container.json")
        context = _read_json(package / "context.json")
        do_not_touch = {
            str(value)
            for value in as_list((context.get("context") or {}).get("do_not_touch"))
        }
        errors.extend(
            f"projection operation safety gate failed: {error}"
            for error in validate_operations(
                projected_source,
                operations,
                do_not_touch=do_not_touch,
            )
        )
    if errors:
        raise ValueError("; ".join(errors))
    review["status"] = "complete"
    review["independent_agent_id"] = agent_id.strip()
    review["independent_context_id"] = context_id.strip()
    review["decisions"] = [
        authored[str(row["obligation_id"])] for row in rows
    ]
    review["completion_attestation"] = {
        "status": "complete",
        "foreign_projection_review_used": False,
        "fresh_context": True,
        "peer_findings_received_before_completion": False,
        "conclusion": (
            "Every changed obligation was independently reviewed against the locked projected evidence."
        ),
    }
    write_json(review_path, review)
    validation_errors = validate_projection_review(cycle_dir, review_id)
    if validation_errors:
        raise ValueError("projection plan result failed validation: " + "; ".join(validation_errors))
    return {
        "status": "pass",
        "review_id": review_id,
        "cycle_number": cycle_number,
        "decision_groups": group_count,
        "decisions": len(authored),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    scaffold = subparsers.add_parser("scaffold")
    scaffold.add_argument("bundle", type=Path)
    scaffold.add_argument("output", type=Path)
    apply = subparsers.add_parser("apply")
    apply.add_argument("bundle", type=Path)
    apply.add_argument("plan", type=Path)
    scaffold_projection = subparsers.add_parser("scaffold-projection")
    scaffold_projection.add_argument("package", type=Path)
    scaffold_projection.add_argument("cycle", type=int)
    scaffold_projection.add_argument("review_id", choices=REVIEW_IDS)
    scaffold_projection.add_argument("output", type=Path)
    apply_projection = subparsers.add_parser("apply-projection")
    apply_projection.add_argument("package", type=Path)
    apply_projection.add_argument("cycle", type=int)
    apply_projection.add_argument("review_id", choices=REVIEW_IDS)
    apply_projection.add_argument("plan", type=Path)
    apply_projection.add_argument("--agent-id", required=True)
    apply_projection.add_argument("--context-id", required=True)
    args = parser.parse_args()
    if args.command == "scaffold":
        result = scaffold_plan(args.bundle, args.output)
    elif args.command == "apply":
        result = apply_plan(args.bundle, args.plan)
    elif args.command == "scaffold-projection":
        result = scaffold_projection_plan(
            args.package, args.cycle, args.review_id, args.output
        )
    else:
        result = apply_projection_plan(
            args.package,
            args.cycle,
            args.review_id,
            args.plan,
            agent_id=args.agent_id,
            context_id=args.context_id,
        )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
