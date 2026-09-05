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
    AUDIT_IDS,
    OPERATION_ID_PATTERN,
    OPERATION_TEXT_FIELDS,
    _agent_context_errors,
    _sealed_audit_record_errors,
    decision_obligation_alignment_errors,
    operation_proposal_errors,
    proposed_deletion_keys,
)
from gtm_lib import as_list, require_safe_package_root, write_json
from gtm_operation_model import (
    merge_exact_operation_ids,
    normalize_operation,
    object_catalog,
    read_operation_source,
    validate_operations,
)

PLAN_FIELDS = {
    "kind",
    "schema_version",
    "owner_id",
    "authoring_contract",
    "candidate_groups",
    "decision_profiles",
    "obligation_overrides",
    "open_discoveries",
    "global_shared_infrastructure_review",
    "global_target_architecture_review",
}
CANDIDATE_GROUP_FIELDS = {"group_id", "obligation_ids"}
PROFILE_FIELDS = {"profile_id", "candidate_group_ids", "decision"}
OVERRIDE_FIELDS = {"override_id", "obligation_ids", "decision"}
PLAN_DECISION_FIELDS = {
    *CANONICAL_DECISION_FIELDS,
    "operation_proposal",
    "evidence_citations",
}
OPERATION_DECISION_FIELDS = ("static_verification", "rollback")
AUTHORED_OPERATION_FIELDS = OPERATION_PROPOSAL_FIELDS - {"source_decision_id"}
MAX_OBLIGATIONS_PER_CANDIDATE_GROUP = 30


def _authoring_contract() -> dict[str, Any]:
    return {
        "authoring_unit": "candidate_group_profile_with_exact_obligation_overrides",
        "decision_rule": (
            "A missing authored exact operation for a source-proven safe technical repair "
            "is unfinished audit work, not an owner decision or evidence limit. Split "
            "that repair from unrelated unresolved ownership questions. If safe target "
            "values or handling genuinely depend on missing evidence or an owner choice, "
            "retain that specific boundary; do not invent values or force an action."
        ),
        "candidate_group_rule": (
            "candidate_groups are locked neutral clerical candidates. Assign groups "
            "with decision_profiles; use obligation_overrides for every obligation in "
            "a candidate whose judgment, target, evidence meaning, or action differs."
        ),
        "profile_fields": sorted(PROFILE_FIELDS),
        "override_fields": sorted(OVERRIDE_FIELDS),
        "candidate_group_fields": sorted(CANDIDATE_GROUP_FIELDS),
        "candidate_group_shape": {
            "group_id": "one unique non-blank string",
            "obligation_ids": ["one or more exact obligation IDs"],
        },
        "every_obligation_id_exactly_once": True,
        "shared_operation_rule": (
            "Multiple obligations may share one OP-* ID only with identical complete "
            "operation content, decision class, priority and confidence. Author a shared "
            "profile or override once when its assessment fits every member; otherwise "
            "retain individual decisions and their exact evidence citations. Shared "
            "operations are simulated once and retain all source decision identities."
        ),
        "decision_classes": list(DECISION_CLASSES),
        "priorities_case_sensitive": list(PRIORITIES),
        "confidence_levels_case_sensitive": list(CONFIDENCE_LEVELS),
        "required_fields_by_class": {
            decision_class: [
                field
                for field in (*BASE_REQUIRED_DECISION_FIELDS, *CLASS_REQUIRED_DECISION_FIELDS[decision_class])
                if decision_class not in ACTIONABLE_DECISION_CLASSES
                or field not in OPERATION_DECISION_FIELDS
            ]
            for decision_class in DECISION_CLASSES
        },
        "actionable_operation_contract": {
            "operation_id_pattern": OPERATION_ID_PATTERN,
            "operation_id_example": "OP-TAG-943-REMOVE-BLOCKER",
            "derived_source_decision_id": "copied from the locked decision identity",
            "decision_fields_projected_from_operation": list(OPERATION_DECISION_FIELDS),
            "at_least_one_structured_action": True,
            "depends_on_rule": "list containing only OP-* operation IDs",
            "required_nonblank_text_fields": list(OPERATION_TEXT_FIELDS),
            "proposal_fields": sorted(AUTHORED_OPERATION_FIELDS),
            "action_row_fields": {
                field: sorted(fields)
                for field, fields in sorted(OPERATION_ACTION_ROW_FIELDS.items())
            },
            "action_json_path_rule": (
                "object-relative JSONPath beginning with $, for example "
                "$.priority; never a $.containerVersion path"
            ),
            "before_reference_rule": (
                "changes/removals require before_source_sha256 copied from the locked "
                "source_sha256. object_key and json_path identify the original value; "
                "never copy it into the proposal. Recovery requires the canonical "
                "operation and its bound locked source."
            ),
            "omitted_lists": "unused action lists and depends_on are completed as empty lists",
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


def _candidate_decision_groups(decisions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[Any, ...], list[str]] = {}
    for row in decisions:
        obligation_id = str(row.get("obligation_id") or "")
        if not obligation_id:
            continue
        key = (
            str(row.get("area_id") or ""),
            str(row.get("scope_level") or ""),
            str(row.get("audit_mechanism") or ""),
            str(row.get("fact_kind") or ""),
            str(row.get("applicability") or ""),
            tuple(sorted(str(value) for value in as_list(row.get("material_verification_triggers")))),
        )
        grouped.setdefault(key, []).append(obligation_id)
    groups: list[dict[str, Any]] = []
    for key in sorted(grouped):
        obligation_ids = sorted(grouped[key])
        for offset in range(0, len(obligation_ids), MAX_OBLIGATIONS_PER_CANDIDATE_GROUP):
            groups.append(
                {
                    "group_id": f"candidate-{len(groups) + 1:03d}",
                    "obligation_ids": obligation_ids[
                        offset : offset + MAX_OBLIGATIONS_PER_CANDIDATE_GROUP
                    ],
                }
            )
    return groups


def _empty_plan(owner_id: str, decisions: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "kind": "gtm_independent_semantic_plan",
        "schema_version": 3,
        "owner_id": owner_id,
        "authoring_contract": _authoring_contract(),
        "candidate_groups": _candidate_decision_groups(decisions),
        "decision_profiles": [],
        "obligation_overrides": [],
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
    payload = _empty_plan(audit_id, as_list(audit.get("decisions")))
    write_json(output, payload)
    return payload


def _plan_errors(
    plan: dict[str, Any], owner_id: str, expected_candidates: list[dict[str, Any]]
) -> list[str]:
    errors: list[str] = []
    if set(plan) != PLAN_FIELDS:
        errors.append("audit plan fields differ from the closed schema")
    if plan.get("kind") != "gtm_independent_semantic_plan":
        errors.append("semantic plan kind is invalid")
    if plan.get("schema_version") != 3:
        errors.append("audit plan schema_version must be 3")
    if plan.get("owner_id") != owner_id:
        errors.append("semantic plan belongs to another owner")
    if plan.get("authoring_contract") != _authoring_contract():
        errors.append("audit plan authoring_contract differs from the current contract")
    if plan.get("candidate_groups") != expected_candidates:
        errors.append("audit plan candidate_groups differ from the locked scaffold")
    for collection, fields, id_field, member_field in (
        ("decision_profiles", PROFILE_FIELDS, "profile_id", "candidate_group_ids"),
        ("obligation_overrides", OVERRIDE_FIELDS, "override_id", "obligation_ids"),
    ):
        row_ids: set[str] = set()
        for index, row in enumerate(as_list(plan.get(collection)), start=1):
            label = f"{collection} row {index}"
            if not isinstance(row, dict) or set(row) != fields:
                errors.append(f"{label} fields differ from the closed schema")
                continue
            row_id = str(row.get(id_field) or "")
            if not row_id or row_id in row_ids:
                errors.append(f"{label} identifier is blank or duplicated")
            row_ids.add(row_id)
            obligation_ids = row.get(member_field)
            if (
                not isinstance(obligation_ids, list)
                or not obligation_ids
                or any(not isinstance(value, str) or not value for value in obligation_ids)
                or len(set(obligation_ids)) != len(obligation_ids)
            ):
                errors.append(f"{label} members must be unique non-blank strings")
            decision = row.get("decision")
            if not isinstance(decision, dict) or set(decision) - PLAN_DECISION_FIELDS:
                errors.append(f"{label} decision uses unsupported fields")
                continue
            if decision.get("decision_class") in ACTIONABLE_DECISION_CLASSES:
                if set(decision) & set(OPERATION_DECISION_FIELDS):
                    errors.append(f"{label}: author verification and rollback only inside operation_proposal")
                proposal = decision.get("operation_proposal")
                if isinstance(proposal, dict):
                    if set(proposal) - AUTHORED_OPERATION_FIELDS:
                        errors.append(f"{label}: operation_proposal contains unsupported or derived fields")
                    for field in (*OPERATION_ACTION_FIELDS, "depends_on"):
                        if field in proposal and not isinstance(proposal[field], list):
                            errors.append(f"{label}: operation_proposal {field} must be a list")
            elif "operation_proposal" in decision and decision["operation_proposal"] != {}:
                errors.append(f"{label}: non-actionable decision operation_proposal must be omitted or empty")
    if not isinstance(plan.get("open_discoveries"), list):
        errors.append("audit plan open_discoveries must be a list")
    else:
        for index, discovery in enumerate(plan["open_discoveries"], start=1):
            errors.extend(discovery_schema_errors(discovery, f"plan discovery {index}"))
    for field in (
        "global_shared_infrastructure_review",
        "global_target_architecture_review",
    ):
        if not isinstance(plan.get(field), str) or not plan[field].strip():
            errors.append(f"audit plan {field} must be a non-blank string")
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
    if decision_class in ACTIONABLE_DECISION_CLASSES:
        for field in OPERATION_DECISION_FIELDS:
            result[field] = result["operation_proposal"].get(field, "")
    return result


def _author_decisions(
    locked_by_obligation: dict[str, dict[str, Any]],
    plan: dict[str, Any],
) -> tuple[dict[str, dict[str, Any]], int, list[str]]:
    errors: list[str] = []
    candidates = as_list(plan.get("candidate_groups"))
    candidate_by_id = {
        str(row.get("group_id") or ""): row for row in candidates if isinstance(row, dict)
    }
    selected_by_obligation: dict[str, dict[str, Any]] = {}
    duplicated_ids: set[str] = set()
    for override in as_list(plan.get("obligation_overrides")):
        if not isinstance(override, dict) or not isinstance(override.get("decision"), dict):
            continue
        for obligation_id in as_list(override.get("obligation_ids")):
            obligation_id = str(obligation_id)
            if obligation_id in selected_by_obligation:
                duplicated_ids.add(obligation_id)
            else:
                selected_by_obligation[obligation_id] = override["decision"]
    assigned_candidates: set[str] = set()
    for profile in as_list(plan.get("decision_profiles")):
        if not isinstance(profile, dict) or not isinstance(profile.get("decision"), dict):
            continue
        for candidate_id in as_list(profile.get("candidate_group_ids")):
            candidate_id = str(candidate_id)
            if candidate_id in assigned_candidates:
                errors.append(f"semantic plan assigns candidate group more than once: {candidate_id}")
                continue
            assigned_candidates.add(candidate_id)
            candidate = candidate_by_id.get(candidate_id)
            if not candidate:
                errors.append(f"semantic plan assigns unknown candidate group: {candidate_id}")
                continue
            expanded_ids = [
                str(value)
                for value in as_list(candidate.get("obligation_ids"))
                if str(value) not in selected_by_obligation
            ]
            for obligation_id in expanded_ids:
                selected_by_obligation[obligation_id] = profile["decision"]
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
    operation_ids: dict[str, str] = {}
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
    return authored, len(as_list(plan.get("decision_profiles"))) + len(as_list(plan.get("obligation_overrides"))), errors


def _amendment_provenance(
    bundle: Path,
    audit: dict[str, Any],
    amendment_of: str | None,
    agent_id: str | None,
    context_id: str | None,
) -> dict[str, str]:
    package = bundle.parent.parent
    audit_id = str(audit.get("audit_id") or "")
    seal_path = package / "audit-seals" / f"{audit_id}.json"
    values = (amendment_of, agent_id, context_id)
    if all(value is None for value in values) and not seal_path.exists():
        return {}
    if any(not isinstance(value, str) or not value.strip() for value in values):
        raise ValueError("amendment apply requires --amendment-of, --agent-id and --context-id")
    if audit_id not in AUDIT_IDS or bundle != package / "audit-bundles" / audit_id:
        raise ValueError("amendment must use its exact audit bundle")
    if not seal_path.is_file():
        raise ValueError("amendment requires a current prior audit seal")
    if (package / "canonical-record-seal.json").exists():
        raise ValueError("source-audit amendment is closed after canonical sealing")
    previous = _read_json(seal_path)
    if amendment_of != previous.get("audit_seal_sha256"):
        raise ValueError("amendment must cite the current audit seal")
    errors = _sealed_audit_record_errors(package, audit_id)
    provenance = {
        "amendment_parent_seal_sha256": amendment_of,
        "independent_agent_id": agent_id.strip(),
        "independent_context_id": context_id.strip(),
    }
    manifest = _read_json(bundle / "bundle-manifest.json")
    errors.extend(_agent_context_errors(
        {**audit, **provenance},
        str(manifest.get("bundle_manifest_sha256") or ""),
        "audit amendment",
    ))
    identities = [previous, _read_json(package / "scan-assurance.json")]
    for peer in AUDIT_IDS:
        peer_seal = package / "audit-seals" / f"{peer}.json"
        if peer != audit_id and peer_seal.is_file():
            identities.append(_read_json(peer_seal))
    for field in ("independent_agent_id", "independent_context_id"):
        if any(provenance[field] == str(row.get(field) or "").strip() for row in identities):
            errors.append(f"audit amendment requires a fresh {field}")
    if errors:
        raise ValueError("amendment provenance gate failed: " + "; ".join(errors))
    return provenance


def apply_plan(
    bundle: Path,
    plan_path: Path,
    *,
    amendment_of: str | None = None,
    agent_id: str | None = None,
    context_id: str | None = None,
) -> dict[str, Any]:
    bundle = bundle.resolve()
    package = bundle.parent.parent
    require_safe_package_root(package)
    audit = _read_json(bundle / "audit.json")
    audit_id = str(audit.get("audit_id") or "")
    provenance = _amendment_provenance(bundle, audit, amendment_of, agent_id, context_id)
    plan_path = _audit_plan_path(package, audit_id, plan_path)
    plan = _read_json(plan_path)
    errors = _plan_errors(
        plan, audit_id, _candidate_decision_groups(as_list(audit.get("decisions")))
    )
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
    ledger = _read_json(package / "obligation-ledger.json")
    obligation_by_id = {
        str(row.get("obligation_id") or ""): row
        for row in as_list(ledger.get("obligations"))
        if isinstance(row, dict)
    }
    source_sha256 = ledger["source_sha256"]
    source = read_operation_source(bundle / "locked-source.json", source_sha256)
    source_catalog = object_catalog(source)
    context = _read_json(bundle / "context.json")
    do_not_touch = {
        str(value)
        for value in as_list((context.get("context") or {}).get("do_not_touch"))
    }
    retired_keys = proposed_deletion_keys(list(authored.values()))
    for obligation_id, decision in authored.items():
        obligation = obligation_by_id.get(obligation_id)
        if obligation:
            errors.extend(
                decision_obligation_alignment_errors(
                    decision,
                    obligation,
                    str(decision.get("decision_id") or obligation_id),
                    source_catalog=source_catalog, source_sha256=source_sha256,
                    do_not_touch=do_not_touch,
                    retired_object_keys=retired_keys,
                )
            )
    operations = [
        normalize_operation(row["operation_proposal"], str(row["decision_id"]), row)
        for row in authored.values()
        if row.get("decision_class") in ACTIONABLE_DECISION_CLASSES
    ]
    if not authored_errors:
        operations = merge_exact_operation_ids(operations)
        errors.extend(
            f"audit operation safety gate failed: {error}"
            for error in validate_operations(
                source,
                operations,
                source_sha256=source_sha256,
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
    audit.update(provenance)
    write_json(bundle / "audit.json", audit)
    return {
        "status": "pass",
        "audit_id": audit_id,
        "decision_groups": group_count,
        "decisions": len(authored),
        "work_units": len(units),
        "strategy": manifest.get("strategy"),
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
    apply.add_argument("--amendment-of")
    apply.add_argument("--agent-id")
    apply.add_argument("--context-id")
    args = parser.parse_args()
    if args.command == "scaffold":
        result = scaffold_plan(args.bundle, args.output)
    else:
        result = apply_plan(
            args.bundle, args.plan,
            amendment_of=args.amendment_of,
            agent_id=args.agent_id,
            context_id=args.context_id,
        )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
