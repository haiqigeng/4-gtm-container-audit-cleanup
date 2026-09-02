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
    DECISION_CLASSES,
    OPERATION_ACTION_FIELDS,
    semantic_contract_errors,
)
from gtm_audit_work_units import (
    WORK_UNIT_MANIFEST,
    declared_work_unit_files,
    discovery_schema_errors,
    merge_work_units,
    work_unit_contract_errors,
    work_unit_identity_hash,
)
from gtm_cleanroom_audit import operation_proposal_errors
from gtm_lib import as_list, require_safe_package_root, write_json
from gtm_projection_review import REVIEW_IDS, validate_projection_review

PLAN_FIELDS = {
    "kind",
    "schema_version",
    "owner_id",
    "authoring_contract",
    "rules",
    "overrides",
    "open_discoveries",
    "global_shared_infrastructure_review",
    "global_target_architecture_review",
}
RULE_FIELDS = {"rule_id", "match", "decision"}
OVERRIDE_FIELDS = {"obligation_id", "decision"}
MATCH_FIELDS = {
    "area_id",
    "scope_level",
    "audit_mechanism",
    "fact_kind",
    "candidate_id",
    "applicability",
    "projection_delta_class",
}
PLAN_DECISION_FIELDS = {
    *CANONICAL_DECISION_FIELDS,
    "operation_proposal",
    "evidence_citations",
}
RULE_DECISION_CLASSES = {"justified_as_is", "not_applicable"}


def _authoring_contract() -> dict[str, Any]:
    return {
        "rule_decision_classes": sorted(RULE_DECISION_CLASSES),
        "candidate_obligations_require_overrides": True,
        "required_fields_by_class": {
            decision_class: [
                *BASE_REQUIRED_DECISION_FIELDS,
                *CLASS_REQUIRED_DECISION_FIELDS[decision_class],
            ]
            for decision_class in DECISION_CLASSES
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
        "schema_version": 1,
        "owner_id": owner_id,
        "authoring_contract": _authoring_contract(),
        "rules": [],
        "overrides": [],
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


def _matches(decision: dict[str, Any], match: dict[str, Any]) -> bool:
    for field, expected in match.items():
        actual = decision.get(field)
        if isinstance(expected, list):
            if actual not in expected:
                return False
        elif actual != expected:
            return False
    return True


def _plan_errors(plan: dict[str, Any], owner_id: str) -> list[str]:
    errors: list[str] = []
    if set(plan) != PLAN_FIELDS:
        errors.append("audit plan fields differ from the closed schema")
    if plan.get("kind") != "gtm_independent_semantic_plan":
        errors.append("semantic plan kind is invalid")
    if plan.get("schema_version") != 1:
        errors.append("audit plan schema_version must be 1")
    if plan.get("owner_id") != owner_id:
        errors.append("semantic plan belongs to another owner")
    if plan.get("authoring_contract") != _authoring_contract():
        errors.append("audit plan authoring_contract differs from the current contract")
    rule_ids: set[str] = set()
    for index, rule in enumerate(as_list(plan.get("rules")), start=1):
        label = f"rule {index}"
        if not isinstance(rule, dict) or set(rule) != RULE_FIELDS:
            errors.append(f"{label} fields differ from the closed schema")
            continue
        rule_id = str(rule.get("rule_id") or "")
        if not rule_id or rule_id in rule_ids:
            errors.append(f"{label} rule_id is blank or duplicated")
        rule_ids.add(rule_id)
        match = rule.get("match")
        if not isinstance(match, dict) or not match or set(match) - MATCH_FIELDS:
            errors.append(f"{label} match is empty or uses unsupported fields")
        decision = rule.get("decision")
        if not isinstance(decision, dict) or set(decision) - PLAN_DECISION_FIELDS:
            errors.append(f"{label} decision uses unsupported fields")
        elif decision.get("decision_class") not in RULE_DECISION_CLASSES:
            errors.append(
                f"{label} must use justified_as_is or not_applicable; "
                "other classes require an obligation override"
            )
    override_ids: set[str] = set()
    for index, override in enumerate(as_list(plan.get("overrides")), start=1):
        label = f"override {index}"
        if not isinstance(override, dict) or set(override) != OVERRIDE_FIELDS:
            errors.append(f"{label} fields differ from the closed schema")
            continue
        obligation_id = str(override.get("obligation_id") or "")
        if not obligation_id or obligation_id in override_ids:
            errors.append(f"{label} obligation_id is blank or duplicated")
        override_ids.add(obligation_id)
        decision = override.get("decision")
        if not isinstance(decision, dict) or set(decision) - PLAN_DECISION_FIELDS:
            errors.append(f"{label} decision uses unsupported fields")
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
    overrides = {
        str(row["obligation_id"]): row["decision"]
        for row in as_list(plan.get("overrides"))
        if isinstance(row, dict) and "obligation_id" in row and "decision" in row
    }
    unknown_overrides = sorted(set(overrides) - set(locked_by_obligation))
    if unknown_overrides:
        errors.append(
            "semantic plan overrides unknown obligations: "
            + ", ".join(unknown_overrides)
        )
    authored: dict[str, dict[str, Any]] = {}
    operation_ids: set[str] = set()
    for obligation_id, locked in locked_by_obligation.items():
        selected = overrides.get(obligation_id)
        if selected is None:
            if str(locked.get("candidate_id") or ""):
                errors.append(
                    f"{obligation_id}: generated candidate requires an exact override"
                )
                continue
            matches = [
                row
                for row in as_list(plan.get("rules"))
                if isinstance(row, dict)
                and isinstance(row.get("match"), dict)
                and _matches(locked, row["match"])
            ]
            if len(matches) != 1:
                errors.append(
                    f"{obligation_id}: expected exactly one rule, observed {len(matches)}"
                )
                continue
            selected = matches[0].get("decision")
        if not isinstance(selected, dict):
            errors.append(f"{obligation_id}: authored decision is missing")
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
    return authored, len(overrides), errors


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
    authored, override_count, authored_errors = _author_decisions(
        locked_by_obligation, plan
    )
    errors.extend(authored_errors)
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
        "rules": len(as_list(plan.get("rules"))),
        "overrides": override_count,
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
    authored, override_count, authored_errors = _author_decisions(
        locked_by_obligation, plan
    )
    errors.extend(authored_errors)
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
        "rules": len(as_list(plan.get("rules"))),
        "overrides": override_count,
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
