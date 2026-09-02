from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

import gtm_cleanroom_audit as cleanroom_audit  # noqa: E402
import gtm_delivery_reviews as delivery_reviews  # noqa: E402
import gtm_projection_review as projection_review  # noqa: E402
from gtm_audit_contract import (  # noqa: E402
    CANONICAL_DECISION_FIELDS,
    DECISION_CLASSES,
    HUMAN_DECISION_LABELS,
    OPERATION_ACTION_FIELDS,
)
from gtm_audit_package_build import build_package as executable_build_package  # noqa: E402
from gtm_audit_plan import (  # noqa: E402
    apply_plan,
    apply_projection_plan,
    scaffold_plan,
    scaffold_projection_plan,
)
from gtm_audit_work_units import merge_work_units  # noqa: E402
from gtm_canonical_record import (  # noqa: E402
    build_canonical_record,
    canonical_record_seal_errors,
)
from gtm_canonical_scan import build_canonical_scan  # noqa: E402
from gtm_cleanroom_audit import (  # noqa: E402
    checkpoint_audit,
    seal_audit,
    sealed_audit_errors,
    validate_audit,
)
from gtm_delivery_mapper import (  # noqa: E402
    create_delivery_map,
    seal_editorial,
    validate_editorial,
)
from gtm_delivery_reviews import scaffold_delivery_reviews, seal_delivery  # noqa: E402
from gtm_fixed_point import (  # noqa: E402
    advance_fixed_point,
    fixed_point_seal_errors,
    start_fixed_point,
)
from gtm_lib import file_sha256, stable_hash  # noqa: E402
from gtm_projection_review import (  # noqa: E402
    finalize_projection_reconciliation,
    scaffold_projection_reconciliation,
    seal_projection_review,
)
from gtm_reconciliation import (  # noqa: E402
    canonical_matches_allowed,
    finalize_reconciliation,
    reconciliation_seal_errors,
    scaffold_reconciliation,
)
from gtm_scan_assurance import assure_scan  # noqa: E402
from gtm_target_synthesis import compile_operation_packet  # noqa: E402


def build_package(export_path: Path, out_dir: Path, **kwargs: object) -> dict:
    scan = build_canonical_scan(
        export_path,
        context_path=kwargs.get("context_path"),
        requirements_path=kwargs.get("requirements_path"),
    )["canonical_scan"]
    assurance = assure_scan(
        export_path,
        scan,
        vendor_registry_path=ROOT / "references" / "03-rules" / "vendor-registry.toml",
        independent_agent_id="fixture-scan-assurance-agent",
        independent_context_id="fixture-scan-assurance-context",
    )
    assurance_path = out_dir.parent / f"{out_dir.name}-scan-assurance.json"
    assurance_path.write_text(json.dumps(assurance, indent=2) + "\n", encoding="utf-8")
    with mock.patch(
        "gtm_audit_package_build.declared_identity_errors",
        return_value=({}, []),
    ):
        return executable_build_package(
            export_path,
            out_dir,
            scan_assurance_path=assurance_path,
            **kwargs,
        )


def run_node_script(node: str, script: Path, package: Path) -> None:
    result = subprocess.run(
        [node, str(script), str(package)],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode:
        raise AssertionError(
            f"{script.name} failed with exit code {result.returncode}\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )


def create_directory_redirect(link: Path, target: Path) -> None:
    if os.name == "nt":
        result = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(link), str(target)],
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode:
            raise AssertionError(result.stderr or result.stdout)
    else:
        link.symlink_to(target, target_is_directory=True)


def remove_directory_redirect(link: Path) -> None:
    if os.name == "nt":
        link.rmdir()
    else:
        link.unlink()


def minimal_export() -> dict:
    return {
        "exportFormatVersion": 2,
        "exportTime": "2026-08-31 10:00:00",
        "containerVersion": {
            "path": "accounts/1/containers/2/versions/3",
            "accountId": "1",
            "containerId": "2",
            "containerVersionId": "3",
            "container": {
                "accountId": "1",
                "containerId": "2",
                "name": "Empty quality fixture",
                "publicId": "GTM-WORKFLOW-TEST",
                "usageContext": ["WEB"],
            },
            "tag": [],
            "trigger": [],
            "variable": [],
            "folder": [],
            "builtInVariable": [],
            "customTemplate": [],
            "zone": [],
            "gtagConfig": [],
        },
    }


def actionable_priority_export() -> dict:
    payload = minimal_export()
    version = payload["containerVersion"]
    version["container"]["name"] = "Actionable priority fixture"
    version["tag"] = [
        {
            "tagId": "1",
            "name": "GA4 - purchase",
            "type": "gaawe",
            "parameter": [
                {"type": "template", "key": "eventName", "value": "purchase"},
            ],
            "firingTriggerId": ["10"],
            "tagFiringPriority": "10",
        }
    ]
    version["trigger"] = [
        {
            "triggerId": "10",
            "name": "CE - purchase",
            "type": "CUSTOM_EVENT",
            "customEventFilter": [
                {
                    "type": "EQUALS",
                    "parameter": [
                        {"type": "TEMPLATE", "key": "arg0", "value": "{{_event}}"},
                        {"type": "TEMPLATE", "key": "arg1", "value": "purchase"},
                    ],
                }
            ],
        }
    ]
    return payload


def complete_semantic_decision(row: dict) -> None:
    not_applicable = row.get("applicability") == "source_counted_zero"
    row.update(
        {
            "status": "complete",
            "decision_class": "not_applicable" if not_applicable else "justified_as_is",
            "current_behavior": (
                "The export contains no configured source object for this audited coverage area."
                if not_applicable
                else "The source-visible objects assigned to this obligation retain their recorded configuration and relationships."
            ),
            "criteria_assessment": (
                "Source-counted coverage is zero, so this area does not apply to the fixture."
                if not_applicable
                else "No additional material defect or optimisation is asserted for this obligation beyond any separately identified candidate."
            ),
            "consequence_or_benefit": (
                "No configuration risk or optimisation benefit exists for an absent source surface."
                if not_applicable
                else "Retaining this bounded configuration preserves the source-supported chain without inventing an unproven change."
            ),
            "preserved_distinctions": (
                "The source-visible configuration and its distinct object relationships remain explicit."
            ),
            "target_direction": (
                "Retain the source-supported configuration for this obligation."
            ),
            "evidence_boundary": "",
            "owner_question": "",
            "next_step": "Retain this state and record the completed static audit conclusion.",
            "priority": "None",
            "confidence": "High",
            "static_verification": (
                "Confirm this projected source surface matches the locked configuration except for separately approved operations."
            ),
            "rollback": "No operation is proposed, so no rollback action is required.",
            "operation_proposal": {},
            "evidence_citations": list(row.get("source_coordinates") or []),
        }
    )


def fixture_plan_decision(applicability: str) -> dict:
    row = {
        "applicability": applicability,
        "source_coordinates": [],
    }
    complete_semantic_decision(row)
    return {
        field: row[field] for field in CANONICAL_DECISION_FIELDS
    } | {"operation_proposal": {}}


def write_fixture_audit_plan(package: Path, audit_id: str) -> Path:
    bundle = package / "audit-bundles" / audit_id
    plan_path = package / "audit-scratch" / audit_id / "audit-plan.json"
    scaffold_plan(bundle, plan_path)
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    audit = json.loads((bundle / "audit.json").read_text(encoding="utf-8"))
    applicability_values = sorted(
        {str(row["applicability"]) for row in audit["decisions"]}
    )
    plan["rules"] = [
        {
            "rule_id": f"fixture-{index:02d}",
            "match": {"applicability": applicability},
            "decision": fixture_plan_decision(applicability),
        }
        for index, applicability in enumerate(applicability_values, start=1)
    ]
    plan["overrides"] = [
        {
            "obligation_id": row["obligation_id"],
            "decision": fixture_plan_decision(str(row["applicability"])),
        }
        for row in audit["decisions"]
        if str(row.get("candidate_id") or "")
    ]
    plan["global_shared_infrastructure_review"] = (
        "The complete fixture has no shared infrastructure object and no unresolved shared ownership."
    )
    plan["global_target_architecture_review"] = (
        "The complete fixture target remains empty because no proven implementation need exists."
    )
    plan_path.write_text(json.dumps(plan, indent=2) + "\n", encoding="utf-8")
    return plan_path


def write_fixture_projection_plan(
    package: Path, cycle_number: int, review_id: str
) -> Path:
    plan_path = (
        package
        / "projection-scratch"
        / f"cycle-{cycle_number:02d}"
        / review_id
        / "review-plan.json"
    )
    scaffold_projection_plan(package, cycle_number, review_id, plan_path)
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    review_path = (
        package
        / "fixed-point"
        / f"cycle-{cycle_number:02d}"
        / "reviews"
        / review_id
        / "review.json"
    )
    review = json.loads(review_path.read_text(encoding="utf-8"))
    applicability_values = sorted(
        {str(row["applicability"]) for row in review["decisions"]}
    )
    plan["rules"] = [
        {
            "rule_id": f"projection-fixture-{index:02d}",
            "match": {"applicability": applicability},
            "decision": fixture_plan_decision(applicability),
        }
        for index, applicability in enumerate(applicability_values, start=1)
    ]
    plan["overrides"] = [
        {
            "obligation_id": row["obligation_id"],
            "decision": fixture_plan_decision(str(row["applicability"])),
        }
        for row in review["decisions"]
        if str(row.get("candidate_id") or "")
    ]
    plan_path.write_text(json.dumps(plan, indent=2) + "\n", encoding="utf-8")
    return plan_path


def complete_checkpoint(
    package: Path,
    audit_id: str,
    context_id: str,
    agent_id: str | None = None,
) -> None:
    path = package / "audit-bundles" / audit_id / "source-checkpoint.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    bundle_manifest = json.loads((path.parent / "bundle-manifest.json").read_text(encoding="utf-8"))
    payload["status"] = "complete"
    payload["independent_agent_id"] = agent_id or f"fixture-{audit_id}-agent"
    payload["independent_context_id"] = context_id
    payload["input_manifest_sha256"] = bundle_manifest["bundle_manifest_sha256"]
    payload["reviewed_inventory_sha256"] = payload["inventory_sha256"]
    payload["source_only_conclusion"] = (
        "The source-only fixture review allocated every object and found no hidden input dependency."
    )
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    checkpoint_audit(package, audit_id)


def complete_priority_removal_decision(row: dict) -> None:
    row.update(
        {
            "status": "complete",
            "decision_class": "correct_but_materially_non_optimal",
            "current_behavior": (
                "The purchase tag carries an explicit firing priority of 10 on its "
                "custom-event route."
            ),
            "criteria_assessment": (
                "No source-visible sequencing dependency or same-trigger ordering need "
                "justifies this explicit priority."
            ),
            "consequence_or_benefit": (
                "Removing the redundant setting makes the tag intent clearer and avoids "
                "implying an ordering contract that the container does not use."
            ),
            "preserved_distinctions": (
                "The purchase event, tag identity, positive trigger, and all configured "
                "parameters remain unchanged."
            ),
            "target_direction": (
                "Remove only tagFiringPriority from tag:1 and retain the complete event chain."
            ),
            "evidence_boundary": "",
            "owner_question": "",
            "next_step": (
                "Review and approve the exact redundant-priority removal before a separate "
                "implementation task."
            ),
            "priority": "Low",
            "confidence": "High",
            "static_verification": (
                "Confirm tag:1 no longer contains tagFiringPriority and every other tag field "
                "matches the locked source."
            ),
            "rollback": ("Restore tagFiringPriority with the original string value 10 on tag:1."),
            "operation_proposal": {
                "operation_id": "OP-REMOVE-REDUNDANT-PRIORITY",
                "source_decision_id": row["decision_id"],
                "operation_family": "Remove redundant firing priority",
                "exact_target_state": (
                    "Tag tag:1 retains its complete configuration without the named "
                    "tagFiringPriority property."
                ),
                "preconditions": (
                    "Tag tag:1 still contains tagFiringPriority with the exact string value 10."
                ),
                "static_verification": (
                    "Compare tag:1 and confirm only tagFiringPriority was removed."
                ),
                "rollback": ("Restore tagFiringPriority with the original string value 10."),
                "depends_on": [],
                **{field: [] for field in OPERATION_ACTION_FIELDS},
                "removals": [
                    {
                        "object_key": "tag:1",
                        "json_path": "$.tagFiringPriority",
                        "before": "10",
                    }
                ],
            },
            "evidence_citations": list(row.get("source_coordinates") or []),
        }
    )


def finalize_audit(
    package: Path,
    audit_id: str,
    *,
    actionable_priority: bool = False,
) -> None:
    path = package / "audit-bundles" / audit_id / "audit.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    for row in payload["decisions"]:
        complete_semantic_decision(row)
        if actionable_priority and row.get("fact_kind") == "explicit_firing_priority":
            complete_priority_removal_decision(row)
    payload["status"] = "complete"
    closure = payload["coverage_closure"]
    closure["reviewed_obligation_ids"] = [row["obligation_id"] for row in payload["decisions"]]
    closure["reviewed_object_keys"] = sorted(
        {key for row in payload["decisions"] for key in row.get("subject_keys", [])}
    )
    closure["reviewed_family_ids"] = sorted(
        {family for row in payload["decisions"] for family in row.get("family_ids", [])}
    )
    closure["reviewed_relationship_candidate_ids"] = sorted(
        {row["candidate_id"] for row in payload["decisions"] if row.get("candidate_id")}
    )
    closure["global_shared_infrastructure_review"] = (
        "The complete fixture has no shared infrastructure object and no unresolved shared ownership."
    )
    closure["global_target_architecture_review"] = (
        "The complete fixture target remains empty because no proven implementation need exists."
    )
    payload["completion_attestation"] = {
        "status": "complete",
        "foreign_audit_artifacts_used": [],
        "test_or_bulk_semantic_helpers_used": [],
        "decision_authoring_method": "independent_test_fixture_review",
        "peer_findings_received_before_completion": False,
    }
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def complete_audit(package: Path, audit_id: str, *, actionable_priority: bool = False) -> None:
    finalize_audit(
        package,
        audit_id,
        actionable_priority=actionable_priority,
    )
    seal_audit(package, audit_id)


def complete_sharded_work_units(package: Path, audit_id: str) -> None:
    bundle = package / "audit-bundles" / audit_id
    work_units = bundle / "work-units"
    manifest = json.loads(
        (work_units / "work-unit-manifest.json").read_text(encoding="utf-8")
    )
    if manifest.get("strategy") != "family_sharded":
        raise AssertionError("fixture did not produce family-sharded work units")
    for record in manifest["work_units"]:
        unit_path = work_units / record["filename"]
        unit = json.loads(unit_path.read_text(encoding="utf-8"))
        for decision in unit["decisions"]:
            complete_semantic_decision(decision)
        unit["unit_closure"] = (
            "Every declared obligation in this complete family unit received an "
            "independent fixture decision before the deterministic merge."
        )
        unit_path.write_text(
            json.dumps(unit, indent=2) + "\n", encoding="utf-8"
        )
    merge_work_units(bundle)


def forge_post_merge_audit_only_drift(package: Path, audit_id: str) -> None:
    path = package / "audit-bundles" / audit_id / "audit.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["decisions"][0]["current_behavior"] += (
        " Forged directly in the merged audit without changing its work unit."
    )
    completion = payload["work_unit_completion"]
    completion["merged_decisions_sha256"] = stable_hash(
        payload["decisions"], 64
    )
    completion["work_unit_completion_sha256"] = stable_hash(
        {
            key: value
            for key, value in completion.items()
            if key != "work_unit_completion_sha256"
        },
        64,
    )
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def write_audit_amendment(
    package: Path,
    audit_id: str,
    *,
    parent_seal_sha256: str,
    context_id: str,
    agent_id: str,
) -> None:
    path = package / "audit-bundles" / audit_id / "audit.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    manifest = json.loads(
        (path.parent / "bundle-manifest.json").read_text(encoding="utf-8")
    )
    payload["independent_agent_id"] = agent_id
    payload["independent_context_id"] = context_id
    payload["input_manifest_sha256"] = manifest["bundle_manifest_sha256"]
    payload["amendment_parent_seal_sha256"] = parent_seal_sha256
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def complete_base_reconciliation(
    package: Path,
    *,
    agent_id: str = "fixture-reconciliation-agent",
    context_id: str = "fixture-reconciliation-context",
) -> None:
    scaffold_reconciliation(package)
    reconciliation_path = package / "reconciliation.json"
    neutral_path = package / "neutral-verification.json"
    reconciliation = json.loads(reconciliation_path.read_text(encoding="utf-8"))
    neutral = json.loads(neutral_path.read_text(encoding="utf-8"))
    reconciliation["independent_agent_id"] = agent_id
    reconciliation["independent_context_id"] = context_id
    neutral_by_id = {}
    for row in neutral["verifications"]:
        comparison = next(
            item
            for item in reconciliation["comparisons"]
            if item["neutral_verification_id"] == row["verification_id"]
        )
        decision = copy.deepcopy(comparison["audit_decisions"]["audit-a"])
        row.update(
            {
                "status": "complete",
                "canonical_decision": decision,
                "evidence_citations": list(row.get("source_coordinates") or []),
                "verification_rationale": (
                    "The supplied source evidence shows the same bounded fixture conclusion without runtime claims."
                ),
            }
        )
        neutral_by_id[row["verification_id"]] = decision
    neutral["status"] = "complete" if neutral["verifications"] else "not_required"
    for row in reconciliation["comparisons"]:
        canonical = (
            neutral_by_id[row["neutral_verification_id"]]
            if row["neutral_verification_required"]
            else copy.deepcopy(row["audit_decisions"]["audit-a"])
        )
        row.update(
            {
                "status": "complete",
                "canonical_decision": canonical,
                "reconciliation_rationale": (
                    "Both source audits support the same evidence-bound fixture decision and unchanged target."
                ),
            }
        )
    reconciliation["status"] = "complete"
    neutral_path.write_text(json.dumps(neutral, indent=2) + "\n", encoding="utf-8")
    reconciliation_path.write_text(json.dumps(reconciliation, indent=2) + "\n", encoding="utf-8")
    finalize_reconciliation(package)


def complete_projection_cycle(
    package: Path,
    cycle: int,
    *,
    force_neutral: bool = False,
    review_agent_override: str | None = None,
    review_context_override: str | None = None,
    review_input_manifest_override: str | None = None,
    reconciliation_agent_override: str | None = None,
    reconciliation_context_override: str | None = None,
) -> None:
    cycle_dir = package / "fixed-point" / f"cycle-{cycle:02d}"
    for review_id, context_id in (
        ("review-a", f"projection-a-context-{cycle:02d}"),
        ("review-b", f"projection-b-context-{cycle:02d}"),
    ):
        path = cycle_dir / "reviews" / review_id / "review.json"
        payload = json.loads(path.read_text(encoding="utf-8"))
        manifest = json.loads((path.parent / "bundle-manifest.json").read_text(encoding="utf-8"))
        payload["status"] = "complete"
        payload["independent_agent_id"] = (
            review_agent_override
            if review_id == "review-a" and review_agent_override
            else f"fixture-projection-{review_id}-agent-{cycle:02d}"
        )
        payload["independent_context_id"] = (
            review_context_override
            if review_id == "review-a" and review_context_override
            else context_id
        )
        payload["input_manifest_sha256"] = (
            review_input_manifest_override
            if review_id == "review-a" and review_input_manifest_override
            else manifest["bundle_manifest_sha256"]
        )
        neutral_forced = False
        for row in payload["decisions"]:
            complete_semantic_decision(row)
            if (
                force_neutral
                and not neutral_forced
                and row.get("decision_class") != "not_applicable"
            ):
                row["priority"] = "High"
                neutral_forced = True
        payload["completion_attestation"] = {
            "status": "complete",
            "foreign_projection_review_used": False,
            "fresh_context": True,
            "peer_findings_received_before_completion": False,
            "conclusion": "The focused projection fixture review completed every changed obligation independently.",
        }
        path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        seal_projection_review(package, cycle, review_id)
    scaffold_projection_reconciliation(cycle_dir)
    rec_path = cycle_dir / "projection-reconciliation.json"
    neutral_path = cycle_dir / "projection-neutral-verification.json"
    reconciliation = json.loads(rec_path.read_text(encoding="utf-8"))
    neutral = json.loads(neutral_path.read_text(encoding="utf-8"))
    reconciliation["independent_agent_id"] = (
        reconciliation_agent_override
        or f"fixture-projection-reconciliation-agent-{cycle:02d}"
    )
    reconciliation["independent_context_id"] = (
        reconciliation_context_override
        or f"fixture-projection-reconciliation-context-{cycle:02d}"
    )
    neutral_by_id = {}
    for row in neutral["verifications"]:
        comparison = next(
            item
            for item in reconciliation["comparisons"]
            if item["neutral_verification_id"] == row["verification_id"]
        )
        decision = copy.deepcopy(comparison["review_decisions"]["review-a"])
        row.update(
            {
                "status": "complete",
                "canonical_decision": decision,
                "evidence_citations": list(row.get("source_coordinates") or []),
                "verification_rationale": (
                    "Projected source evidence supports the same bounded fixture conclusion without a new target."
                ),
            }
        )
        neutral_by_id[row["verification_id"]] = decision
    neutral["status"] = "complete" if neutral["verifications"] else "not_required"
    for row in reconciliation["comparisons"]:
        row.update(
            {
                "status": "complete",
                "canonical_decision": copy.deepcopy(
                    neutral_by_id.get(row["neutral_verification_id"])
                    or row["review_decisions"]["review-a"]
                ),
                "reconciliation_rationale": (
                    "Both projected reviews support the same source-bound fixture decision and target."
                ),
            }
        )
    rec_path.write_text(json.dumps(reconciliation, indent=2) + "\n", encoding="utf-8")
    neutral_path.write_text(json.dumps(neutral, indent=2) + "\n", encoding="utf-8")
    finalize_projection_reconciliation(cycle_dir)


def complete_editorial(package: Path) -> None:
    path = package / "delivery" / "editorial.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["status"] = "complete"
    payload["completion_attestation"] = {
        "semantic_fields_changed": False,
        "technical_identifiers_preserved": True,
        "conclusion": "The human wording remains faithful, standalone, bounded, and suitable for analyst review.",
    }
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    seal_editorial(package)


def complete_delivery_reviews(package: Path) -> None:
    current = json.loads((package / "delivery" / "current-build.json").read_text(encoding="utf-8"))
    root = package / "delivery" / current["build_path"] / "reviews"
    fidelity_path = root / "fidelity" / "fidelity-review.json"
    fidelity = json.loads(fidelity_path.read_text(encoding="utf-8"))
    fidelity_manifest = json.loads(
        (fidelity_path.parent / "bundle-manifest.json").read_text(encoding="utf-8")
    )
    fidelity["status"] = "complete"
    fidelity["independent_agent_id"] = "fixture-fidelity-agent-001"
    fidelity["independent_context_id"] = "fixture-fidelity-context-001"
    fidelity["input_manifest_sha256"] = fidelity_manifest["bundle_manifest_sha256"]
    fidelity["overview_review"] = {
        "verdict": "pass",
        "meaning_preserved": True,
        "evidence_limits_preserved": True,
        "next_action_preserved": True,
        "issues": [],
    }
    for row in fidelity["row_reviews"]:
        row.update(
            {
                "verdict": "pass",
                "meaning_preserved": True,
                "caveats_preserved": True,
                "action_matches": True,
                "identifiers_preserved": True,
                "issues": [],
            }
        )
    fidelity["completion_attestation"] = (
        "Every visible fixture row preserves its bound decision, caveats, identifiers, and action."
    )
    fidelity_path.write_text(json.dumps(fidelity, indent=2) + "\n", encoding="utf-8")
    reader_path = root / "reader" / "reader-review.json"
    reader = json.loads(reader_path.read_text(encoding="utf-8"))
    reader_manifest = json.loads(
        (reader_path.parent / "bundle-manifest.json").read_text(encoding="utf-8")
    )
    reader["status"] = "complete"
    reader["independent_agent_id"] = "fixture-reader-agent-001"
    reader["independent_context_id"] = "fixture-reader-context-001"
    reader["input_manifest_sha256"] = reader_manifest["bundle_manifest_sha256"]
    reader["received_only_workbook_audience_brief_and_previews"] = True
    for row in reader["sheet_reviews"]:
        row.update(
            {
                "verdict": "pass",
                "standalone_and_clear": True,
                "next_action_clear": True,
                "wording_human_readable": True,
                "layout_legible": True,
                "navigation_usable": True,
                "issues": [],
            }
        )
    reader["completion_attestation"] = (
        "The fixture workbook is standalone, readable, navigable, and clear about its next action."
    )
    reader_path.write_text(json.dumps(reader, indent=2) + "\n", encoding="utf-8")


class V2WorkflowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.export = self.root / "container.json"
        self.export.write_text(json.dumps(minimal_export()), encoding="utf-8")
        self.package = self.root / "audit-package"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_audit_plan_applies_and_seals_single_file_audit(self) -> None:
        build_package(self.export, self.package)
        complete_checkpoint(self.package, "audit-a", "plan-single-context")
        plan_path = write_fixture_audit_plan(self.package, "audit-a")

        result = apply_plan(
            self.package / "audit-bundles" / "audit-a",
            plan_path,
        )

        self.assertEqual("single_file", result["strategy"])
        self.assertGreater(result["decisions"], 0)
        self.assertEqual([], validate_audit(self.package, "audit-a"))
        seal_audit(self.package, "audit-a")

    def test_audit_plan_applies_and_merges_sharded_audit(self) -> None:
        build_package(self.export, self.package)
        with mock.patch("gtm_audit_work_units.MAX_SINGLE_OBLIGATIONS", 1):
            complete_checkpoint(self.package, "audit-a", "plan-sharded-context")
            plan_path = write_fixture_audit_plan(self.package, "audit-a")
            result = apply_plan(
                self.package / "audit-bundles" / "audit-a",
                plan_path,
            )
            self.assertEqual("family_sharded", result["strategy"])
            self.assertGreater(result["work_units"], 0)
            self.assertEqual([], validate_audit(self.package, "audit-a"))
            seal_audit(self.package, "audit-a")

    def test_audit_plan_rejects_a_path_outside_its_audit_scratch(self) -> None:
        build_package(self.export, self.package)
        complete_checkpoint(self.package, "audit-a", "plan-path-context")
        with self.assertRaisesRegex(ValueError, "isolated path"):
            scaffold_plan(
                self.package / "audit-bundles" / "audit-a",
                self.root / "guessed-plan.json",
            )

    def test_audit_plan_applies_an_exact_actionable_override(self) -> None:
        self.export.write_text(
            json.dumps(actionable_priority_export()), encoding="utf-8"
        )
        build_package(self.export, self.package)
        complete_checkpoint(self.package, "audit-a", "plan-actionable-context")
        plan_path = write_fixture_audit_plan(self.package, "audit-a")
        plan = json.loads(plan_path.read_text(encoding="utf-8"))
        audit_path = self.package / "audit-bundles" / "audit-a" / "audit.json"
        audit = json.loads(audit_path.read_text(encoding="utf-8"))
        priority = next(
            row for row in audit["decisions"]
            if row.get("fact_kind") == "explicit_firing_priority"
        )
        authored = copy.deepcopy(priority)
        complete_semantic_decision(authored)
        complete_priority_removal_decision(authored)
        priority_override = next(
            row for row in plan["overrides"]
            if row["obligation_id"] == priority["obligation_id"]
        )
        priority_override["decision"] = {
            field: authored[field] for field in CANONICAL_DECISION_FIELDS
        } | {"operation_proposal": authored["operation_proposal"]}
        plan_path.write_text(json.dumps(plan, indent=2) + "\n", encoding="utf-8")

        apply_plan(audit_path.parent, plan_path)

        completed = json.loads(audit_path.read_text(encoding="utf-8"))
        result = next(
            row for row in completed["decisions"]
            if row["obligation_id"] == priority["obligation_id"]
        )
        self.assertEqual(
            result["decision_id"],
            result["operation_proposal"]["source_decision_id"],
        )
        self.assertEqual("correct_but_materially_non_optimal", result["decision_class"])
        self.assertEqual([], validate_audit(self.package, "audit-a"))

    def test_audit_plan_rejects_ambiguous_rules_before_writing(self) -> None:
        build_package(self.export, self.package)
        complete_checkpoint(self.package, "audit-a", "plan-ambiguous-context")
        plan_path = write_fixture_audit_plan(self.package, "audit-a")
        plan = json.loads(plan_path.read_text(encoding="utf-8"))
        plan["rules"].append(copy.deepcopy(plan["rules"][0]))
        plan["rules"][-1]["rule_id"] = "fixture-overlap"
        plan_path.write_text(json.dumps(plan, indent=2) + "\n", encoding="utf-8")
        audit_path = self.package / "audit-bundles" / "audit-a" / "audit.json"
        before = audit_path.read_bytes()

        with self.assertRaisesRegex(ValueError, "expected exactly one rule"):
            apply_plan(audit_path.parent, plan_path)

        self.assertEqual(before, audit_path.read_bytes())

    def test_audit_plan_requires_candidate_and_owner_specific_overrides(self) -> None:
        self.export.write_text(
            json.dumps(actionable_priority_export()), encoding="utf-8"
        )
        build_package(self.export, self.package)
        complete_checkpoint(self.package, "audit-a", "plan-specific-context")
        plan_path = write_fixture_audit_plan(self.package, "audit-a")
        audit_bundle = self.package / "audit-bundles" / "audit-a"
        plan = json.loads(plan_path.read_text(encoding="utf-8"))
        plan["overrides"] = []
        plan_path.write_text(json.dumps(plan, indent=2) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "candidate requires an exact override"):
            apply_plan(audit_bundle, plan_path)

        plan["rules"][0]["decision"]["decision_class"] = "owner_decision"
        plan_path.write_text(json.dumps(plan, indent=2) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "require an obligation override"):
            apply_plan(audit_bundle, plan_path)

    def test_audit_plan_rejects_changed_authoring_contract(self) -> None:
        build_package(self.export, self.package)
        complete_checkpoint(self.package, "audit-a", "plan-contract-context")
        plan_path = write_fixture_audit_plan(self.package, "audit-a")
        plan = json.loads(plan_path.read_text(encoding="utf-8"))
        plan["authoring_contract"]["candidate_obligations_require_overrides"] = False
        plan_path.write_text(json.dumps(plan, indent=2) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "authoring_contract differs"):
            apply_plan(self.package / "audit-bundles" / "audit-a", plan_path)

    def test_delivery_review_file_hash_inventory_is_exact(self) -> None:
        review_root = self.root / "review-files"
        review_root.mkdir()
        (review_root / "evidence.json").write_text("{}\n", encoding="utf-8")
        self.assertEqual(
            {"evidence.json": file_sha256(review_root / "evidence.json")},
            delivery_reviews._relative_file_hashes(review_root),
        )
        self.assertEqual(
            {},
            delivery_reviews._relative_file_hashes(self.root / "missing-review"),
        )

    def test_package_requires_separately_produced_scan_assurance(self) -> None:
        with mock.patch(
            "gtm_audit_package_build.declared_identity_errors",
            return_value=({}, []),
        ), self.assertRaisesRegex(RuntimeError, "separately produced scan-assurance"):
            executable_build_package(self.export, self.root / "missing-assurance")

    def test_package_reconstructs_separate_scan_assurance_before_use(self) -> None:
        scan = build_canonical_scan(self.export)["canonical_scan"]
        assurance = assure_scan(
            self.export,
            scan,
            vendor_registry_path=ROOT
            / "references"
            / "03-rules"
            / "vendor-registry.toml",
            independent_agent_id="fresh-scan-agent",
            independent_context_id="fresh-scan-context",
        )
        assurance["checks"][0]["detail"] = "forged after independent review"
        assurance_path = self.root / "forged-scan-assurance.json"
        assurance_path.write_text(
            json.dumps(assurance, indent=2) + "\n", encoding="utf-8"
        )
        with mock.patch(
            "gtm_audit_package_build.declared_identity_errors",
            return_value=({}, []),
        ), self.assertRaisesRegex(
            RuntimeError, "differs from independent raw-source reconstruction"
        ):
            executable_build_package(
                self.export,
                self.root / "forged-assurance-package",
                scan_assurance_path=assurance_path,
            )

    def test_audit_independence_contract_is_portable_and_peer_blind(self) -> None:
        build_package(self.export, self.package)
        assurance = json.loads(
            (self.package / "scan-assurance.json").read_text(encoding="utf-8")
        )
        self.assertEqual(
            "fixture-scan-assurance-agent", assurance["independent_agent_id"]
        )
        self.assertEqual(
            "fixture-scan-assurance-context", assurance["independent_context_id"]
        )
        self.assertRegex(assurance["input_manifest_sha256"], r"^[0-9a-f]{64}$")
        for audit_id in ("audit-a", "audit-b"):
            manifest = json.loads(
                (
                    self.package
                    / "audit-bundles"
                    / audit_id
                    / cleanroom_audit.BUNDLE_MANIFEST_FILE
                ).read_text(encoding="utf-8")
            )
            contract = manifest["independence_contract"]
            self.assertTrue(contract["required"])
            self.assertIn("version-locked shared skill rules", contract["scope"])
            self.assertIn("fresh agent and fresh context", contract["boundary"])
            self.assertIn("No host or filesystem isolation", contract["boundary"])
            self.assertIn("the other audit bundle or output", manifest["prohibited_inputs"])
            self.assertIn("reconciliation output", manifest["prohibited_inputs"])
            serialized = json.dumps(manifest).lower()
            for forbidden in ("receipt_id", "acl", "sandbox", "host-enforced"):
                self.assertNotIn(forbidden, serialized)

    def test_protected_tree_enumeration_never_crosses_redirects(self) -> None:
        tree = self.root / "protected-tree"
        nested = tree / "nested"
        nested.mkdir(parents=True)
        expected_file = nested / "evidence.json"
        expected_file.write_text("{}\n", encoding="utf-8")
        files, errors = cleanroom_audit._regular_tree_files(tree)
        self.assertEqual([expected_file], files)
        self.assertEqual([], errors)

        external = self.root / "external-tree"
        external.mkdir()
        redirect = tree / "redirect"
        create_directory_redirect(redirect, external)
        try:
            files, errors = cleanroom_audit._regular_tree_files(tree)
            self.assertEqual([expected_file], files)
            self.assertTrue(any("link or reparse point" in error for error in errors))
            self.assertTrue(
                cleanroom_audit._contained_child_errors(
                    redirect, tree, "redirected child"
                )
            )
        finally:
            remove_directory_redirect(redirect)

        with mock.patch.object(Path, "iterdir", side_effect=OSError("denied")):
            _files, errors = cleanroom_audit._regular_tree_files(tree)
        self.assertTrue(any("cannot enumerate protected tree" in error for error in errors))

    def test_rehashed_locked_input_paths_cannot_escape_review_bundles(self) -> None:
        outside = self.root / "outside-locked-input.json"
        outside.write_text('{"outside": true}\n', encoding="utf-8")
        outside_before = outside.read_bytes()

        audit_bundle = self.root / "audit-bundle"
        audit_bundle.mkdir()
        audit_manifest = {
            "allowed_files": [
                {
                    "path": "../outside-locked-input.json",
                    "sha256": file_sha256(outside),
                    "mutable": False,
                }
            ]
        }
        audit_manifest["bundle_manifest_sha256"] = stable_hash(
            audit_manifest, 64
        )
        (audit_bundle / cleanroom_audit.BUNDLE_MANIFEST_FILE).write_text(
            json.dumps(audit_manifest, indent=2) + "\n",
            encoding="utf-8",
        )
        _manifest, errors = cleanroom_audit._bundle_manifest_errors(audit_bundle)
        self.assertTrue(any("remain inside" in error for error in errors), errors)

        projection_bundle = self.root / "projection-bundle"
        projection_bundle.mkdir()
        projection_manifest = {
            "locked_files": [
                {
                    "path": "../outside-locked-input.json",
                    "sha256": file_sha256(outside),
                }
            ]
        }
        projection_manifest["bundle_manifest_sha256"] = stable_hash(
            projection_manifest, 64
        )
        (projection_bundle / projection_review.REVIEW_MANIFEST_FILE).write_text(
            json.dumps(projection_manifest, indent=2) + "\n",
            encoding="utf-8",
        )
        errors = projection_review._manifest_errors(projection_bundle)
        self.assertTrue(any("remain inside" in error for error in errors), errors)
        self.assertEqual(outside_before, outside.read_bytes())

    def test_rehashed_coverage_release_paths_cannot_escape_audit_bundle(self) -> None:
        build_package(self.export, self.package)
        complete_checkpoint(
            self.package,
            "audit-a",
            "release-path-boundary-context-001",
        )
        outside = self.root / "outside-release-input.json"
        outside.write_text('{"outside": true}\n', encoding="utf-8")
        outside_before = outside.read_bytes()
        release_path = (
            self.package
            / "audit-bundles"
            / "audit-a"
            / cleanroom_audit.RELEASE_MANIFEST_FILE
        )
        release = json.loads(release_path.read_text(encoding="utf-8"))
        release["released_files"][0]["path"] = "../../../outside-release-input.json"
        release["released_files"][0]["sha256"] = file_sha256(outside)
        release["work_units"]["manifest"] = "../outside-release-input.json"
        release["release_manifest_sha256"] = stable_hash(
            {
                key: value
                for key, value in release.items()
                if key != "release_manifest_sha256"
            },
            64,
        )
        release_path.write_text(
            json.dumps(release, indent=2) + "\n",
            encoding="utf-8",
        )
        errors = validate_audit(self.package, "audit-a")
        self.assertTrue(
            any("released audit input path" in error for error in errors),
            errors,
        )
        self.assertTrue(
            any("released work-unit manifest path" in error for error in errors),
            errors,
        )
        self.assertEqual(outside_before, outside.read_bytes())

    def test_package_root_redirect_is_rejected_before_any_write(self) -> None:
        empty_target = self.root / "external-empty-package-target"
        empty_target.mkdir()
        redirected_package = self.root / "redirected-audit-package"
        create_directory_redirect(redirected_package, empty_target)
        try:
            with self.assertRaisesRegex(RuntimeError, "package root"):
                build_package(self.export, redirected_package)
            self.assertEqual([], list(empty_target.iterdir()))
        finally:
            remove_directory_redirect(redirected_package)
            empty_target.rmdir()

        guarded_package = self.root / "guarded-audit-package"
        build_package(self.export, guarded_package)
        external_package = self.root / "external-built-package-target"
        guarded_package.replace(external_package)
        before = {
            path.relative_to(external_package).as_posix(): path.read_bytes()
            for path in external_package.rglob("*")
            if path.is_file()
        }
        create_directory_redirect(guarded_package, external_package)
        try:
            with self.assertRaisesRegex(ValueError, "package root"):
                checkpoint_audit(guarded_package, "audit-a")
            with self.assertRaisesRegex(ValueError, "package root"):
                seal_audit(guarded_package, "audit-a")
            for guarded_call in (
                lambda: scaffold_reconciliation(guarded_package),
                lambda: compile_operation_packet(guarded_package),
                lambda: start_fixed_point(guarded_package),
                lambda: build_canonical_record(guarded_package),
                lambda: create_delivery_map(guarded_package),
                lambda: scaffold_delivery_reviews(guarded_package),
                lambda: merge_work_units(
                    guarded_package / "audit-bundles" / "audit-a"
                ),
            ):
                with self.assertRaisesRegex(ValueError, "package root"):
                    guarded_call()
            self.assertTrue(
                any(
                    "package root" in error
                    for error in validate_audit(guarded_package, "audit-a")
                )
            )
            self.assertTrue(
                any(
                    "package root" in error
                    for error in sealed_audit_errors(guarded_package)
                )
            )
            if os.environ.get("CODEX_NODE") and os.environ.get(
                "CODEX_ARTIFACT_NODE_MODULES"
            ):
                for workbook_script in (
                    "gtm_workbook_build.mjs",
                    "gtm_workbook_verify.mjs",
                ):
                    result = subprocess.run(
                        [
                            os.environ["CODEX_NODE"],
                            str(SCRIPTS / workbook_script),
                            str(guarded_package),
                        ],
                        cwd=ROOT,
                        check=False,
                        capture_output=True,
                        text=True,
                    )
                    self.assertNotEqual(0, result.returncode)
                    self.assertIn(
                        "link or reparse point", result.stdout + result.stderr
                    )
            self.assertEqual(
                before,
                {
                    path.relative_to(external_package).as_posix(): path.read_bytes()
                    for path in external_package.rglob("*")
                    if path.is_file()
                },
            )
        finally:
            remove_directory_redirect(guarded_package)
            external_package.replace(guarded_package)

    def test_material_optimisation_class_is_canonical_across_delivery(self) -> None:
        decision_class = "correct_but_materially_non_optimal"
        self.assertIn(decision_class, DECISION_CLASSES)
        self.assertEqual("Optimisation", HUMAN_DECISION_LABELS[decision_class])
        self.assertNotIn("correct_but_non_optimal", DECISION_CLASSES)

    def test_reconciliation_cannot_invent_semantic_delivery_fields(self) -> None:
        source = {}
        complete_semantic_decision(source)
        invented = copy.deepcopy(source)
        invented["current_behavior"] = "Invented current behavior not authored by an audit."
        invented["target_direction"] = "Delete everything without source support."
        self.assertTrue(canonical_matches_allowed(copy.deepcopy(source), [source]))
        self.assertFalse(canonical_matches_allowed(invented, [source]))

    def run_to_editorial(self) -> None:
        build_package(self.export, self.package)
        complete_checkpoint(self.package, "audit-a", "fixture-a-context-001")
        complete_checkpoint(self.package, "audit-b", "fixture-b-context-001")
        complete_audit(self.package, "audit-a")
        complete_audit(self.package, "audit-b")
        complete_base_reconciliation(self.package)
        compile_operation_packet(self.package)
        result = start_fixed_point(self.package)
        while result["status"] == "awaiting_projection_reviews":
            cycle = int(result["cycle"])
            complete_projection_cycle(self.package, cycle)
            result = advance_fixed_point(self.package)
        self.assertEqual(result["status"], "pass")
        build_canonical_record(self.package)
        create_delivery_map(self.package)
        complete_editorial(self.package)

    def run_actionable_to_editorial(self) -> None:
        self.export.write_text(json.dumps(actionable_priority_export()), encoding="utf-8")
        build_package(self.export, self.package)
        complete_checkpoint(self.package, "audit-a", "actionable-a-context-001")
        complete_checkpoint(self.package, "audit-b", "actionable-b-context-001")
        complete_audit(self.package, "audit-a", actionable_priority=True)
        complete_audit(self.package, "audit-b", actionable_priority=True)
        complete_base_reconciliation(self.package)
        compile_result = compile_operation_packet(self.package)
        self.assertEqual(compile_result["operations"], 1)
        packet = json.loads((self.package / "operation-packet.json").read_text(encoding="utf-8"))
        self.assertEqual(len(packet["operations"]), 1)
        self.assertEqual(
            packet["operations"][0]["removals"],
            [
                {
                    "object_key": "tag:1",
                    "json_path": "$.tagFiringPriority",
                    "before": "10",
                }
            ],
        )
        result = start_fixed_point(self.package)
        while result["status"] == "awaiting_projection_reviews":
            cycle = int(result["cycle"])
            complete_projection_cycle(self.package, cycle)
            result = advance_fixed_point(self.package)
        self.assertEqual(result["status"], "pass")
        build_canonical_record(self.package)
        create_delivery_map(self.package)
        complete_editorial(self.package)

    def test_audit_b_is_candidate_blind_until_its_source_checkpoint(self) -> None:
        build_package(self.export, self.package)
        audit_b = self.package / "audit-bundles" / "audit-b"
        self.assertFalse((audit_b / "canonical-scan.json").exists())
        self.assertFalse((audit_b / "obligation-ledger.json").exists())
        self.assertTrue((audit_b / "blind-inventory.json").is_file())
        checkpoint = json.loads((audit_b / "source-checkpoint.json").read_text(encoding="utf-8"))
        self.assertTrue(checkpoint["candidate_blind_discovery"])
        self.assertEqual("", checkpoint["reviewed_inventory_sha256"])

    def test_source_audit_peers_require_distinct_agents_and_contexts(self) -> None:
        for shared_field in ("agent", "context"):
            with self.subTest(shared_field=shared_field):
                package = self.root / f"shared-{shared_field}-package"
                build_package(self.export, package)
                complete_checkpoint(
                    package,
                    "audit-a",
                    "shared-context" if shared_field == "context" else "audit-a-context",
                    "shared-agent" if shared_field == "agent" else "audit-a-agent",
                )
                complete_checkpoint(
                    package,
                    "audit-b",
                    "shared-context" if shared_field == "context" else "audit-b-context",
                    "shared-agent" if shared_field == "agent" else "audit-b-agent",
                )
                complete_audit(package, "audit-a")
                complete_audit(package, "audit-b")
                errors = sealed_audit_errors(package)
                expected = (
                    "the two sealed audits reuse one agent"
                    if shared_field == "agent"
                    else "the two sealed audits reuse one reasoning context"
                )
                self.assertIn(expected, errors)

    def test_source_checkpoint_rejects_wrong_input_manifest(self) -> None:
        build_package(self.export, self.package)
        checkpoint = (
            self.package
            / "audit-bundles"
            / "audit-a"
            / "source-checkpoint.json"
        )
        payload = json.loads(checkpoint.read_text(encoding="utf-8"))
        payload["status"] = "complete"
        payload["independent_agent_id"] = "wrong-manifest-agent"
        payload["independent_context_id"] = "wrong-manifest-context"
        payload["input_manifest_sha256"] = "f" * 64
        checkpoint.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "not bound to its audit bundle"):
            checkpoint_audit(self.package, "audit-a")

    def test_source_checkpoint_discoveries_are_concise_string_notes(self) -> None:
        build_package(self.export, self.package)
        checkpoint = (
            self.package
            / "audit-bundles"
            / "audit-a"
            / "source-checkpoint.json"
        )
        payload = json.loads(checkpoint.read_text(encoding="utf-8"))
        payload["open_discoveries"] = [
            "The source-only inventory exposes one bounded question for later semantic review."
        ]
        checkpoint.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

        complete_checkpoint(self.package, "audit-a", "string-discovery-context")

        other = self.root / "object-discovery-package"
        build_package(self.export, other)
        invalid = other / "audit-bundles" / "audit-a" / "source-checkpoint.json"
        invalid_payload = json.loads(invalid.read_text(encoding="utf-8"))
        invalid_payload["open_discoveries"] = [{"note": "undeclared object shape"}]
        invalid.write_text(
            json.dumps(invalid_payload, indent=2) + "\n", encoding="utf-8"
        )
        with self.assertRaisesRegex(ValueError, "list of non-blank strings"):
            complete_checkpoint(other, "audit-a", "object-discovery-context")

    def test_source_audits_cannot_reuse_scan_assurance_identity(self) -> None:
        for shared_field in ("agent", "context"):
            with self.subTest(shared_field=shared_field):
                package = self.root / f"scan-reuse-{shared_field}"
                build_package(self.export, package)
                with self.assertRaisesRegex(
                    ValueError,
                    (
                        "source audit must use an agent distinct from scan assurance"
                        if shared_field == "agent"
                        else "source audit must use a context distinct from scan assurance"
                    ),
                ):
                    complete_checkpoint(
                        package,
                        "audit-a",
                        (
                            "fixture-scan-assurance-context"
                            if shared_field == "context"
                            else "fresh-audit-context"
                        ),
                        (
                            "fixture-scan-assurance-agent"
                            if shared_field == "agent"
                            else "fresh-audit-agent"
                        ),
                    )

    def test_reconciliation_cannot_reuse_scan_assurance_identity(self) -> None:
        for shared_field in ("agent", "context"):
            with self.subTest(shared_field=shared_field):
                package = self.root / f"reconciliation-scan-reuse-{shared_field}"
                build_package(self.export, package)
                complete_checkpoint(package, "audit-a", "audit-a-context")
                complete_checkpoint(package, "audit-b", "audit-b-context")
                complete_audit(package, "audit-a")
                complete_audit(package, "audit-b")
                with self.assertRaisesRegex(
                    ValueError,
                    (
                        "reconciliation must use an agent distinct from scan assurance"
                        if shared_field == "agent"
                        else "reconciliation must use a context distinct from scan assurance"
                    ),
                ):
                    complete_base_reconciliation(
                        package,
                        agent_id=(
                            "fixture-scan-assurance-agent"
                            if shared_field == "agent"
                            else "fresh-reconciliation-agent"
                        ),
                        context_id=(
                            "fixture-scan-assurance-context"
                            if shared_field == "context"
                            else "fresh-reconciliation-context"
                        ),
                    )

    def test_coverage_release_cannot_rebind_its_source_checkpoint(self) -> None:
        build_package(self.export, self.package)
        complete_checkpoint(self.package, "audit-a", "release-binding-context-a")
        release_path = (
            self.package / "audit-bundles" / "audit-a" / "release-manifest.json"
        )
        release = json.loads(release_path.read_text(encoding="utf-8"))
        release["source_checkpoint_seal_sha256"] = "f" * 64
        release["release_manifest_sha256"] = stable_hash(
            {
                key: value
                for key, value in release.items()
                if key != "release_manifest_sha256"
            },
            64,
        )
        release_path.write_text(
            json.dumps(release, indent=2) + "\n", encoding="utf-8"
        )
        with self.assertRaisesRegex(
            ValueError, "coverage release manifest is bound to another checkpoint"
        ):
            complete_audit(self.package, "audit-a")

    def test_source_audit_amendment_is_fresh_bound_and_append_only(self) -> None:
        build_package(self.export, self.package)
        complete_checkpoint(self.package, "audit-a", "amendment-source-a-context")
        complete_checkpoint(self.package, "audit-b", "amendment-source-b-context")
        complete_audit(self.package, "audit-a")
        complete_audit(self.package, "audit-b")
        seal_a_path = self.package / "audit-seals" / "audit-a.json"
        first_seal = json.loads(seal_a_path.read_text(encoding="utf-8"))
        parent = first_seal["audit_seal_sha256"]
        current_seal_before = seal_a_path.read_bytes()
        canonical_audit_path = self.package / "audits" / "audit-a.json"
        canonical_audit_before = canonical_audit_path.read_bytes()
        checkpoint_path = (
            self.package
            / "audit-bundles"
            / "audit-a"
            / "source-checkpoint-seal.json"
        )
        checkpoint_before = checkpoint_path.read_bytes()
        with self.assertRaisesRegex(ValueError, "already sealed and immutable"):
            checkpoint_audit(self.package, "audit-a")
        self.assertEqual(checkpoint_before, checkpoint_path.read_bytes())

        write_audit_amendment(
            self.package,
            "audit-a",
            parent_seal_sha256=parent,
            context_id=first_seal["independent_context_id"],
            agent_id="fresh-amendment-agent-001",
        )
        with self.assertRaisesRegex(
            ValueError, "audit amendment requires a fresh reasoning context"
        ):
            seal_audit(self.package, "audit-a", amendment_of=parent)

        write_audit_amendment(
            self.package,
            "audit-a",
            parent_seal_sha256=parent,
            context_id="fresh-amendment-context-001",
            agent_id=first_seal["independent_agent_id"],
        )
        with self.assertRaisesRegex(
            ValueError, "audit amendment requires a fresh agent"
        ):
            seal_audit(self.package, "audit-a", amendment_of=parent)
        self.assertFalse((self.package / "audit-seals" / "history").exists())
        self.assertEqual(current_seal_before, seal_a_path.read_bytes())
        self.assertEqual(canonical_audit_before, canonical_audit_path.read_bytes())

        write_audit_amendment(
            self.package,
            "audit-a",
            parent_seal_sha256=parent,
            context_id="fresh-amendment-context-001",
            agent_id="fresh-amendment-agent-001",
        )
        original_copy2 = cleanroom_audit.shutil.copy2
        for backup_name in ("prior-seal.json", "prior-audit.json"):
            injected_backup = {"failed": False}

            def fail_partial_backup_once(
                source: Path,
                target: Path,
                *,
                follow_symlinks: bool = True,
                _backup_name: str = backup_name,
                _injected_backup: dict[str, bool] = injected_backup,
            ) -> str:
                if (
                    Path(target).name == _backup_name
                    and not _injected_backup["failed"]
                ):
                    _injected_backup["failed"] = True
                    Path(target).write_bytes(b"partial-backup")
                    raise OSError(f"injected partial {_backup_name} failure")
                return str(
                    original_copy2(
                        source,
                        target,
                        follow_symlinks=follow_symlinks,
                    )
                )

            with (
                self.subTest(backup=backup_name),
                mock.patch(
                    "gtm_cleanroom_audit.shutil.copy2",
                    side_effect=fail_partial_backup_once,
                ),
                self.assertRaisesRegex(OSError, f"partial {backup_name}"),
            ):
                seal_audit(self.package, "audit-a", amendment_of=parent)
            self.assertEqual(current_seal_before, seal_a_path.read_bytes())
            self.assertEqual(canonical_audit_before, canonical_audit_path.read_bytes())
            self.assertFalse((self.package / "audit-seals" / "history").exists())
            self.assertEqual(
                [],
                list(
                    (self.package / "audit-seals").glob(
                        ".audit-a-transition-*"
                    )
                ),
            )

        original_replace = cleanroom_audit._atomic_replace
        injected = {"failed": False}

        def fail_final_seal_once(source: Path, target: Path) -> None:
            if target == seal_a_path and not injected["failed"]:
                injected["failed"] = True
                raise OSError("injected final audit-seal replacement failure")
            original_replace(source, target)

        with (
            mock.patch(
                "gtm_cleanroom_audit._atomic_replace",
                side_effect=fail_final_seal_once,
            ),
            self.assertRaisesRegex(OSError, "injected final audit-seal"),
        ):
            seal_audit(self.package, "audit-a", amendment_of=parent)
        self.assertFalse((self.package / "audit-seals" / "history").exists())
        self.assertEqual(current_seal_before, seal_a_path.read_bytes())
        self.assertEqual(canonical_audit_before, canonical_audit_path.read_bytes())
        self.assertEqual(
            [],
            list((self.package / "audit-seals").glob(".audit-a-transition-*")),
        )
        self.assertFalse(
            (
                self.package
                / "audit-seals"
                / "work-unit-snapshots"
                / "audit-a"
                / "sequence-001"
            ).exists()
        )

        amended = seal_audit(self.package, "audit-a", amendment_of=parent)
        self.assertEqual(1, amended["amendment_sequence"])
        self.assertEqual(parent, amended["amendment_parent_seal_sha256"])
        self.assertEqual(checkpoint_before, checkpoint_path.read_bytes())
        current_audit = json.loads(
            (self.package / "audits" / "audit-a.json").read_text(encoding="utf-8")
        )
        self.assertEqual(
            "fresh-amendment-context-001",
            current_audit["independent_context_id"],
        )
        history = self.package / "audit-seals" / "history"
        self.assertEqual(1, len(list(history.glob("*.seal.json"))))
        self.assertEqual(1, len(list(history.glob("*.audit.json"))))
        historical_seal_path = next(history.glob("*.seal.json"))
        historical_seal_before = historical_seal_path.read_bytes()
        historical_seal_path.unlink()
        self.assertTrue(
            any(
                "history seal count is incomplete" in error
                or "current amendment parent chain is invalid" in error
                for error in sealed_audit_errors(self.package)
            )
        )
        historical_seal_path.write_bytes(historical_seal_before)
        checkpoint_seal_path = checkpoint_path.with_name(
            "source-checkpoint-seal.json"
        )
        checkpoint_seal_before = checkpoint_seal_path.read_bytes()
        tampered_checkpoint_seal = json.loads(
            checkpoint_seal_before.decode("utf-8")
        )
        tampered_checkpoint_seal["independent_context_id"] = (
            "tampered-checkpoint-context"
        )
        tampered_checkpoint_seal["checkpoint_seal_sha256"] = stable_hash(
            {
                key: value
                for key, value in tampered_checkpoint_seal.items()
                if key != "checkpoint_seal_sha256"
            },
            64,
        )
        checkpoint_seal_path.write_text(
            json.dumps(tampered_checkpoint_seal, indent=2) + "\n",
            encoding="utf-8",
        )
        release_path = (
            self.package / "audit-bundles" / "audit-a" / "release-manifest.json"
        )
        release_before = release_path.read_bytes()
        tampered_release = json.loads(release_before.decode("utf-8"))
        tampered_release["source_checkpoint_seal_sha256"] = (
            tampered_checkpoint_seal["checkpoint_seal_sha256"]
        )
        tampered_release["release_manifest_sha256"] = stable_hash(
            {
                key: value
                for key, value in tampered_release.items()
                if key != "release_manifest_sha256"
            },
            64,
        )
        release_path.write_text(
            json.dumps(tampered_release, indent=2) + "\n",
            encoding="utf-8",
        )
        self.assertTrue(
            any(
                "bound to another checkpoint" in error
                for error in sealed_audit_errors(self.package)
            )
        )
        amended_seal_before = seal_a_path.read_bytes()
        amended_audit_before = canonical_audit_path.read_bytes()
        history_before = {
            path: path.read_bytes() for path in history.glob("audit-a.*.json")
        }
        write_audit_amendment(
            self.package,
            "audit-a",
            parent_seal_sha256=amended["audit_seal_sha256"],
            context_id="fresh-amendment-context-002",
            agent_id="fresh-amendment-agent-002",
        )
        with self.assertRaisesRegex(
            ValueError, "existing audit provenance failed before amendment"
        ):
            seal_audit(
                self.package,
                "audit-a",
                amendment_of=amended["audit_seal_sha256"],
            )
        self.assertEqual(amended_seal_before, seal_a_path.read_bytes())
        self.assertEqual(amended_audit_before, canonical_audit_path.read_bytes())
        self.assertEqual(
            history_before,
            {path: path.read_bytes() for path in history.glob("audit-a.*.json")},
        )
        checkpoint_seal_path.write_bytes(checkpoint_seal_before)
        release_path.write_bytes(release_before)
        self.assertEqual([], sealed_audit_errors(self.package))

    def test_family_sharded_amendment_preserves_each_sealed_work_unit_snapshot(
        self,
    ) -> None:
        build_package(self.export, self.package)
        ceiling_patch = mock.patch(
            "gtm_audit_work_units.MAX_SINGLE_OBLIGATIONS", 1
        )
        ceiling_patch.start()
        self.addCleanup(ceiling_patch.stop)
        complete_checkpoint(
            self.package,
            "audit-a",
            "sharded-amendment-source-a-context",
        )
        complete_checkpoint(
            self.package,
            "audit-b",
            "sharded-amendment-source-b-context",
        )
        for audit_id in ("audit-a", "audit-b"):
            complete_sharded_work_units(self.package, audit_id)
            finalize_audit(self.package, audit_id)
            if audit_id == "audit-a":
                forge_post_merge_audit_only_drift(self.package, audit_id)
                with self.assertRaisesRegex(
                    ValueError,
                    "not the exact deterministic work-unit merge",
                ):
                    seal_audit(self.package, audit_id)
                merge_work_units(
                    self.package / "audit-bundles" / audit_id
                )
            seal_audit(self.package, audit_id)

        seal_path = self.package / "audit-seals" / "audit-a.json"
        initial_seal = json.loads(seal_path.read_text(encoding="utf-8"))
        parent = initial_seal["audit_seal_sha256"]
        initial_snapshot = (
            self.package
            / "audit-seals"
            / initial_seal["work_unit_snapshot_path"]
        )
        initial_snapshot_before = {
            path.relative_to(initial_snapshot).as_posix(): path.read_bytes()
            for path in initial_snapshot.rglob("*")
            if path.is_file()
        }

        bundle = self.package / "audit-bundles" / "audit-a"
        work_units = bundle / "work-units"
        manifest = json.loads(
            (work_units / "work-unit-manifest.json").read_text(encoding="utf-8")
        )
        amended_unit_path = work_units / manifest["work_units"][0]["filename"]
        amended_unit = json.loads(amended_unit_path.read_text(encoding="utf-8"))
        amended_unit["decisions"][0]["current_behavior"] += (
            " This independently authored amendment clarifies the same bounded "
            "source-visible behavior."
        )
        amended_unit["unit_closure"] = (
            "Every obligation in this family unit was independently reread and "
            "resealed for the amendment."
        )
        amended_unit_path.write_text(
            json.dumps(amended_unit, indent=2) + "\n",
            encoding="utf-8",
        )
        merge_work_units(bundle)
        write_audit_amendment(
            self.package,
            "audit-a",
            parent_seal_sha256=parent,
            context_id="sharded-amendment-fresh-context-001",
            agent_id="sharded-amendment-fresh-agent-001",
        )
        forge_post_merge_audit_only_drift(self.package, "audit-a")
        with self.assertRaisesRegex(
            ValueError,
            "not the exact deterministic work-unit merge",
        ):
            seal_audit(
                self.package,
                "audit-a",
                amendment_of=parent,
            )
        merge_work_units(bundle)
        history_redirect = self.package / "audit-seals" / "history"
        external_history = self.root / "external-audit-history"
        external_history.mkdir()
        create_directory_redirect(history_redirect, external_history)
        try:
            with self.assertRaisesRegex(
                ValueError,
                "link or reparse point",
            ):
                seal_audit(
                    self.package,
                    "audit-a",
                    amendment_of=parent,
                )
            self.assertEqual([], list(external_history.iterdir()))
        finally:
            remove_directory_redirect(history_redirect)
            external_history.rmdir()
        amended_seal = seal_audit(
            self.package,
            "audit-a",
            amendment_of=parent,
        )

        self.assertEqual(1, amended_seal["amendment_sequence"])
        self.assertEqual(
            initial_snapshot_before,
            {
                path.relative_to(initial_snapshot).as_posix(): path.read_bytes()
                for path in initial_snapshot.rglob("*")
                if path.is_file()
            },
        )
        snapshot_root = self.package / "audit-seals" / "work-unit-snapshots"
        self.assertEqual(
            {"sequence-000", "sequence-001"},
            {
                path.name
                for path in (snapshot_root / "audit-a").iterdir()
                if path.is_dir()
            },
        )
        self.assertEqual(
            {"sequence-000"},
            {
                path.name
                for path in (snapshot_root / "audit-b").iterdir()
                if path.is_dir()
            },
        )
        self.assertEqual([], sealed_audit_errors(self.package))

        initial_unit_snapshot = next(
            path
            for path in initial_snapshot.rglob("unit-*.json")
            if path.is_file()
        )
        initial_unit_before = initial_unit_snapshot.read_bytes()
        tampered_unit = json.loads(initial_unit_before.decode("utf-8"))
        tampered_unit["unit_closure"] += " Tampered after sealing."
        initial_unit_snapshot.write_text(
            json.dumps(tampered_unit, indent=2) + "\n",
            encoding="utf-8",
        )
        self.assertTrue(
            any(
                "work-unit snapshot files differ from their manifest" in error
                for error in sealed_audit_errors(self.package)
            )
        )
        initial_unit_snapshot.write_bytes(initial_unit_before)
        orphan_snapshot = snapshot_root / "audit-a" / "sequence-999"
        orphan_snapshot.mkdir()
        self.assertTrue(
            any(
                "snapshot history identity is incomplete" in error
                for error in sealed_audit_errors(self.package)
            )
        )
        orphan_snapshot.rmdir()
        self.assertEqual([], sealed_audit_errors(self.package))

        current_snapshot = (
            self.package
            / "audit-seals"
            / amended_seal["work_unit_snapshot_path"]
        )
        external_snapshot = self.root / "external-work-unit-snapshot"
        current_snapshot.replace(external_snapshot)
        try:
            create_directory_redirect(current_snapshot, external_snapshot)
            self.assertTrue(
                any(
                    "link or reparse point" in error
                    or "leaves its sealed root" in error
                    for error in sealed_audit_errors(self.package)
                )
            )
        finally:
            if current_snapshot.exists():
                remove_directory_redirect(current_snapshot)
            external_snapshot.replace(current_snapshot)
        self.assertEqual([], sealed_audit_errors(self.package))

    def test_reconciliation_agent_and_context_are_distinct_from_both_audits(self) -> None:
        for shared_field in ("agent", "context"):
            with self.subTest(shared_field=shared_field):
                package = self.root / f"reconciliation-shared-{shared_field}"
                build_package(self.export, package)
                complete_checkpoint(
                    package, "audit-a", "audit-a-context", "audit-a-agent"
                )
                complete_checkpoint(
                    package, "audit-b", "audit-b-context", "audit-b-agent"
                )
                complete_audit(package, "audit-a")
                complete_audit(package, "audit-b")
                kwargs = {
                    "agent_id": (
                        "audit-a-agent"
                        if shared_field == "agent"
                        else "reconciliation-agent"
                    ),
                    "context_id": (
                        "audit-a-context"
                        if shared_field == "context"
                        else "reconciliation-context"
                    ),
                }
                expected = (
                    "reconciliation must use an agent distinct from scan assurance and both audits"
                    if shared_field == "agent"
                    else "reconciliation must use a context distinct from scan assurance and both audits"
                )
                with self.assertRaisesRegex(ValueError, expected):
                    complete_base_reconciliation(package, **kwargs)

    def test_neutral_rows_have_no_agent_context_or_receipt_fields(self) -> None:
        self.export.write_text(json.dumps(actionable_priority_export()), encoding="utf-8")
        build_package(self.export, self.package)
        complete_checkpoint(self.package, "audit-a", "neutral-a-context")
        complete_checkpoint(self.package, "audit-b", "neutral-b-context")
        complete_audit(self.package, "audit-a", actionable_priority=True)
        complete_audit(self.package, "audit-b", actionable_priority=True)
        complete_base_reconciliation(self.package)
        neutral = json.loads(
            (self.package / "neutral-verification.json").read_text(encoding="utf-8")
        )
        self.assertTrue(neutral["verifications"])
        forbidden = {
            "independent_agent_id",
            "independent_context_id",
            "host_isolation_receipt",
            "receipt_id",
        }
        for row in neutral["verifications"]:
            self.assertTrue(forbidden.isdisjoint(row))

    def test_projection_reviews_require_distinct_agents_and_contexts(self) -> None:
        for shared_field in ("agent", "context"):
            with self.subTest(shared_field=shared_field):
                package = self.root / f"projection-shared-{shared_field}"
                self.export.write_text(
                    json.dumps(actionable_priority_export()), encoding="utf-8"
                )
                build_package(self.export, package)
                complete_checkpoint(package, "audit-a", "projection-a-source")
                complete_checkpoint(package, "audit-b", "projection-b-source")
                complete_audit(package, "audit-a", actionable_priority=True)
                complete_audit(package, "audit-b", actionable_priority=True)
                complete_base_reconciliation(package)
                compile_operation_packet(package)
                result = start_fixed_point(package)
                cycle = int(result["cycle"])
                kwargs = {
                    "review_agent_override": (
                        f"fixture-projection-review-b-agent-{cycle:02d}"
                        if shared_field == "agent"
                        else None
                    ),
                    "review_context_override": (
                        f"projection-b-context-{cycle:02d}"
                        if shared_field == "context"
                        else None
                    ),
                }
                expected = (
                    "projection reviews reuse one agent"
                    if shared_field == "agent"
                    else "projection reviews reuse one reasoning context"
                )
                with self.assertRaisesRegex(ValueError, expected):
                    complete_projection_cycle(package, cycle, **kwargs)

    def test_projection_review_rejects_wrong_input_manifest(self) -> None:
        self.export.write_text(json.dumps(actionable_priority_export()), encoding="utf-8")
        build_package(self.export, self.package)
        complete_checkpoint(self.package, "audit-a", "projection-manifest-a")
        complete_checkpoint(self.package, "audit-b", "projection-manifest-b")
        complete_audit(self.package, "audit-a", actionable_priority=True)
        complete_audit(self.package, "audit-b", actionable_priority=True)
        complete_base_reconciliation(self.package)
        compile_operation_packet(self.package)
        result = start_fixed_point(self.package)
        with self.assertRaisesRegex(ValueError, "not bound to this review bundle"):
            complete_projection_cycle(
                self.package,
                int(result["cycle"]),
                review_input_manifest_override="f" * 64,
            )

    def test_projection_plan_completes_review_without_ad_hoc_resolver(self) -> None:
        self.export.write_text(json.dumps(actionable_priority_export()), encoding="utf-8")
        build_package(self.export, self.package)
        complete_checkpoint(self.package, "audit-a", "projection-plan-a")
        complete_checkpoint(self.package, "audit-b", "projection-plan-b")
        complete_audit(self.package, "audit-a", actionable_priority=True)
        complete_audit(self.package, "audit-b", actionable_priority=True)
        complete_base_reconciliation(self.package)
        compile_operation_packet(self.package)
        result = start_fixed_point(self.package)
        cycle = int(result["cycle"])
        plan_path = write_fixture_projection_plan(
            self.package, cycle, "review-a"
        )

        applied = apply_projection_plan(
            self.package,
            cycle,
            "review-a",
            plan_path,
            agent_id="projection-plan-agent",
            context_id="projection-plan-context",
        )
        seal = seal_projection_review(self.package, cycle, "review-a")

        self.assertEqual("pass", applied["status"])
        self.assertGreater(applied["decisions"], 0)
        self.assertEqual("pass", seal["validator_status"])

    def test_projection_plan_rejects_wrong_owner_path_and_provenance(self) -> None:
        self.export.write_text(json.dumps(actionable_priority_export()), encoding="utf-8")
        build_package(self.export, self.package)
        complete_checkpoint(self.package, "audit-a", "projection-guard-a")
        complete_checkpoint(self.package, "audit-b", "projection-guard-b")
        complete_audit(self.package, "audit-a", actionable_priority=True)
        complete_audit(self.package, "audit-b", actionable_priority=True)
        complete_base_reconciliation(self.package)
        compile_operation_packet(self.package)
        cycle = int(start_fixed_point(self.package)["cycle"])
        with self.assertRaisesRegex(ValueError, "unsupported projection review"):
            scaffold_projection_plan(
                self.package,
                cycle,
                "review-x",
                self.root / "invalid-review-plan.json",
            )
        with self.assertRaisesRegex(ValueError, "isolated path"):
            scaffold_projection_plan(
                self.package,
                cycle,
                "review-a",
                self.root / "misplaced-review-plan.json",
            )
        plan_path = write_fixture_projection_plan(
            self.package, cycle, "review-a"
        )
        with self.assertRaisesRegex(FileExistsError, "already exists"):
            scaffold_projection_plan(
                self.package, cycle, "review-a", plan_path
            )
        with self.assertRaisesRegex(ValueError, "non-blank agent"):
            apply_projection_plan(
                self.package,
                cycle,
                "review-a",
                plan_path,
                agent_id="",
                context_id="projection-guard-context",
            )
        plan = json.loads(plan_path.read_text(encoding="utf-8"))
        plan["owner_id"] = "review-b"
        plan_path.write_text(json.dumps(plan, indent=2) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "another owner"):
            apply_projection_plan(
                self.package,
                cycle,
                "review-a",
                plan_path,
                agent_id="projection-guard-agent",
                context_id="projection-guard-context",
            )

    def test_projection_reconciliation_is_distinct_from_both_reviews(self) -> None:
        for shared_field in ("agent", "context"):
            with self.subTest(shared_field=shared_field):
                package = self.root / f"projection-reconciliation-{shared_field}"
                self.export.write_text(
                    json.dumps(actionable_priority_export()), encoding="utf-8"
                )
                build_package(self.export, package)
                complete_checkpoint(package, "audit-a", "projection-rec-a")
                complete_checkpoint(package, "audit-b", "projection-rec-b")
                complete_audit(package, "audit-a", actionable_priority=True)
                complete_audit(package, "audit-b", actionable_priority=True)
                complete_base_reconciliation(package)
                compile_operation_packet(package)
                result = start_fixed_point(package)
                cycle = int(result["cycle"])
                kwargs = {
                    "reconciliation_agent_override": (
                        f"fixture-projection-review-a-agent-{cycle:02d}"
                        if shared_field == "agent"
                        else None
                    ),
                    "reconciliation_context_override": (
                        f"projection-a-context-{cycle:02d}"
                        if shared_field == "context"
                        else None
                    ),
                }
                expected = (
                    "projection reconciliation must use a distinct agent"
                    if shared_field == "agent"
                    else "projection reconciliation must use a distinct context"
                )
                with self.assertRaisesRegex(ValueError, expected):
                    complete_projection_cycle(package, cycle, **kwargs)

    def test_editorial_artifact_has_no_agent_context_identity(self) -> None:
        self.run_actionable_to_editorial()
        editorial_path = self.package / "delivery" / "editorial.json"
        editorial = json.loads(editorial_path.read_text(encoding="utf-8"))
        self.assertNotIn("independent_agent_id", editorial)
        self.assertNotIn("independent_context_id", editorial)
        self.assertNotIn("host_isolation_receipt", editorial)

    def test_next_cycle_failure_preserves_packet_and_projection_decisions(self) -> None:
        self.export.write_text(json.dumps(actionable_priority_export()), encoding="utf-8")
        build_package(self.export, self.package)
        complete_checkpoint(self.package, "audit-a", "atomic-source-a-checkpoint")
        complete_checkpoint(self.package, "audit-b", "atomic-source-b-checkpoint")
        complete_audit(self.package, "audit-a", actionable_priority=True)
        complete_audit(self.package, "audit-b", actionable_priority=True)
        complete_base_reconciliation(self.package)
        compile_operation_packet(self.package)
        result = start_fixed_point(self.package)
        self.assertEqual("awaiting_projection_reviews", result["status"])
        packet_path = self.package / "operation-packet.json"
        decisions_path = self.package / "fixed-point" / "projection-decisions.json"
        original_packet = packet_path.read_bytes()
        original_decisions = decisions_path.read_bytes()
        decision = {
            "canonical_decision_id": "PCD-ATOMIC-FAILURE",
            "decision": {"decision_class": "defect"},
        }
        candidate_payload = json.loads(original_decisions.decode("utf-8"))
        candidate_payload["canonical_decisions"] = [decision]
        with (
            mock.patch(
                "gtm_fixed_point._closure_errors", return_value=({}, [])
            ),
            mock.patch(
                "gtm_fixed_point._projection_decision_candidate",
                return_value=(candidate_payload, [decision]),
            ),
            mock.patch(
                "gtm_fixed_point._packet_with_projection_operations",
                return_value=json.loads(original_packet.decode("utf-8")),
            ),
            mock.patch(
                "gtm_fixed_point._create_cycle",
                side_effect=ValueError("forced next-cycle assurance failure"),
            ),
        ):
            blocked = advance_fixed_point(self.package)
        self.assertEqual("non_convergent_target_state", blocked["status"])
        self.assertEqual(original_packet, packet_path.read_bytes())
        self.assertEqual(original_decisions, decisions_path.read_bytes())
        self.assertFalse((self.package / "fixed-point" / "cycle-02").exists())
        self.assertEqual(
            [],
            list((self.package / "fixed-point").glob(".cycle-02-*")),
        )

    def test_complete_static_workflow_reaches_sealed_canonical_record(self) -> None:
        self.run_to_editorial()
        canonical = json.loads((self.package / "canonical-record.json").read_text(encoding="utf-8"))
        self.assertEqual(canonical["fixed_point"]["status"], "pass")
        self.assertEqual(canonical["summary"]["operation_count"], 0)
        self.assertTrue(canonical["audit_decisions"])
        self.assertFalse(
            any(
                str(row["canonical_decision_id"]).startswith("PCD-")
                for row in canonical["audit_decisions"]
            )
        )
        self.assertTrue(
            all(
                row["record_owner"]["repair_rule"].startswith("Reopen ")
                and row["record_owner"]["owner_kind"]
                in {
                    "source_audit_and_reconciliation",
                    "projection_review_and_reconciliation",
                }
                for row in canonical["audit_decisions"]
            )
        )
        delivery_map = json.loads(
            (self.package / "delivery" / "delivery-map.json").read_text(encoding="utf-8")
        )
        self.assertEqual(HUMAN_DECISION_LABELS, delivery_map["overview"]["decision_labels"])
        area_24_focuses = [
            row["locked"]["audit_focus"]
            for row in delivery_map["rows"]
            if row["primary_sheet"] == "04 Full Audit" and row["locked"]["area_id"] == "AREA-24"
        ]
        self.assertEqual(len(area_24_focuses), len(set(area_24_focuses)))

    def test_actionable_priority_removal_reaches_canonical_delivery(self) -> None:
        self.run_actionable_to_editorial()
        canonical = json.loads((self.package / "canonical-record.json").read_text(encoding="utf-8"))
        self.assertEqual(canonical["summary"]["operation_count"], 1)
        operation = canonical["operations"][0]
        self.assertEqual(operation["operation_id"], "OP-REMOVE-REDUNDANT-PRIORITY")
        self.assertEqual(operation["removals"][0]["json_path"], "$.tagFiringPriority")
        projected = json.loads(
            (self.package / "fixed-point" / "replay" / "projected-container.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertNotIn("tagFiringPriority", projected["containerVersion"]["tag"][0])
        delivery_map = json.loads(
            (self.package / "delivery" / "delivery-map.json").read_text(encoding="utf-8")
        )
        recommendations = [
            row for row in delivery_map["rows"] if row["primary_sheet"] == "02 Recommendations"
        ]
        self.assertEqual(len(recommendations), 1)
        highest_value = delivery_map["overview"]["highest_value_actions"][0]
        self.assertIn("Remove redundant firing priority", highest_value)
        self.assertIn("OP-REMOVE-REDUNDANT-PRIORITY", highest_value)
        self.assertEqual(
            recommendations[0]["locked"]["technical_note"]["removals"],
            operation["removals"],
        )

    def test_delivery_cannot_patch_a_changed_sealed_semantic_record(self) -> None:
        self.run_to_editorial()
        record_path = self.package / "canonical-record.json"
        canonical = json.loads(record_path.read_text(encoding="utf-8"))
        canonical["audit_decisions"][0]["decision"]["current_behavior"] = ""
        record_path.write_text(json.dumps(canonical, indent=2) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "canonical record gate failed"):
            create_delivery_map(self.package)

    def test_reconciliation_rebuilds_scaffolds_and_rejects_expected_answers(self) -> None:
        build_package(self.export, self.package)
        complete_checkpoint(self.package, "audit-a", "fixture-a-context-001")
        complete_checkpoint(self.package, "audit-b", "fixture-b-context-001")
        complete_audit(self.package, "audit-a")
        complete_audit(self.package, "audit-b")
        complete_base_reconciliation(self.package)

        scaffold_path = self.package / "reconciliation-scaffold.json"
        scaffold = json.loads(scaffold_path.read_text(encoding="utf-8"))
        scaffold["comparisons"][0]["audit_decisions"]["audit-a"][
            "current_behavior"
        ] = "Invented mutable scaffold authority."
        scaffold["reconciliation_scaffold_sha256"] = stable_hash(
            {
                key: value
                for key, value in scaffold.items()
                if key != "reconciliation_scaffold_sha256"
            },
            64,
        )
        scaffold_path.write_text(
            json.dumps(scaffold, indent=2) + "\n", encoding="utf-8"
        )

        queue_path = self.package / "neutral-verification-queue.json"
        queue = json.loads(queue_path.read_text(encoding="utf-8"))
        queue["expected_answer"] = "Delete every configured tag."
        queue["neutral_queue_sha256"] = stable_hash(
            {
                key: value
                for key, value in queue.items()
                if key != "neutral_queue_sha256"
            },
            64,
        )
        queue_path.write_text(json.dumps(queue, indent=2) + "\n", encoding="utf-8")
        errors = reconciliation_seal_errors(self.package)
        self.assertTrue(any("reconstruction" in error for error in errors))

    def test_rehashed_replay_and_canonical_forgery_are_rejected(self) -> None:
        self.run_actionable_to_editorial()
        replay_path = (
            self.package / "fixed-point" / "replay" / "projected-container.json"
        )
        replay_before = replay_path.read_bytes()
        replay = json.loads(replay_path.read_text(encoding="utf-8"))
        replay["containerVersion"]["tag"][0]["name"] = "Forged replay tag"
        replay_path.write_text(json.dumps(replay, indent=2) + "\n", encoding="utf-8")
        fixed_seal_path = self.package / "fixed-point" / "fixed-point-seal.json"
        fixed_seal_before = fixed_seal_path.read_bytes()
        fixed_seal = json.loads(fixed_seal_path.read_text(encoding="utf-8"))
        fixed_seal["stable_projected_container_sha256"] = file_sha256(replay_path)
        fixed_seal["fixed_point_seal_sha256"] = stable_hash(
            {
                key: value
                for key, value in fixed_seal.items()
                if key != "fixed_point_seal_sha256"
            },
            64,
        )
        fixed_seal_path.write_text(
            json.dumps(fixed_seal, indent=2) + "\n", encoding="utf-8"
        )
        self.assertTrue(
            any("differs from reconstruction" in error for error in fixed_point_seal_errors(self.package))
        )
        replay_path.write_bytes(replay_before)
        fixed_seal_path.write_bytes(fixed_seal_before)

        record_path = self.package / "canonical-record.json"
        record = json.loads(record_path.read_text(encoding="utf-8"))
        record["audit_decisions"][0]["decision"][
            "target_direction"
        ] = "Replace every tag with an unsupported placeholder."
        record["canonical_record_sha256"] = stable_hash(
            {
                key: value
                for key, value in record.items()
                if key != "canonical_record_sha256"
            },
            64,
        )
        record_path.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
        self.assertTrue(
            any("deterministic reconstruction" in error for error in canonical_record_seal_errors(self.package))
        )

    def test_rehashed_delivery_map_cannot_detach_workbook_semantics(self) -> None:
        self.run_actionable_to_editorial()
        map_path = self.package / "delivery" / "delivery-map.json"
        delivery_map = json.loads(map_path.read_text(encoding="utf-8"))
        recommendation = next(
            row
            for row in delivery_map["rows"]
            if row["primary_sheet"] == "02 Recommendations"
        )
        recommendation["locked"][
            "exact_target_state"
        ] = "Replace every configured tag with one blank placeholder."
        delivery_map["delivery_map_sha256"] = stable_hash(
            {
                key: value
                for key, value in delivery_map.items()
                if key != "delivery_map_sha256"
            },
            64,
        )
        map_path.write_text(
            json.dumps(delivery_map, indent=2) + "\n", encoding="utf-8"
        )
        seal_path = self.package / "delivery" / "delivery-map-seal.json"
        seal = json.loads(seal_path.read_text(encoding="utf-8"))
        seal["delivery_map_sha256"] = delivery_map["delivery_map_sha256"]
        seal["delivery_map_file_sha256"] = file_sha256(map_path)
        seal["delivery_map_seal_sha256"] = stable_hash(
            {
                key: value
                for key, value in seal.items()
                if key != "delivery_map_seal_sha256"
            },
            64,
        )
        seal_path.write_text(json.dumps(seal, indent=2) + "\n", encoding="utf-8")
        self.assertTrue(
            any("canonical reconstruction" in error for error in validate_editorial(self.package))
        )

    def test_operation_packet_is_reconstructed_from_sealed_reconciliation(self) -> None:
        self.export.write_text(json.dumps(actionable_priority_export()), encoding="utf-8")
        build_package(self.export, self.package)
        complete_checkpoint(self.package, "audit-a", "packet-a-context-001")
        complete_checkpoint(self.package, "audit-b", "packet-b-context-001")
        complete_audit(self.package, "audit-a", actionable_priority=True)
        complete_audit(self.package, "audit-b", actionable_priority=True)
        complete_base_reconciliation(self.package)
        compile_operation_packet(self.package)
        packet_path = self.package / "operation-packet.json"
        packet = json.loads(packet_path.read_text(encoding="utf-8"))
        packet["operations"][0][
            "exact_target_state"
        ] = "Delete every configured tag without source support."
        packet["operation_record_sha256"] = stable_hash(
            {
                key: value
                for key, value in packet.items()
                if key != "operation_record_sha256"
            },
            64,
        )
        packet_path.write_text(json.dumps(packet, indent=2) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(
            ValueError, "differs from sealed semantic reconstruction"
        ):
            start_fixed_point(self.package)

    def test_sealed_semantic_repair_starts_a_bound_successor_package(self) -> None:
        self.run_to_editorial()
        predecessor_path = self.package / "canonical-record.json"
        predecessor = json.loads(predecessor_path.read_text(encoding="utf-8"))
        decision = predecessor["audit_decisions"][0]
        repair_brief = self.root / "semantic-repair-brief.json"
        repair_brief.write_text(
            json.dumps(
                {
                    "kind": "gtm_semantic_repair_brief",
                    "schema_version": 1,
                    "status": "approved",
                    "canonical_record_sha256": predecessor[
                        "canonical_record_sha256"
                    ],
                    "repair_records": [
                        {
                            "repair_id": "REPAIR-MISSING-NEXT-STEP",
                            "canonical_decision_id": decision[
                                "canonical_decision_id"
                            ],
                            "fields": ["next_step"],
                            "reason": (
                                "The sealed decision lacks the required canonical next "
                                "step needed for faithful human delivery."
                            ),
                        }
                    ],
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        successor = self.root / "successor-package"
        manifest = build_package(
            self.export,
            successor,
            predecessor_record_path=predecessor_path,
            repair_brief_path=repair_brief,
        )
        self.assertEqual(
            predecessor["canonical_record_sha256"],
            manifest["semantic_successor_of"]["canonical_record_sha256"],
        )
        self.assertTrue((successor / "superseded-canonical-record.json").is_file())
        ledger = json.loads(
            (successor / "obligation-ledger.json").read_text(encoding="utf-8")
        )
        repairs = [
            row
            for row in ledger["obligations"]
            if row.get("semantic_repair_records")
        ]
        self.assertEqual(1, len(repairs))
        self.assertEqual(decision["obligation_id"], repairs[0]["obligation_id"])
        self.assertIn(
            "semantic_repair", repairs[0]["material_verification_triggers"]
        )
        checkpoint_ledger = json.loads(
            (
                successor
                / "audit-bundles"
                / "audit-a"
                / "source-obligations.json"
            ).read_text(encoding="utf-8")
        )
        self.assertFalse(
            any(row.get("semantic_repair_records") for row in checkpoint_ledger["obligations"])
        )
        complete_checkpoint(successor, "audit-a", "successor-source-a-checkpoint")
        released_ledger = json.loads(
            (
                successor / "audit-bundles" / "audit-a" / "obligation-ledger.json"
            ).read_text(encoding="utf-8")
        )
        self.assertTrue(
            any(row.get("semantic_repair_records") for row in released_ledger["obligations"])
        )
        self.assertTrue(
            (successor / "audit-bundles" / "audit-a" / "semantic-repair-brief.json").is_file()
        )
        mismatched_export = self.root / "mismatched-container.json"
        changed_source = minimal_export()
        changed_source["containerVersion"]["container"]["publicId"] = "GTM-OTHER"
        mismatched_export.write_text(json.dumps(changed_source), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "same locked source"):
            build_package(
                mismatched_export,
                self.root / "mismatched-successor",
                predecessor_record_path=predecessor_path,
                repair_brief_path=repair_brief,
            )

    @unittest.skipUnless(
        os.environ.get("CODEX_NODE") and os.environ.get("CODEX_ARTIFACT_NODE_MODULES"),
        "The explicit bundled Node.js and artifact-tool runtime are required",
    )
    def test_artifact_workbook_build_verify_and_delivery_seal(self) -> None:
        self.run_actionable_to_editorial()
        node = os.environ["CODEX_NODE"]
        run_node_script(
            node,
            SCRIPTS / "gtm_workbook_build.mjs",
            self.package,
        )
        run_node_script(
            node,
            SCRIPTS / "gtm_workbook_verify.mjs",
            self.package,
        )
        current = json.loads(
            (self.package / "delivery" / "current-build.json").read_text(encoding="utf-8")
        )
        current_path = self.package / "delivery" / "current-build.json"
        current_before = current_path.read_bytes()
        outside_build = self.root / "outside-workbook-build"
        outside_build.mkdir()
        outside_sentinel = outside_build / "sentinel.bin"
        outside_sentinel.write_bytes(b"outside-build-must-not-be-read-or-written")
        outside_before = outside_sentinel.read_bytes()
        escaped_current = copy.deepcopy(current)
        escaped_current["build_path"] = "../../outside-workbook-build"
        escaped_current["current_build_sha256"] = stable_hash(
            {
                key: value
                for key, value in escaped_current.items()
                if key != "current_build_sha256"
            },
            64,
        )
        current_path.write_text(
            json.dumps(escaped_current, indent=2) + "\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValueError, "remain inside"):
            scaffold_delivery_reviews(self.package)
        escaped_result = subprocess.run(
            [node, str(SCRIPTS / "gtm_workbook_verify.mjs"), str(self.package)],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(0, escaped_result.returncode)
        self.assertIn("remain inside", escaped_result.stdout + escaped_result.stderr)
        self.assertEqual(outside_before, outside_sentinel.read_bytes())
        current_path.write_bytes(current_before)

        build_dir = self.package / "delivery" / current["build_path"]
        build_manifest_path = build_dir / "workbook-build-manifest.json"
        build_manifest_before = build_manifest_path.read_bytes()
        build_manifest = json.loads(build_manifest_before)
        outside_workbook = self.root / "outside-workbook.xlsx"
        outside_workbook.write_bytes(b"outside-workbook-must-not-be-read")
        outside_workbook_before = outside_workbook.read_bytes()
        escaped_manifest = copy.deepcopy(build_manifest)
        escaped_manifest["workbook_path"] = "../outside-workbook.xlsx"
        escaped_manifest["workbook_build_manifest_sha256"] = stable_hash(
            {
                key: value
                for key, value in escaped_manifest.items()
                if key != "workbook_build_manifest_sha256"
            },
            64,
        )
        build_manifest_path.write_text(
            json.dumps(escaped_manifest, indent=2) + "\n",
            encoding="utf-8",
        )
        rebound_current = copy.deepcopy(current)
        rebound_current["workbook_build_manifest_sha256"] = escaped_manifest[
            "workbook_build_manifest_sha256"
        ]
        rebound_current["current_build_sha256"] = stable_hash(
            {
                key: value
                for key, value in rebound_current.items()
                if key != "current_build_sha256"
            },
            64,
        )
        current_path.write_text(
            json.dumps(rebound_current, indent=2) + "\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValueError, "remain inside"):
            scaffold_delivery_reviews(self.package)
        escaped_result = subprocess.run(
            [node, str(SCRIPTS / "gtm_workbook_verify.mjs"), str(self.package)],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(0, escaped_result.returncode)
        self.assertIn("remain inside", escaped_result.stdout + escaped_result.stderr)
        self.assertEqual(outside_workbook_before, outside_workbook.read_bytes())
        build_manifest_path.write_bytes(build_manifest_before)
        current_path.write_bytes(current_before)

        verification = json.loads(
            (
                self.package / "delivery" / current["build_path"] / "technical-verification.json"
            ).read_text(encoding="utf-8")
        )
        self.assertTrue(verification["comment_checks"])
        self.assertTrue(all(row["status"] == "pass" for row in verification["comment_checks"]))
        scaffold_delivery_reviews(self.package)
        for bundle_name, review_name, expected_error in (
            (
                "fidelity",
                "fidelity-review.json",
                "fidelity workbook copy differs from the authoritative workbook",
            ),
            (
                "reader",
                "reader-review.json",
                "reader workbook copy differs from the authoritative workbook",
            ),
        ):
            review_dir = build_dir / "reviews" / bundle_name
            workbook_copy = review_dir / "workbook.xlsx"
            review_manifest_path = review_dir / "bundle-manifest.json"
            review_path = review_dir / review_name
            workbook_before = workbook_copy.read_bytes()
            review_manifest_before = review_manifest_path.read_bytes()
            review_before = review_path.read_bytes()
            workbook_copy.write_bytes(workbook_before + b"forged-workbook-copy")
            review_manifest = json.loads(review_manifest_before)
            for locked_file in review_manifest["locked_files"]:
                if locked_file["path"] == "workbook.xlsx":
                    locked_file["sha256"] = file_sha256(workbook_copy)
            review_manifest["bundle_manifest_sha256"] = stable_hash(
                {
                    key: value
                    for key, value in review_manifest.items()
                    if key != "bundle_manifest_sha256"
                },
                64,
            )
            review_manifest_path.write_text(
                json.dumps(review_manifest, indent=2) + "\n", encoding="utf-8"
            )
            review = json.loads(review_before)
            review["input_manifest_sha256"] = review_manifest[
                "bundle_manifest_sha256"
            ]
            review_path.write_text(
                json.dumps(review, indent=2) + "\n", encoding="utf-8"
            )
            with self.assertRaisesRegex(ValueError, expected_error):
                seal_delivery(self.package)
            workbook_copy.write_bytes(workbook_before)
            review_manifest_path.write_bytes(review_manifest_before)
            review_path.write_bytes(review_before)

        reader_dir = build_dir / "reviews" / "reader"
        reader_manifest_path = reader_dir / "bundle-manifest.json"
        reader_review_path = reader_dir / "reader-review.json"

        def rebind_reader_input(relative_path: str) -> None:
            review_manifest = json.loads(
                reader_manifest_path.read_text(encoding="utf-8")
            )
            for locked_file in review_manifest["locked_files"]:
                if locked_file["path"] == relative_path:
                    locked_file["sha256"] = file_sha256(reader_dir / relative_path)
            review_manifest["bundle_manifest_sha256"] = stable_hash(
                {
                    key: value
                    for key, value in review_manifest.items()
                    if key != "bundle_manifest_sha256"
                },
                64,
            )
            reader_manifest_path.write_text(
                json.dumps(review_manifest, indent=2) + "\n", encoding="utf-8"
            )
            reader_review = json.loads(
                reader_review_path.read_text(encoding="utf-8")
            )
            reader_review["input_manifest_sha256"] = review_manifest[
                "bundle_manifest_sha256"
            ]
            reader_review_path.write_text(
                json.dumps(reader_review, indent=2) + "\n", encoding="utf-8"
            )

        authoritative_audience_path = self.package / "delivery" / "audience-brief.json"
        reader_audience_path = reader_dir / "audience-brief.json"
        audience_before = authoritative_audience_path.read_bytes()
        reader_audience_before = reader_audience_path.read_bytes()
        reader_manifest_before = reader_manifest_path.read_bytes()
        reader_review_before = reader_review_path.read_bytes()
        forged_audience = json.loads(audience_before)
        forged_audience["primary_audience"] = "Forged reader audience"
        forged_audience["audience_brief_sha256"] = stable_hash(
            {
                key: value
                for key, value in forged_audience.items()
                if key != "audience_brief_sha256"
            },
            64,
        )
        forged_audience_bytes = (
            json.dumps(forged_audience, indent=2) + "\n"
        ).encode("utf-8")
        authoritative_audience_path.write_bytes(forged_audience_bytes)
        reader_audience_path.write_bytes(forged_audience_bytes)
        rebind_reader_input("audience-brief.json")
        with self.assertRaisesRegex(
            ValueError, "reader audience brief differs from canonical reconstruction"
        ):
            seal_delivery(self.package)
        authoritative_audience_path.write_bytes(audience_before)
        reader_audience_path.write_bytes(reader_audience_before)
        reader_manifest_path.write_bytes(reader_manifest_before)
        reader_review_path.write_bytes(reader_review_before)

        preview_record = build_manifest["previews"][0]
        authoritative_preview_path = self.package / preview_record["path"]
        preview_relative = authoritative_preview_path.relative_to(
            build_dir / "previews"
        )
        reader_preview_path = reader_dir / "previews" / preview_relative
        preview_before = authoritative_preview_path.read_bytes()
        reader_preview_before = reader_preview_path.read_bytes()
        reader_manifest_before = reader_manifest_path.read_bytes()
        reader_review_before = reader_review_path.read_bytes()
        forged_preview = preview_before + b"forged-preview"
        authoritative_preview_path.write_bytes(forged_preview)
        reader_preview_path.write_bytes(forged_preview)
        rebind_reader_input(f"previews/{preview_relative.as_posix()}")
        with self.assertRaisesRegex(
            ValueError, "authoritative previews differ from the workbook build manifest"
        ):
            seal_delivery(self.package)
        authoritative_preview_path.write_bytes(preview_before)
        reader_preview_path.write_bytes(reader_preview_before)
        reader_manifest_path.write_bytes(reader_manifest_before)
        reader_review_path.write_bytes(reader_review_before)
        fidelity_manifest_path = (
            build_dir / "reviews" / "fidelity" / "bundle-manifest.json"
        )
        fidelity_manifest_before = fidelity_manifest_path.read_bytes()
        fidelity_manifest = json.loads(fidelity_manifest_before)
        fidelity_manifest["locked_files"][0]["path"] = (
            "../../../../../outside-workbook.xlsx"
        )
        fidelity_manifest["locked_files"][0]["sha256"] = file_sha256(
            outside_workbook
        )
        fidelity_manifest["bundle_manifest_sha256"] = stable_hash(
            {
                key: value
                for key, value in fidelity_manifest.items()
                if key != "bundle_manifest_sha256"
            },
            64,
        )
        fidelity_manifest_path.write_text(
            json.dumps(fidelity_manifest, indent=2) + "\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValueError, "remain inside"):
            seal_delivery(self.package)
        self.assertEqual(outside_workbook_before, outside_workbook.read_bytes())
        fidelity_manifest_path.write_bytes(fidelity_manifest_before)
        fidelity_input_path = (
            build_dir / "reviews" / "fidelity" / "fidelity-input.json"
        )
        fidelity_input_before = fidelity_input_path.read_bytes()
        fidelity_manifest_before = fidelity_manifest_path.read_bytes()
        fidelity_input = json.loads(fidelity_input_before)
        fidelity_input["review_contract"] = "forged but internally rehashed"
        fidelity_input["fidelity_input_sha256"] = stable_hash(
            {
                key: value
                for key, value in fidelity_input.items()
                if key != "fidelity_input_sha256"
            },
            64,
        )
        fidelity_input_path.write_text(
            json.dumps(fidelity_input, indent=2) + "\n", encoding="utf-8"
        )
        fidelity_manifest = json.loads(fidelity_manifest_before)
        for locked_file in fidelity_manifest["locked_files"]:
            if locked_file["path"] == "fidelity-input.json":
                locked_file["sha256"] = file_sha256(fidelity_input_path)
        fidelity_manifest["bundle_manifest_sha256"] = stable_hash(
            {
                key: value
                for key, value in fidelity_manifest.items()
                if key != "bundle_manifest_sha256"
            },
            64,
        )
        fidelity_manifest_path.write_text(
            json.dumps(fidelity_manifest, indent=2) + "\n", encoding="utf-8"
        )
        with self.assertRaisesRegex(
            ValueError, "fidelity input differs from canonical reconstruction"
        ):
            seal_delivery(self.package)
        fidelity_input_path.write_bytes(fidelity_input_before)
        fidelity_manifest_path.write_bytes(fidelity_manifest_before)
        complete_delivery_reviews(self.package)
        reader_path = (
            self.package
            / "delivery"
            / current["build_path"]
            / "reviews"
            / "reader"
            / "reader-review.json"
        )
        reader = json.loads(reader_path.read_text(encoding="utf-8"))
        fidelity_path = reader_path.parents[1] / "fidelity" / "fidelity-review.json"
        fidelity = json.loads(fidelity_path.read_text(encoding="utf-8"))
        original_agent = reader["independent_agent_id"]
        original_context = reader["independent_context_id"]
        original_manifest = reader["input_manifest_sha256"]
        reader["independent_agent_id"] = fidelity["independent_agent_id"]
        reader_path.write_text(json.dumps(reader, indent=2) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(
            ValueError, "fidelity and reader reviews must use different agents"
        ):
            seal_delivery(self.package)
        reader["independent_agent_id"] = original_agent
        reader["independent_context_id"] = fidelity["independent_context_id"]
        reader_path.write_text(json.dumps(reader, indent=2) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(
            ValueError, "fidelity and reader reviews must use different contexts"
        ):
            seal_delivery(self.package)
        reader["independent_context_id"] = original_context
        reader["input_manifest_sha256"] = "f" * 64
        reader_path.write_text(json.dumps(reader, indent=2) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(
            ValueError, "reader review is not bound to its review bundle"
        ):
            seal_delivery(self.package)
        reader["input_manifest_sha256"] = original_manifest
        reader_path.write_text(json.dumps(reader, indent=2) + "\n", encoding="utf-8")
        result = seal_delivery(self.package)
        self.assertEqual(result["status"], "pass")
        self.assertTrue(Path(result["workbook"]).is_file())
        delivery_manifest = json.loads(
            (build_dir / "delivery-manifest.json").read_text(encoding="utf-8")
        )
        delivery_seal = json.loads(
            (build_dir / "delivery-seal.json").read_text(encoding="utf-8")
        )
        self.assertEqual(
            file_sha256(fidelity_path),
            delivery_manifest["fidelity_review_file_sha256"],
        )
        self.assertEqual(
            file_sha256(reader_path),
            delivery_manifest["reader_review_file_sha256"],
        )
        self.assertEqual(
            delivery_manifest["fidelity_review_file_sha256"],
            delivery_seal["fidelity_review_file_sha256"],
        )
        self.assertEqual(
            delivery_manifest["reader_review_file_sha256"],
            delivery_seal["reader_review_file_sha256"],
        )


if __name__ == "__main__":
    unittest.main()
