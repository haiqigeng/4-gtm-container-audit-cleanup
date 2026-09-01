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
from gtm_audit_contract import (  # noqa: E402
    DECISION_CLASSES,
    HUMAN_DECISION_LABELS,
    OPERATION_ACTION_FIELDS,
)
from gtm_audit_package_build import build_package  # noqa: E402
from gtm_audit_work_units import merge_work_units  # noqa: E402
from gtm_canonical_record import (  # noqa: E402
    build_canonical_record,
    canonical_record_seal_errors,
)
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
from gtm_target_synthesis import compile_operation_packet  # noqa: E402


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
            "client": [],
            "transformation": [],
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


def complete_checkpoint(package: Path, audit_id: str, context_id: str) -> None:
    path = package / "audit-bundles" / audit_id / "source-checkpoint.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    bundle_manifest = json.loads((path.parent / "bundle-manifest.json").read_text(encoding="utf-8"))
    payload["status"] = "complete"
    payload["independent_context_id"] = context_id
    payload["host_isolation_receipt"] = {
        "status": "enforced",
        "receipt_id": f"fixture-host-receipt-{audit_id}",
        "mechanism": "orchestrator_scoped_context",
        "allowed_bundle_manifest_sha256": bundle_manifest["bundle_manifest_sha256"],
        "other_audit_accessible": False,
        "prohibited_artifacts_accessible": False,
    }
    for row in payload["object_behavior_map"]:
        row["configured_role"] = (
            "Fixture source object role recorded from its locked configuration."
        )
        row["current_configured_behavior"] = (
            "The locked fixture object has only the configuration visible at its source path."
        )
        row["evidence_coordinates"] = [row["source_json_path"]]
    payload["singleton_object_keys"] = [row["object_key"] for row in payload["object_behavior_map"]]
    if audit_id == "audit-a":
        scan = json.loads((package / "canonical-scan.json").read_text(encoding="utf-8"))
        payload["generated_candidate_ids_reviewed"] = [
            row["comparison_id"] for row in scan["architecture_evidence"]["relationships"]
        ]
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
        "host_scope_preserved_through_completion": True,
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
    receipt_id: str,
) -> None:
    path = package / "audit-bundles" / audit_id / "audit.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    manifest = json.loads(
        (path.parent / "bundle-manifest.json").read_text(encoding="utf-8")
    )
    payload["independent_context_id"] = context_id
    payload["amendment_parent_seal_sha256"] = parent_seal_sha256
    payload["host_isolation_receipt"] = {
        "status": "enforced",
        "receipt_id": receipt_id,
        "mechanism": "orchestrator_scoped_context",
        "allowed_bundle_manifest_sha256": manifest["bundle_manifest_sha256"],
        "other_audit_accessible": False,
        "prohibited_artifacts_accessible": False,
        "amendment_parent_seal_sha256": parent_seal_sha256,
    }
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def complete_base_reconciliation(
    package: Path, neutral_context_override: str | None = None
) -> None:
    scaffold_reconciliation(package)
    reconciliation_path = package / "reconciliation.json"
    neutral_path = package / "neutral-verification.json"
    reconciliation = json.loads(reconciliation_path.read_text(encoding="utf-8"))
    neutral = json.loads(neutral_path.read_text(encoding="utf-8"))
    neutral_by_id = {}
    for index, row in enumerate(neutral["verifications"], start=1):
        comparison = next(
            item
            for item in reconciliation["comparisons"]
            if item["neutral_verification_id"] == row["verification_id"]
        )
        decision = copy.deepcopy(comparison["audit_decisions"]["audit-a"])
        row.update(
            {
                "status": "complete",
                "independent_context_id": (
                    neutral_context_override
                    if index == 1 and neutral_context_override
                    else f"neutral-test-context-{index:03d}"
                ),
                "host_isolation_receipt": {
                    "status": "enforced",
                    "receipt_id": f"neutral-test-receipt-{index:03d}",
                    "mechanism": "orchestrator_scoped_context",
                    "allowed_bundle_manifest_sha256": row[
                        "neutral_bundle_manifest_sha256"
                    ],
                    "prior_reasoning_contexts_accessible": False,
                    "peer_neutral_contexts_accessible": False,
                    "prohibited_artifacts_accessible": False,
                },
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
    neutral_context_override: str | None = None,
    *,
    force_neutral: bool = False,
    review_context_override: str | None = None,
    review_receipt_override: str | None = None,
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
        payload["independent_context_id"] = (
            review_context_override
            if review_id == "review-a" and review_context_override
            else context_id
        )
        payload["host_isolation_receipt"] = {
            "status": "enforced",
            "receipt_id": (
                review_receipt_override
                if review_id == "review-a" and review_receipt_override
                else f"fixture-projection-receipt-{review_id}-{cycle:02d}"
            ),
            "mechanism": "orchestrator_scoped_context",
            "allowed_bundle_manifest_sha256": manifest["bundle_manifest_sha256"],
            "peer_review_accessible": False,
            "prohibited_artifacts_accessible": False,
        }
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
            "host_scope_preserved_through_completion": True,
            "conclusion": "The focused projection fixture review completed every changed obligation independently.",
        }
        path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        seal_projection_review(package, cycle, review_id)
    scaffold_projection_reconciliation(cycle_dir)
    rec_path = cycle_dir / "projection-reconciliation.json"
    neutral_path = cycle_dir / "projection-neutral-verification.json"
    reconciliation = json.loads(rec_path.read_text(encoding="utf-8"))
    neutral = json.loads(neutral_path.read_text(encoding="utf-8"))
    neutral_by_id = {}
    for index, row in enumerate(neutral["verifications"], start=1):
        comparison = next(
            item
            for item in reconciliation["comparisons"]
            if item["neutral_verification_id"] == row["verification_id"]
        )
        decision = copy.deepcopy(comparison["review_decisions"]["review-a"])
        row.update(
            {
                "status": "complete",
                "independent_context_id": (
                    neutral_context_override
                    if index == 1 and neutral_context_override
                    else f"projection-neutral-{cycle:02d}-{index:03d}"
                ),
                "host_isolation_receipt": {
                    "status": "enforced",
                    "receipt_id": (
                        f"projection-neutral-receipt-{cycle:02d}-{index:03d}"
                    ),
                    "mechanism": "orchestrator_scoped_context",
                    "allowed_bundle_manifest_sha256": row[
                        "neutral_bundle_manifest_sha256"
                    ],
                    "prior_reasoning_contexts_accessible": False,
                    "peer_neutral_contexts_accessible": False,
                    "prohibited_artifacts_accessible": False,
                },
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
    payload["independent_context_id"] = "fixture-editorial-context-001"
    payload["completion_attestation"] = {
        "fresh_editorial_context": True,
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
    fidelity["independent_context_id"] = "fixture-fidelity-context-001"
    fidelity["host_isolation_receipt"] = {
        "status": "enforced",
        "receipt_id": "fixture-fidelity-receipt-001",
        "mechanism": "orchestrator_scoped_context",
        "allowed_bundle_manifest_sha256": fidelity_manifest["bundle_manifest_sha256"],
        "peer_review_accessible": False,
        "prohibited_artifacts_accessible": False,
    }
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
    reader["independent_context_id"] = "fixture-reader-context-001"
    reader["host_isolation_receipt"] = {
        "status": "enforced",
        "receipt_id": "fixture-reader-receipt-001",
        "mechanism": "orchestrator_scoped_context",
        "allowed_bundle_manifest_sha256": reader_manifest["bundle_manifest_sha256"],
        "peer_review_accessible": False,
        "prohibited_artifacts_accessible": False,
    }
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
        self.assertEqual([], checkpoint["generated_candidate_ids_reviewed"])

    def test_cleanroom_checkpoints_cannot_reuse_one_reasoning_context(self) -> None:
        build_package(self.export, self.package)
        complete_checkpoint(self.package, "audit-a", "shared-context-test-001")
        with self.assertRaisesRegex(
            ValueError, "reasoning context identity is already used"
        ):
            complete_checkpoint(self.package, "audit-b", "shared-context-test-001")

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
        seal_b = json.loads(
            (self.package / "audit-seals" / "audit-b.json").read_text(
                encoding="utf-8"
            )
        )
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
            context_id="fresh-amendment-context-001",
            receipt_id=seal_b["host_isolation_receipt"]["receipt_id"],
        )
        with self.assertRaisesRegex(
            ValueError, "host isolation receipt identity is already used"
        ):
            seal_audit(self.package, "audit-a", amendment_of=parent)

        write_audit_amendment(
            self.package,
            "audit-a",
            parent_seal_sha256=parent,
            context_id=seal_b["independent_context_id"],
            receipt_id="fresh-amendment-receipt-001",
        )
        with self.assertRaisesRegex(
            ValueError, "reasoning context identity is already used"
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
            receipt_id="fresh-amendment-receipt-001",
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
            receipt_id="fresh-amendment-receipt-002",
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
            receipt_id="sharded-amendment-fresh-receipt-001",
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

    def test_neutral_verifier_cannot_reuse_a_source_audit_context(self) -> None:
        self.export.write_text(json.dumps(actionable_priority_export()), encoding="utf-8")
        build_package(self.export, self.package)
        complete_checkpoint(self.package, "audit-a", "neutral-source-a-checkpoint")
        complete_checkpoint(self.package, "audit-b", "neutral-source-b-checkpoint")
        complete_audit(self.package, "audit-a", actionable_priority=True)
        complete_audit(self.package, "audit-b", actionable_priority=True)
        audit_a_seal = json.loads(
            (self.package / "audit-seals" / "audit-a.json").read_text(
                encoding="utf-8"
            )
        )
        with self.assertRaisesRegex(
            ValueError, "(?:neutral context identity|reasoning context identity).*reused"
        ):
            complete_base_reconciliation(
                self.package,
                str(audit_a_seal["independent_context_id"]),
            )

    def test_projection_neutral_cannot_reuse_prior_reasoning_context(self) -> None:
        self.export.write_text(json.dumps(actionable_priority_export()), encoding="utf-8")
        build_package(self.export, self.package)
        complete_checkpoint(self.package, "audit-a", "projection-source-a-checkpoint")
        complete_checkpoint(self.package, "audit-b", "projection-source-b-checkpoint")
        complete_audit(self.package, "audit-a", actionable_priority=True)
        complete_audit(self.package, "audit-b", actionable_priority=True)
        complete_base_reconciliation(self.package)
        compile_operation_packet(self.package)
        result = start_fixed_point(self.package)
        self.assertEqual("awaiting_projection_reviews", result["status"])
        audit_a_context = json.loads(
            (self.package / "audit-seals" / "audit-a.json").read_text(
                encoding="utf-8"
            )
        )["independent_context_id"]
        with self.assertRaisesRegex(ValueError, "neutral context identity is reused"):
            complete_projection_cycle(
                self.package,
                int(result["cycle"]),
                str(audit_a_context),
                force_neutral=True,
            )

    def _assert_projection_review_rejects_base_neutral_identity(
        self, identity_kind: str
    ) -> None:
        package = self.root / f"projection-{identity_kind}-reuse"
        self.export.write_text(json.dumps(actionable_priority_export()), encoding="utf-8")
        build_package(self.export, package)
        complete_checkpoint(package, "audit-a", f"{identity_kind}-source-a-context")
        complete_checkpoint(package, "audit-b", f"{identity_kind}-source-b-context")
        complete_audit(package, "audit-a", actionable_priority=True)
        complete_audit(package, "audit-b", actionable_priority=True)
        complete_base_reconciliation(package)
        neutral = json.loads(
            (package / "neutral-verification.json").read_text(encoding="utf-8")
        )
        self.assertTrue(neutral["verifications"])
        prior = neutral["verifications"][0]
        compile_operation_packet(package)
        result = start_fixed_point(package)
        self.assertEqual("awaiting_projection_reviews", result["status"])
        kwargs = {
            "review_context_override": prior["independent_context_id"]
            if identity_kind == "context"
            else None,
            "review_receipt_override": prior["host_isolation_receipt"]["receipt_id"]
            if identity_kind == "receipt"
            else None,
        }
        expected = (
            "reasoning context identity is already used"
            if identity_kind == "context"
            else "host isolation receipt identity is already used"
        )
        with self.assertRaisesRegex(ValueError, expected):
            complete_projection_cycle(
                package,
                int(result["cycle"]),
                **kwargs,
            )

    def test_projection_review_cannot_reuse_base_neutral_context(self) -> None:
        self._assert_projection_review_rejects_base_neutral_identity("context")

    def test_projection_review_cannot_reuse_base_neutral_receipt(self) -> None:
        self._assert_projection_review_rejects_base_neutral_identity("receipt")

    def test_editorial_amendment_cannot_reuse_source_audit_context(self) -> None:
        self.run_actionable_to_editorial()
        editorial_path = self.package / "delivery" / "editorial.json"
        editorial = json.loads(editorial_path.read_text(encoding="utf-8"))
        source_seal = json.loads(
            (self.package / "audit-seals" / "audit-a.json").read_text(
                encoding="utf-8"
            )
        )
        current_seal = json.loads(
            (self.package / "delivery" / "editorial-seal.json").read_text(
                encoding="utf-8"
            )
        )
        editorial["independent_context_id"] = source_seal["independent_context_id"]
        editorial_path.write_text(
            json.dumps(editorial, indent=2) + "\n", encoding="utf-8"
        )
        with self.assertRaisesRegex(
            ValueError, "reasoning context identity is already used"
        ):
            seal_editorial(
                self.package,
                amendment_of=current_seal["editorial_seal_sha256"],
            )

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
        verification = json.loads(
            (
                self.package / "delivery" / current["build_path"] / "technical-verification.json"
            ).read_text(encoding="utf-8")
        )
        self.assertTrue(verification["comment_checks"])
        self.assertTrue(all(row["status"] == "pass" for row in verification["comment_checks"]))
        scaffold_delivery_reviews(self.package)
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
        original_context = reader["independent_context_id"]
        original_receipt = reader["host_isolation_receipt"]["receipt_id"]
        source_seal = json.loads(
            (self.package / "audit-seals" / "audit-a.json").read_text(
                encoding="utf-8"
            )
        )
        reader["host_isolation_receipt"]["receipt_id"] = source_seal[
            "host_isolation_receipt"
        ]["receipt_id"]
        reader_path.write_text(json.dumps(reader, indent=2) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(
            ValueError, "host isolation receipt identity is already used"
        ):
            seal_delivery(self.package)
        reader["host_isolation_receipt"]["receipt_id"] = original_receipt
        reader["independent_context_id"] = source_seal["independent_context_id"]
        reader_path.write_text(json.dumps(reader, indent=2) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(
            ValueError, "reasoning context identity is already used"
        ):
            seal_delivery(self.package)
        reader["independent_context_id"] = original_context
        reader_path.write_text(json.dumps(reader, indent=2) + "\n", encoding="utf-8")
        result = seal_delivery(self.package)
        self.assertEqual(result["status"], "pass")
        self.assertTrue(Path(result["workbook"]).is_file())


if __name__ == "__main__":
    unittest.main()
