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

from gtm_audit_contract import (  # noqa: E402
    DECISION_CLASSES,
    HUMAN_DECISION_LABELS,
    OPERATION_ACTION_FIELDS,
)
from gtm_audit_package_build import build_package  # noqa: E402
from gtm_canonical_record import build_canonical_record  # noqa: E402
from gtm_cleanroom_audit import checkpoint_audit, seal_audit  # noqa: E402
from gtm_delivery_mapper import create_delivery_map, seal_editorial  # noqa: E402
from gtm_delivery_reviews import scaffold_delivery_reviews, seal_delivery  # noqa: E402
from gtm_fixed_point import advance_fixed_point, start_fixed_point  # noqa: E402
from gtm_projection_review import (  # noqa: E402
    finalize_projection_reconciliation,
    scaffold_projection_reconciliation,
    seal_projection_review,
)
from gtm_reconciliation import (  # noqa: E402
    canonical_matches_allowed,
    finalize_reconciliation,
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
            "operation_proposal": None,
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


def complete_audit(package: Path, audit_id: str, *, actionable_priority: bool = False) -> None:
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
    seal_audit(package, audit_id)


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
        payload["independent_context_id"] = context_id
        payload["host_isolation_receipt"] = {
            "status": "enforced",
            "receipt_id": f"fixture-projection-receipt-{review_id}-{cycle:02d}",
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
        with self.assertRaisesRegex(ValueError, "cannot reuse one reasoning-context"):
            complete_checkpoint(self.package, "audit-b", "shared-context-test-001")

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
        with self.assertRaisesRegex(ValueError, "neutral context identity is reused"):
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
            "decision": {"decision_class": "incorrect_configuration"},
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
        result = seal_delivery(self.package)
        self.assertEqual(result["status"], "pass")
        self.assertTrue(Path(result["workbook"]).is_file())


if __name__ == "__main__":
    unittest.main()
