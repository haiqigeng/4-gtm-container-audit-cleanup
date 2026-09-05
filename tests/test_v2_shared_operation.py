"""Focused regressions for separately evidenced obligations sharing one operation."""
from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from test_v2_workflow import (
    CANONICAL_DECISION_FIELDS,
    OPERATION_ACTION_FIELDS,
    apply_plan,
    build_canonical_record,
    build_package,
    canonical_record_seal_errors,
    compile_operation_packet,
    complete_base_reconciliation,
    complete_checkpoint,
    complete_priority_removal_decision,
    create_delivery_map,
    minimal_export,
    seal_audit,
    validate_audit,
    validate_target,
    write_fixture_audit_plan,
)

from gtm_audit_plan import _author_decisions
from gtm_delivery_mapper import (
    AUDIT_AREA_CATEGORIES,
    _audit_area_category,
    display_prose_defaults,
)
from gtm_target_synthesis import build_operation_packet_payloads


class SharedOperationWorkflowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.package = self.root / "package"
        source = minimal_export()
        source["containerVersion"]["variable"] = [{
            "variableId": "21", "name": "Unused Variable", "type": "c",
            "parameter": [{"type": "TEMPLATE", "key": "value", "value": "unused"}],
        }]
        export = self.root / "source.json"
        export.write_text(json.dumps(source), encoding="utf-8")
        build_package(export, self.package)

    def shared_plan(self, audit_id: str, *, profile: bool = False) -> tuple:
        complete_checkpoint(self.package, audit_id, f"shared-{audit_id}-context")
        plan_path = write_fixture_audit_plan(self.package, audit_id)
        plan = json.loads(plan_path.read_text(encoding="utf-8"))
        audit_path = self.package / "audit-bundles" / audit_id / "audit.json"
        audit = json.loads(audit_path.read_text(encoding="utf-8"))
        owners = [row for row in audit["decisions"] if row["subject_keys"] == ["variable:21"]]
        self.assertEqual(
            {"unused_object", "naming_architecture_mismatch", "unfiled_objects"},
            {row["fact_kind"] for row in owners},
        )
        self.assertEqual(3, len(owners))
        authored = copy.deepcopy(owners[0])
        complete_priority_removal_decision(authored, audit["source_sha256"])
        authored.update({
            "current_behavior": "An unused constant remains under a nonstandard name.",
            "criteria_assessment": "No consumers require this variable or its name.",
            "consequence_or_benefit": "Deletion removes unused configuration and its naming mismatch.",
            "preserved_distinctions": "All other objects and their references remain unchanged.",
            "target_direction": "Delete variable:21.",
            "next_step": "Review the exact variable deletion.",
        })
        authored["operation_proposal"] = {
            "operation_id": "OP-DELETE-UNUSED-VARIABLE",
            "operation_family": "Remove unused variable",
            "exact_target_state": "variable:21 is absent.",
            "preconditions": "variable:21 is the locked unused constant with no consumers.",
            "static_verification": "Confirm variable:21 is absent and all references resolve.",
            "rollback": "Restore variable:21 from the locked source.",
            "depends_on": [],
            **{field: [] for field in OPERATION_ACTION_FIELDS},
            "deletions": [{"object_key": "variable:21"}],
        }
        decision = {field: authored[field] for field in CANONICAL_DECISION_FIELDS
                    if field not in {"static_verification", "rollback"}}
        decision["operation_proposal"] = authored["operation_proposal"]
        owner_ids = {row["obligation_id"] for row in owners}
        if profile:
            groups = [row for row in plan["candidate_groups"] if set(row["obligation_ids"]) & owner_ids]
            self.assertEqual(owner_ids, {oid for row in groups for oid in row["obligation_ids"]})
            group_ids = {row["group_id"] for row in groups}
            for row in plan["decision_profiles"]:
                row["candidate_group_ids"] = [gid for gid in row["candidate_group_ids"] if gid not in group_ids]
            plan["decision_profiles"] = [row for row in plan["decision_profiles"] if row["candidate_group_ids"]]
            plan["decision_profiles"].append({"profile_id": "shared-delete", "candidate_group_ids": sorted(group_ids), "decision": decision})
        else:
            plan["obligation_overrides"].append({"override_id": "shared-delete", "obligation_ids": sorted(owner_ids), "decision": decision})
        return plan_path, audit_path, plan, owners

    def test_shared_deletion_from_profile_and_override_retains_all_findings(self) -> None:
        for audit_id, profile in (("audit-a", True), ("audit-b", False)):
            plan_path, audit_path, plan, owners = self.shared_plan(audit_id, profile=profile)
            plan_path.write_text(json.dumps(plan), encoding="utf-8")
            apply_plan(audit_path.parent, plan_path)
            self.assertEqual([], validate_audit(self.package, audit_id))
            completed = json.loads(audit_path.read_text(encoding="utf-8"))
            actual = [row for row in completed["decisions"] if row["obligation_id"] in {o["obligation_id"] for o in owners}]
            self.assertEqual(3, len(actual))
            for row in actual:
                self.assertEqual(row["decision_id"], row["operation_proposal"]["source_decision_id"])
                self.assertEqual(row["source_coordinates"], row["evidence_citations"])
            # A shared operation never excuses an incomplete contributing finding.
            broken = copy.deepcopy(completed)
            next(row for row in broken["decisions"] if row["decision_id"] == actual[1]["decision_id"])["criteria_assessment"] = ""
            audit_path.write_text(json.dumps(broken), encoding="utf-8")
            errors = validate_audit(self.package, audit_id)
            self.assertTrue(any(actual[1]["decision_id"] in error and "criteria_assessment" in error for error in errors), errors)
            audit_path.write_text(json.dumps(completed), encoding="utf-8")
            seal_audit(self.package, audit_id)
        complete_base_reconciliation(self.package)
        packet, projected = build_operation_packet_payloads(self.package)
        self.assertEqual([], projected["containerVersion"]["variable"])
        self.assertEqual(1, len(packet["operations"]))
        operation = packet["operations"][0]
        record = json.loads((self.package / "reconciled-decisions.json").read_text(encoding="utf-8"))
        findings = [row for row in record["canonical_decisions"] if row["decision"].get("operation_proposal")]
        self.assertEqual(3, len(findings))
        expected_ids = sorted(row["canonical_decision_id"] for row in findings)
        self.assertEqual(expected_ids, operation["source_reconciled_decision_ids"])
        self.assertEqual({cid: operation["operation_id"] for cid in expected_ids}, packet["decision_to_operation"])

        self.assertEqual(1, compile_operation_packet(self.package)["operations"])
        self.assertEqual("pass", validate_target(self.package)["status"])
        build_canonical_record(self.package)
        self.assertEqual([], canonical_record_seal_errors(self.package))
        canonical = json.loads((self.package / "canonical-record.json").read_text(encoding="utf-8"))
        self.assertEqual(1, canonical["summary"]["operation_count"])
        self.assertEqual(expected_ids, canonical["operations"][0]["source_reconciled_decision_ids"])
        retained = [row for row in canonical["audit_decisions"] if row["canonical_decision_id"] in expected_ids]
        self.assertEqual(3, len(retained))
        self.assertEqual(
            {"unused_object", "naming_architecture_mismatch", "unfiled_objects"},
            {row["fact_kind"] for row in retained},
        )
        create_delivery_map(self.package)
        delivery = json.loads((self.package / "delivery" / "delivery-map.json").read_text(encoding="utf-8"))
        recommendations = [row for row in delivery["rows"] if row["primary_sheet"] == "02 Recommendations"]
        self.assertEqual(1, len(recommendations))
        recommendation = recommendations[0]
        self.assertEqual(expected_ids, recommendation["locked"]["source_decision_ids"])
        self.assertEqual(
            sorted({row["area_id"] for row in retained}),
            recommendation["locked"]["source_audit_areas"],
        )
        coverage = delivery["coverage"]
        self.assertEqual([operation["operation_id"]], coverage["recommendation_operation_ids"])
        self.assertEqual(
            {row["canonical_decision_id"] for row in canonical["audit_decisions"]},
            set(coverage["primary_decision_owner"]),
        )
        for finding in retained:
            cid = finding["canonical_decision_id"]
            self.assertIn(cid, coverage["full_audit_decision_ids"])
            self.assertEqual("04 Full Audit", coverage["primary_decision_owner"][cid])
            rows = [row for row in delivery["rows"] if row["locked"].get("decision_id") == cid]
            self.assertEqual(1, len(rows))
            self.assertEqual(finding["fact_kind"], rows[0]["locked"]["fact_kind"])
            self.assertEqual(operation["operation_id"], rows[0]["locked"]["operation_id"])
            self.assertEqual(
                _audit_area_category(finding),
                rows[0]["canonical_prose"]["audit_area"],
            )
        # Equal source priorities use stable decision identity for the primary filter.
        primary = min(retained, key=lambda row: row["canonical_decision_id"])
        self.assertEqual(AUDIT_AREA_CATEGORIES[primary["area_id"]], recommendation["canonical_prose"]["audit_area"])
        display = display_prose_defaults(delivery)
        for sheet in ("02 Recommendations", "04 Full Audit"):
            self.assertEqual("Audit area", display["sheets"][sheet]["headers"][1])

    def test_source_audit_rejects_shared_priority_confidence_and_class_conflicts(self) -> None:
        plan_path, audit_path, plan, owners = self.shared_plan("audit-a")
        plan_path.write_text(json.dumps(plan), encoding="utf-8")
        apply_plan(audit_path.parent, plan_path)
        self.assertEqual([], validate_audit(self.package, "audit-a"))
        completed = json.loads(audit_path.read_text(encoding="utf-8"))
        owner_ids = {row["decision_id"] for row in owners}
        for field, value in {"priority": "High", "confidence": "Medium", "decision_class": "defect"}.items():
            with self.subTest(field=field):
                broken = copy.deepcopy(completed)
                shared = [row for row in broken["decisions"] if row["decision_id"] in owner_ids]
                shared[1][field] = value
                audit_path.write_text(json.dumps(broken), encoding="utf-8")
                errors = validate_audit(self.package, "audit-a")
                self.assertTrue(any(
                    shared[1]["decision_id"] in error and "contradictory operation semantics" in error
                    for error in errors
                ), errors)
        audit_path.write_text(json.dumps(completed), encoding="utf-8")
        self.assertEqual([], validate_audit(self.package, "audit-a"))

    def test_shared_plan_rejects_contradictions_and_distinct_duplicate_actions_before_writing(self) -> None:
        plan_path, audit_path, plan, owners = self.shared_plan("audit-a")
        before = audit_path.read_bytes()
        shared = plan["obligation_overrides"].pop()
        for index, owner in enumerate(owners):
            plan["obligation_overrides"].append({**copy.deepcopy(shared), "override_id": f"owner-{index}", "obligation_ids": [owner["obligation_id"]]})
        for field, value in {
            "exact_target_state": "Keep a renamed variable instead.",
            "depends_on": ["OP-PREPARE"],
            "deletions": [],
            "operation_id": "OP-SECOND-DELETE",
        }.items():
            with self.subTest(field=field):
                invalid = copy.deepcopy(plan)
                invalid["obligation_overrides"][1]["decision"]["operation_proposal"][field] = value
                plan_path.write_text(json.dumps(invalid), encoding="utf-8")
                with self.assertRaises(ValueError):
                    apply_plan(audit_path.parent, plan_path)
                self.assertEqual(before, audit_path.read_bytes())

    def test_shared_authoring_validates_each_obligations_own_citations(self) -> None:
        _, audit_path, plan, owners = self.shared_plan("audit-a")
        audit = json.loads(audit_path.read_text(encoding="utf-8"))
        locked = {row["obligation_id"]: row for row in audit["decisions"]}
        # Give the three fixture obligations distinct coordinate allowlists.
        for field, owner in zip(("variableId", "name", "type"), owners, strict=True):
            locked[owner["obligation_id"]]["source_coordinates"] = [
                f"$.containerVersion.variable[0].{field}"
            ]
        authored, _, errors = _author_decisions(locked, plan)
        self.assertEqual([], errors)
        for owner in owners:
            oid = owner["obligation_id"]
            self.assertEqual(locked[oid]["source_coordinates"], authored[oid]["evidence_citations"])
        plan["obligation_overrides"][0]["decision"]["evidence_citations"] = locked[owners[0]["obligation_id"]]["source_coordinates"]
        _, _, errors = _author_decisions(locked, plan)
        self.assertTrue(any(owners[1]["decision_id"] in error and "citations" in error for error in errors), errors)


if __name__ == "__main__":
    unittest.main()
