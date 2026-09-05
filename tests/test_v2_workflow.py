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
import gtm_delivery_mapper as delivery_mapper  # noqa: E402
import gtm_delivery_reviews as delivery_reviews  # noqa: E402
import gtm_reconciliation as reconciliation_module  # noqa: E402
from gtm_audit_contract import (  # noqa: E402
    CANONICAL_DECISION_FIELDS,
    DECISION_CLASSES,
    HUMAN_DECISION_LABELS,
    OPERATION_ACTION_FIELDS,
)
from gtm_audit_package_build import build_package as executable_build_package  # noqa: E402
from gtm_audit_plan import (  # noqa: E402
    MAX_OBLIGATIONS_PER_CANDIDATE_GROUP,
    _candidate_decision_groups,
    apply_plan,
    scaffold_plan,
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
from gtm_lib import file_sha256, locked_evidence_coordinates, stable_hash  # noqa: E402
from gtm_reconciliation import (  # noqa: E402
    canonical_matches_allowed,
    finalize_reconciliation,
    reconciliation_seal_errors,
    scaffold_reconciliation,
)
from gtm_scan_assurance import assure_scan  # noqa: E402
from gtm_target_synthesis import compile_operation_packet  # noqa: E402
from gtm_target_validation import validate_target  # noqa: E402


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
            "blockingTriggerId": ["11"],
            "priority": {"type": "INTEGER", "value": "10"},
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
        },
        {
            "triggerId": "11",
            "name": "Block - analytics denied",
            "type": "CUSTOM_EVENT",
            "filter": [
                {
                    "type": "DOES_NOT_CONTAIN",
                    "parameter": [
                        {
                            "type": "TEMPLATE",
                            "key": "arg0",
                            "value": "didomi.enabledVendors",
                        },
                        {"type": "TEMPLATE", "key": "arg1", "value": "google"},
                    ],
                }
            ],
        },
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


def fixture_decision_profiles(plan: dict, decisions: list[dict], prefix: str) -> list[dict]:
    applicability_by_id = {
        str(row["obligation_id"]): str(row["applicability"]) for row in decisions
    }
    grouped: dict[str, list[str]] = {}
    for candidate in plan["candidate_groups"]:
        values = {
            applicability_by_id[obligation_id]
            for obligation_id in candidate["obligation_ids"]
        }
        assert len(values) == 1
        grouped.setdefault(values.pop(), []).append(candidate["group_id"])
    return [
        {
            "profile_id": f"{prefix}-{index:02d}",
            "candidate_group_ids": grouped[applicability],
            "decision": fixture_plan_decision(applicability),
        }
        for index, applicability in enumerate(sorted(grouped), start=1)
    ]


def write_fixture_audit_plan(package: Path, audit_id: str) -> Path:
    bundle = package / "audit-bundles" / audit_id
    plan_path = package / "audit-scratch" / audit_id / "audit-plan.json"
    scaffold_plan(bundle, plan_path)
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    audit = json.loads((bundle / "audit.json").read_text(encoding="utf-8"))
    plan["decision_profiles"] = fixture_decision_profiles(
        plan, audit["decisions"], "fixture"
    )
    plan["global_shared_infrastructure_review"] = (
        "No shared infrastructure."
    )
    plan["global_target_architecture_review"] = (
        "Retain the empty target."
    )
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
    payload["source_only_conclusion"] = "No hidden input dependency."
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    checkpoint_audit(package, audit_id)


def complete_priority_removal_decision(row: dict, source_sha256: str) -> None:
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
                "Remove only priority from tag:1 and retain the complete event chain."
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
                "Confirm tag:1 no longer contains priority and every other tag field "
                "matches the locked source."
            ),
            "rollback": ("Restore priority with the original INTEGER parameter value 10 on tag:1."),
            "operation_proposal": {
                "operation_id": "OP-REMOVE-REDUNDANT-PRIORITY",
                "source_decision_id": row["decision_id"],
                "operation_family": "Remove redundant firing priority",
                "exact_target_state": (
                    "Tag tag:1 retains its complete configuration without the named "
                    "priority property."
                ),
                "preconditions": (
                    "Tag tag:1 still contains priority with the exact INTEGER parameter value 10."
                ),
                "static_verification": (
                    "Compare tag:1 and confirm only priority was removed."
                ),
                "rollback": ("Restore priority with the original INTEGER parameter value 10."),
                "depends_on": [],
                **{field: [] for field in OPERATION_ACTION_FIELDS},
                "removals": [
                    {
                        "object_key": "tag:1",
                        "json_path": "$.priority",
                        "before_source_sha256": source_sha256,
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
            complete_priority_removal_decision(row, payload["source_sha256"])
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
    unit_root = package / "reconciliation-units"
    manifest = json.loads((unit_root / "manifest.json").read_text(encoding="utf-8"))
    for record in manifest["units"]:
        unit_path = unit_root / record["filename"]
        unit = json.loads(unit_path.read_text(encoding="utf-8"))
        for row in unit["verifications"]:
            allowed = list(row.get("allowed_evidence_citations") or [])
            row.update(
                {
                    "status": "complete",
                    "selected_audit_id": "audit-a",
                    "evidence_citations": allowed[:1],
                    "verification_rationale": (
                        "The locked record directly supports this bounded conclusion."
                    ),
                }
            )
        unit_path.write_text(json.dumps(unit, indent=2) + "\n", encoding="utf-8")
    completion_path = package / "reconciliation-completion.json"
    completion = json.loads(completion_path.read_text(encoding="utf-8"))
    completion.update(
        {
            "independent_agent_id": agent_id,
            "independent_context_id": context_id,
            "status": "complete",
        }
    )
    completion_path.write_text(
        json.dumps(completion, indent=2) + "\n", encoding="utf-8"
    )
    finalize_reconciliation(package)


def complete_editorial(package: Path) -> None:
    path = package / "delivery" / "editorial.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["status"] = "complete"
    payload["completion_attestation"] = {
        "semantic_fields_changed": False,
        "technical_identifiers_preserved": True,
        "conclusion": "Canonical meaning preserved.",
    }
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    seal_editorial(package)


def complete_delivery_reviews(package: Path) -> None:
    current = json.loads((package / "delivery" / "current-build.json").read_text(encoding="utf-8"))
    root = package / "delivery" / current["build_path"] / "reviews"
    reader_path = root / "reader" / "reader-review.json"
    reader = json.loads(reader_path.read_text(encoding="utf-8"))
    reader_manifest = json.loads(
        (reader_path.parent / "bundle-manifest.json").read_text(encoding="utf-8")
    )
    reader["status"] = "complete"
    reader["independent_agent_id"] = "fixture-reader-agent-001"
    reader["independent_context_id"] = "fixture-reader-context-001"
    reader["input_manifest_sha256"] = reader_manifest["bundle_manifest_sha256"]
    reader["received_only_declared_review_inputs"] = True
    reader["reviewed_workbook_before_meaning_reference"] = True
    reader["compared_every_visible_row_to_canonical_meaning"] = True
    for row in reader["sheet_reviews"]:
        row.update(
            {
                "verdict": "pass",
                "standalone_and_clear": True,
                "next_action_clear": True,
                "wording_human_readable": True,
                "semantic_meaning_faithful": True,
                "content_specific_and_useful": True,
                "layout_legible": True,
                "navigation_usable": True,
                "issues": [],
            }
        )
    reader["completion_attestation"] = (
        "Workbook is readable and actionable."
    )
    reader_path.write_text(json.dumps(reader, indent=2) + "\n", encoding="utf-8")


class V2WorkflowTests(unittest.TestCase):
    def test_locked_evidence_coordinates_expose_exact_supplied_json_paths(self) -> None:
        self.assertEqual(
            [
                "$.containerVersion.tag[1]",
                "$.containerVersion.tag[1].parameter[0].value",
                "$.containerVersion.trigger[2]",
            ],
            locked_evidence_coordinates(
                ["$.containerVersion.tag[1]"],
                {
                    "source_json_path": "$.containerVersion.trigger[2]",
                    "evidence_anchors": [
                        "$.containerVersion.tag[1].parameter[0].value"
                    ],
                    "statement": "No path is inferred from this prose.",
                },
            ),
        )

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

    def test_workload_estimate_reflects_compact_exact_id_groups(self) -> None:
        build_package(self.export, self.package)
        complete_checkpoint(self.package, "audit-a", "compact-plan-context")
        manifest = json.loads(
            (
                self.package
                / "audit-bundles"
                / "audit-a"
                / "work-units"
                / "work-unit-manifest.json"
            ).read_text(encoding="utf-8")
        )
        estimate = manifest["workload_estimate"]
        scan = json.loads(
            (self.package / "canonical-scan.json").read_text(encoding="utf-8")
        )
        candidate_count = min(
            estimate["obligation_count"], scan["counts"]["operational_candidates"]
        )
        expected = (
            candidate_count * 90
            + (estimate["obligation_count"] - candidate_count) * 16
        )
        self.assertEqual(expected, estimate["estimated_authored_tokens"])

    def test_shared_infrastructure_is_bounded_without_splitting_obligations(self) -> None:
        build_package(self.export, self.package)
        with (
            mock.patch("gtm_audit_work_units.MAX_SINGLE_OBLIGATIONS", 1),
            mock.patch("gtm_audit_work_units.MAX_SHARED_AREA_OBLIGATIONS", 1),
        ):
            complete_checkpoint(self.package, "audit-a", "bounded-shared-context")
        manifest = json.loads(
            (
                self.package
                / "audit-bundles"
                / "audit-a"
                / "work-units"
                / "work-unit-manifest.json"
            ).read_text(encoding="utf-8")
        )
        shared = [
            row
            for row in manifest["work_units"]
            if row["owner_family_id"] == "shared-infrastructure"
        ]
        self.assertGreater(len(shared), 1)
        self.assertTrue(all(len(row["obligation_ids"]) == 1 for row in shared))
        all_ids = [
            obligation_id
            for row in manifest["work_units"]
            for obligation_id in row["obligation_ids"]
        ]
        self.assertEqual(len(all_ids), len(set(all_ids)))

    def test_audit_plan_rejects_a_path_outside_its_audit_scratch(self) -> None:
        build_package(self.export, self.package)
        complete_checkpoint(self.package, "audit-a", "plan-path-context")
        with self.assertRaisesRegex(ValueError, "isolated path"):
            scaffold_plan(
                self.package / "audit-bundles" / "audit-a",
                self.root / "guessed-plan.json",
            )

    def test_audit_plan_scaffolds_neutral_exact_once_candidate_groups(self) -> None:
        build_package(self.export, self.package)
        complete_checkpoint(self.package, "audit-a", "candidate-group-context")
        bundle = self.package / "audit-bundles" / "audit-a"
        plan_path = self.package / "audit-scratch" / "audit-a" / "audit-plan.json"
        plan = scaffold_plan(bundle, plan_path)
        audit = json.loads((bundle / "audit.json").read_text(encoding="utf-8"))
        obligation_ids = [
            obligation_id
            for group in plan["candidate_groups"]
            for obligation_id in group["obligation_ids"]
        ]
        self.assertEqual(
            sorted(row["obligation_id"] for row in audit["decisions"]),
            sorted(obligation_ids),
        )
        self.assertEqual(len(obligation_ids), len(set(obligation_ids)))
        self.assertEqual([], plan["decision_profiles"])
        self.assertEqual([], plan["obligation_overrides"])
        self.assertLessEqual(len(plan["candidate_groups"]), len(audit["decisions"]))

    def test_candidate_groups_are_deterministically_bounded(self) -> None:
        decisions = [
            {"obligation_id": f"OB-{index:03d}"}
            for index in range(MAX_OBLIGATIONS_PER_CANDIDATE_GROUP + 5)
        ]
        groups = _candidate_decision_groups(decisions)
        self.assertEqual(
            [MAX_OBLIGATIONS_PER_CANDIDATE_GROUP, 5],
            [len(group["obligation_ids"]) for group in groups],
        )
        self.assertEqual(
            [f"OB-{index:03d}" for index in range(MAX_OBLIGATIONS_PER_CANDIDATE_GROUP + 5)],
            [
                obligation_id
                for group in groups
                for obligation_id in group["obligation_ids"]
            ],
        )

    def test_audit_plan_applies_an_exact_actionable_group(self) -> None:
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
        complete_priority_removal_decision(authored, audit["source_sha256"])
        plan["obligation_overrides"].append(
            {
                "override_id": "priority-removal",
                "obligation_ids": [priority["obligation_id"]],
                "decision": {
                    field: authored[field] for field in CANONICAL_DECISION_FIELDS
                    if field not in {"static_verification", "rollback"}
                }
                | {"operation_proposal": {
                    field: value for field, value in authored["operation_proposal"].items()
                    if field != "source_decision_id" and value != []
                }},
            }
        )
        removal = plan["obligation_overrides"][-1]["decision"]["operation_proposal"][
            "removals"
        ][0]
        removal["json_path"] = "$.containerVersion.tag[0].priority"
        plan_path.write_text(json.dumps(plan, indent=2) + "\n", encoding="utf-8")
        before = audit_path.read_bytes()
        with self.assertRaisesRegex(ValueError, "audit operation safety gate failed"):
            apply_plan(audit_path.parent, plan_path)
        self.assertEqual(before, audit_path.read_bytes())

        removal["json_path"] = "$.priority"
        removal["before_source_sha256"] = "0" * 64
        plan_path.write_text(json.dumps(plan, indent=2) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "source reference"):
            apply_plan(audit_path.parent, plan_path)
        self.assertEqual(before, audit_path.read_bytes())
        removal["before_source_sha256"] = audit["source_sha256"]
        for location, field, value, expected in (
            ("decision", "rollback", "Duplicated prose.", "only inside operation_proposal"),
            ("proposal", "source_decision_id", "forged", "unsupported or derived fields"),
            ("proposal", "creations", {}, "creations must be a list"),
        ):
            with self.subTest(field=field):
                invalid = copy.deepcopy(plan)
                target = invalid["obligation_overrides"][-1]["decision"]
                if location == "proposal":
                    target = target["operation_proposal"]
                target[field] = value
                plan_path.write_text(json.dumps(invalid), encoding="utf-8")
                with self.assertRaisesRegex(ValueError, expected):
                    apply_plan(audit_path.parent, plan_path)
                self.assertEqual(before, audit_path.read_bytes())
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
        for field in ("static_verification", "rollback"):
            self.assertEqual(authored["operation_proposal"][field], result[field])
            self.assertEqual(result[field], result["operation_proposal"][field])
        self.assertEqual([], result["operation_proposal"]["creations"])
        self.assertEqual([], result["operation_proposal"]["depends_on"])
        self.assertEqual([], validate_audit(self.package, "audit-a"))

    def test_audit_plan_rejects_duplicate_obligation_assignment_before_writing(self) -> None:
        build_package(self.export, self.package)
        complete_checkpoint(self.package, "audit-a", "plan-ambiguous-context")
        plan_path = write_fixture_audit_plan(self.package, "audit-a")
        plan = json.loads(plan_path.read_text(encoding="utf-8"))
        plan["decision_profiles"].append(copy.deepcopy(plan["decision_profiles"][0]))
        plan["decision_profiles"][-1]["profile_id"] = "fixture-overlap"
        plan_path.write_text(json.dumps(plan, indent=2) + "\n", encoding="utf-8")
        audit_path = self.package / "audit-bundles" / "audit-a" / "audit.json"
        before = audit_path.read_bytes()

        with self.assertRaisesRegex(ValueError, "assigns candidate group more than once"):
            apply_plan(audit_path.parent, plan_path)

        self.assertEqual(before, audit_path.read_bytes())

    def test_audit_plan_rejects_non_actionable_proposals_before_writing(self) -> None:
        build_package(self.export, self.package)
        complete_checkpoint(self.package, "audit-a", "plan-non-actionable-context")
        plan_path = write_fixture_audit_plan(self.package, "audit-a")
        plan = json.loads(plan_path.read_text(encoding="utf-8"))
        audit_path = self.package / "audit-bundles" / "audit-a" / "audit.json"
        before = audit_path.read_bytes()
        for proposal in ({"source_decision_id": "forged", "creations": {}}, None, [], "discarded"):
            with self.subTest(proposal=proposal):
                plan["decision_profiles"][0]["decision"]["operation_proposal"] = proposal
                plan_path.write_text(json.dumps(plan), encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "non-actionable decision operation_proposal"):
                    apply_plan(audit_path.parent, plan_path)
                self.assertEqual(before, audit_path.read_bytes())

    def test_audit_plan_requires_exact_complete_groups(self) -> None:
        self.export.write_text(
            json.dumps(actionable_priority_export()), encoding="utf-8"
        )
        build_package(self.export, self.package)
        complete_checkpoint(self.package, "audit-a", "plan-specific-context")
        plan_path = write_fixture_audit_plan(self.package, "audit-a")
        audit_bundle = self.package / "audit-bundles" / "audit-a"
        plan = json.loads(plan_path.read_text(encoding="utf-8"))
        plan["decision_profiles"][0]["candidate_group_ids"].pop()
        plan_path.write_text(json.dumps(plan, indent=2) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "leaves obligations unassigned"):
            apply_plan(audit_bundle, plan_path)

    def test_audit_plan_rejects_changed_authoring_contract(self) -> None:
        build_package(self.export, self.package)
        complete_checkpoint(self.package, "audit-a", "plan-contract-context")
        plan_path = write_fixture_audit_plan(self.package, "audit-a")
        plan = json.loads(plan_path.read_text(encoding="utf-8"))
        plan["authoring_contract"]["every_obligation_id_exactly_once"] = False
        plan_path.write_text(json.dumps(plan, indent=2) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "authoring_contract differs"):
            apply_plan(self.package / "audit-bundles" / "audit-a", plan_path)

    def test_audit_plan_contract_exposes_nesting_vocabulary_and_discoveries(self) -> None:
        build_package(self.export, self.package)
        complete_checkpoint(self.package, "audit-a", "plan-self-describing-context")
        plan_path = write_fixture_audit_plan(self.package, "audit-a")
        plan = json.loads(plan_path.read_text(encoding="utf-8"))
        contract = plan["authoring_contract"]
        self.assertEqual(
            ["group_id", "obligation_ids"],
            contract["candidate_group_fields"],
        )
        self.assertEqual(
            ["candidate_group_ids", "decision", "profile_id"],
            contract["profile_fields"],
        )
        self.assertEqual(
            ["decision", "obligation_ids", "override_id"],
            contract["override_fields"],
        )
        self.assertIn("High", contract["priorities_case_sensitive"])
        self.assertIn("Evidence limited", contract["confidence_levels_case_sensitive"])
        self.assertEqual(
            r"OP-[A-Z0-9][A-Z0-9_-]{5,80}",
            contract["actionable_operation_contract"]["operation_id_pattern"],
        )
        self.assertRegex(
            contract["actionable_operation_contract"]["operation_id_example"],
            r"^OP-[A-Z0-9][A-Z0-9_-]{5,80}$",
        )
        self.assertEqual(
            ["operation_family", "exact_target_state", "preconditions", "static_verification", "rollback"],
            contract["actionable_operation_contract"][
                "required_nonblank_text_fields"
            ],
        )
        self.assertNotIn(
            "source_decision_id", contract["actionable_operation_contract"]["proposal_fields"]
        )
        self.assertEqual(
            ["static_verification", "rollback"],
            contract["actionable_operation_contract"]["decision_fields_projected_from_operation"],
        )
        for decision_class in ("defect", "correct_but_materially_non_optimal"):
            for field in ("static_verification", "rollback"):
                self.assertNotIn(field, contract["required_fields_by_class"][decision_class])
        self.assertTrue(
            contract["actionable_operation_contract"][
                "at_least_one_structured_action"
            ]
        )
        self.assertEqual(
            "list containing only OP-* operation IDs",
            contract["actionable_operation_contract"]["depends_on_rule"],
        )
        self.assertIn(
            "object-relative JSONPath",
            contract["actionable_operation_contract"]["action_json_path_rule"],
        )
        self.assertEqual([], contract["open_discoveries_contract"]["default"])
        self.assertTrue(
            contract["open_discoveries_contract"][
                "checkpoint_string_notes_are_not_plan_discoveries"
            ]
        )

    def test_audit_plan_rejects_flattened_groups_and_checkpoint_string_notes(self) -> None:
        build_package(self.export, self.package)
        complete_checkpoint(self.package, "audit-a", "plan-shape-context")
        plan_path = write_fixture_audit_plan(self.package, "audit-a")
        plan = json.loads(plan_path.read_text(encoding="utf-8"))
        group = plan["decision_profiles"][0]
        decision = group.pop("decision")
        group.update(decision)
        plan["open_discoveries"] = ["checkpoint-only note"]
        plan_path.write_text(json.dumps(plan, indent=2) + "\n", encoding="utf-8")
        audit_bundle = self.package / "audit-bundles" / "audit-a"
        before = (audit_bundle / "audit.json").read_bytes()

        with self.assertRaisesRegex(ValueError, "fields differ from the closed schema"):
            apply_plan(audit_bundle, plan_path)

        self.assertEqual(before, (audit_bundle / "audit.json").read_bytes())

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

    def test_package_identity_and_missing_source_fail_before_output_creation(self) -> None:
        cases = (
            (self.export, ["changed runtime file"], "runtime identity preflight"),
            (self.root / "absent-source.json", [], "confirmed GTM source does not exist"),
        )
        for index, (source, identity_errors, expected) in enumerate(cases):
            with self.subTest(expected=expected):
                output = self.root / f"preflight-{index}"
                with mock.patch(
                    "gtm_audit_package_build.declared_identity_errors",
                    return_value=({}, identity_errors),
                ), self.assertRaisesRegex(RuntimeError, expected):
                    executable_build_package(source, output)
                self.assertFalse(output.exists())

    def test_package_rejects_registry_errors_and_staleness_before_evidence_writes(self) -> None:
        assurance_path = self.root / "assurance.json"
        assurance_path.write_text("{}", encoding="utf-8")
        for index, registry_result in enumerate(((["invalid registry"], []), ([], ["stale registry"]))):
            with self.subTest(registry_result=registry_result):
                output = self.root / f"registry-{index}"
                with mock.patch(
                    "gtm_audit_package_build.declared_identity_errors", return_value=({}, [])
                ), mock.patch(
                    "gtm_audit_package_build.validate_registry", return_value=registry_result
                ), self.assertRaisesRegex(RuntimeError, "locked vendor registry is invalid or stale"):
                    executable_build_package(self.export, output, scan_assurance_path=assurance_path)
                self.assertEqual([], list(output.iterdir()))

    def test_package_requires_both_assurance_provenance_labels(self) -> None:
        scan = build_canonical_scan(self.export)["canonical_scan"]
        assurance = assure_scan(
            self.export, scan,
            vendor_registry_path=ROOT / "references" / "03-rules" / "vendor-registry.toml",
            independent_agent_id="fresh-assurance-agent",
            independent_context_id="fresh-assurance-context",
        )
        for field in ("independent_agent_id", "independent_context_id"):
            with self.subTest(field=field):
                invalid = copy.deepcopy(assurance)
                invalid[field] = "   "
                assurance_path = self.root / f"missing-{field}.json"
                assurance_path.write_text(json.dumps(invalid), encoding="utf-8")
                output = self.root / f"missing-{field}"
                with mock.patch(
                    "gtm_audit_package_build.declared_identity_errors", return_value=({}, [])
                ), self.assertRaisesRegex(RuntimeError, "requires fresh agent and context labels"):
                    executable_build_package(self.export, output, scan_assurance_path=assurance_path)
                self.assertEqual([], list(output.iterdir()))

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
                lambda: validate_target(guarded_package),
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

    def test_delivery_scope_is_compact_with_exact_ids_kept_for_row_notes(self) -> None:
        keys = [f"tag:{value}" for value in range(1, 6)]
        names = {key: f"Tag {index}" for index, key in enumerate(keys, 1)}
        displayed = delivery_mapper._display_scope(keys, names)
        self.assertIn("Tag 1 (tag:1)", displayed)
        self.assertIn("+2 more (see row note)", displayed)
        self.assertNotIn("tag:4", displayed)

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
        result = validate_target(self.package)
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
                    "json_path": "$.priority",
                    "before_source_sha256": file_sha256(self.package / "locked-source.json"),
                }
            ],
        )
        result = validate_target(self.package)
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

    def test_checkpoint_inventory_keeps_all_coordinates_and_dependency_evidence(self) -> None:
        build_package(self.export, self.package)
        scan = json.loads((self.package / "canonical-scan.json").read_text(encoding="utf-8"))
        bundle = self.package / "audit-bundles" / "audit-b"
        inventory = json.loads((bundle / "blind-inventory.json").read_text(encoding="utf-8"))
        source_objects = {row["object_key"]: row for row in scan["objects"]}
        self.assertEqual(set(source_objects), {row["object_key"] for row in inventory["objects"]})
        for row in inventory["objects"]:
            original = source_objects[row["object_key"]]
            self.assertEqual([fact["json_path"] for fact in original["source_leaf_facts"]],
                             row["source_leaf_paths"])
            self.assertNotIn("source_leaf_facts", row)
            for field in ("source_absence_facts", "execution_dependency_traces",
                          "reference_trace_requirements", "consumers", "firing_trigger_ids",
                          "blocking_trigger_ids", "trigger_group_member_ids", "setup_tags",
                          "teardown_tags"):
                self.assertEqual(original.get(field, []), row[field])
        self.assertEqual(self.export.read_bytes(), (bundle / "locked-source.json").read_bytes())
        complete_checkpoint(self.package, "audit-b", "compact-inventory-context")
        self.assertTrue((bundle / cleanroom_audit.CHECKPOINT_SEAL_FILE).is_file())

    def test_compact_checkpoint_still_rejects_a_changed_locked_source_value(self) -> None:
        self.export.write_text(json.dumps(actionable_priority_export()), encoding="utf-8")
        build_package(self.export, self.package)
        source_path = self.package / "audit-bundles" / "audit-b" / "locked-source.json"
        changed_source = json.loads(source_path.read_text(encoding="utf-8"))
        changed_source["containerVersion"]["tag"][0]["name"] = "Changed after source locking"
        source_path.write_text(json.dumps(changed_source), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "locked-source"):
            complete_checkpoint(self.package, "audit-b", "changed-source-context")

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

    def test_checkpoint_conclusion_requires_text_not_length(self) -> None:
        for value in ("No hidden dependency.", "", "   ", None, 42, {"text": "Reviewed"}):
            with self.subTest(value=value):
                errors = cleanroom_audit._checkpoint_errors(
                    {"source_only_conclusion": value}, "audit-a", "source", [], "manifest"
                )
                conclusion_errors = [error for error in errors if "source_only_conclusion" in error]
                self.assertEqual(
                    [] if value == "No hidden dependency." else [
                        "source_only_conclusion must be a non-blank string"
                    ],
                    conclusion_errors,
                )

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

    def test_source_neutral_citations_respect_empty_and_nonempty_allowlists(self) -> None:
        coordinate = "$.containerVersion.tag[0]"
        invented = "invented:$.not_evidence"
        cases = (
            ([], [], True),
            ([], [invented], False),
            ([coordinate], [], False),
            ([coordinate], [coordinate], True),
            ([coordinate], [coordinate, invented], False),
        )
        for allowed, citations, valid in cases:
            with self.subTest(allowed=allowed, citations=citations):
                row = {}
                row.update(
                    {
                        "verification_id": "NV-CITATION-FIXTURE",
                        "source_coordinates": allowed,
                        "verification_reasons": ["conflicting_verdict"],
                        "neutral_question": "What does the locked source support?",
                        "neutral_evidence": {},
                        "allowed_evidence_citations": allowed,
                        "prohibited_context": "Do not invent evidence.",
                        "status": "pending",
                        "canonical_decision": {},
                        "evidence_citations": [],
                        "verification_rationale": "",
                    }
                )
                row["neutral_bundle_manifest_sha256"] = (
                    reconciliation_module.neutral_bundle_manifest_sha256(row)
                )
                expected = {"status": "pending", "verifications": [row]}
                supplied = copy.deepcopy(expected)
                supplied["status"] = "complete"
                supplied["verifications"][0].update(
                    {
                        "status": "complete",
                        "canonical_decision": fixture_plan_decision("applicable"),
                        "evidence_citations": citations,
                        "verification_rationale": "Source supports retention.",
                    }
                )
                errors = reconciliation_module._neutral_errors(
                    self.root, supplied, expected
                )
                if valid:
                    self.assertEqual([], errors)
                    for invalid_rationale in ("", "   ", None, 42, {"text": "Retain"}):
                        with self.subTest(rationale=invalid_rationale):
                            invalid = copy.deepcopy(supplied)
                            invalid["verifications"][0]["verification_rationale"] = invalid_rationale
                            invalid_errors = reconciliation_module._neutral_errors(
                                self.root, invalid, expected
                            )
                            self.assertTrue(
                                any("non-blank string" in error for error in invalid_errors)
                            )
                else:
                    self.assertTrue(any("citations" in error for error in errors))

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
            self.assertEqual(
                locked_evidence_coordinates(
                    row["source_coordinates"], row["neutral_evidence"]
                ),
                row["allowed_evidence_citations"],
            )

    def test_editorial_artifact_has_no_agent_context_identity(self) -> None:
        self.run_actionable_to_editorial()
        editorial_path = self.package / "delivery" / "editorial.json"
        editorial = json.loads(editorial_path.read_text(encoding="utf-8"))
        self.assertNotIn("independent_agent_id", editorial)
        self.assertNotIn("independent_context_id", editorial)
        self.assertNotIn("host_isolation_receipt", editorial)
        original = editorial_path.read_bytes()
        for invalid in ("", " ", None, [], 42):
            with self.subTest(conclusion=invalid):
                editorial["completion_attestation"]["conclusion"] = invalid
                editorial_path.write_text(json.dumps(editorial), encoding="utf-8")
                self.assertIn(
                    "editorial completion conclusion must be a non-blank string",
                    validate_editorial(self.package),
                )
        editorial_path.write_bytes(original)

    def test_complete_static_workflow_reaches_sealed_canonical_record(self) -> None:
        self.run_to_editorial()
        canonical = json.loads((self.package / "canonical-record.json").read_text(encoding="utf-8"))
        self.assertEqual(canonical["target_validation"]["status"], "pass")
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
                == "source_audit_and_reconciliation"
                for row in canonical["audit_decisions"]
            )
        )
        delivery_map = json.loads(
            (self.package / "delivery" / "delivery-map.json").read_text(encoding="utf-8")
        )
        self.assertEqual(HUMAN_DECISION_LABELS, delivery_map["overview"]["decision_labels"])
        area_24_focuses = [
            row["canonical_prose"]["audit_focus"]
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
        self.assertEqual(operation["removals"][0]["json_path"], "$.priority")
        projected = json.loads(
            (self.package / "target-validation" / "projected-container.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertNotIn("priority", projected["containerVersion"]["tag"][0])
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
            [{**operation["removals"][0], "before": {"type": "INTEGER", "value": "10"}}],
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

    def test_reconciliation_scaffolds_bounded_exact_work_units(self) -> None:
        build_package(self.export, self.package)
        complete_checkpoint(self.package, "audit-a", "fixture-a-context-001")
        complete_checkpoint(self.package, "audit-b", "fixture-b-context-001")
        complete_audit(self.package, "audit-a")
        complete_audit(self.package, "audit-b")

        with mock.patch(
            "gtm_reconciliation.MAX_RECONCILIATION_UNIT_COMPARISONS", 1
        ):
            result = scaffold_reconciliation(self.package)

        unit_root = self.package / "reconciliation-units"
        manifest = json.loads(
            (unit_root / "manifest.json").read_text(encoding="utf-8")
        )
        self.assertEqual(result["work_units"], len(manifest["units"]))
        self.assertTrue(
            all(len(row["comparison_ids"]) <= 1 for row in manifest["units"])
        )
        comparison_ids = [
            comparison_id
            for row in manifest["units"]
            for comparison_id in row["comparison_ids"]
        ]
        self.assertEqual(len(comparison_ids), manifest["comparison_count"])
        self.assertEqual(len(comparison_ids), len(set(comparison_ids)))
        comparisons = []
        for record in manifest["units"]:
            unit = json.loads(
                (unit_root / record["filename"]).read_text(encoding="utf-8")
            )
            comparisons.extend(unit["comparisons"])
        for row in comparisons:
            if not row["neutral_verification_required"]:
                self.assertEqual("complete", row["status"])
                self.assertTrue(row["canonical_decision"])
                self.assertTrue(row["reconciliation_rationale"])

    def test_reconciliation_projects_neutral_result_without_duplicate_authoring(
        self,
    ) -> None:
        self.export.write_text(
            json.dumps(actionable_priority_export()), encoding="utf-8"
        )
        build_package(self.export, self.package)
        complete_checkpoint(self.package, "audit-a", "neutral-projection-a")
        complete_checkpoint(self.package, "audit-b", "neutral-projection-b")
        complete_audit(self.package, "audit-a", actionable_priority=True)
        complete_audit(self.package, "audit-b", actionable_priority=True)
        complete_base_reconciliation(self.package)
        reconciliation = json.loads(
            (self.package / "reconciliation.json").read_text(encoding="utf-8")
        )
        neutral = json.loads(
            (self.package / "neutral-verification.json").read_text(encoding="utf-8")
        )
        neutral_by_id = {
            row["verification_id"]: row for row in neutral["verifications"]
        }
        for row in reconciliation["comparisons"]:
            if row["neutral_verification_required"]:
                verification = neutral_by_id[row["neutral_verification_id"]]
                self.assertEqual(
                    verification["canonical_decision"], row["canonical_decision"]
                )
                self.assertEqual(
                    row["audit_decisions"][verification["selected_audit_id"]],
                    row["canonical_decision"],
                )
                self.assertEqual(
                    verification["verification_rationale"],
                    row["reconciliation_rationale"],
                )

    def test_neutral_selection_resolves_exact_present_source_decision(self) -> None:
        candidates = {
            "audit-a": {
                "decision_id": "A",
                "criteria_assessment": "Keep A",
                "operation_proposal": {"operation_id": "OP-A"},
            },
            "audit-b": {
                "decision_id": "B",
                "criteria_assessment": "Keep B",
                "evidence_citations": ["$.B"],
            },
        }
        for selected in candidates:
            result = reconciliation_module._resolve_neutral_decision(
                {"selected_audit_id": selected, "non_actionable_decision": {}},
                {"audit_decisions": candidates},
            )
            self.assertEqual(candidates[selected], result)
            self.assertIsNot(candidates[selected], result)
        one_sided = {
            "audit_decisions": {"audit-a": {}, "audit-b": candidates["audit-b"]}
        }
        self.assertEqual(
            candidates["audit-b"],
            reconciliation_module._resolve_neutral_decision(
                {"selected_audit_id": "audit-b", "non_actionable_decision": {}},
                one_sided,
            ),
        )
        with self.assertRaisesRegex(ValueError, "present audit decision"):
            reconciliation_module._resolve_neutral_decision(
                {"selected_audit_id": "audit-a", "non_actionable_decision": {}},
                one_sided,
            )

    def test_neutral_selection_and_narrowing_have_one_closed_authored_choice(
        self,
    ) -> None:
        narrowed = {
            "decision_class": "justified_as_is",
            "criteria_assessment": "Distinct scope.",
            "priority": "None",
            "confidence": "High",
            "evidence_citations": ["$.scope"],
        }
        comparison = {"audit_decisions": {"audit-a": narrowed, "audit-b": narrowed}}
        row = {
            "selected_audit_id": "",
            "non_actionable_decision": narrowed,
            "allowed_evidence_citations": ["$.scope"],
        }
        self.assertEqual(
            narrowed, reconciliation_module._resolve_neutral_decision(row, comparison)
        )
        invalid_rows = [
            {**row, "selected_audit_id": "audit-a"},
            {**row, "non_actionable_decision": {}},
            {**row, "selected_audit_id": None},
            {**row, "non_actionable_decision": []},
            {**row, "selected_audit_id": "audit-c", "non_actionable_decision": {}},
        ]
        for field, value in (
            ("decision_class", "defect"),
            ("operation_proposal", {}),
            ("unexpected", "injected"),
            ("criteria_assessment", []),
            ("evidence_citations", "$.scope"),
            ("evidence_citations", [None]),
            ("evidence_citations", ["$.scope", "$.scope"]),
            ("evidence_citations", ["$.invented"]),
            ("evidence_citations", []),
            ("confidence", "invented"),
            ("criteria_assessment", ""),
        ):
            invalid_rows.append(
                {**row, "non_actionable_decision": {**narrowed, field: value}}
            )
        for invalid in invalid_rows:
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                reconciliation_module._resolve_neutral_decision(invalid, comparison)

    def test_neutral_selection_rejects_manual_copy_and_sealed_payload_substitution(
        self,
    ) -> None:
        self.export.write_text(
            json.dumps(actionable_priority_export()), encoding="utf-8"
        )
        build_package(self.export, self.package)
        complete_checkpoint(self.package, "audit-a", "selection-a")
        complete_checkpoint(self.package, "audit-b", "selection-b")
        complete_audit(self.package, "audit-a", actionable_priority=True)
        complete_audit(self.package, "audit-b", actionable_priority=True)
        complete_base_reconciliation(self.package)
        self.assertEqual([], reconciliation_seal_errors(self.package))
        unit_root = self.package / "reconciliation-units"
        manifest = json.loads((unit_root / "manifest.json").read_text(encoding="utf-8"))
        for item in manifest["units"]:
            path = unit_root / item["filename"]
            unit = json.loads(path.read_text(encoding="utf-8"))
            if unit["verifications"]:
                break
        original = path.read_bytes()
        unit["verifications"][0]["canonical_decision"] = {}
        path.write_text(json.dumps(unit), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "neutral authoring schema"):
            finalize_reconciliation(self.package)
        path.write_bytes(original)
        reconciliation_path = self.package / "reconciliation.json"
        neutral_path = self.package / "neutral-verification.json"
        reconciliation = json.loads(reconciliation_path.read_text(encoding="utf-8"))
        neutral = json.loads(neutral_path.read_text(encoding="utf-8"))
        verification = neutral["verifications"][0]
        verification["canonical_decision"]["criteria_assessment"] = (
            "Substituted retained claim."
        )
        comparison = next(
            row
            for row in reconciliation["comparisons"]
            if row["neutral_verification_id"] == verification["verification_id"]
        )
        comparison["canonical_decision"] = copy.deepcopy(
            verification["canonical_decision"]
        )
        neutral_path.write_text(json.dumps(neutral), encoding="utf-8")
        reconciliation_path.write_text(json.dumps(reconciliation), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "explicit neutral selection"):
            finalize_reconciliation(self.package, reconciliation_path, neutral_path)
        self.assertTrue(
            any(
                "explicit neutral selection" in error
                for error in reconciliation_seal_errors(self.package)
            )
        )

    def test_reconciliation_narrowing_survives_sealing_and_enforces_class_fields(self) -> None:
        self.export.write_text(json.dumps(actionable_priority_export()), encoding="utf-8")
        build_package(self.export, self.package)
        complete_checkpoint(self.package, "audit-a", "narrow-a")
        complete_checkpoint(self.package, "audit-b", "narrow-b")
        complete_audit(self.package, "audit-a", actionable_priority=True)
        complete_audit(self.package, "audit-b", actionable_priority=True)
        complete_base_reconciliation(self.package)
        unit_root = self.package / "reconciliation-units"
        manifest = json.loads((unit_root / "manifest.json").read_text(encoding="utf-8"))
        found = None
        for item in manifest["units"]:
            path = unit_root / item["filename"]
            unit = json.loads(path.read_text(encoding="utf-8"))
            for row in unit["verifications"]:
                if row["fact_kind"] == "explicit_firing_priority":
                    found = (path, unit, row)
                    break
            if found:
                break
        self.assertIsNotNone(found)
        path, unit, row = found
        for decision_class in ("justified_as_is", "owner_decision", "container_evidence_limit"):
            narrowed = {
                "decision_class": decision_class,
                "criteria_assessment": "The fixture retains its configured ordering pending confirmation.",
                "priority": "None", "confidence": "High",
                "current_behavior": "The fixture exports explicit priority 10.",
                "consequence_or_benefit": "Confirm whether this ordering has an owner-approved purpose.",
                "owner_question": "Is this explicit start order required?",
                "evidence_boundary": "The fixture does not establish an owner-approved start order.",
                "next_step": "Confirm the ordering requirement with its owner.",
                "evidence_citations": row["allowed_evidence_citations"][:1],
            }
            row.update(selected_audit_id="", non_actionable_decision=narrowed)
            path.write_text(json.dumps(unit), encoding="utf-8")
            finalize_reconciliation(self.package)
            self.assertEqual([], reconciliation_seal_errors(self.package))
            saved = json.loads((self.package / "neutral-verification.json").read_text(encoding="utf-8"))
            result = next(item for item in saved["verifications"]
                          if item["verification_id"] == row["verification_id"])
            self.assertEqual(narrowed, result["canonical_decision"])
            self.assertEqual(row["verification_rationale"], result["verification_rationale"])
            self.assertEqual(row["evidence_citations"], result["evidence_citations"])
            required = {"owner_decision": "owner_question", "container_evidence_limit": "evidence_boundary"}.get(decision_class)
            if required:
                original = narrowed[required]
                narrowed[required] = ""
                path.write_text(json.dumps(unit), encoding="utf-8")
                with self.assertRaisesRegex(ValueError, required):
                    finalize_reconciliation(self.package)
                narrowed[required] = original
        narrowed["decision_class"] = "not_applicable"
        path.write_text(json.dumps(unit), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "applicable obligation cannot be Not applicable"):
            finalize_reconciliation(self.package)

    def test_reconciliation_narrowing_cannot_suppress_source_known_repair(self) -> None:
        payload = minimal_export()
        payload["containerVersion"]["tag"] = [{
            "tagId": "1", "name": "Custom HTML fixture", "type": "html",
            "parameter": [
                {
                    "type": "TEMPLATE",
                    "key": "html",
                    "value": "<script>document.write('fixture');</script>",
                },
            ],
        }]
        self.export.write_text(json.dumps(payload), encoding="utf-8")
        build_package(self.export, self.package)
        ledger = json.loads((self.package / "obligation-ledger.json").read_text(encoding="utf-8"))
        required = [row for row in ledger["obligations"] if
                    row.get("evidence", {}).get("configuration_obligation", {}).get("source_known_repair")]
        self.assertEqual(1, len(required))
        obligation = required[0]
        obligation_id = obligation["obligation_id"]
        repair = obligation["evidence"]["configuration_obligation"]["source_known_repair"]
        original_complete = complete_semantic_decision

        def complete_known_repair(row):
            original_complete(row)
            if row["obligation_id"] != obligation_id:
                return
            row.update({field: "Enable required document.write support." for field in CANONICAL_DECISION_FIELDS})
            row.update(decision_class="defect", priority="High", confidence="High")
            row["operation_proposal"] = {
                "operation_id": "OP-ENABLE-DOCUMENT-WRITE",
                "source_decision_id": row["decision_id"],
                "operation_family": "Enable required document.write support",
                "exact_target_state": "Keep the HTML and enable its required document.write support.",
                "preconditions": "The HTML contains document.write and the support field is absent.",
                "static_verification": "The parameter list contains the existing HTML and enabled support.",
                "rollback": "Restore the original parameter list.", "depends_on": [],
                **{field: [] for field in OPERATION_ACTION_FIELDS},
                "changes": [{
                    "object_key": repair["object_key"],
                    "json_path": "$.parameter",
                    "before_source_sha256": file_sha256(self.package / "locked-source.json"),
                    "after": repair["after"],
                }],
            }

        for audit_id in ("audit-a", "audit-b"):
            complete_checkpoint(self.package, audit_id, "known-repair-" + audit_id)
            with mock.patch(__name__ + ".complete_semantic_decision", side_effect=complete_known_repair):
                complete_audit(self.package, audit_id)
        complete_base_reconciliation(self.package)
        self.assertEqual([], reconciliation_seal_errors(self.package))
        unit_root = self.package / "reconciliation-units"
        manifest = json.loads((unit_root / "manifest.json").read_text(encoding="utf-8"))
        found = False
        for item in manifest["units"]:
            path = unit_root / item["filename"]
            unit = json.loads(path.read_text(encoding="utf-8"))
            for row in unit["verifications"]:
                if row["obligation_id"] == obligation_id:
                    row["selected_audit_id"] = ""
                    row["non_actionable_decision"] = {
                        "decision_class": "justified_as_is", "priority": "None", "confidence": "High",
                        "criteria_assessment": "Unsupported retention of the known unused flag.",
                        "evidence_citations": row["allowed_evidence_citations"][:1],
                    }
                    found = True
                    path.write_text(json.dumps(unit), encoding="utf-8")
            if found:
                break
        self.assertTrue(found)
        with self.assertRaisesRegex(ValueError, "source-known configuration repair must be actionable"):
            finalize_reconciliation(self.package)

    def test_reconciliation_narrowing_preserves_source_counted_zero(self) -> None:
        build_package(self.export, self.package)
        original_complete = complete_semantic_decision

        def distinguish_zero(row):
            original_complete(row)
            if row["applicability"] == "source_counted_zero":
                row["criteria_assessment"] += " Independently confirmed empty inventory."

        complete_checkpoint(self.package, "audit-a", "zero-narrow-a")
        with mock.patch(__name__ + ".complete_semantic_decision", side_effect=distinguish_zero):
            complete_audit(self.package, "audit-a")
        complete_checkpoint(self.package, "audit-b", "zero-narrow-b")
        complete_audit(self.package, "audit-b")
        complete_base_reconciliation(self.package)
        unit_root = self.package / "reconciliation-units"
        manifest = json.loads((unit_root / "manifest.json").read_text(encoding="utf-8"))
        found = None
        for item in manifest["units"]:
            path = unit_root / item["filename"]
            unit = json.loads(path.read_text(encoding="utf-8"))
            empty_ids = {row["neutral_verification_id"] for row in unit["comparisons"]
                         if row["applicability"] == "source_counted_zero"}
            for row in unit["verifications"]:
                if row["verification_id"] in empty_ids:
                    found = path, unit, row
                    break
            if found:
                break
        self.assertIsNotNone(found)
        path, unit, row = found
        row["selected_audit_id"] = ""
        row["non_actionable_decision"] = {
            "decision_class": "not_applicable", "priority": "None", "confidence": "High",
            "criteria_assessment": "The locked inventory contains zero applicable objects.",
            "evidence_citations": row["allowed_evidence_citations"][:1],
        }
        path.write_text(json.dumps(unit), encoding="utf-8")
        finalize_reconciliation(self.package)
        self.assertEqual([], reconciliation_seal_errors(self.package))
        row["non_actionable_decision"]["decision_class"] = "justified_as_is"
        path.write_text(json.dumps(unit), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "source-counted zero must be Not applicable"):
            finalize_reconciliation(self.package)

    def test_reconciliation_rejects_changed_unit_membership_before_output(self) -> None:
        build_package(self.export, self.package)
        complete_checkpoint(self.package, "audit-a", "fixture-a-context-001")
        complete_checkpoint(self.package, "audit-b", "fixture-b-context-001")
        complete_audit(self.package, "audit-a")
        complete_audit(self.package, "audit-b")
        scaffold_reconciliation(self.package)

        manifest = json.loads(
            (self.package / "reconciliation-units" / "manifest.json").read_text(
                encoding="utf-8"
            )
        )
        first_unit_path = (
            self.package
            / "reconciliation-units"
            / manifest["units"][0]["filename"]
        )
        first_unit = json.loads(first_unit_path.read_text(encoding="utf-8"))
        first_unit["comparisons"].pop()
        first_unit_path.write_text(
            json.dumps(first_unit, indent=2) + "\n", encoding="utf-8"
        )

        with self.assertRaisesRegex(ValueError, "comparison membership changed"):
            finalize_reconciliation(self.package)
        self.assertFalse((self.package / "reconciliation.json").exists())

    def test_reconciliation_rejects_authored_comparison_rows(self) -> None:
        build_package(self.export, self.package)
        complete_checkpoint(self.package, "audit-a", "fixture-a-context-001")
        complete_checkpoint(self.package, "audit-b", "fixture-b-context-001")
        complete_audit(self.package, "audit-a")
        complete_audit(self.package, "audit-b")
        scaffold_reconciliation(self.package)

        unit_root = self.package / "reconciliation-units"
        manifest = json.loads((unit_root / "manifest.json").read_text(encoding="utf-8"))
        unit_path = unit_root / manifest["units"][0]["filename"]
        unit = json.loads(unit_path.read_text(encoding="utf-8"))
        unit["comparisons"][0]["reconciliation_rationale"] = (
            "An agent must not author this deterministic comparison row."
        )
        unit_path.write_text(json.dumps(unit, indent=2) + "\n", encoding="utf-8")

        with self.assertRaisesRegex(
            ValueError, "deterministic comparison rows changed"
        ):
            finalize_reconciliation(self.package)

    def test_rehashed_canonical_forgery_is_rejected(self) -> None:
        self.run_actionable_to_editorial()
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

    def test_canonical_validation_checks_reconciliation_once_and_rejects_drift(self) -> None:
        self.run_to_editorial()
        with mock.patch("gtm_target_synthesis.reconciliation_seal_errors",
                        wraps=reconciliation_seal_errors) as check:
            self.assertEqual([], canonical_record_seal_errors(self.package))
            check.assert_called_once_with(self.package)
        path = self.package / "reconciled-decisions.json"
        record = json.loads(path.read_text(encoding="utf-8"))
        record["reconciled_record_sha256"] = "altered-record"
        path.write_text(json.dumps(record), encoding="utf-8")
        before = (self.package / "canonical-record.json").read_bytes()
        with mock.patch("gtm_target_synthesis.reconciliation_seal_errors",
                        wraps=reconciliation_seal_errors) as check:
            self.assertTrue(canonical_record_seal_errors(self.package))
            check.assert_called_once_with(self.package)
        self.assertEqual(before, (self.package / "canonical-record.json").read_bytes())

    def test_reconciliation_verification_reconstructs_once_and_rejects_drift(self) -> None:
        self.run_to_editorial()
        scaffold = reconciliation_module._reconciliation_scaffold_payloads
        paths = [self.package / name for name in (
            "reconciliation-scaffold.json", "neutral-verification-queue.json",
            "reconciled-decisions.json", "reconciliation-seal.json",
        )]
        with mock.patch.object(reconciliation_module, "_reconciliation_scaffold_payloads",
                               wraps=scaffold) as reconstruct:
            self.assertEqual([], reconciliation_seal_errors(self.package))
            reconstruct.assert_called_once_with(self.package)
        for path in paths:
            original = path.read_bytes()
            changed = json.loads(original)
            changed["source_sha256"] = "changed-source"
            path.write_text(json.dumps(changed), encoding="utf-8")
            before = {item: item.read_bytes() for item in paths}
            with self.subTest(path=path.name), mock.patch.object(
                reconciliation_module, "_reconciliation_scaffold_payloads", wraps=scaffold
            ) as reconstruct:
                self.assertTrue(reconciliation_seal_errors(self.package))
                reconstruct.assert_called_once_with(self.package)
                self.assertEqual(before, {item: item.read_bytes() for item in paths})
            path.write_bytes(original)

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

    def test_editorial_category_is_controlled_without_changing_audit_identity(self) -> None:
        self.run_to_editorial()
        path = self.package / "delivery" / "editorial.json"
        editorial = json.loads(path.read_text(encoding="utf-8"))
        canonical_path = self.package / "canonical-record.json"
        canonical_before = canonical_path.read_bytes()
        for category, accepted in (("CMP & consent", True), ("Invented category", False),
                                   ([], False), (None, False)):
            editorial["rows"][0]["prose"]["audit_area"] = category
            path.write_text(json.dumps(editorial), encoding="utf-8")
            errors = validate_editorial(self.package)
            self.assertEqual(accepted, not errors, errors)
            self.assertEqual(canonical_before, canonical_path.read_bytes())

    def test_delivery_commands_validate_canonical_once_and_reject_drift(self) -> None:
        self.run_to_editorial()
        canonical_path = self.package / "canonical-record.json"
        original = canonical_path.read_bytes()
        for drift in (False, True):
            if drift:
                canonical = json.loads(original)
                canonical["canonical_record_sha256"] = "altered-record"
                canonical_path.write_text(json.dumps(canonical), encoding="utf-8")
            for command in (scaffold_delivery_reviews, seal_delivery):
                with self.subTest(command=command.__name__, drift=drift):
                    before = {path.relative_to(self.package): path.read_bytes()
                              for path in self.package.rglob("*") if path.is_file()}
                    with mock.patch.object(
                        delivery_mapper, "canonical_record_seal_errors",
                        wraps=canonical_record_seal_errors,
                    ) as canonical_check:
                        # There is deliberately no workbook build. Both commands
                        # must still validate their source once and write nothing.
                        with self.assertRaises(ValueError) as failure:
                            command(self.package)
                        canonical_check.assert_called_once_with(self.package)
                    self.assertIn("current workbook build pointer is missing", str(failure.exception))
                    if drift:
                        self.assertIn("canonical", str(failure.exception).lower())
                    after = {path.relative_to(self.package): path.read_bytes()
                             for path in self.package.rglob("*") if path.is_file()}
                    self.assertEqual(before, after)

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
            ValueError, "differs from sealed source semantic reconstruction"
        ):
            validate_target(self.package)

    @unittest.skipUnless(
        os.environ.get("CODEX_NODE") and os.environ.get("CODEX_ARTIFACT_NODE_MODULES"),
        "The explicit bundled Node.js and artifact-tool runtime are required",
    )
    def test_custom_code_workbook_has_visible_decision_labels(self) -> None:
        payload = minimal_export()
        payload["containerVersion"]["tag"] = [
            {
                "tagId": "1",
                "name": "Support marker",
                "type": "html",
                "parameter": [
                    {
                        "type": "template",
                        "key": "html",
                        "value": "<script>dataLayer.push({event: 'audit_fixture'});</script>",
                    }
                ],
                "firingTriggerId": ["2147479553"],
            }
        ]
        self.export.write_text(json.dumps(payload), encoding="utf-8")
        self.run_to_editorial()
        node = os.environ["CODEX_NODE"]
        run_node_script(node, SCRIPTS / "gtm_workbook_build.mjs", self.package)
        run_node_script(node, SCRIPTS / "gtm_workbook_verify.mjs", self.package)
        current = json.loads(
            (self.package / "delivery" / "current-build.json").read_text(encoding="utf-8")
        )
        manifest = json.loads(
            (
                self.package / "delivery" / current["build_path"] / "workbook-build-manifest.json"
            ).read_text(encoding="utf-8")
        )
        code_sheet = next(
            sheet for sheet in manifest["normalized_model"]["sheets"]
            if sheet["name"] == "05 Custom Code"
        )
        self.assertTrue(code_sheet["rows"])
        for sheet in manifest["normalized_model"]["sheets"]:
            if "headers" in sheet:
                self.assertEqual("Audit area", sheet["headers"][1])
                self.assertTrue(all(row["values"][1] for row in sheet["rows"]))
        self.assertEqual("Audit area", code_sheet["headers"][1])
        self.assertTrue(all(row["values"][1] for row in code_sheet["rows"]))
        decision_column = code_sheet["headers"].index("Decision")
        self.assertTrue(all(row["values"][decision_column] for row in code_sheet["rows"]))

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
        reader_comments = [
            row["text"]
            for row in build_manifest["normalized_model"]["comments"]
            if row["sheet"] != "02 Recommendations"
        ]
        self.assertTrue(reader_comments)
        self.assertTrue(
            all(
                "decision_id:" not in text
                and "area_id:" not in text
                and "audit_mechanism:" not in text
                and "fact_kind:" not in text
                and "justified_as_is" not in text
                and "correct_but_materially_non_optimal" not in text
                and "source_counted_coverage" not in text
                and "configured_leaf_branch_trace_review" not in text
                for text in reader_comments
            )
        )
        overview = next(
            sheet
            for sheet in build_manifest["normalized_model"]["sheets"]
            if sheet["name"] == "01 Overview"
        )
        overview_cells = {
            (cell["row"], cell["column"]): cell["value"]
            for cell in overview["cells"]
        }
        delta_header_row = next(
            row
            for (row, column), value in overview_cells.items()
            if column == 0 and value == "Material object-count changes"
        )
        self.assertTrue(
            all(overview_cells[(delta_header_row + 1, column)] for column in range(4))
        )
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

        changed_manifest = copy.deepcopy(build_manifest)
        delivered_rows = [
            row
            for sheet in changed_manifest["normalized_model"]["sheets"]
            for row in sheet.get("rows", [])
        ]
        self.assertTrue(delivered_rows)
        delivered_rows[0]["locked"]["priority"] = "forged"
        changed_manifest["normalized_workbook_sha256"] = stable_hash(
            changed_manifest["normalized_model"], 64
        )
        changed_manifest["recovery_normalized_workbook_sha256"] = changed_manifest[
            "normalized_workbook_sha256"
        ]
        changed_manifest["workbook_build_manifest_sha256"] = stable_hash(
            {
                key: value
                for key, value in changed_manifest.items()
                if key != "workbook_build_manifest_sha256"
            },
            64,
        )
        build_manifest_path.write_text(
            json.dumps(changed_manifest, indent=2) + "\n", encoding="utf-8"
        )
        changed_current = copy.deepcopy(current)
        changed_current["workbook_build_manifest_sha256"] = changed_manifest[
            "workbook_build_manifest_sha256"
        ]
        changed_current["current_build_sha256"] = stable_hash(
            {
                key: value
                for key, value in changed_current.items()
                if key != "current_build_sha256"
            },
            64,
        )
        current_path.write_text(
            json.dumps(changed_current, indent=2) + "\n", encoding="utf-8"
        )
        with self.assertRaisesRegex(
            ValueError, "workbook locked fields differ from the canonical delivery map"
        ):
            scaffold_delivery_reviews(self.package)
        build_manifest_path.write_bytes(build_manifest_before)
        current_path.write_bytes(current_before)

        verification = json.loads(
            (
                self.package / "delivery" / current["build_path"] / "technical-verification.json"
            ).read_text(encoding="utf-8")
        )
        self.assertTrue(verification["comment_checks"])
        self.assertTrue(all(row["status"] == "pass" for row in verification["comment_checks"]))
        self.assertTrue(verification["pane_checks"])
        self.assertTrue(all(row["status"] == "pass" for row in verification["pane_checks"]))
        self.assertTrue(verification["overview_cell_checks"])
        self.assertTrue(all(row["status"] == "pass" for row in verification["overview_cell_checks"]))
        review_scaffold = scaffold_delivery_reviews(self.package)
        self.assertEqual("ready_for_workbook_delivery_review", review_scaffold["status"])
        self.assertEqual(
            {"reader"},
            {path.name for path in (build_dir / "reviews").iterdir()},
        )
        reader_dir = build_dir / "reviews" / "reader"
        reader_manifest_path = reader_dir / "bundle-manifest.json"
        reader_review_path = reader_dir / "reader-review.json"
        workbook_copy = reader_dir / "workbook.xlsx"
        workbook_before = workbook_copy.read_bytes()
        reader_manifest_before = reader_manifest_path.read_bytes()
        reader_review_before = reader_review_path.read_bytes()
        workbook_copy.write_bytes(workbook_before + b"forged-workbook-copy")
        reader_manifest = json.loads(reader_manifest_before)
        for locked_file in reader_manifest["locked_files"]:
            if locked_file["path"] == "workbook.xlsx":
                locked_file["sha256"] = file_sha256(workbook_copy)
        reader_manifest["bundle_manifest_sha256"] = stable_hash(
            {
                key: value
                for key, value in reader_manifest.items()
                if key != "bundle_manifest_sha256"
            },
            64,
        )
        reader_manifest_path.write_text(
            json.dumps(reader_manifest, indent=2) + "\n", encoding="utf-8"
        )
        reader_review = json.loads(reader_review_before)
        reader_review["input_manifest_sha256"] = reader_manifest[
            "bundle_manifest_sha256"
        ]
        reader_review_path.write_text(
            json.dumps(reader_review, indent=2) + "\n", encoding="utf-8"
        )
        with self.assertRaisesRegex(
            ValueError, "reader workbook copy differs from the authoritative workbook"
        ):
            seal_delivery(self.package)
        workbook_copy.write_bytes(workbook_before)
        reader_manifest_path.write_bytes(reader_manifest_before)
        reader_review_path.write_bytes(reader_review_before)

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

        reader_meaning_path = reader_dir / "meaning-reference.json"
        reader_meaning_before = reader_meaning_path.read_bytes()
        reader_manifest_before = reader_manifest_path.read_bytes()
        reader_review_before = reader_review_path.read_bytes()
        forged_meaning = json.loads(reader_meaning_before)
        forged_meaning["rows"][0]["canonical_prose"]["current_behavior"] = (
            "Forged workbook meaning"
        )
        reader_meaning_path.write_text(
            json.dumps(forged_meaning, indent=2) + "\n", encoding="utf-8"
        )
        rebind_reader_input("meaning-reference.json")
        with self.assertRaisesRegex(
            ValueError, "reader meaning reference differs from canonical reconstruction"
        ):
            seal_delivery(self.package)
        reader_meaning_path.write_bytes(reader_meaning_before)
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
        reader_manifest_before = reader_manifest_path.read_bytes()
        reader_manifest = json.loads(reader_manifest_before)
        reader_manifest["locked_files"][0]["path"] = (
            "../../../../../outside-workbook.xlsx"
        )
        reader_manifest["locked_files"][0]["sha256"] = file_sha256(
            outside_workbook
        )
        reader_manifest["bundle_manifest_sha256"] = stable_hash(
            {
                key: value
                for key, value in reader_manifest.items()
                if key != "bundle_manifest_sha256"
            },
            64,
        )
        reader_manifest_path.write_text(
            json.dumps(reader_manifest, indent=2) + "\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValueError, "remain inside"):
            seal_delivery(self.package)
        self.assertEqual(outside_workbook_before, outside_workbook.read_bytes())
        reader_manifest_path.write_bytes(reader_manifest_before)
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
        original_manifest = reader["input_manifest_sha256"]
        reader["input_manifest_sha256"] = "f" * 64
        reader_path.write_text(json.dumps(reader, indent=2) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(
            ValueError, "reader review is not bound to its review bundle"
        ):
            seal_delivery(self.package)
        reader["input_manifest_sha256"] = original_manifest
        reader_path.write_text(json.dumps(reader, indent=2) + "\n", encoding="utf-8")
        for field, message in (
            (
                "reviewed_workbook_before_meaning_reference",
                "reader must assess the workbook before opening the meaning reference",
            ),
            (
                "compared_every_visible_row_to_canonical_meaning",
                "reader did not compare every visible row with canonical meaning",
            ),
        ):
            changed = copy.deepcopy(reader)
            changed[field] = False
            reader_path.write_text(json.dumps(changed), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, message):
                seal_delivery(self.package)
        changed = copy.deepcopy(reader)
        changed["sheet_reviews"][0]["semantic_meaning_faithful"] = False
        reader_path.write_text(json.dumps(changed), encoding="utf-8")
        with self.assertRaisesRegex(
            ValueError, "semantic_meaning_faithful did not pass"
        ):
            seal_delivery(self.package)
        for invalid in ("", []):
            with self.subTest(attestation=invalid):
                changed = copy.deepcopy(reader)
                changed["completion_attestation"] = invalid
                reader_path.write_text(json.dumps(changed), encoding="utf-8")
                with self.assertRaisesRegex(
                    ValueError,
                    "reader completion attestation must be a non-blank string",
                ):
                    seal_delivery(self.package)
        reader_path.write_text(json.dumps(reader), encoding="utf-8")
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
            file_sha256(reader_path),
            delivery_manifest["reader_review_file_sha256"],
        )
        self.assertEqual(
            delivery_manifest["reader_review_file_sha256"],
            delivery_seal["reader_review_file_sha256"],
        )


if __name__ == "__main__":
    unittest.main()
