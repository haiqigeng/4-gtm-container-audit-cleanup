from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

from gtm_audit_contract import (  # noqa: E402
    CANONICAL_DECISION_FIELDS,
    OPERATION_ACTION_FIELDS,
    semantic_contract_errors,
)
from gtm_audit_work_units import (  # noqa: E402
    MAX_SINGLE_OBLIGATIONS,
    build_work_units,
    declared_work_unit_files,
    discovery_schema_errors,
    merge_work_units,
    operation_proposal_schema_errors,
    semantic_audit_decision_schema_errors,
    work_unit_completion_errors,
    work_unit_identity_hash,
    workload_estimate_schema_errors,
)
from gtm_cleanroom_audit import (  # noqa: E402
    decision_obligation_alignment_errors,
    operation_proposal_errors,
)
from gtm_fixed_point import MAX_CYCLES, _block_non_convergent  # noqa: E402
from gtm_lib import container_version, stable_hash  # noqa: E402
from gtm_operation_model import (  # noqa: E402
    apply_operations,
    dependency_order,
    operation_packet_sha256,
    operation_write_conflicts,
    validate_operations,
)
from gtm_target_synthesis import (  # noqa: E402
    server_consent_gate_regression_errors,
)


def operation(operation_id: str, **actions: list[dict]) -> dict:
    row = {
        "operation_id": operation_id,
        "depends_on": [],
        **{field: [] for field in OPERATION_ACTION_FIELDS},
    }
    row.update(actions)
    return row


def operation_fixture() -> dict:
    return {
        "containerVersion": {
            "accountId": "1",
            "containerId": "2",
            "containerVersionId": "3",
            "container": {
                "accountId": "1",
                "containerId": "2",
                "publicId": "GTM-OPS-TEST",
                "usageContext": ["WEB"],
            },
            "tag": [
                {
                    "tagId": "1",
                    "name": "Google tag",
                    "type": "googtag",
                    "parameter": [
                        {"key": "tagId", "type": "TEMPLATE", "value": "G-OLD"},
                        {
                            "key": "shared",
                            "type": "TEMPLATE",
                            "value": "{{Old Variable}}",
                        },
                    ],
                    "firingTriggerId": ["10"],
                    "tagFiringPriority": "10",
                    "paused": False,
                }
            ],
            "trigger": [
                {"triggerId": "10", "name": "Old event", "type": "CUSTOM_EVENT"},
                {"triggerId": "11", "name": "Canonical event", "type": "CUSTOM_EVENT"},
            ],
            "variable": [
                {
                    "variableId": "20",
                    "name": "Old Variable",
                    "type": "c",
                    "parameter": [{"key": "value", "value": "old"}],
                },
                {
                    "variableId": "21",
                    "name": "Unused Variable",
                    "type": "c",
                    "parameter": [{"key": "value", "value": "unused"}],
                },
            ],
            "folder": [],
            "builtInVariable": [],
            "customTemplate": [],
            "gtagConfig": [],
        }
    }


def work_unit_decision(index: int) -> dict:
    return {
        "decision_id": f"AUDIT-A-OBL-{index:04d}",
        "obligation_id": f"OBL-{index:04d}",
        "obligation_sha256": f"obligation-{index:04d}",
        "area_id": "AREA-01",
        "scope_level": "coverage",
        "audit_mechanism": "source_counted_coverage",
        "fact_kind": "coverage_attestation",
        "subject_keys": [],
        "family_ids": [],
        "candidate_id": "",
        "source_coordinates": [],
        "applicability": "applicable",
        "material_verification_triggers": [],
        "semantic_repair_records": [],
        "status": "pending",
        **{field: "" for field in CANONICAL_DECISION_FIELDS},
        "operation_proposal": {},
        "evidence_citations": [],
    }


class V2OperationSafetyTests(unittest.TestCase):
    def test_source_proven_obligations_cannot_be_grouped_as_justified(self) -> None:
        justified = {
            "decision_class": "justified_as_is",
            "operation_proposal": {},
        }
        known_repair = {
            "fact_kind": "configuration_obligation",
            "evidence": {
                "source_json_path": "$.containerVersion.tag[0]",
                "configuration_obligation": {
                    "obligation_key": "unused_document_write_support",
                    "required_outcome": "Issue",
                    "source_known_repair": {
                        "mode": "change",
                        "object_key": "tag:1",
                        "json_path": "$.containerVersion.tag[0].parameter[1].value",
                        "before": "true",
                        "after": "false",
                    },
                },
            },
        }
        self.assertTrue(
            any(
                "source-known configuration repair must be actionable" in error
                for error in decision_obligation_alignment_errors(
                    justified, known_repair, "decision"
                )
            )
        )

        ineffective_blocker = {
            "fact_kind": "ineffective_blocking_trigger",
            "evidence": {"object_ids": ["1", "9"]},
        }
        self.assertTrue(
            any(
                "statically ineffective blocker is a defect" in error
                for error in decision_obligation_alignment_errors(
                    justified, ineffective_blocker, "decision"
                )
            )
        )

        late_consent_default = {
            "fact_kind": "source_visible_default_update_architecture",
            "evidence": {
                "writer_facts": [
                    {
                        "object_key": "tag:2",
                        "commands": ["default", "update"],
                        "firing_trigger_ids": ["2147479572"],
                        "default_uses_consent_initialization": False,
                    }
                ]
            },
        }
        self.assertTrue(
            any(
                "late default consent writer is a defect" in error
                for error in decision_obligation_alignment_errors(
                    justified, late_consent_default, "decision"
                )
            )
        )

    def test_source_known_repair_requires_the_exact_operation(self) -> None:
        obligation = {
            "fact_kind": "configuration_obligation",
            "evidence": {
                "source_json_path": "$.containerVersion.tag[0]",
                "configuration_obligation": {
                    "obligation_key": "unused_document_write_support",
                    "required_outcome": "Issue",
                    "source_known_repair": {
                        "mode": "change",
                        "object_key": "tag:1",
                        "json_path": "$.containerVersion.tag[0].parameter[1].value",
                        "before": "true",
                        "after": "false",
                    },
                },
            },
        }
        decision = {
            "decision_class": "correct_but_materially_non_optimal",
            "operation_proposal": {
                **{field: [] for field in OPERATION_ACTION_FIELDS},
                "changes": [
                    {
                        "object_key": "tag:1",
                        "json_path": "$.parameter[1].value",
                        "before": "true",
                        "after": "false",
                    }
                ],
            },
        }
        self.assertEqual(
            [], decision_obligation_alignment_errors(decision, obligation, "decision")
        )
        decision["operation_proposal"]["changes"][0]["after"] = "true"
        self.assertTrue(
            any(
                "exactly implement the source-known repair" in error
                for error in decision_obligation_alignment_errors(
                    decision, obligation, "decision"
                )
            )
        )

    def test_non_actionable_decision_uses_compact_class_specific_fields(self) -> None:
        decision = {
            "decision_class": "justified_as_is",
            "criteria_assessment": "The locked evidence supports the configured distinction.",
            "priority": "None",
            "confidence": "High",
        }
        self.assertEqual([], semantic_contract_errors(decision, "decision"))

        actionable = {**decision, "decision_class": "defect"}
        errors = semantic_contract_errors(actionable, "decision")
        self.assertIn("decision: current_behavior is missing", errors)
        self.assertIn("decision: rollback is missing", errors)

    def test_operation_family_requires_a_human_readable_phrase(self) -> None:
        decision = {"decision_id": "AUDIT-A-DECISION-1"}
        proposal = {
            "operation_id": "OP-TEST-FAMILY",
            "source_decision_id": decision["decision_id"],
            "operation_family": "remove_priority",
            "exact_target_state": "The redundant priority field is absent.",
            "preconditions": "The locked source still contains that field.",
            "static_verification": "Replay confirms the field remains absent.",
            "rollback": "Restore the exact original priority field value.",
            "depends_on": [],
            **{field: [] for field in OPERATION_ACTION_FIELDS},
            "field_removals": [
                {"object_key": "tag:1", "field_path": "tagFiringPriority"}
            ],
        }
        errors = operation_proposal_errors(proposal, decision, set(), "decision")
        self.assertIn(
            "decision: operation operation_family must be a human-readable phrase "
            "of at least two words, not an underscore token",
            errors,
        )

        proposal["operation_family"] = "Remove priority"
        proposal["preconditions"] = []
        errors = operation_proposal_errors(proposal, decision, set(), "decision")
        self.assertIn(
            "decision: operation preconditions must be a string of at least 4 words",
            errors,
        )

    def test_recursive_work_unit_schema_type_failures_are_explicit(self) -> None:
        self.assertTrue(workload_estimate_schema_errors(None))
        malformed_workload = {
            "obligation_count": True,
            "object_count": -1,
            "relationship_count": "one",
            "custom_code_segment_count": 0,
            "shared_dependency_count": 0,
            "estimated_authored_tokens": 0,
            "schema_ceiling": {
                "single_obligations": 0,
                "single_estimated_tokens": True,
                "family_obligations": -1,
                "foreign": 1,
            },
        }
        workload_errors = workload_estimate_schema_errors(malformed_workload)
        self.assertGreaterEqual(len(workload_errors), 6)

        decision = work_unit_decision(1)
        decision["subject_keys"] = "tag:1"
        decision["semantic_repair_records"] = ["foreign"]
        decision["operation_proposal"] = None
        decision_errors = semantic_audit_decision_schema_errors(
            decision, "malformed decision"
        )
        self.assertTrue(any("string list" in error for error in decision_errors))
        self.assertTrue(any("object list" in error for error in decision_errors))
        self.assertTrue(any("operation_proposal" in error for error in decision_errors))

        self.assertTrue(discovery_schema_errors(None, "malformed discovery"))
        discovery_errors = discovery_schema_errors(
            {
                "discovery_id": "DISC-1",
                "area_id": "AREA-01",
                "scope_level": "relationship",
                "subject_keys": "tag:1",
                "family_ids": [],
                "source_coordinates": [],
                "decision": None,
            },
            "malformed discovery",
        )
        self.assertTrue(any("string list" in error for error in discovery_errors))
        self.assertTrue(any("semantic decision" in error for error in discovery_errors))

        self.assertTrue(operation_proposal_schema_errors("delete", "proposal"))
        _files, manifest_errors = declared_work_unit_files({})
        self.assertTrue(any("closed schema" in error for error in manifest_errors))

    def test_all_supported_actions_apply_in_dependency_order(self) -> None:
        source = operation_fixture()
        first = operation(
            "OP-001",
            creations=[
                {
                    "layer": "variable",
                    "object": {
                        "variableId": "22",
                        "name": "Created Variable",
                        "type": "c",
                        "parameter": [{"key": "value", "value": "created"}],
                    },
                }
            ],
            additions=[
                {"object_key": "tag:1", "json_path": "$.notes", "value": "Reviewed"}
            ],
            changes=[
                {
                    "object_key": "tag:1",
                    "json_path": "$.parameter[0].value",
                    "before": "G-OLD",
                    "after": "G-NEW",
                }
            ],
            removals=[
                {
                    "object_key": "tag:1",
                    "json_path": "$.tagFiringPriority",
                    "before": "10",
                }
            ],
            remaps=[
                {
                    "from_object_key": "trigger:10",
                    "to_object_key": "trigger:11",
                    "consumer_object_keys": ["tag:1"],
                }
            ],
            renames=[
                {
                    "object_key": "variable:20",
                    "before": "Old Variable",
                    "after": "Canonical Variable",
                }
            ],
            pauses=[
                {"object_key": "tag:1", "before": False, "after": True}
            ],
        )
        second = operation(
            "OP-002",
            deletions=[{"object_key": "variable:21"}],
        )
        second["depends_on"] = ["OP-001"]
        operations = [second, first]
        self.assertEqual([], validate_operations(source, operations))
        projected = apply_operations(source, operations)
        cv = container_version(projected)
        tag = cv["tag"][0]
        self.assertEqual("G-NEW", tag["parameter"][0]["value"])
        self.assertEqual("{{Canonical Variable}}", tag["parameter"][1]["value"])
        self.assertEqual(["11"], tag["firingTriggerId"])
        self.assertEqual("Reviewed", tag["notes"])
        self.assertNotIn("tagFiringPriority", tag)
        self.assertTrue(tag["paused"])
        self.assertEqual(
            {"20", "22"}, {row["variableId"] for row in cv["variable"]}
        )
        self.assertNotIn("zone", cv)
        self.assertEqual(
            operation_packet_sha256([first, second]),
            operation_packet_sha256([second, first]),
        )

    def test_conflicts_cycles_and_do_not_touch_are_blocked(self) -> None:
        source = operation_fixture()
        left = operation(
            "OP-A",
            changes=[
                {
                    "object_key": "tag:1",
                    "json_path": "$.parameter[0].value",
                    "before": "G-OLD",
                    "after": "G-A",
                }
            ],
        )
        right = operation(
            "OP-B",
            changes=[
                {
                    "object_key": "tag:1",
                    "json_path": "$.parameter[0].value",
                    "before": "G-OLD",
                    "after": "G-B",
                }
            ],
        )
        errors = validate_operations(source, [left, right], do_not_touch={"tag:1"})
        self.assertTrue(any("conflicting writes" in error for error in errors))
        self.assertTrue(any("do_not_touch" in error for error in errors))
        self.assertTrue(operation_write_conflicts([left, right]))

        cycle_a = operation("OP-CYCLE-A")
        cycle_b = operation("OP-CYCLE-B")
        cycle_a["depends_on"] = ["OP-CYCLE-B"]
        cycle_b["depends_on"] = ["OP-CYCLE-A"]
        with self.assertRaisesRegex(ValueError, "cycle"):
            dependency_order([cycle_a, cycle_b])

    def test_pause_and_rename_writes_are_conflict_checked_and_cannot_be_no_ops(self) -> None:
        source = operation_fixture()
        pause = operation(
            "OP-PAUSE",
            pauses=[{"object_key": "tag:1", "before": False, "after": True}],
        )
        contradictory_pause = operation(
            "OP-KEEP-ACTIVE",
            pauses=[{"object_key": "tag:1", "before": False, "after": False}],
        )
        self.assertTrue(operation_write_conflicts([pause, contradictory_pause]))
        self.assertTrue(
            any(
                "conflicting writes" in error
                for error in validate_operations(source, [pause, contradictory_pause])
            )
        )
        self.assertTrue(
            any(
                "pause is a no-op" in error
                for error in validate_operations(source, [contradictory_pause])
            )
        )

        rename_a = operation(
            "OP-RENAME-A",
            renames=[
                {
                    "object_key": "variable:20",
                    "before": "Old Variable",
                    "after": "Canonical Variable A",
                }
            ],
        )
        rename_b = operation(
            "OP-RENAME-B",
            renames=[
                {
                    "object_key": "variable:20",
                    "before": "Old Variable",
                    "after": "Canonical Variable B",
                }
            ],
        )
        self.assertTrue(operation_write_conflicts([rename_a, rename_b]))
        self.assertTrue(
            any(
                "conflicting writes" in error
                for error in validate_operations(source, [rename_a, rename_b])
            )
        )

    def test_do_not_touch_blocks_implicit_rename_consumer_changes(self) -> None:
        source = operation_fixture()
        rename = operation(
            "OP-RENAME",
            renames=[
                {
                    "object_key": "variable:20",
                    "before": "Old Variable",
                    "after": "Canonical Variable",
                }
            ],
        )
        errors = validate_operations(source, [rename], do_not_touch={"tag:1"})
        self.assertTrue(
            any("implicit operation" in error and "tag:1" in error for error in errors)
        )

    def test_server_route_client_gate_removal_requires_approved_owner(self) -> None:
        def consent_route_source(*, inherited_from_gtag_config: bool) -> dict:
            source = operation_fixture()
            cv = container_version(source)
            cv["tag"][0]["blockingTriggerId"] = ["12"]
            cv["trigger"].append(
                {
                    "triggerId": "12",
                    "name": "Block without vendor consent",
                    "type": "CUSTOM_EVENT",
                    "filter": [
                        {
                            "type": "DOES_NOT_CONTAIN",
                            "parameter": [
                                {
                                    "key": "arg0",
                                    "type": "TEMPLATE",
                                    "value": "{{didomiVendorsEnabled}}",
                                },
                                {
                                    "key": "arg1",
                                    "type": "TEMPLATE",
                                    "value": "vendor-42",
                                },
                            ],
                        }
                    ],
                }
            )
            route_parameter = {
                "key": "transport_url",
                "type": "TEMPLATE",
                "value": "https://collect.example.test",
            }
            if inherited_from_gtag_config:
                cv["gtagConfig"].append(
                    {
                        "gtagConfigId": "30",
                        "name": "Google destination settings",
                        "type": "googtag",
                        "parameter": [
                            {
                                "key": "tagId",
                                "type": "TEMPLATE",
                                "value": "G-OLD",
                            },
                            route_parameter,
                        ],
                    }
                )
            else:
                cv["tag"][0]["parameter"].append(route_parameter)
            return source

        remove_gate = operation(
            "OP-REMOVE-CLIENT-GATE",
            removals=[
                {
                    "object_key": "tag:1",
                    "json_path": "$.blockingTriggerId",
                    "before": ["12"],
                }
            ],
        )
        for inherited in (False, True):
            with self.subTest(inherited_from_gtag_config=inherited):
                source = consent_route_source(
                    inherited_from_gtag_config=inherited
                )
                projected = apply_operations(source, [remove_gate])
                errors = server_consent_gate_regression_errors(
                    source,
                    projected,
                    {"context": {"server_consent_gating_hosts": []}},
                )
                self.assertTrue(
                    any(
                        "collect.example.test" in error
                        and "retain a client gate" in error
                        for error in errors
                    )
                )
                self.assertEqual(
                    [],
                    server_consent_gate_regression_errors(
                        source,
                        projected,
                        {
                            "context": {
                                "server_consent_gating_hosts": [
                                    "https://collect.example.test"
                                ]
                            }
                        },
                    ),
                )

        source = consent_route_source(inherited_from_gtag_config=True)
        deleted = apply_operations(
            source,
            [operation("OP-DELETE-TAG", deletions=[{"object_key": "tag:1"}])],
        )
        self.assertEqual(
            [],
            server_consent_gate_regression_errors(
                source,
                deleted,
                {"context": {"server_consent_gating_hosts": []}},
            ),
        )

    def test_same_packet_route_addition_and_gate_removal_requires_owner(self) -> None:
        source = operation_fixture()
        cv = container_version(source)
        cv["tag"][0]["blockingTriggerId"] = ["12"]
        cv["trigger"].append(
            {
                "triggerId": "12",
                "name": "Block without vendor consent",
                "type": "CUSTOM_EVENT",
                "filter": [
                    {
                        "type": "DOES_NOT_CONTAIN",
                        "parameter": [
                            {
                                "key": "arg0",
                                "type": "TEMPLATE",
                                "value": "{{didomiVendorsEnabled}}",
                            },
                            {
                                "key": "arg1",
                                "type": "TEMPLATE",
                                "value": "vendor-42",
                            },
                        ],
                    }
                ],
            }
        )
        route_and_remove = operation(
            "OP-ADD-ROUTE-REMOVE-GATE",
            creations=[
                {
                    "layer": "gtagConfig",
                    "object": {
                        "gtagConfigId": "30",
                        "name": "Destination-linked server route",
                        "type": "googtag",
                        "parameter": [
                            {"key": "tagId", "type": "TEMPLATE", "value": "G-OLD"},
                            {
                                "key": "transport_url",
                                "type": "TEMPLATE",
                                "value": "https://collect.example.test",
                            },
                        ],
                    },
                }
            ],
            removals=[
                {
                    "object_key": "tag:1",
                    "json_path": "$.blockingTriggerId",
                    "before": ["12"],
                }
            ],
        )
        self.assertEqual([], validate_operations(source, [route_and_remove]))
        projected = apply_operations(source, [route_and_remove])
        errors = server_consent_gate_regression_errors(
            source,
            projected,
            {"context": {"server_consent_gating_hosts": []}},
        )
        self.assertTrue(
            any("collect.example.test" in error for error in errors), errors
        )
        self.assertEqual(
            [],
            server_consent_gate_regression_errors(
                source,
                projected,
                {
                    "context": {
                        "server_consent_gating_hosts": [
                            "https://collect.example.test"
                        ]
                    }
                },
            ),
        )

    def test_deletion_does_not_materialize_absent_layers(self) -> None:
        source = operation_fixture()
        projected = apply_operations(
            source,
            [operation("OP-DELETE", deletions=[{"object_key": "variable:21"}])],
        )
        cv = container_version(projected)
        self.assertNotIn("zone", cv)

    def test_non_convergence_has_a_fixed_blocking_outcome(self) -> None:
        self.assertEqual(3, MAX_CYCLES)
        with tempfile.TemporaryDirectory() as temporary:
            package = Path(temporary)
            (package / "fixed-point").mkdir()
            state = {
                "kind": "gtm_fixed_point_state",
                "schema_version": 1,
                "status": "awaiting_projection_reviews",
                "max_cycles": MAX_CYCLES,
                "current_cycle": MAX_CYCLES,
                "cycle_history": [
                    {"cycle_number": number, "status": "actionable"}
                    for number in range(1, MAX_CYCLES + 1)
                ],
            }
            result = _block_non_convergent(
                package,
                copy.deepcopy(state),
                "the third projection cycle produced a new actionable obligation",
            )
            self.assertEqual("non_convergent_target_state", result["status"])
            proof = json.loads(
                (package / "fixed-point" / "fixed-point-proof.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual("non_convergent_target_state", proof["status"])
            self.assertEqual(MAX_CYCLES, proof["max_cycles"])
            self.assertIn("reseal", proof["required_next_step"])

    def test_required_shards_must_be_closed_merged_and_unchanged(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            bundle = Path(temporary)
            decisions = [
                work_unit_decision(index)
                for index in range(MAX_SINGLE_OBLIGATIONS + 1)
            ]
            audit = {
                "audit_id": "audit-a",
                "source_sha256": "source-hash",
                "obligation_ledger_sha256": "ledger-hash",
                "decisions": decisions,
                "open_discoveries": [],
            }
            (bundle / "audit.json").write_text(
                json.dumps(audit, indent=2) + "\n", encoding="utf-8"
            )
            scan = {
                "counts": {"objects": 0, "relationships": 0},
                "objects": [],
                "architecture_evidence": {"families": []},
            }
            assurance = {"recomputed_invariants": {"custom_code_segments": []}}
            (bundle / "canonical-scan.json").write_text(
                json.dumps(scan, indent=2) + "\n", encoding="utf-8"
            )
            (bundle / "scan-assurance.json").write_text(
                json.dumps(assurance, indent=2) + "\n", encoding="utf-8"
            )
            manifest = build_work_units(bundle, audit, scan, assurance)
            self.assertEqual("family_sharded", manifest["strategy"])
            self.assertIn(
                "must be merged",
                " ".join(work_unit_completion_errors(bundle, audit, manifest)),
            )
            unit_record = manifest["work_units"][0]
            unit_path = bundle / "work-units" / unit_record["filename"]
            unit = json.loads(unit_path.read_text(encoding="utf-8"))
            manifest_path = bundle / "work-units" / "work-unit-manifest.json"
            forged_manifest = copy.deepcopy(manifest)
            forged_manifest["undeclared_context"] = "foreign audit verdict"
            manifest_path.write_text(
                json.dumps(forged_manifest, indent=2) + "\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "closed schema"):
                merge_work_units(bundle)
            manifest_path.write_text(
                json.dumps(manifest, indent=2) + "\n",
                encoding="utf-8",
            )
            forged_workload = copy.deepcopy(manifest)
            forged_workload["workload_estimate"]["object_count"] += 1
            forged_workload["work_unit_manifest_sha256"] = work_unit_identity_hash(
                forged_workload
            )
            manifest_path.write_text(
                json.dumps(forged_workload, indent=2) + "\n", encoding="utf-8"
            )
            with self.assertRaisesRegex(ValueError, "deterministic reconstruction"):
                merge_work_units(bundle)
            manifest_path.write_text(
                json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
            )
            forged_unknown = copy.deepcopy(unit)
            forged_unknown["undeclared_context"] = "foreign audit verdict"
            forged_unknown["unit_closure"] = "Forged unit presented as complete."
            unit_path.write_text(
                json.dumps(forged_unknown, indent=2) + "\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "closed schema"):
                merge_work_units(bundle)
            forged_nested_decision = copy.deepcopy(unit)
            forged_nested_decision["decisions"][0][
                "undeclared_judgment_context"
            ] = "foreign verdict"
            forged_nested_decision["unit_closure"] = "Forged nested decision."
            unit_path.write_text(
                json.dumps(forged_nested_decision, indent=2) + "\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "decision fields.*closed schema"):
                merge_work_units(bundle)
            forged_discovery = copy.deepcopy(unit)
            forged_discovery["open_discoveries"] = [
                {
                    "discovery_id": "AUDIT-A-DISC-FOREIGN",
                    "area_id": "AREA-10",
                    "scope_level": "relationship",
                    "subject_keys": ["tag:1"],
                    "family_ids": [],
                    "source_coordinates": ["$.containerVersion.tag[0]"],
                    "decision": {
                        "decision_id": "AUDIT-A-DISC-FOREIGN",
                        **{field: "" for field in CANONICAL_DECISION_FIELDS},
                        "operation_proposal": {},
                        "evidence_citations": [],
                        "undeclared_judgment_context": "foreign verdict",
                    },
                }
            ]
            forged_discovery["unit_closure"] = "Forged nested discovery."
            unit_path.write_text(
                json.dumps(forged_discovery, indent=2) + "\n", encoding="utf-8"
            )
            with self.assertRaisesRegex(
                ValueError, "discovery decision fields.*closed schema"
            ):
                merge_work_units(bundle)
            forged_action = copy.deepcopy(unit)
            forged_action["decisions"][0]["operation_proposal"] = {
                "operation_id": "OP-NESTED-SCHEMA",
                "source_decision_id": forged_action["decisions"][0]["decision_id"],
                "operation_family": "consent_control",
                "exact_target_state": "One exact target state is retained.",
                "preconditions": "The locked source remains unchanged.",
                "static_verification": "The exact structured action is replayed.",
                "rollback": "Restore the exact prior source field.",
                "depends_on": [],
                **{field: [] for field in OPERATION_ACTION_FIELDS},
            }
            forged_action["decisions"][0]["operation_proposal"]["deletions"] = [
                {"object_key": "tag:1", "foreign_context": "delete it"}
            ]
            forged_action["unit_closure"] = "Forged nested action."
            unit_path.write_text(
                json.dumps(forged_action, indent=2) + "\n", encoding="utf-8"
            )
            with self.assertRaisesRegex(
                ValueError, "operation deletions.*closed schema"
            ):
                merge_work_units(bundle)
            for field, forged_value, recompute_identity in (
                ("audit_id", "audit-b", False),
                ("source_sha256", "forged-source", False),
                ("owner_family_id", "forged-owner", True),
            ):
                forged = copy.deepcopy(unit)
                forged[field] = forged_value
                forged["unit_closure"] = "Forged unit presented as complete."
                if recompute_identity:
                    forged["work_unit_identity_sha256"] = work_unit_identity_hash(
                        forged
                    )
                unit_path.write_text(
                    json.dumps(forged, indent=2) + "\n", encoding="utf-8"
                )
                with (
                    self.subTest(forged_field=field),
                    self.assertRaisesRegex(ValueError, "work unit contract changed"),
                ):
                    merge_work_units(bundle)
            unit_path.write_text(
                json.dumps(unit, indent=2) + "\n", encoding="utf-8"
            )
            for declared_unit in manifest["work_units"]:
                declared_path = bundle / "work-units" / declared_unit["filename"]
                closed_unit = json.loads(declared_path.read_text(encoding="utf-8"))
                closed_unit["unit_closure"] = (
                    "Every obligation in this complete work unit was reviewed."
                )
                declared_path.write_text(
                    json.dumps(closed_unit, indent=2) + "\n", encoding="utf-8"
                )
            merge_work_units(bundle)
            merged = json.loads((bundle / "audit.json").read_text(encoding="utf-8"))
            self.assertEqual([], work_unit_completion_errors(bundle, merged, manifest))
            forged_audit = copy.deepcopy(merged)
            forged_audit["decisions"][0]["scope_level"] = "forged-after-merge"
            forged_completion = forged_audit["work_unit_completion"]
            forged_completion["merged_decisions_sha256"] = stable_hash(
                forged_audit["decisions"], 64
            )
            forged_completion["work_unit_completion_sha256"] = stable_hash(
                {
                    key: value
                    for key, value in forged_completion.items()
                    if key != "work_unit_completion_sha256"
                },
                64,
            )
            self.assertTrue(
                any(
                    "not the exact deterministic work-unit merge" in error
                    for error in work_unit_completion_errors(
                        bundle, forged_audit, manifest
                    )
                )
            )
            malformed_unit = copy.deepcopy(unit)
            malformed_unit["decisions"].append("foreign non-object decision")
            unit_path.write_text(
                json.dumps(malformed_unit, indent=2) + "\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "declared-only object list"):
                merge_work_units(bundle)
            malformed_unit_audit = copy.deepcopy(merged)
            malformed_completion = malformed_unit_audit["work_unit_completion"]
            malformed_completion["completed_units"][0][
                "completed_work_unit_sha256"
            ] = stable_hash(malformed_unit, 64)
            malformed_completion["work_unit_completion_sha256"] = stable_hash(
                {
                    key: value
                    for key, value in malformed_completion.items()
                    if key != "work_unit_completion_sha256"
                },
                64,
            )
            self.assertTrue(
                any(
                    "declared-only object list" in error
                    for error in work_unit_completion_errors(
                        bundle,
                        malformed_unit_audit,
                        manifest,
                    )
                )
            )
            unit_path.write_text(
                json.dumps(unit, indent=2) + "\n", encoding="utf-8"
            )
            malformed_proof_audit = copy.deepcopy(merged)
            malformed_proof = malformed_proof_audit["work_unit_completion"]
            malformed_proof["undeclared_context"] = "foreign proof context"
            malformed_proof["completed_units"].append(
                copy.deepcopy(malformed_proof["completed_units"][0])
            )
            malformed_proof["completed_units"].append("foreign non-object row")
            malformed_proof["work_unit_completion_sha256"] = stable_hash(
                {
                    key: value
                    for key, value in malformed_proof.items()
                    if key != "work_unit_completion_sha256"
                },
                64,
            )
            malformed_proof_errors = work_unit_completion_errors(
                bundle,
                malformed_proof_audit,
                manifest,
            )
            self.assertTrue(
                any("closed schema" in error for error in malformed_proof_errors)
            )
            self.assertTrue(
                any("non-object row" in error for error in malformed_proof_errors)
            )
            self.assertTrue(
                any("duplicate identities" in error for error in malformed_proof_errors)
            )
            unit["unit_closure"] += " Changed after merge."
            unit_path.write_text(json.dumps(unit, indent=2) + "\n", encoding="utf-8")
            self.assertTrue(
                any(
                    "changed after merge" in error
                    for error in work_unit_completion_errors(bundle, merged, manifest)
                )
            )


if __name__ == "__main__":
    unittest.main()
