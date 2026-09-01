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

from gtm_audit_contract import OPERATION_ACTION_FIELDS  # noqa: E402
from gtm_audit_work_units import (  # noqa: E402
    MAX_SINGLE_OBLIGATIONS,
    build_work_units,
    merge_work_units,
    work_unit_completion_errors,
)
from gtm_fixed_point import MAX_CYCLES, _block_non_convergent  # noqa: E402
from gtm_lib import container_version  # noqa: E402
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


class V2OperationSafetyTests(unittest.TestCase):
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

    def test_deletion_does_not_materialize_absent_layers(self) -> None:
        source = operation_fixture()
        projected = apply_operations(
            source,
            [operation("OP-DELETE", deletions=[{"object_key": "variable:21"}])],
        )
        cv = container_version(projected)
        self.assertNotIn("zone", cv)
        self.assertNotIn("client", cv)

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
                {
                    "decision_id": f"AUDIT-A-OBL-{index:04d}",
                    "obligation_id": f"OBL-{index:04d}",
                    "scope_level": "coverage",
                    "family_ids": [],
                    "subject_keys": [],
                }
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
            manifest = build_work_units(bundle, audit, scan, assurance)
            self.assertEqual("family_sharded", manifest["strategy"])
            self.assertIn(
                "must be merged",
                " ".join(work_unit_completion_errors(bundle, audit, manifest)),
            )
            unit_record = manifest["work_units"][0]
            unit_path = bundle / "work-units" / unit_record["filename"]
            unit = json.loads(unit_path.read_text(encoding="utf-8"))
            unit["unit_closure"] = (
                "Every shared-infrastructure obligation in this complete work unit was reviewed."
            )
            unit_path.write_text(json.dumps(unit, indent=2) + "\n", encoding="utf-8")
            merge_work_units(bundle)
            merged = json.loads((bundle / "audit.json").read_text(encoding="utf-8"))
            self.assertEqual([], work_unit_completion_errors(bundle, merged, manifest))
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
