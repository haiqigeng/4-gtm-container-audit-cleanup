from __future__ import annotations

import copy
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

from gtm_approval_response import (  # noqa: E402
    CLEANUP_PACKET_SCHEMA_VERSION,
    approval_contract,
)
from gtm_change_log_build import build_change_log  # noqa: E402
from gtm_diff_operations import execution_verification  # noqa: E402
from gtm_diff_operations import operations as diff_operations  # noqa: E402
from gtm_execution_guard import live_readback_binding  # noqa: E402
from gtm_future_state_check import apply_operations  # noqa: E402
from gtm_lib import container_version  # noqa: E402


def mutation_export() -> dict:
    return {
        "containerVersion": {
            "publicId": "GTM-MUTATION-TEST",
            "tag": [
                {"tagId": "1", "name": "Source Tag", "type": "html"},
                {"tagId": "2", "name": "Target Tag", "type": "html"},
                {
                    "tagId": "3",
                    "name": "Consumer Tag",
                    "type": "html",
                    "parentFolderId": "30",
                    "firingTriggerId": ["10"],
                    "blockingTriggerId": ["10"],
                    "setupTag": [{"tagName": "Source Tag"}],
                    "teardownTag": [{"tagName": "Source Tag"}],
                    "parameter": [
                        {
                            "type": "TEMPLATE",
                            "key": "value",
                            "value": "{{Source Var}}",
                        }
                    ],
                },
            ],
            "trigger": [
                {"triggerId": "10", "name": "Source Trigger", "type": "CUSTOM_EVENT"},
                {"triggerId": "11", "name": "Target Trigger", "type": "CUSTOM_EVENT"},
            ],
            "variable": [
                {"variableId": "20", "name": "Source Var", "type": "c"},
                {"variableId": "21", "name": "Target Var", "type": "c"},
            ],
            "folder": [
                {"folderId": "30", "name": "Source Folder"},
                {"folderId": "31", "name": "Target Folder"},
            ],
            "zone": [
                {
                    "zoneId": "40",
                    "name": "Zone Consumer",
                    "boundary": {"customEvaluationTriggerId": ["10"]},
                }
            ],
        }
    }


def empty_actions(**values: object) -> dict:
    operation = {
        "creations": [],
        "additions": [],
        "changes": [],
        "remaps": [],
        "renames": [],
        "deletions": [],
    }
    operation.update(values)
    return operation


def cleanup_packet(operation_rows: list[dict] | None = None) -> dict:
    packet = {
        "kind": "gtm_reconciled_operations",
        "schema_version": CLEANUP_PACKET_SCHEMA_VERSION,
        "source_sha256": "source",
        "plan_status": "complete",
        "operations": list(operation_rows or []),
    }
    packet["approval_contract"] = approval_contract(packet)
    return packet


class MutationSafetyTests(unittest.TestCase):
    def test_live_binding_accepts_additional_compatible_identity_fields(self) -> None:
        source = {"containerVersion": {"publicId": "GTM-SAME", "tag": []}}
        readback = {
            "containerVersion": {
                "publicId": "GTM-SAME",
                "accountId": "1",
                "containerId": "2",
                "tag": [],
            }
        }

        report, errors = live_readback_binding(
            source, readback, "source", "source"
        )

        self.assertEqual([], errors)
        self.assertEqual("pass", report["container_identity_binding"]["status"])

    def test_live_binding_rejects_identity_free_equal_graphs(self) -> None:
        source = {"containerVersion": {"tag": []}}

        report, errors = live_readback_binding(
            source, copy.deepcopy(source), "source", "source"
        )

        self.assertEqual("fail", report["status"])
        self.assertTrue(errors)
        self.assertTrue(any("identity" in error for error in errors))

    def test_executed_workbook_rejects_uncertified_readback(self) -> None:
        payload = {
            "execution_mode": "executed",
            "execution_verification": {"status": "fail"},
            "changes": [],
        }
        with (
            tempfile.TemporaryDirectory() as directory,
            self.assertRaisesRegex(ValueError, "final complete-readback"),
        ):
            build_change_log(payload, Path(directory) / "change-log.xlsx")

    def test_executed_workbook_accepts_only_the_certified_final_readback(self) -> None:
        fingerprint = "a" * 64
        payload = {
            "execution_mode": "executed",
            "execution_verification": {
                "status": "pass",
                "authoritative_result": "final_complete_gtm_readback",
                "matches_approved_future_state": True,
                "unlinked_change_ids": [],
                "expected_configuration_sha256": fingerprint,
                "readback_configuration_sha256": fingerprint,
                "container_identity_binding": {"status": "pass"},
                "operation_packet_binding": {"status": "pass"},
            },
            "final_readback": {"authoritative": True},
            "changes": [],
        }
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "change-log.xlsx"
            build_change_log(payload, output)
            self.assertTrue(output.is_file())

    def test_future_state_applies_every_supported_remap_and_rename(self) -> None:
        operation = empty_actions(
            remaps=[
                {
                    "from_object_key": "trigger:10",
                    "to_object_key": "trigger:11",
                    "consumer_object_keys": ["tag:3", "zone:40"],
                },
                {
                    "from_object_key": "variable:20",
                    "to_object_key": "variable:21",
                    "consumer_object_keys": ["tag:3"],
                },
                {
                    "from_object_key": "tag:1",
                    "to_object_key": "tag:2",
                    "consumer_object_keys": ["tag:3"],
                },
                {
                    "from_object_key": "folder:30",
                    "to_object_key": "folder:31",
                    "consumer_object_keys": ["tag:3"],
                },
            ],
            renames=[
                {
                    "object_key": "variable:21",
                    "before": "Target Var",
                    "after": "DLV - Canonical Value",
                },
                {
                    "object_key": "tag:2",
                    "before": "Target Tag",
                    "after": "Vendor - Canonical Event",
                },
            ],
            deletions=[
                {"object_key": "trigger:10"},
                {"object_key": "variable:20"},
                {"object_key": "tag:1"},
                {"object_key": "folder:30"},
            ],
        )
        future, errors = apply_operations(mutation_export(), {"operations": [operation]})
        self.assertEqual([], errors)
        cv = container_version(future)
        consumer = next(row for row in cv["tag"] if row["tagId"] == "3")
        self.assertEqual(["11"], consumer["firingTriggerId"])
        self.assertEqual(["11"], consumer["blockingTriggerId"])
        self.assertEqual(["11"], cv["zone"][0]["boundary"]["customEvaluationTriggerId"])
        self.assertEqual("31", consumer["parentFolderId"])
        self.assertEqual("{{DLV - Canonical Value}}", consumer["parameter"][0]["value"])
        self.assertEqual("Vendor - Canonical Event", consumer["setupTag"][0]["tagName"])
        self.assertEqual("Vendor - Canonical Event", consumer["teardownTag"][0]["tagName"])
        self.assertEqual({"2", "3"}, {row["tagId"] for row in cv["tag"]})
        self.assertEqual({"11"}, {row["triggerId"] for row in cv["trigger"]})
        self.assertEqual({"21"}, {row["variableId"] for row in cv["variable"]})
        self.assertEqual({"31"}, {row["folderId"] for row in cv["folder"]})

    def test_change_log_attribution_honors_global_phase_order(self) -> None:
        remap = empty_actions(
            operation_id="OP-REMAP",
            why_it_matters="Replace the source variable with the newly created canonical value.",
            remaps=[
                {
                    "from_object_key": "variable:20",
                    "to_object_key": "variable:99",
                    "consumer_object_keys": ["tag:3"],
                }
            ],
            deletions=[{"object_key": "variable:20"}],
        )
        creation = empty_actions(
            operation_id="OP-CREATE",
            why_it_matters="Create the canonical value required by the approved remap.",
            creations=[
                {
                    "layer": "variable",
                    "object": {"variableId": "99", "name": "Canonical Var", "type": "c"},
                }
            ],
        )
        payload = {"operations": [remap, creation]}
        future, errors = apply_operations(mutation_export(), payload)
        self.assertEqual([], errors)
        rows = diff_operations(
            container_version(mutation_export()),
            container_version(future),
            "Direct GTM/MCP/API",
            payload,
            "executed",
        )
        created = next(row for row in rows if row["object_id"] == "99")
        deleted = next(row for row in rows if row["object_id"] == "20")
        remapped = next(
            row
            for row in rows
            if row["object_id"] == "3" and "parameter" in row["field_path"]
        )
        self.assertEqual("OP-CREATE", created["operation_id"])
        self.assertEqual("OP-REMAP", deleted["operation_id"])
        self.assertEqual("OP-REMAP", remapped["operation_id"])
        self.assertTrue(all(row["status"] == "Applied" for row in (created, deleted, remapped)))

    def test_created_object_with_two_owning_operations_is_not_falsely_linked(self) -> None:
        creation = empty_actions(
            operation_id="OP-CREATE",
            creations=[
                {
                    "layer": "variable",
                    "object": {
                        "variableId": "99",
                        "name": "Canonical Var",
                        "type": "c",
                        "parameter": [],
                    },
                }
            ],
        )
        addition = empty_actions(
            operation_id="OP-ADD",
            additions=[
                {
                    "object_key": "variable:99",
                    "json_path": "$.containerVersion.variable[2].parameter",
                    "mode": "append",
                    "value": {"type": "TEMPLATE", "key": "value", "value": "canonical"},
                }
            ],
        )
        payload = {"operations": [addition, creation]}
        future, errors = apply_operations(mutation_export(), payload)
        self.assertEqual([], errors)
        rows = diff_operations(
            container_version(mutation_export()),
            container_version(future),
            "Direct GTM/MCP/API",
            payload,
            "executed",
        )
        created = next(row for row in rows if row["object_id"] == "99")
        self.assertEqual("", created["operation_id"])
        self.assertEqual("Blocked: missing approved operation link", created["status"])

    def test_invalid_mutations_fail_closed_without_partial_guessing(self) -> None:
        source = mutation_export()
        invalid = empty_actions(
            creations=[
                {"layer": "variable", "object": {"variableId": "20", "name": "Duplicate"}},
                {"layer": "unsupported", "object": {"name": "Unknown"}},
            ],
            additions=[
                {
                    "object_key": "tag:404",
                    "json_path": "$.missing",
                    "mode": "set",
                    "value": True,
                },
                {
                    "object_key": "tag:3",
                    "json_path": "$.name",
                    "mode": "set",
                    "value": "Duplicate field",
                },
            ],
            changes=[
                {
                    "object_key": "tag:3",
                    "json_path": "$.name",
                    "before": "Stale name",
                    "after": "New name",
                }
            ],
            remaps=[
                {
                    "from_object_key": "trigger:10",
                    "to_object_key": "variable:21",
                    "consumer_object_keys": ["tag:3"],
                }
            ],
            renames=[
                {"object_key": "tag:3", "before": "Stale name", "after": "New name"}
            ],
            deletions=[{"object_key": "tag:404"}],
        )
        future, errors = apply_operations(source, {"operations": [invalid]})
        self.assertGreaterEqual(len(errors), 7)
        self.assertTrue(any("duplicates existing object" in error for error in errors))
        self.assertTrue(any("supported GTM layer" in error for error in errors))
        self.assertTrue(any("crosses GTM layers" in error for error in errors))
        self.assertEqual(mutation_export()["containerVersion"]["tag"], future["containerVersion"]["tag"])

    def test_input_export_is_never_mutated_in_place(self) -> None:
        source = mutation_export()
        original = copy.deepcopy(source)
        apply_operations(
            source,
            {
                "operations": [
                    empty_actions(
                        renames=[
                            {
                                "object_key": "tag:3",
                                "before": "Consumer Tag",
                                "after": "Vendor - Consumer Event",
                            }
                        ]
                    )
                ]
            },
        )
        self.assertEqual(original, source)

    def test_execution_verification_certifies_exact_approved_readback(self) -> None:
        approved = cleanup_packet(
            [
                empty_actions(
                    operation_id="OP-RENAME",
                    why_it_matters="Give the retained tag its approved canonical name.",
                    renames=[
                        {
                            "object_key": "tag:3",
                            "before": "Consumer Tag",
                            "after": "Vendor - Consumer Event",
                        }
                    ],
                )
            ]
        )
        source_cv = container_version(mutation_export())
        future, errors = apply_operations(mutation_export(), approved)
        self.assertEqual([], errors)
        future_cv = container_version(future)
        rows = diff_operations(
            source_cv,
            future_cv,
            "Direct GTM/MCP/API",
            approved,
            "executed",
        )

        verification = execution_verification(source_cv, future_cv, approved, rows)

        self.assertEqual("pass", verification["status"])
        self.assertTrue(verification["matches_approved_future_state"])
        self.assertEqual([], verification["unlinked_change_ids"])
        self.assertEqual(0, verification["unexpected_or_missing_field_count"])
        self.assertEqual(
            "final_complete_gtm_readback", verification["authoritative_result"]
        )
        self.assertEqual(
            verification["expected_configuration_sha256"],
            verification["readback_configuration_sha256"],
        )
        self.assertEqual(
            {
                "missing_object_keys": [],
                "unexpected_object_keys": [],
                "changed_object_keys": [],
            },
            verification["configuration_differences"],
        )

    def test_execution_verification_rejects_readback_drift(self) -> None:
        approved = cleanup_packet(
            [
                empty_actions(
                    operation_id="OP-RENAME",
                    why_it_matters="Give the retained tag its approved canonical name.",
                    renames=[
                        {
                            "object_key": "tag:3",
                            "before": "Consumer Tag",
                            "after": "Vendor - Consumer Event",
                        }
                    ],
                )
            ]
        )
        source_cv = container_version(mutation_export())
        readback, errors = apply_operations(mutation_export(), approved)
        self.assertEqual([], errors)
        readback_cv = container_version(readback)
        consumer = next(row for row in readback_cv["tag"] if row["tagId"] == "3")
        consumer["firingTriggerId"] = ["11"]
        rows = diff_operations(
            source_cv,
            readback_cv,
            "Direct GTM/MCP/API",
            approved,
            "executed",
        )

        verification = execution_verification(source_cv, readback_cv, approved, rows)

        self.assertEqual("fail", verification["status"])
        self.assertFalse(verification["matches_approved_future_state"])
        self.assertGreater(verification["unexpected_or_missing_field_count"], 0)
        self.assertTrue(verification["unlinked_change_ids"])
        self.assertIn(
            "tag:3", verification["configuration_differences"]["changed_object_keys"]
        )

    def test_execution_verification_rejects_another_container_with_same_graph(self) -> None:
        approved = cleanup_packet()
        source_cv = container_version(mutation_export())
        other_cv = copy.deepcopy(source_cv)
        other_cv["publicId"] = "GTM-OTHER-CONTAINER"

        verification = execution_verification(source_cv, other_cv, approved, [])

        self.assertEqual("fail", verification["status"])
        self.assertEqual(
            "fail", verification["container_identity_binding"]["status"]
        )
        self.assertTrue(
            any("identity" in error for error in verification["errors"])
        )

    def test_execution_verification_ignores_workspace_id_only(self) -> None:
        approved = cleanup_packet()
        source_cv = container_version(mutation_export())
        source_cv["workspaceId"] = "100"
        readback_cv = copy.deepcopy(source_cv)
        readback_cv["workspaceId"] = "101"

        verification = execution_verification(
            source_cv, readback_cv, approved, []
        )

        self.assertEqual("pass", verification["status"])
        self.assertEqual(0, verification["unexpected_or_missing_field_count"])

    def test_execution_verification_ignores_readback_tag_manager_url(self) -> None:
        approved = cleanup_packet()
        source_cv = container_version(mutation_export())
        readback_cv = copy.deepcopy(source_cv)
        readback_cv["tag"][0]["tagManagerUrl"] = (
            "https://tagmanager.google.com/#/container/accounts/1/containers/2"
        )

        verification = execution_verification(
            source_cv, readback_cv, approved, []
        )

        self.assertEqual("pass", verification["status"])
        self.assertEqual(0, verification["unexpected_or_missing_field_count"])

    def test_execution_verification_rejects_legacy_packet_schema(self) -> None:
        approved = cleanup_packet()
        approved["schema_version"] = 4
        approved["approval_contract"] = approval_contract(approved)
        source_cv = container_version(mutation_export())

        verification = execution_verification(
            source_cv, copy.deepcopy(source_cv), approved, []
        )

        self.assertEqual("fail", verification["status"])
        self.assertEqual("fail", verification["operation_packet_binding"]["status"])
        self.assertFalse(verification["matches_approved_future_state"])


if __name__ == "__main__":
    unittest.main()
