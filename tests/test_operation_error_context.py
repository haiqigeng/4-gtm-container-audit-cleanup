"""Safety diagnostics must not turn packet membership into repair ownership."""

import copy
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from gtm_target_synthesis import operation_error_context


def operation(identity, **actions):
    return {
        "operation_id": identity,
        "source_reconciled_decision_ids": ["CD-" + identity],
        **actions,
    }


class OperationErrorContextTests(unittest.TestCase):
    def test_exact_operation_id_takes_precedence_over_object_matches(self):
        rows = [
            operation("OP-1", changes=[{"object_key": "tag:1"}]),
            operation("OP-10", changes=[{"object_key": "tag:1"}]),
        ]
        message = operation_error_context(rows, ["OP-10: invalid source path tag:1"])[0]
        self.assertTrue(message.endswith(
            "[packet operations: OP-10; owning source decisions: CD-OP-10]"
        ))

    def test_conflict_retains_all_explicit_owners_and_merged_decisions(self):
        rows = [operation("OP-ONE"), operation("OP-TWO"), operation("OP-OTHER")]
        rows[0]["source_reconciled_decision_ids"] = ["CD-B", "CD-A", "CD-A"]
        message = operation_error_context(rows, ["OP-TWO: conflicting writes with OP-ONE"])[0]
        self.assertTrue(message.endswith(
            "[packet operations: OP-ONE, OP-TWO; owning source decisions: CD-A, CD-B, CD-OP-TWO]"
        ))

    def test_object_errors_match_each_existing_action_target_without_prefix_collision(self):
        for field in ("additions", "changes", "removals", "renames", "pauses", "deletions"):
            with self.subTest(field=field):
                rows = [
                    operation("OP-RELEVANT", **{field: [{"object_key": "tag:10"}]}),
                    operation("OP-UNRELATED", **{field: [{"object_key": "tag:1"}]}),
                ]
                message = operation_error_context(rows, ["tag:10: visible client gate would be removed"])[0]
                self.assertTrue(message.endswith(
                    "[candidate operations (object match): OP-RELEVANT; "
                    "candidate source decisions: CD-OP-RELEVANT; operation ownership unresolved]"
                ))
                self.assertNotIn("owning source decisions", message)

    def test_remap_source_destination_and_consumers_are_related(self):
        rows = [
            operation("OP-REMAP", remaps=[{
                "from_object_key": "variable:20", "to_object_key": "variable:21",
                "consumer_object_keys": ["tag:1"],
            }]),
            operation("OP-OTHER", deletions=[{"object_key": "variable:200"}]),
        ]
        for target in ("variable:20", "variable:21", "tag:1"):
            with self.subTest(target=target):
                message = operation_error_context(rows, [f"missing dependency {target}"])[0]
                self.assertIn("candidate operations (object match): OP-REMAP;", message)
                self.assertNotIn("OP-OTHER", message)

    def test_created_objects_use_their_layer_identity(self):
        for layer, id_key in (("tag", "tagId"), ("variable", "variableId"),
                              ("customTemplate", "templateId")):
            with self.subTest(layer=layer):
                rows = [
                    operation("OP-CREATE", creations=[{
                        "layer": layer, "object": {id_key: "42", "name": "New object"},
                    }]),
                    operation("OP-OTHER", creations=[{
                        "layer": layer, "object": {id_key: "420"},
                    }]),
                ]
                message = operation_error_context(rows, [f"{layer}:42: missing dependency"])[0]
                self.assertIn("candidate operations (object match): OP-CREATE;", message)
                self.assertNotIn("OP-OTHER", message)

    def test_multiple_related_targets_do_not_claim_exact_causality(self):
        rows = [
            operation("OP-CHANGE", changes=[{"object_key": "tag:1"}]),
            operation("OP-DELETE", deletions=[{"object_key": "variable:20"}]),
            operation("OP-OTHER", renames=[{"object_key": "tag:2"}]),
        ]
        message = operation_error_context(rows, [
            "target graph regression: tag:1: missing dependency variable_reference:variable:20"
        ])[0]
        self.assertIn("candidate operations (object match): OP-CHANGE, OP-DELETE;", message)
        self.assertNotIn("owning source decisions", message)
        self.assertNotIn("OP-OTHER", message)

    def test_consumer_match_does_not_prove_ownership_of_deleted_dependency_failure(self):
        rows = [
            operation("OP-PRIORITY", removals=[{
                "object_key": "tag:1", "json_path": "$.priority",
                "before": {"type": "INTEGER", "value": "0"},
            }]),
            operation("OP-DELETE-VARIABLE", deletions=[{"object_key": "variable:20"}]),
        ]
        message = operation_error_context(rows, [
            "target graph regression: tag:1: missing dependency variable_reference:Deleted Variable"
        ])[0]
        # The message names the consumer, but does not identify variable:20.
        # A matching consumer operation must never become a proven cause.
        self.assertIn("candidate operations (object match): OP-PRIORITY;", message)
        self.assertIn("candidate source decisions: CD-OP-PRIORITY;", message)
        self.assertIn("operation ownership unresolved", message)
        self.assertNotIn("owning source decisions", message)

    def test_unresolved_errors_never_attribute_the_whole_packet(self):
        rows = [operation("OP-KNOWN", changes=[{"object_key": "tag:1"}])]
        for error in ("scan assurance failed", "tag:99: missing dependency",
                      "OP-KNOWN-OTHER: invalid action"):
            for packet in (rows, []):
                with self.subTest(error=error, empty=not packet):
                    message = operation_error_context(packet, [error])[0]
                    self.assertEqual(
                        error + " [packet-wide validation; operation ownership unresolved]",
                        message,
                    )

    def test_error_order_and_inputs_are_preserved(self):
        rows = [operation("OP-ONE", changes=[{"object_key": "tag:1"}])]
        errors = ["tag:1: missing dependency", "scan assurance failed", "OP-ONE: invalid action"]
        before = copy.deepcopy((rows, errors))
        result = operation_error_context(rows, errors)
        self.assertEqual(3, len(result))
        self.assertTrue(all(
            message.startswith(error + " [")
            for error, message in zip(errors, result, strict=True)
        ))
        self.assertEqual(before, (rows, errors))


if __name__ == "__main__":
    unittest.main()
