"""Object positions may change; exact operation values must remain source-bound."""

from __future__ import annotations

import copy
import unittest

from test_v2_operation_safety import operation, operation_fixture

# The fixture module adds scripts/ to sys.path before this runtime import.
# isort: split
from gtm_lib import stable_hash
from gtm_operation_model import apply_operations, validate_operations


class ProjectionPositionTests(unittest.TestCase):
    def setUp(self):
        self.source = operation_fixture()
        self.source["containerVersion"]["tag"].insert(
            0, {"tagId": "99", "name": "Unused preceding tag", "type": "html"}
        )
        self.delete = operation(
            "OP-DELETE-PRECEDING", deletions=[{"object_key": "tag:99"}]
        )

    def test_deleting_preceding_object_preserves_remaining_objects_and_input(self):
        before = copy.deepcopy(self.source)
        self.assertEqual([], validate_operations(self.source, [self.delete], source_sha256=stable_hash(self.source, 64)))
        projected = apply_operations(self.source, [self.delete], source_sha256=stable_hash(self.source, 64))
        expected = copy.deepcopy(before)
        expected["containerVersion"]["tag"].pop(0)
        self.assertEqual(expected, projected)
        self.assertEqual(before, self.source)

    def test_dependent_change_resolves_object_identity_after_position_shift(self):
        change = operation(
            "OP-CHANGE",
            changes=[{
                "object_key": "tag:1", "json_path": "$.parameter[0].value",
                "before_source_sha256": stable_hash(self.source, 64), "after": "G-NEW",
            }],
        )
        change["depends_on"] = [self.delete["operation_id"]]
        before = copy.deepcopy([self.source, self.delete, change])
        self.assertEqual([], validate_operations(self.source, [change, self.delete], source_sha256=stable_hash(self.source, 64)))
        first = apply_operations(self.source, [change, self.delete], source_sha256=stable_hash(self.source, 64))
        second = apply_operations(self.source, [self.delete, change], source_sha256=stable_hash(self.source, 64))
        self.assertEqual(first, second)
        self.assertEqual("1", first["containerVersion"]["tag"][0]["tagId"])
        self.assertEqual("G-NEW", first["containerVersion"]["tag"][0]["parameter"][0]["value"])
        self.assertEqual(before, [self.source, self.delete, change])

    def test_literal_source_path_is_preserved_when_object_moves(self):
        tag = self.source["containerVersion"]["tag"][1]
        tag["notes"] = "$.containerVersion.tag[1]"
        projected = apply_operations(self.source, [self.delete], source_sha256=stable_hash(self.source, 64))
        self.assertEqual(tag, projected["containerVersion"]["tag"][0])
        self.assertEqual("$.containerVersion.tag[1]", projected["containerVersion"]["tag"][0]["notes"])

    def test_ordered_values_are_preserved_without_an_exact_change(self):
        tag = self.source["containerVersion"]["tag"][1]
        tag["notes"] = ["a", "b"]
        projected = apply_operations(self.source, [self.delete], source_sha256=stable_hash(self.source, 64))
        self.assertEqual(["a", "b"], projected["containerVersion"]["tag"][0]["notes"])
        change = operation(
            "OP-REORDER",
            changes=[{
                "object_key": "tag:1", "json_path": "$.notes",
                "before_source_sha256": stable_hash(self.source, 64), "after": ["b", "a"],
            }],
        )
        self.assertEqual([], validate_operations(self.source, [change], source_sha256=stable_hash(self.source, 64)))
        self.assertEqual(
            ["b", "a"],
            apply_operations(self.source, [change], source_sha256=stable_hash(self.source, 64))["containerVersion"]["tag"][1]["notes"],
        )

    def test_literal_path_and_order_drift_cannot_satisfy_before_value(self):
        for current, stale in (
            ("$.containerVersion.tag[1]", "$.containerVersion.tag[0]"),
            (["a", "b"], ["b", "a"]),
        ):
            with self.subTest(current=current):
                self.source["containerVersion"]["tag"][1]["notes"] = current
                change = operation(
                    "OP-STALE",
                    changes=[{
                        "object_key": "tag:1", "json_path": "$.notes",
                        "before_source_sha256": "0" * 64, "after": "replacement",
                    }],
                )
                stale_source = copy.deepcopy(self.source)
                stale_source["containerVersion"]["tag"][1]["notes"] = stale
                change["changes"][0]["before_source_sha256"] = stable_hash(stale_source, 64)
                before = copy.deepcopy(self.source)
                self.assertTrue(validate_operations(self.source, [change], source_sha256=stable_hash(self.source, 64)))
                with self.assertRaisesRegex(ValueError, "before source identity differs"):
                    apply_operations(self.source, [change], source_sha256=stable_hash(self.source, 64))
                self.assertEqual(before, self.source)


if __name__ == "__main__":
    unittest.main()
