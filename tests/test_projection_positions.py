"""Serialization positions must not create new semantic review work."""

import copy
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from gtm_fixed_point import _projection_delta
from gtm_lib import stable_hash


class ProjectionPositionTests(unittest.TestCase):
    def row(self, identity, position, value="original code"):
        path = f"$.containerVersion.tag[{position}]"
        evidence = {"object_key": "tag:42", "source_json_path": path, "code": value}
        return {
            "obligation_id": identity, "subject_keys": ["tag:42"],
            "source_coordinates": [path], "evidence": evidence,
            "evidence_sha256": stable_hash(evidence, 64),
            "obligation_sha256": identity,
        }

    def delta(self, before, after):
        def scan(rows):
            return {"objects": [{"object_key": "tag:42", "source_json_path": rows[0]["source_coordinates"][0]}]}
        return _projection_delta(
            2, {"obligations": before}, {"obligations": after},
            scan(after), {}, scan(before),
        )

    def test_position_only_move_is_not_new_or_retired(self):
        before, after = self.row("old", 9), self.row("new", 8)
        original = copy.deepcopy([before, after])
        self.assertEqual(self.delta([before], [after])["counts"], {"new": 0, "changed": 0, "retired": 0})
        self.assertEqual([before, after], original)

    def test_move_with_real_code_change_still_requires_review(self):
        result = self.delta([self.row("old", 9)], [self.row("new", 8, "changed code")])
        self.assertEqual(len(result["obligations"]), 1)

    def test_literal_path_value_is_not_normalized(self):
        result = self.delta([self.row("old", 9, "$.containerVersion.tag[9]")], [self.row("new", 8, "$.containerVersion.tag[8]")])
        self.assertEqual(len(result["obligations"]), 1)

    def test_ordered_values_still_require_review(self):
        result = self.delta([self.row("old", 9, ["a", "b"])], [self.row("new", 8, ["b", "a"])])
        self.assertEqual(len(result["obligations"]), 1)

    def test_ambiguous_semantic_matches_are_not_skipped(self):
        result = self.delta([self.row("old1", 9), self.row("old2", 9)], [self.row("new", 8)])
        self.assertEqual(len(result["obligations"]), 1)

    def test_topology_digest_is_recomputed_only_if_valid(self):
        before, after = self.row("old", 9), self.row("new", 8)
        for row in [before, after]:
            row["evidence"]["control_topology_sha256"] = stable_hash(row["evidence"], 32)
            row["evidence"]["review_area_ids"] = ["AREA-07", "AREA-08"]
        self.assertFalse(self.delta([before], [after])["obligations"])
        after["evidence"]["review_area_ids"].append("AREA-09")
        self.assertEqual(len(self.delta([before], [after])["obligations"]), 1)
        after["evidence"]["review_area_ids"].pop()
        after["evidence"]["control_topology_sha256"] = "opaque changed digest"
        self.assertEqual(len(self.delta([before], [after])["obligations"]), 1)


if __name__ == "__main__":
    unittest.main()
