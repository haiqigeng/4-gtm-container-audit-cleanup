"""Relationship obligations retain their already supplied source anchors."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from gtm_obligation_ledger import _obligation, _source_paths


class RelationshipCoordinateTests(unittest.TestCase):
    def test_object_paths_and_member_anchors_reach_the_obligation(self):
        evidence = {
            "candidate_object_keys": ["variable:1", "variable:2"],
            "candidate_source_paths": {
                "variable:1": "$.containerVersion.variable[0]",
                "variable:2": "$.containerVersion.variable[1]",
            },
            "available_member_evidence_anchors": {
                "variable:1": ["$.containerVersion.variable[0].parameter[0].value"],
                "variable:2": ["$.containerVersion.variable[1].type"],
            },
        }
        obligation = _obligation("AREA-05", "relationship", "relationship_candidate_review",
                                 "functional_relationship_candidate", evidence)
        self.assertEqual(obligation["source_coordinates"], [
            "$.containerVersion.variable[0]",
            "$.containerVersion.variable[0].parameter[0].value",
            "$.containerVersion.variable[1]",
            "$.containerVersion.variable[1].type",
        ])
        self.assertEqual(obligation["subject_keys"], ["variable:1", "variable:2"])

    def test_repeated_anchors_are_unique_without_changing_spelling(self):
        path = "$.containerVersion.tag[0].parameter[2].value"
        self.assertEqual(_source_paths({
            "json_path": path,
            "available_member_evidence_anchors": {"tag:1": [path, path]},
        }), [path])

    def test_arbitrary_configuration_values_are_not_promoted_to_paths(self):
        self.assertEqual(_source_paths({
            "value": "$.containerVersion.variable[99]",
            "candidate_object_names": ["$.containerVersion.tag[3]"],
            "details": "$.not.a.source.coordinate",
        }), [])

    def test_nested_typed_maps_and_existing_scalar_paths_are_retained(self):
        self.assertEqual(_source_paths({"evidence": [
            {"source_reference_path": "$.containerVersion.tag[0].parameter[0].value"},
            {"candidate_source_paths": {"tag:1": "$.containerVersion.tag[0]", "invalid": "not a path"}},
        ]}), ["$.containerVersion.tag[0]", "$.containerVersion.tag[0].parameter[0].value"])


if __name__ == "__main__":
    unittest.main()
