from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from gtm_audit_contract import HUMAN_DECISION_MEANINGS  # noqa: E402
from gtm_delivery_mapper import (  # noqa: E402
    _custom_code_rows,
    _full_audit_rows,
    _name_index,
    _overview,
    _owner_rows,
)


def record(decision_class: str, **fields: str) -> dict:
    return {
        "audit_decisions": [{
            "canonical_decision_id": "CD-ONE", "area_id": "AREA-26",
            "subject_keys": ["tag:1"],
            "decision": {
                "decision_class": decision_class,
                "criteria_assessment": "The separate event preserves its distinct destination.",
                "priority": "None", "confidence": "High", **fields,
            },
        }],
        "decision_to_operation": {},
        "owner_decision_ids": ["CD-ONE"] if decision_class == "owner_decision" else [],
    }


class DeliveryClassTests(unittest.TestCase):
    def test_name_index_does_not_append_target_objects_to_canonical_source(self) -> None:
        source = {
            "source": {"object_directory": [{"object_key": "tag:1", "object_name": "Original"}]},
            "target": {"object_directory": [
                {"object_key": "tag:1", "object_name": "Renamed"},
                {"object_key": "tag:2", "object_name": "New tag"},
            ]},
        }
        original = copy.deepcopy(source)
        expected = {"tag:1": "Original", "tag:2": "New tag"}
        self.assertEqual(expected, _name_index(source))
        self.assertEqual(expected, _name_index(source))
        self.assertEqual(original, source)

    def test_compact_classes_have_faithful_nonblank_outcomes(self) -> None:
        for decision_class in ("justified_as_is", "not_applicable"):
            with self.subTest(decision_class=decision_class):
                source = record(decision_class)
                original = copy.deepcopy(source)
                audit = _full_audit_rows(source, {"tag:1": "Separate event"}, set())[0]
                code = _custom_code_rows(source, {"tag:1": "Separate event"}, {"CD-ONE"})[0]
                meaning = HUMAN_DECISION_MEANINGS[decision_class]
                self.assertEqual(meaning, audit["canonical_prose"]["outcome_linked_action"])
                self.assertEqual(meaning, code["canonical_prose"]["safest_target"])
                self.assertEqual(audit["canonical_prose"]["plain_finding"],
                                 code["canonical_prose"]["current_behavior"])
                self.assertTrue(all(code["canonical_prose"].values()))
                self.assertEqual(original, source)

    def test_owner_uses_authored_next_step_without_inventing_a_target(self) -> None:
        source = record(
            "owner_decision", owner_question="Is this integration still required?",
            current_behavior="An unused definition is retained.",
            consequence_or_benefit="Retirement requires the owner's lifecycle decision.",
            next_step="Keep the definition until its owner confirms permanent retirement.",
        )
        row = _owner_rows(source, {"tag:1": "Separate event"})[0]
        self.assertEqual(source["audit_decisions"][0]["decision"]["next_step"],
                         row["canonical_prose"]["recommendation"])
        self.assertNotIn("target_direction", source["audit_decisions"][0]["decision"])

    def test_evidence_boundary_remains_visible_without_a_speculative_target(self) -> None:
        source = record(
            "container_evidence_limit", current_behavior="A custom loader sends the event.",
            evidence_boundary="Vendor receipt is not visible in this export.",
            next_step="Obtain the vendor contract before proposing a change.",
        )
        audit = _full_audit_rows(source, {}, set())[0]["canonical_prose"]
        code = _custom_code_rows(source, {}, {"CD-ONE"})[0]["canonical_prose"]
        boundary = source["audit_decisions"][0]["decision"]["evidence_boundary"]
        self.assertIn(boundary, audit["plain_finding"])
        self.assertIn(boundary, code["finding"])
        self.assertEqual(source["audit_decisions"][0]["decision"]["next_step"],
                         code["safest_target"])

    def test_actionable_targets_are_not_replaced_by_generic_outcomes(self) -> None:
        for decision_class in ("defect", "correct_but_materially_non_optimal"):
            source = record(decision_class, current_behavior="Current source configuration.",
                            target_direction="Preserve the exact configured target.",
                            next_step="Apply only the approved operation.")
            code = _custom_code_rows(source, {}, {"CD-ONE"})[0]["canonical_prose"]
            self.assertEqual("Preserve the exact configured target.", code["safest_target"])
            del source["audit_decisions"][0]["decision"]["target_direction"]
            self.assertEqual("", _custom_code_rows(source, {}, {"CD-ONE"})[0]
                             ["canonical_prose"]["safest_target"])

    def test_overview_uses_compact_assessment_not_empty_optional_fields(self) -> None:
        source = record("justified_as_is")
        assessment = source["audit_decisions"][0]["decision"]["criteria_assessment"]
        overview = _overview(source, [])
        self.assertEqual(assessment, overview["target_architecture_summary"])
        self.assertEqual(assessment, overview["important_retained_summary"])


if __name__ == "__main__":
    unittest.main()
