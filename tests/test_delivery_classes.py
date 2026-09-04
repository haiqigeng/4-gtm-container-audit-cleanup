from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from gtm_audit_contract import HUMAN_DECISION_MEANINGS  # noqa: E402
from gtm_delivery_mapper import (  # noqa: E402
    AUDIT_AREA_CATEGORIES,
    _audit_area_category,
    _custom_code_rows,
    _full_audit_rows,
    _name_index,
    _operation_audit_area,
    _overview,
    _owner_rows,
    _recommendation_rows,
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
    def test_retained_code_keeps_explicit_source_behavior_and_pending_handoff(self) -> None:
        source = record(
            "justified_as_is", current_behavior="The source still contains the log.",
            criteria_assessment="Retain the event; OP-REMOVE-LOG separately removes the log.",
            next_step="See OP-REMOVE-LOG in 02 Recommendations; preserve the event.",
        )
        row = _custom_code_rows(source, {}, {"CD-ONE"})[0]["canonical_prose"]
        self.assertEqual("The source still contains the log.", row["current_behavior"])
        self.assertIn("OP-REMOVE-LOG", row["finding"])
        self.assertEqual(source["audit_decisions"][0]["decision"]["next_step"], row["linked_action"])
        self.assertIn("OP-REMOVE-LOG", _full_audit_rows(source, {}, set())[0][
            "canonical_prose"]["outcome_linked_action"])

    def test_display_focus_can_be_edited_without_unlocking_audit_identity(self) -> None:
        source = record("justified_as_is")
        source["audit_decisions"][0].update(
            fact_kind="functional_relationship_candidate",
            audit_mechanism="optimization_candidate_review",
        )
        before = copy.deepcopy(source)
        row = _full_audit_rows(source, {}, set())[0]
        self.assertEqual("Comparison of related configurations",
                         row["canonical_prose"]["audit_focus"])
        self.assertIn("audit_focus", row["allowed_prose_fields"])
        self.assertNotIn("audit_focus", row["locked"])
        self.assertEqual("functional_relationship_candidate", row["locked"]["fact_kind"])
        self.assertEqual("optimization_candidate_review", row["locked"]["audit_mechanism"])
        code_row = _custom_code_rows(source, {}, {"CD-ONE"})[0]
        self.assertEqual("functional_relationship_candidate", code_row["locked"]["fact_kind"])
        self.assertEqual("optimization_candidate_review", code_row["locked"]["audit_mechanism"])
        self.assertEqual(before, source)

    def test_audit_area_categories_cover_contract_and_preserve_distinct_focus(self) -> None:
        self.assertEqual({f"AREA-{number:02d}" for number in range(1, 28)},
                         set(AUDIT_AREA_CATEGORIES))
        cases = [
            ("AREA-04", "unused_object", "Unused & obsolete elements"),
            ("AREA-05", "duplicate_configuration", "Duplicates & consolidation"),
            ("AREA-09", "configuration_obligation", "CMP & consent"),
            ("AREA-15", "shared_event_setting", "Google shared settings"),
            ("AREA-07", "legacy_name_only_candidate", "Naming"),
            ("AREA-24", "naming_architecture_mismatch", "Naming"),
            ("AREA-24", "container_organisation", "Folders & organization"),
        ]
        for area, fact, expected in cases:
            with self.subTest(area=area, fact=fact):
                source = record("owner_decision", owner_question="Is it required?")
                source["audit_decisions"][0].update(area_id=area, fact_kind=fact)
                before = copy.deepcopy(source)
                rows = [
                    _owner_rows(source, {})[0],
                    _full_audit_rows(source, {}, set())[0],
                    _custom_code_rows(source, {}, {"CD-ONE"})[0],
                ]
                for row in rows:
                    self.assertEqual(expected, row["canonical_prose"]["audit_area"])
                    self.assertEqual(area, row["locked"]["area_id"])
                    self.assertIn("audit_area", row["allowed_prose_fields"])
                self.assertEqual(before, source)

    def test_operation_primary_area_is_stable_and_keeps_source_evidence(self) -> None:
        sources = [
            {"canonical_decision_id": "CD-A", "area_id": "AREA-24",
             "decision": {"priority": "Low"}},
            {"canonical_decision_id": "CD-B", "area_id": "AREA-09",
             "decision": {"priority": "High"}},
        ]
        self.assertEqual("CMP & consent", _operation_audit_area(sources))
        self.assertEqual("CMP & consent", _operation_audit_area(list(reversed(sources))))
        with self.assertRaises(ValueError):
            _operation_audit_area([])
        with self.assertRaises(KeyError):
            _audit_area_category({"area_id": "AREA-UNKNOWN"})

    def test_reconciled_handoffs_remain_bound_for_fidelity_review(self) -> None:
        source = record("justified_as_is")
        rationale = "Keep the event distinct; alias removal is owned by OP-ALIAS."
        source["audit_decisions"][0]["reconciliation_rationale"] = rationale
        original = copy.deepcopy(source)
        for row in (
            _full_audit_rows(source, {"tag:1": "Event"}, set())[0],
            _custom_code_rows(source, {"tag:1": "Event"}, {"CD-ONE"})[0],
        ):
            self.assertEqual(rationale, row["locked"]["reconciliation_rationale"])
            self.assertNotIn("reconciliation_rationale", row["allowed_prose_fields"])
        self.assertEqual(original, source)

    def test_shared_owner_handoff_remains_bound_for_fidelity_review(self) -> None:
        source = record("owner_decision", owner_question="Which destination is intended?")
        rationale = "The setup answer is shared with CD-SETUP; purchase meaning is separate."
        source["audit_decisions"][0]["reconciliation_rationale"] = rationale
        row = _owner_rows(source, {"tag:1": "Paused tag"})[0]
        self.assertEqual(rationale, row["locked"]["reconciliation_rationale"])
        self.assertNotIn("reconciliation_rationale", row["allowed_prose_fields"])

    def test_recommendation_scope_includes_declared_actions_not_only_finding_owner(self) -> None:
        source = record("defect", current_behavior="Shared setup needs correction.",
                        consequence_or_benefit="Keep all declared consumers connected.",
                        target_direction="Apply the complete shared setup change.",
                        next_step="Review the complete operation before implementation.")
        source["operations"] = [{
            "operation_id": "OP-SCOPE", "operation_family": "Repair shared setup",
            "source_reconciled_decision_ids": ["CD-ONE"],
            "creations": [{"layer": "variable", "object": {
                "variableId": "9", "name": "New settings", "type": "c",
            }}],
            "changes": [{"object_key": "tag:2", "json_path": "$.notes", "before_source_sha256": "a" * 64, "after": "new"}],
            "removals": [{"object_key": "tag:3", "json_path": "$.notes", "before_source_sha256": "a" * 64}],
            "deletions": [{"object_key": "variable:4"}],
            "remaps": [{"from_object_key": "trigger:5", "to_object_key": "trigger:6",
                        "consumer_object_keys": ["tag:2", "trigger:7"]}],
        }]
        original = copy.deepcopy(source)
        expected = ["tag:1", "tag:2", "tag:3", "trigger:5", "trigger:6", "trigger:7",
                    "variable:4", "variable:9"]
        row = _recommendation_rows(source, {key: f"Object {key}" for key in expected},
            {"containerVersion": {"tag": [{"tagId": "2", "notes": "old"}, {"tagId": "3", "notes": "obsolete"}]}}, "a" * 64)[0]
        self.assertEqual(expected, row["locked"]["subject_keys"])
        self.assertIn("+5 more (see row note)", row["canonical_prose"]["affected_scope"])
        self.assertEqual(["CD-ONE"], row["locked"]["source_decision_ids"])
        self.assertEqual(original, source)

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
