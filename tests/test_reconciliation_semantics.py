from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from gtm_reconciliation import (  # noqa: E402
    comparison_classification,
    material_verification_reasons,
)


class ReconciliationSemanticTests(unittest.TestCase):
    def setUp(self) -> None:
        self.left = {
            "decision_id": "AUDIT-A-ONE", "decision_class": "justified_as_is",
            "criteria_assessment": "Keep the configuration fields inline on each tag.",
            "target_direction": "", "priority": "None", "confidence": "High",
            "operation_proposal": {}, "evidence_citations": ["$.one", "$.two"],
        }
        self.right = copy.deepcopy(self.left)
        self.right["decision_id"] = "AUDIT-B-ONE"

    def reasons(self, obligation: dict | None = None) -> list[str]:
        return material_verification_reasons(
            obligation or {}, self.left, self.right,
            comparison_classification(self.left, self.right),
        )

    def test_opposite_assessments_cannot_bypass_review_on_equal_verdicts(self) -> None:
        self.right["criteria_assessment"] = (
            "The same fields are centralized by the separately owned operation."
        )
        self.assertIn("different_semantic_content", self.reasons())

    def test_different_operation_references_require_review(self) -> None:
        self.left["criteria_assessment"] = "OP-ALIAS owns the complete consumer repair."
        self.right["criteria_assessment"] = "OP-DEDUP owns the complete consumer repair."
        self.assertIn("different_semantic_content", self.reasons())

    def test_identity_and_citation_order_alone_do_not_require_review(self) -> None:
        self.right["evidence_citations"].reverse()
        self.assertEqual([], self.reasons())

    def test_existing_required_review_contract_is_preserved(self) -> None:
        self.right["criteria_assessment"] = "A different assessed reason is already reviewed."
        self.assertEqual(
            ["high_fan_out_shared_setting"],
            self.reasons({"material_verification_triggers": ["high_fan_out_shared_setting"]}),
        )

    def test_changed_evidence_or_confidence_is_not_automatic_equivalence(self) -> None:
        for field, value in (("evidence_citations", ["$.other"]), ("confidence", "Medium")):
            with self.subTest(field=field):
                self.right = copy.deepcopy(self.left)
                self.right[field] = value
                self.assertIn("different_semantic_content", self.reasons())


if __name__ == "__main__":
    unittest.main()
