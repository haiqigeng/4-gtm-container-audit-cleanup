from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from gtm_architecture_review import deterministic_comparison_policy_errors  # noqa: E402
from gtm_relationships import relationship_candidates  # noqa: E402


def tag_pair() -> dict:
    primary = {
        "tagId": "1",
        "name": "Analytics event",
        "type": "html",
        "parameter": [
            {
                "type": "TEMPLATE",
                "key": "html",
                "value": "<script>window.analyticsEvent=true;</script>",
            }
        ],
        "firingTriggerId": ["10"],
        "blockingTriggerId": [],
        "tagFiringOption": "ONCE_PER_EVENT",
        "consentSettings": {"consentStatus": "NOT_SET"},
    }
    duplicate = copy.deepcopy(primary)
    duplicate.update({"tagId": "2", "name": "Analytics event copy"})
    return {
        "tag": [primary, duplicate],
        "trigger": [
            {"triggerId": "10", "name": "Primary event", "type": "CUSTOM_EVENT"},
            {"triggerId": "11", "name": "Alternate event", "type": "CUSTOM_EVENT"},
        ],
        "variable": [],
    }


class ArchitecturePolicyTests(unittest.TestCase):
    def test_same_payload_requires_a_real_execution_control_difference(self) -> None:
        container = tag_pair()
        exact_pair = next(
            row
            for row in relationship_candidates(container)
            if {"tag:1", "tag:2"} == set(row["candidate_object_keys"])
        )
        self.assertIn("exact_configuration", exact_pair["comparison_types"])
        self.assertNotIn(
            "same_tag_payload_different_route", exact_pair["comparison_types"]
        )

        container["tag"][1]["firingTriggerId"] = ["11"]
        route_pair = next(
            row
            for row in relationship_candidates(container)
            if {"tag:1", "tag:2"}.issubset(row["candidate_object_keys"])
            and "same_tag_payload_different_route" in row["comparison_types"]
        )
        self.assertNotIn("exact_configuration", route_pair["comparison_types"])

    def test_consent_semantics_override_raw_exact_code_policy(self) -> None:
        owner_decision = {
            "relationship_verdict": "Owner decision needed",
            "disposition": "owner_decision_needed",
            "operations": [],
        }
        mixed_expected = {
            "comparison_types": [
                "different_consent_purposes_same_logic",
                "equivalent_custom_code",
                "exact_configuration",
            ],
            "candidate_object_keys": ["variable:910", "variable:911"],
            "recommended_canonical_object_key": "variable:910",
        }
        self.assertEqual(
            [],
            deterministic_comparison_policy_errors(
                owner_decision,
                mixed_expected,
                "mixed consent comparison",
            ),
        )

        exact_expected = {
            **mixed_expected,
            "comparison_types": ["exact_configuration"],
        }
        exact_errors = deterministic_comparison_policy_errors(
            owner_decision,
            exact_expected,
            "ordinary exact comparison",
        )
        self.assertTrue(
            any("identical source configuration" in error for error in exact_errors)
        )


if __name__ == "__main__":
    unittest.main()
