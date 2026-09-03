"""Naming candidates must not invent a blanket owner-approval requirement."""

import copy
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from gtm_baseline_audit import BaselineBuilder, add_naming_architecture_findings, infer_tag_order
from gtm_obligation_ledger import _operational_area


class NamingPolicyTests(unittest.TestCase):
    def findings(self, container):
        policy = infer_tag_order(container.get("tag", []))
        builder = BaselineBuilder()
        add_naming_architecture_findings(builder, container, policy)
        return policy, builder.findings

    def test_default_policy_reviews_each_layer_without_approval_gate(self):
        container = {
            "tag": [{"tagId": "1", "name": "Legacy tracker", "type": "html"}],
            "trigger": [{"triggerId": "2", "name": "Checkout", "type": "CUSTOM_EVENT"}],
            "variable": [{"variableId": "3", "name": "Currency", "type": "v"}],
            "folder": [{"folderId": "4", "name": "Media - France"}],
        }
        before = copy.deepcopy(container)
        policy, rows = self.findings(container)
        self.assertEqual(policy["selected_policy"], "default-standardized")
        self.assertEqual({row["object_type"] for row in rows}, {"tag", "trigger", "variable", "folder"})
        self.assertEqual(len(rows), 4)
        self.assertTrue(all(row["object_ids"] for row in rows))
        self.assertTrue(all("policy_confirmation_required" not in row for row in rows))
        self.assertTrue(all(row["finding_class"] == "review_candidate" for row in rows))
        self.assertEqual(container, before)

    def test_no_tags_does_not_skip_other_layers(self):
        _, rows = self.findings({
            "trigger": [{"triggerId": "2", "name": "Checkout", "type": "CUSTOM_EVENT"}],
            "variable": [{"variableId": "3", "name": "Currency", "type": "v"}],
        })
        self.assertEqual({row["object_type"] for row in rows}, {"trigger", "variable"})

    def test_naming_candidates_keep_their_domain_across_object_layers(self):
        for layer in ("tag", "trigger", "variable", "folder"):
            with self.subTest(layer=layer):
                self.assertEqual(_operational_area({
                    "finding_type": (
                        "folder_naming_review" if layer == "folder"
                        else "naming_architecture_mismatch"
                    ),
                    "object_type": layer,
                    "details": "Preserve consumer references and the blocking trigger role.",
                }), "AREA-24")

    def test_reliable_local_order_is_preserved(self):
        policy, rows = self.findings({"tag": [
            {"tagId": "1", "name": "GA4 - All - purchase", "type": "gaawe"},
            {"tagId": "2", "name": "GA4 - All - page_view", "type": "gaawe"},
            {"tagId": "3", "name": "Unstructured tracker", "type": "html"},
        ]})
        self.assertEqual(policy["selected_policy"], "local-normalized")
        self.assertEqual(policy["tag_order"], "vendor_scope_event")
        self.assertEqual([row["object_ids"] for row in rows], [["3"]])
        self.assertEqual(rows[0]["target_naming_pattern"], "Vendor - Scope - Event")

    def test_ambiguous_business_tokens_remain_object_specific(self):
        _, rows = self.findings({"tag": [
            {"tagId": "1", "name": "Opaque internal tracker", "type": "html"},
        ]})
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["object_ids"], ["1"])
        self.assertEqual(rows[0]["proposed_final_name"], "")
        self.assertTrue(rows[0]["rename_blocker"])

    def test_default_candidates_preserve_collision_blockers(self):
        _, rows = self.findings({"variable": [
            {"variableId": "1", "name": "Currency", "type": "v"},
            {"variableId": "2", "name": "Currency", "type": "v"},
        ]})
        self.assertEqual(len(rows), 2)
        self.assertTrue(all(not row["rename_candidate_unique"] for row in rows))
        self.assertTrue(all(row["rename_blocker"] for row in rows))


if __name__ == "__main__":
    unittest.main()
