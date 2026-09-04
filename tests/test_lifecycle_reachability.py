from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from gtm_baseline_audit import (
    BaselineBuilder,
    add_lifecycle_findings,
    add_unused_findings,
    build_consumers,
    build_execution_reachability,
    build_lifecycle_matrix,
)


def parameter(value: str) -> list[dict]:
    return [{"type": "TEMPLATE", "key": "value", "value": value}]


def fixture() -> dict:
    return {
        "trigger": [
            {"triggerId": "group", "name": "Group", "type": "TRIGGER_GROUP",
             "parameter": [{"key": "triggerIds", "type": "LIST",
                            "list": [{"value": "child"}]}]},
            {"triggerId": "child", "name": "Child", "type": "CUSTOM_EVENT",
             "parameter": parameter("{{Head}} {{_event}}"), "parentFolderId": "members"},
            {"triggerId": "empty", "name": "Unused trigger", "type": "PAGEVIEW"},
        ],
        "variable": [
            {"variableId": "head", "name": "Head", "type": "cvt_1_template",
             "parameter": parameter("{{Leaf}}")},
            {"variableId": "leaf", "name": "Leaf", "type": "c"},
            {"variableId": "empty", "name": "Unused variable", "type": "c"},
        ],
        "builtInVariable": [{"name": "Event", "type": "EVENT"},
                            {"name": "Click URL", "type": "CLICK_URL"}],
        "customTemplate": [{"templateId": "template", "accountId": "1", "name": "Template"},
                           {"templateId": "empty", "name": "Unused template"}],
        "folder": [{"folderId": "members", "name": "Members"},
                   {"folderId": "empty", "name": "Empty"}],
    }


def inspect(cv: dict) -> tuple[dict, list[dict]]:
    rows = build_lifecycle_matrix(cv, *build_consumers(cv), build_execution_reachability(cv))
    builder = BaselineBuilder()
    add_unused_findings(builder, cv, rows)
    add_lifecycle_findings(builder, rows)
    return {row["object_key"]: row for row in rows}, builder.findings


def unused_keys(findings: list[dict]) -> set[str]:
    return {f"{row['object_type']}:{oid}" for row in findings
            if row["module_name"].startswith("unused_") for oid in row["object_ids"]}


class LifecycleReachabilityTests(unittest.TestCase):
    referenced = {"trigger:child", "variable:head", "variable:leaf",
                  "builtInVariable:Event", "customTemplate:template", "folder:members"}
    unreferenced = {"trigger:group", "trigger:empty", "variable:empty",
                    "builtInVariable:Click URL", "customTemplate:empty", "folder:empty"}

    def test_unreachable_chain_preserves_every_candidate_and_actual_consumers(self):
        rows, findings = inspect(fixture())
        expected_consumers = {
            "trigger:child": ["trigger:group"], "variable:head": ["trigger:child"],
            "variable:leaf": ["variable:head"], "builtInVariable:Event": ["trigger:child"],
            "customTemplate:template": ["variable:head"], "folder:members": ["trigger:child"],
        }
        for key in self.referenced:
            with self.subTest(key=key):
                self.assertEqual("referenced_unreachable", rows[key]["usage_state"])
                self.assertEqual(expected_consumers[key], rows[key]["consumer_keys"])
        for key in self.unreferenced:
            with self.subTest(key=key):
                self.assertEqual("unreferenced", rows[key]["usage_state"])
                self.assertEqual([], rows[key]["consumer_keys"])
        self.assertEqual(self.referenced | self.unreferenced, unused_keys(findings))

    def test_active_and_paused_roots_propagate_through_whole_chain(self):
        for paused in (False, True):
            with self.subTest(paused=paused):
                cv = fixture()
                cv["tag"] = [{"tagId": "root", "name": "Root", "paused": paused,
                              "firingTriggerId": ["group"]}]
                rows, findings = inspect(cv)
                reached = self.referenced | {"trigger:group"}
                expected = "used_only_by_paused_tags" if paused else "used"
                for key in reached:
                    self.assertEqual(expected, rows[key]["usage_state"], key)
                self.assertEqual(self.unreferenced - {"trigger:group"}, unused_keys(findings))
                paused_keys = {f"{row['object_type']}:{oid}" for row in findings
                               if row["module_name"] == "used_only_by_paused_tags"
                               for oid in row["object_ids"]}
                self.assertEqual(reached if paused else set(), paused_keys)

    def test_active_root_wins_over_paused_consumers(self):
        cv = fixture()
        cv["tag"] = [
            {"tagId": "active", "name": "Active", "firingTriggerId": ["group"]},
            {"tagId": "paused", "name": "Paused", "paused": True,
             "firingTriggerId": ["group"], "setupTag": [{"tagName": "Active"}]},
        ]
        rows, findings = inspect(cv)
        self.assertEqual("active_direct", rows["tag:active"]["usage_state"])
        self.assertEqual("paused", rows["tag:paused"]["usage_state"])
        for key in self.referenced | {"trigger:group"}:
            self.assertEqual("used", rows[key]["usage_state"], key)
        self.assertEqual(self.unreferenced - {"trigger:group"}, unused_keys(findings))

    def test_unreachable_variable_cycle_keeps_both_candidates(self):
        cv = {"variable": [
            {"variableId": "a", "name": "A", "parameter": parameter("{{B}}")},
            {"variableId": "b", "name": "B", "parameter": parameter("{{A}}")},
        ]}
        rows, findings = inspect(cv)
        self.assertEqual({"referenced_unreachable"}, {r["usage_state"] for r in rows.values()})
        self.assertEqual({"variable:a", "variable:b"}, unused_keys(findings))

    def test_configured_root_folder_is_not_an_unused_candidate(self):
        cv = {"gtagConfig": [{"gtagConfigId": "config", "parentFolderId": "folder"}],
              "folder": [{"folderId": "folder"}]}
        rows, findings = inspect(cv)
        self.assertEqual("used", rows["folder:folder"]["usage_state"])
        self.assertNotIn("folder:folder", unused_keys(findings))


if __name__ == "__main__":
    unittest.main()
