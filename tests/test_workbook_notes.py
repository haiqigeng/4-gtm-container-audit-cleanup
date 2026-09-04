"""Exercise production note helpers without building or touching a workbook."""
from __future__ import annotations

import copy
import json
import os
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from gtm_delivery_mapper import (  # noqa: E402
    _custom_code_rows,
    _full_audit_rows,
    _owner_rows,
    _recommendation_rows,
)
from gtm_lib import stable_hash  # noqa: E402


def fixture():
    keys = [f"tag:{i}" for i in range(1, 6)]
    return {
        "audit_decisions": [{"canonical_decision_id": "CD-ONE", "area_id": "AREA-22",
                             "subject_keys": keys, "decision": {"decision_class": "defect"}}],
        "owner_decision_ids": ["CD-ONE"],
        "operations": [{"operation_id": "OP-ONE", "source_reconciled_decision_ids": ["CD-ONE"],
                        "depends_on": ["OP-FIRST"], "exact_target_state": "Remove obsolete template field.",
                        "changes": [{"object_key": "tag:1", "json_path": "$.templateData",
                                     "before": "a" * 82000, "after": "b" * 81000}]}],
    }, {key: f"Named object {key}" for key in keys}


def render(row):
    node = os.environ.get("CODEX_NODE") or shutil.which("node")
    if not node:
        raise RuntimeError("Set CODEX_NODE to the bundled Node executable")
    # Isolate the production pure helpers and comment insertion; no artifact imports,
    # fake artifact files or alternate spreadsheet library are involved.
    program = r'''
const fs = require('node:fs'), vm = require('node:vm'), crypto = require('node:crypto');
const source = fs.readFileSync(process.argv[1], 'utf8');
const stable = source.slice(source.indexOf('function stableObject('), source.indexOf('async function fileHash('));
const notes = source.slice(source.indexOf('function noteValue('), source.indexOf('function buildOverview('));
const row = JSON.parse(fs.readFileSync(0, 'utf8'));
const inserted = [], model = {comments: []};
const context = {crypto, row, model, inserted};
vm.createContext(context);
vm.runInContext(stable + notes + `
  const workbook = {comments: {addThread: (location, text) => inserted.push({location, text})}};
  const sheet = {name: row.primary_sheet, getRange: address => address};
  addTechnicalComment(workbook, sheet, 'A6', row, model);
  addTechnicalComment(workbook, sheet, 'A6', row, model);
`, context);
process.stdout.write(JSON.stringify({inserted, model}));
'''
    result = subprocess.run([node, "-e", program, str(ROOT / "scripts/gtm_workbook_build.mjs")],
                            input=json.dumps(row), text=True, encoding="utf-8", capture_output=True, check=True)
    return json.loads(result.stdout)


class WorkbookNoteTests(unittest.TestCase):
    def test_all_audit_surfaces_bind_complete_named_scope(self):
        source, names = fixture()
        original = copy.deepcopy(source)
        builders = [lambda names: _owner_rows(source, names)[0],
                    lambda names: _full_audit_rows(source, names, set())[0],
                    lambda names: _custom_code_rows(source, names, {"CD-ONE"})[0]]
        for build in builders:
            row = build(names)
            self.assertIn("+2 more", row["canonical_prose"]["affected_scope"])
            text = render(row)["model"]["comments"][0]["text"]
            for key, name in names.items():
                self.assertIn(f"{name} ({key})", text)
            self.assertIn("CD-ONE", text)
            changed = copy.deepcopy(names)
            changed["tag:5"] = "Changed name"
            self.assertNotEqual(row["binding_sha256"],
                                build(changed)["binding_sha256"])
        self.assertEqual(original, source)

    def test_scalar_budget_is_explicit_and_scope_and_paths_are_never_cut(self):
        source, names = fixture()
        names["tag:5"] = "Named " + "n" * 700
        operation = source["operations"][0]
        operation["changes"] = [{"object_key": "tag:1", "json_path": "$." + "p" * 700,
                                 "before": "a" * 600, "after": "b" * 601}]
        operation["action_payload_sha256"] = stable_hash(operation, 64)
        text = render(_recommendation_rows(source, names)[0])["model"]["comments"][0]["text"]
        self.assertIn("a" * 600, text)
        self.assertNotIn("b" * 600, text)
        self.assertIn("601 characters after redaction", text)
        self.assertIn(names["tag:5"], text)
        self.assertIn(operation["changes"][0]["json_path"], text)

    def test_large_payload_omissions_are_explicit_and_exact_record_is_unchanged(self):
        source, names = fixture()
        operation = source["operations"][0]
        operation["action_payload_sha256"] = stable_hash(operation, 64)
        original = copy.deepcopy(source)
        row = _recommendation_rows(source, names)[0]
        result = render(row)
        comment = result["model"]["comments"][0]
        text = comment["text"]
        self.assertLess(len(text), 3000)
        for expected in ["82000 characters", "81000 characters", "Bulk string omitted",
                         "canonical-record.json", "OP-ONE", "OP-FIRST", "changes[0]",
                         "$.templateData", operation["action_payload_sha256"]]:
            self.assertIn(expected, text)
        self.assertEqual(operation["changes"], row["locked"]["technical_note"]["changes"])
        self.assertEqual(original, source)
        self.assertEqual(result["model"]["comments"][0], result["model"]["comments"][1])
        self.assertEqual({"cell": "A6"}, result["inserted"][0]["location"])
        self.assertEqual(text, result["inserted"][0]["text"])
        self.assertEqual(stable_hash({k: comment[k] for k in ("sheet", "cell", "text")}, 64),
                         comment["comment_sha256"])

    def test_relevant_nested_changes_action_kinds_and_redaction(self):
        source, names = fixture()
        operation = source["operations"][0]
        operation.update(
            changes=[{"object_key": "tag:1", "json_path": "$.parameter",
                      "before": [{"key": "mode", "value": "old"}, {"key": "token", "value": "private-value"}],
                      "after": [{"key": "mode", "value": "new"}, {"key": "token", "value": "private-value"}]}],
            additions=[{"object_key": "tag:2", "json_path": "$.priority", "value": 0}],
            removals=[{"object_key": "tag:3", "json_path": "$.notes", "before": "obsolete"}],
            renames=[{"object_key": "tag:4", "before": "Old", "after": "New"}],
            pauses=[{"object_key": "tag:5", "before": False, "after": True}],
            deletions=[{"object_key": "trigger:6"}],
            remaps=[{"from_object_key": "trigger:6", "to_object_key": "trigger:7", "consumer_object_keys": ["tag:5"]}],
            creations=[{"layer": "variable", "object": {"variableId": "9", "name": "New variable", "type": "c"}}],
        )
        names.update({"trigger:6": "Old trigger", "trigger:7": "New trigger", "variable:9": "New variable"})
        text = render(_recommendation_rows(source, names)[0])["model"]["comments"][0]["text"]
        self.assertNotIn("private-value", text)
        self.assertIn('$.parameter[0].value: "old" → "new"', text)
        self.assertNotIn("$.parameter[1]", text)
        for kind in ["changes", "additions", "removals", "renames", "pauses", "deletions", "remaps", "creations"]:
            self.assertIn(f"{kind}[0]", text)
        for path in ["$.priority", "$.notes", "$.name", "$.paused"]:
            self.assertIn(path, text)
        for key, name in names.items():
            self.assertIn(f"{name} ({key})", text)

    def test_500_short_values_have_explicit_bounded_detail_and_complete_paths(self):
        source, names = fixture()
        operation = source["operations"][0]
        before = [{"key": f"field_{index}", "value": "a" * 60} for index in range(500)]
        after = [{"key": f"field_{index}", "value": "b" * 60} for index in range(500)]
        operation["changes"] = [{"object_key": "tag:1", "json_path": "$.parameter",
                                 "before": before, "after": after}]
        operation["additions"] = [{"object_key": "tag:2", "json_path": "$.parameter", "value": after}]
        operation["creations"] = [{"layer": "variable", "object": {
            "variableId": "9", "name": "New variable", "type": "c", "parameter": after}}]
        names["variable:9"] = "New variable"
        operation["action_payload_sha256"] = stable_hash(operation, 64)
        original = copy.deepcopy(source)
        row = _recommendation_rows(source, names)[0]
        result = render(row)
        text = result["model"]["comments"][0]["text"]
        self.assertLess(len(text), 17000)  # All 500 paths remain; their values do not.
        self.assertIn("Bulk changed values omitted", text)
        self.assertIn("Bulk structured value omitted", text)
        self.assertNotIn("a" * 60, text)
        self.assertNotIn("b" * 60, text)
        for index in range(500):
            self.assertIn(f"$.parameter[{index}].value", text)
        for value in ["canonical-record.json", "OP-ONE", "OP-FIRST",
                      operation["action_payload_sha256"], "additions[0]", "creations[0]"]:
            self.assertIn(value, text)
        for key, name in names.items():
            self.assertIn(f"{name} ({key})", text)
        self.assertEqual(original, source)
        self.assertEqual(operation["changes"], row["locked"]["technical_note"]["changes"])
        self.assertEqual(result["model"]["comments"][0], result["model"]["comments"][1])

    def test_public_and_sensitive_changes_both_keep_their_exact_paths(self):
        source, names = fixture()
        operation = source["operations"][0]
        operation["changes"] = [{"object_key": "tag:1", "json_path": "$.parameter",
                                 "before": [{"key": "mode", "value": "old"},
                                            {"key": "token", "value": "first-private-value"}],
                                 "after": [{"key": "mode", "value": "new"},
                                           {"key": "token", "value": "second-private-value"}]}]
        operation["action_payload_sha256"] = stable_hash(operation, 64)
        original = copy.deepcopy(source)
        row = _recommendation_rows(source, names)[0]
        result = render(row)
        text = result["model"]["comments"][0]["text"]
        self.assertIn('$.parameter[0].value: "old" → "new"', text)
        self.assertIn("$.parameter[1].value: [Changed value redacted]", text)
        self.assertEqual({"changes[0]": ["$.parameter[1].value"]},
                         row["locked"]["redacted_change_paths"])
        for secret in ["first-private-value", "second-private-value"]:
            self.assertNotIn(secret, json.dumps(row))
            self.assertNotIn(secret, text)
        self.assertIn(operation["action_payload_sha256"], text)
        self.assertEqual(original, source)
        self.assertEqual(result["model"]["comments"][0], result["model"]["comments"][1])


if __name__ == "__main__":
    unittest.main()
