from __future__ import annotations

import copy
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from gtm_audit_contract import OPERATION_ACTION_FIELDS
from gtm_delivery_mapper import _operation_note, _row  # noqa: E402
from gtm_operation_model import (
    apply_operations,
    object_catalog,
    read_operation_source,
    same_json_value,
    validate_operations,
)
from gtm_privacy import redact_delivery_value  # noqa: E402


class DeliveryPrivacyTests(unittest.TestCase):
    def test_scalar_and_ancestor_redactions_preserve_changed_path_and_types(self):
        source = {"containerVersion": {"tag": [{"tagId": "1", "parameter": [
            {"key": "oauthClientSecret", "map": [{"key": "nested", "value": "synthetic-old"}]},
            {"key": "public", "value": False},
        ]}]}}
        from gtm_lib import stable_hash
        digest = stable_hash(source, 64)
        actions = [
            {"object_key": "tag:1", "json_path": "$.parameter[0].map[0].value",
             "before_source_sha256": digest, "after": "synthetic-new"},
            {"object_key": "tag:1", "json_path": "$.parameter[1].value",
             "before_source_sha256": digest, "after": 0},
        ]
        note, hidden = _operation_note({"changes": actions}, object_catalog(source), digest)
        self.assertEqual("<redacted>", note["changes"][0]["before"])
        self.assertEqual("<redacted>", note["changes"][0]["after"])
        self.assertEqual({"changes[0]": ["$.parameter[0].map[0].value"]}, hidden)
        self.assertIs(note["changes"][1]["before"], False)
        self.assertEqual(type(note["changes"][1]["after"]), int)
        self.assertNotIn("synthetic-old", json.dumps(note))
        self.assertNotIn("synthetic-new", json.dumps(note))


    def test_source_reference_removal_replays_without_copying_old_value(self):
        source = {"containerVersion": {"tag": [{"tagId": "1", "name": "Synthetic",
            "parameter": [{"key": "oauthClientSecret", "value": "synthetic-secret"}]}]}}
        raw = json.dumps(source).encode()
        digest = hashlib.sha256(raw).hexdigest()
        action = {"object_key": "tag:1", "json_path": "$.parameter[0].value", "before_source_sha256": digest}
        operation = {"operation_id": "OP-REMOVE", "depends_on": [],
            **{field: [] for field in OPERATION_ACTION_FIELDS}, "removals": [action]}
        original = copy.deepcopy(operation)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "source.json"
            path.write_bytes(raw)
            bound = read_operation_source(path, digest)
            self.assertEqual([], validate_operations(bound, [operation], source_sha256=digest))
            target = apply_operations(bound, [operation], source_sha256=digest)
            self.assertNotIn("value", target["containerVersion"]["tag"][0]["parameter"][0])
            note, _ = _operation_note(operation, object_catalog(bound), digest)
            self.assertEqual("<redacted>", note["removals"][0]["before"])
            self.assertNotIn("synthetic-secret", json.dumps([operation, note]))
            self.assertEqual(original, operation)
            self.assertEqual(source, bound)
            path.write_bytes(raw.replace(b"synthetic-secret", b"different-value"))
            with self.assertRaisesRegex(ValueError, "independently locked"):
                read_operation_source(path, digest)
        for left, right in ((False, 0), (None, "null"), ([False], [0])):
            self.assertFalse(same_json_value(left, right))

    def test_sensitive_gtm_parameter_payloads_are_redacted(self) -> None:
        for payload, value in (
            ("value", "synthetic-secret"),
            ("list", [{"value": "synthetic-secret"}]),
            ("map", [{"key": "nested", "value": "synthetic-secret"}]),
        ):
            with self.subTest(payload=payload):
                source = {"type": "TEMPLATE", "key": "oauthClientSecret", payload: value}
                original = copy.deepcopy(source)
                result = redact_delivery_value(source)
                self.assertEqual(result[payload], "<redacted>")
                self.assertEqual(result["key"], "oauthClientSecret")
                self.assertEqual(result["type"], "TEMPLATE")
                self.assertEqual(source, original)

    def test_gtm_table_name_value_pairs_redact_only_sensitive_values(self) -> None:
        for name_key, value_key in (
            ("parameter", "parameterValue"),
            ("name", "value"),
            ("property", "propertyValue"),
            ("fieldName", "fieldValue"),
        ):
            with self.subTest(name_key=name_key):
                source = {
                    "type": "MAP",
                    "map": [
                        {"type": "TEMPLATE", "key": name_key, "value": "consumer_secret"},
                        {"type": "TEMPLATE", "key": value_key, "value": "synthetic-secret"},
                        {"type": "BOOLEAN", "key": "enabled", "value": "true"},
                    ],
                }
                original = copy.deepcopy(source)
                result = redact_delivery_value(source)
                self.assertEqual(result["map"][0], source["map"][0])
                self.assertEqual(result["map"][1]["value"], "<redacted>")
                self.assertEqual(result["map"][2], source["map"][2])
                self.assertEqual(source, original)

                public = copy.deepcopy(source)
                public["map"][0]["value"] = "event_name"
                self.assertEqual(redact_delivery_value(public), public)

    def test_nested_operation_comment_payload_is_redacted_without_changing_identity(self) -> None:
        locked = {
            "operation_id": "OP-SYNTHETIC",
            "action_payload_sha256": "a" * 64,
            "technical_note": {
                "changes": [
                    {
                        "object_key": "tag:1",
                        "json_path": "$.parameter[1].list",
                        "before": [
                            {
                                "type": "MAP",
                                "map": [
                                    {"key": "parameter", "value": "token_secret"},
                                    {"key": "parameterValue", "value": "synthetic-secret"},
                                ],
                            }
                        ],
                        "after": [],
                    }
                ],
            },
        }
        original = copy.deepcopy(locked)
        result = _row(
            row_id="REC-OP-SYNTHETIC",
            sheet="02 Recommendations",
            locked=locked,
            prose={"current_setup": "A credential is configured in a tag parameter."},
        )
        self.assertNotIn("synthetic-secret", json.dumps(result))
        self.assertEqual(result["locked"]["operation_id"], "OP-SYNTHETIC")
        self.assertEqual(result["locked"]["action_payload_sha256"], "a" * 64)
        self.assertEqual(locked, original)

    def test_plain_objects_and_malformed_entries_do_not_gain_redactions(self) -> None:
        source = {
            "map": [None, "text", {"key": 2, "value": "public"}, {"key": [], "value": "public"}],
            "count": 3,
        }
        self.assertEqual(redact_delivery_value(source), source)
        self.assertEqual(
            redact_delivery_value({"api_secret": "synthetic-secret"}), {"api_secret": "<redacted>"}
        )


if __name__ == "__main__":
    unittest.main()
