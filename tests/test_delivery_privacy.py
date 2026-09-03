from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from gtm_delivery_mapper import _row  # noqa: E402
from gtm_privacy import redact_delivery_value  # noqa: E402


class DeliveryPrivacyTests(unittest.TestCase):
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
