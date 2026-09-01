from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

from gtm_canonical_scan import (  # noqa: E402
    build_canonical_scan,
    neutral_fact_judgment_leaks,
)
from gtm_obligation_ledger import build_obligation_ledger  # noqa: E402
from gtm_optimization_facts import _consent_metadata  # noqa: E402
from gtm_scan_assurance import assure_scan  # noqa: E402


def table_parameter(key: str, rows: list[tuple[str, str]]) -> dict:
    return {
        "type": "LIST",
        "key": key,
        "list": [
            {
                "type": "MAP",
                "map": [
                    {"type": "TEMPLATE", "key": "parameter", "value": name},
                    {
                        "type": "TEMPLATE",
                        "key": "parameterValue",
                        "value": value,
                    },
                ],
            }
            for name, value in rows
        ],
    }


def event_trigger(trigger_id: str, name: str, event: str, extra: list[dict] | None = None) -> dict:
    return {
        "triggerId": trigger_id,
        "name": name,
        "type": "CUSTOM_EVENT",
        "customEventFilter": [
            {
                "type": "EQUALS",
                "parameter": [
                    {"type": "TEMPLATE", "key": "arg0", "value": "{{_event}}"},
                    {"type": "TEMPLATE", "key": "arg1", "value": event},
                ],
            }
        ],
        "filter": list(extra or []),
    }


def rich_export() -> dict:
    return {
        "exportFormatVersion": 2,
        "exportTime": "2026-09-01 08:00:00",
        "containerVersion": {
            "path": "accounts/10/containers/20/versions/30",
            "accountId": "10",
            "containerId": "20",
            "containerVersionId": "30",
            "container": {
                "accountId": "10",
                "containerId": "20",
                "name": "Settings and consent fixture",
                "publicId": "GTM-SCAN-TEST",
                "usageContext": ["WEB"],
            },
            "variable": [
                {
                    "variableId": "101",
                    "name": "Google - Configuration Settings",
                    "type": "gtcs",
                    "parameter": [
                        table_parameter(
                            "configSettingsTable",
                            [
                                ("transport_url", "https://collect.example.test"),
                                ("consent_state", "{{Consent State}}"),
                                ("language", "en"),
                            ],
                        )
                    ],
                },
                {
                    "variableId": "102",
                    "name": "Google - Event Settings",
                    "type": "gtes",
                    "parameter": [
                        table_parameter(
                            "eventSettingsTable",
                            [("content_group", "{{Page Type}}")],
                        )
                    ],
                },
                {
                    "variableId": "103",
                    "name": "Consent State",
                    "type": "v",
                    "parameter": [
                        {"type": "TEMPLATE", "key": "name", "value": "consent_state"}
                    ],
                },
                {
                    "variableId": "104",
                    "name": "Page Type",
                    "type": "v",
                    "parameter": [
                        {"type": "TEMPLATE", "key": "name", "value": "page_type"}
                    ],
                },
                {
                    "variableId": "105",
                    "name": "didomiVendorsEnabled",
                    "type": "v",
                    "parameter": [
                        {
                            "type": "TEMPLATE",
                            "key": "name",
                            "value": "didomiVendorsEnabled",
                        }
                    ],
                },
                {
                    "variableId": "106",
                    "name": "Custom value",
                    "type": "jsm",
                    "parameter": [
                        {
                            "type": "TEMPLATE",
                            "key": "javascript",
                            "value": (
                                "function(){\n"
                                "  var page = {{Page Type}};\n"
                                "  if (!page) { return 'unknown'; }\n"
                                "  return page.toLowerCase();\n"
                                "}"
                            ),
                        }
                    ],
                },
            ],
            "trigger": [
                event_trigger("201", "Didomi consent timing", "didomi-consent"),
                event_trigger(
                    "202",
                    "Block when vendor is not enabled",
                    "didomi-consent",
                    [
                        {
                            "type": "DOES_NOT_CONTAIN",
                            "parameter": [
                                {
                                    "type": "TEMPLATE",
                                    "key": "arg0",
                                    "value": "{{didomiVendorsEnabled}}",
                                },
                                {
                                    "type": "TEMPLATE",
                                    "key": "arg1",
                                    "value": "vendor-42",
                                },
                            ],
                        }
                    ],
                ),
                event_trigger("203", "Business - ecommerce", "purchase"),
            ],
            "tag": [
                {
                    "tagId": "301",
                    "name": "Google tag - server route",
                    "type": "googtag",
                    "parameter": [
                        {"type": "TEMPLATE", "key": "tagId", "value": "G-TEST"},
                        {
                            "type": "TEMPLATE",
                            "key": "configSettingsVariable",
                            "value": "{{Google - Configuration Settings}}",
                        },
                        table_parameter(
                            "configSettingsTable", [("language", "fr")]
                        ),
                    ],
                    "firingTriggerId": ["201"],
                    "tagFiringPriority": "0",
                },
                {
                    "tagId": "302",
                    "name": "GA4 - purchase",
                    "type": "gaawe",
                    "parameter": [
                        {"type": "TEMPLATE", "key": "eventName", "value": "purchase"},
                        {
                            "type": "TEMPLATE",
                            "key": "configSettingsVariable",
                            "value": "{{Google - Configuration Settings}}",
                        },
                        {
                            "type": "TEMPLATE",
                            "key": "eventSettingsVariable",
                            "value": "{{Google - Event Settings}}",
                        },
                        table_parameter("eventSettingsTable", [("currency", "EUR")]),
                    ],
                    "firingTriggerId": ["203"],
                    "tagFiringPriority": "10",
                },
                {
                    "tagId": "303",
                    "name": "GA4 - add to cart",
                    "type": "gaawe",
                    "parameter": [
                        {
                            "type": "TEMPLATE",
                            "key": "eventName",
                            "value": "add_to_cart",
                        },
                        {
                            "type": "TEMPLATE",
                            "key": "configSettingsVariable",
                            "value": "{{Google - Configuration Settings}}",
                        },
                        {
                            "type": "TEMPLATE",
                            "key": "eventSettingsVariable",
                            "value": "{{Google - Event Settings}}",
                        },
                        table_parameter("eventSettingsTable", [("currency", "EUR")]),
                    ],
                    "firingTriggerId": ["203"],
                },
                {
                    "tagId": "304",
                    "name": "Direct vendor loader",
                    "type": "html",
                    "parameter": [
                        {
                            "type": "TEMPLATE",
                            "key": "html",
                            "value": (
                                "<script>\n"
                                "window.vendorQueue = window.vendorQueue || [];\n"
                                "var s = document.createElement('script');\n"
                                "s.src = 'https://unknown-vendor.example/loader.js';\n"
                                "document.head.appendChild(s);\n"
                                "</script>"
                            ),
                        }
                    ],
                    "firingTriggerId": ["201"],
                    "blockingTriggerId": ["202"],
                },
            ],
            "folder": [],
            "builtInVariable": [{"name": "Event", "type": "EVENT"}],
            "customTemplate": [],
            "zone": [],
            "gtagConfig": [],
            "client": [],
            "transformation": [],
        },
    }


class V2ScanAndOptimizationTests(unittest.TestCase):
    def test_neutral_fact_projection_rejects_unknown_judgment_shaped_fields(self) -> None:
        self.assertEqual(
            ["$.candidate.recommended_target"],
            neutral_fact_judgment_leaks(
                {"candidate": {"recommended_target": "merge tags"}}
            ),
        )
        self.assertEqual(
            [],
            neutral_fact_judgment_leaks(
                {"candidate_status": "neutral_candidate_not_a_verdict"}
            ),
        )

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.export = self.root / "container.json"
        self.export.write_text(json.dumps(rich_export()), encoding="utf-8")
        self.registry = ROOT / "references" / "03-rules" / "vendor-registry.toml"
        self.scan = build_canonical_scan(self.export)["canonical_scan"]

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def assurance(self, scan: dict | None = None) -> dict:
        return assure_scan(
            self.export,
            scan or self.scan,
            vendor_registry_path=self.registry,
        )

    def test_scan_assurance_covers_deep_identity_classes(self) -> None:
        self.assertEqual(
            {
                "account_id": "10",
                "container_id": "20",
                "public_id": "GTM-SCAN-TEST",
                "container_name": "Settings and consent fixture",
                "version_id": "30",
                "path": "accounts/10/containers/20/versions/30",
                "container_type": "WEB",
            },
            self.scan["container_identity"],
        )
        result = self.assurance()
        failures = [row for row in result["checks"] if row["status"] != "pass"]
        self.assertEqual([], failures)
        check_ids = {row["check_id"] for row in result["checks"]}
        self.assertTrue(
            {
                "reference_endpoints_and_consumers",
                "recursive_terminal_sources",
                "effective_google_settings",
                "effective_route_and_consent_forwarding",
                "custom_code_segment_identities",
                "custom_code_parser_coverage",
                "vendor_classification_and_research_ownership",
                "candidate_identity_integrity",
                "branch_identity_and_ownership",
            }
            <= check_ids
        )

    def test_effective_settings_priority_and_consent_topology_are_neutral_facts(self) -> None:
        self.assertFalse(_consent_metadata({"parameter": []})["contains_consent_value"])
        optimization = self.scan["optimization_facts"]
        purchase = next(
            row
            for row in optimization["effective_google_settings"]
            if row["object_key"] == "tag:302" and row["settings_scope"] == "event"
        )
        by_name = {row["parameter_name"]: row for row in purchase["effective_settings"]}
        self.assertEqual("inherited", by_name["content_group"]["origin"])
        self.assertEqual("local", by_name["currency"]["origin"])

        config = next(
            row
            for row in optimization["effective_google_settings"]
            if row["object_key"] == "tag:301"
            and row["settings_scope"] == "configuration"
        )
        config_by_name = {
            row["parameter_name"]: row for row in config["effective_settings"]
        }
        self.assertEqual("local_override", config_by_name["language"]["origin"])

        topology = {
            row["object_key"]: row for row in optimization["tag_control_topology"]
        }
        self.assertEqual(
            ["collect.example.test"], topology["tag:302"]["server_route_hosts"]
        )
        self.assertEqual(
            ["consent_state"],
            [
                row["parameter_name"]
                for row in topology["tag:302"]["consent_forwarding_settings"]
            ],
        )
        self.assertFalse(topology["tag:304"]["positive_route_contains_consent"])
        self.assertTrue(topology["tag:304"]["blocker_contains_consent"])
        self.assertIn("didomi-consent", topology["tag:304"]["cmp_lifecycle_event_candidates"])

        priorities = [
            row
            for row in optimization["optimization_candidates"]
            if row["candidate_type"] == "explicit_firing_priority"
        ]
        self.assertEqual({"tag:301", "tag:302"}, {row["object_key"] for row in priorities})
        zero = next(row for row in priorities if row["object_key"] == "tag:301")
        self.assertEqual(0, zero["parsed_value"])
        self.assertEqual(["tag:304"], zero["same_trigger_competitor_keys"])

        shared_candidates = [
            row
            for row in optimization["optimization_candidates"]
            if row["candidate_type"] == "shared_event_setting"
        ]
        names = {row["parameter_name"] for row in shared_candidates}
        self.assertIn("currency", names)
        self.assertNotIn("content_group", names)

    def test_assurance_blocks_tampered_settings_code_and_candidate_identity(self) -> None:
        tampered = copy.deepcopy(self.scan)
        settings = tampered["optimization_facts"]["effective_google_settings"]
        target = next(
            row
            for row in settings
            if row["object_key"] == "tag:301"
            and row["settings_scope"] == "configuration"
        )
        target["effective_settings"][0]["origin"] = "local"
        code_obj = next(
            row
            for row in tampered["configuration_evidence"]["objects"]
            if row["object_key"] == "tag:304"
        )
        code_obj["code_line_facts"][0]["line_hash"] = "tampered"
        candidate = tampered["optimization_facts"]["optimization_candidates"][0]
        candidate["candidate_id"] = "OPT-TAMPERED"
        result = self.assurance(tampered)
        self.assertEqual("blocked", result["status"])
        failures = {
            row["check_id"] for row in result["checks"] if row["status"] != "pass"
        }
        self.assertIn("effective_google_settings", failures)
        self.assertIn("custom_code_segment_identities", failures)
        self.assertIn("candidate_identity_integrity", failures)

    def test_obligation_ledger_owns_each_code_segment_and_candidate(self) -> None:
        assurance = self.assurance()
        ledger = build_obligation_ledger(self.scan, assurance)
        code_rows = [
            row
            for row in ledger["obligations"]
            if row["audit_mechanism"] == "custom_code_segment_review"
        ]
        self.assertTrue(code_rows)
        self.assertTrue(
            all(row["candidate_id"] == row["candidate_owner"] for row in code_rows)
        )
        candidate_ids = {
            row["candidate_id"]
            for row in ledger["obligations"]
            if row["candidate_id"]
        }
        scan_candidate_ids = {
            row["candidate_id"]
            for row in self.scan["optimization_facts"]["optimization_candidates"]
        } | {
            row["comparison_id"]
            for row in self.scan["architecture_evidence"]["relationships"]
        }
        self.assertTrue(scan_candidate_ids <= candidate_ids)


if __name__ == "__main__":
    unittest.main()
