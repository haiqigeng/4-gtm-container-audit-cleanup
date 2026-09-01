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
    ARCHITECTURE_DISCOVERY_FACT_FIELDS,
    ARCHITECTURE_FAMILY_FACT_FIELDS,
    ARCHITECTURE_RELATIONSHIP_FACT_FIELDS,
    CODE_ROW_FACT_FIELDS,
    CONFIGURATION_OBJECT_FACT_FIELDS,
    OPERATIONAL_CANDIDATE_FACT_FIELDS,
    build_canonical_scan,
    neutral_fact_judgment_leaks,
)
from gtm_context_model import build_context_model  # noqa: E402
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
    def advanced_mode_export(self, *, server_routed: bool) -> dict:
        payload = rich_export()
        cv = payload["containerVersion"]
        configuration_rows = [
            ("consent_state", "{{Consent State}}"),
            ("language", "en"),
        ]
        if server_routed:
            configuration_rows.insert(
                0, ("transport_url", "https://collect.example.test")
            )
        cv["variable"][0]["parameter"] = [
            table_parameter("configSettingsTable", configuration_rows)
        ]
        cv["tag"].extend(
            [
                {
                    "tagId": "305",
                    "name": "Consent defaults",
                    "type": "html",
                    "parameter": [
                        {
                            "type": "TEMPLATE",
                            "key": "html",
                            "value": (
                                "<script>gtag('consent','default', {"
                                "'analytics_storage':'denied',"
                                "'ad_storage':'denied'});</script>"
                            ),
                        }
                    ],
                    "firingTriggerId": ["2147479593"],
                },
                {
                    "tagId": "306",
                    "name": "Consent updates",
                    "type": "html",
                    "parameter": [
                        {
                            "type": "TEMPLATE",
                            "key": "html",
                            "value": (
                                "<script>gtag('consent','update', {"
                                "'analytics_storage':'granted',"
                                "'ad_storage':'granted'});</script>"
                            ),
                        }
                    ],
                    "firingTriggerId": ["201"],
                },
            ]
        )
        return payload

    def test_neutral_fact_projection_rejects_unknown_judgment_shaped_fields(self) -> None:
        self.assertEqual(
            [
                "$.candidate.recommended_target",
                "$.candidate.default_action",
                "$.candidate.required_resolution",
                "$.candidate.selected_naming_policy",
            ],
            neutral_fact_judgment_leaks(
                {
                    "candidate": {
                        "recommended_target": "merge tags",
                        "default_action": "remove duplicate",
                        "required_resolution": "cleanup operation",
                        "selected_naming_policy": "default-standardized",
                    }
                }
            ),
        )
        self.assertEqual(
            [],
            neutral_fact_judgment_leaks(
                {"candidate_status": "neutral_candidate_not_a_verdict"}
            ),
        )

    def test_canonical_scan_exposes_only_declared_neutral_fact_schemas(self) -> None:
        operational = self.scan["operational_evidence"]
        self.assertEqual(
            {"kind", "schema_version", "source_sha256", "candidates"},
            set(operational),
        )
        operational_candidates = operational["candidates"]
        prohibited = {
            "default_action",
            "deterministic_action_candidate",
            "finding_class",
            "operation_packet_required",
            "required_resolution",
            "policy_confirmation_required",
            "selected_naming_policy",
            "target_naming_pattern",
            "technical_action_candidate",
            "technical_cleanup_implication",
            "technical_code_recommendation",
            "technical_disposition",
            "technical_disposition_vocabulary",
            "technical_exact_proposed_action",
            "technical_expected_clean_state",
        }
        self.assertTrue(operational_candidates)
        self.assertTrue(
            all(not (prohibited & set(candidate)) for candidate in operational_candidates)
        )
        self.assertTrue(
            all(
                set(candidate) <= OPERATIONAL_CANDIDATE_FACT_FIELDS
                for candidate in operational_candidates
            )
        )
        self.assertEqual([], neutral_fact_judgment_leaks(self.scan))
        self.assertTrue(
            all(
                not (prohibited & set(row)) and set(row) <= CODE_ROW_FACT_FIELDS
                for row in self.scan["code_evidence"].get("rows", [])
            )
        )
        for row in self.scan["configuration_evidence"]["objects"]:
            self.assertTrue(set(row) <= CONFIGURATION_OBJECT_FACT_FIELDS)
            if isinstance(row.get("technical_code_facts"), dict):
                self.assertTrue(set(row["technical_code_facts"]) <= CODE_ROW_FACT_FIELDS)
        architecture = self.scan["architecture_evidence"]
        self.assertTrue(
            all(set(row) <= ARCHITECTURE_FAMILY_FACT_FIELDS for row in architecture["families"])
        )
        self.assertTrue(
            all(
                set(row) <= ARCHITECTURE_RELATIONSHIP_FACT_FIELDS
                for row in architecture["relationships"]
            )
        )
        self.assertTrue(
            all(
                set(row) <= ARCHITECTURE_DISCOVERY_FACT_FIELDS
                for row in architecture["open_discovery_methods"]
            )
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

    def test_behavior_scope_keeps_cross_level_areas_applicable_and_assured(self) -> None:
        export = rich_export()
        cv = export["containerVersion"]
        cv["variable"] = []
        cv["gtagConfig"] = []
        cv["customTemplate"] = []
        cv["transformation"] = []
        cv["zone"] = []
        export_path = self.root / "behavior-only-cross-level.json"
        export_path.write_text(json.dumps(export), encoding="utf-8")
        scan = build_canonical_scan(export_path)["canonical_scan"]
        coverage = {
            row["area_id"]: row
            for row in scan["coverage_ledger"]
            if row["area_id"] in {"AREA-20", "AREA-23"}
        }
        self.assertEqual({"AREA-20", "AREA-23"}, set(coverage))
        self.assertTrue(all(row["applicability"] == "applicable" for row in coverage.values()))
        self.assertTrue(all(row["source_count"] > 0 for row in coverage.values()))
        assurance = assure_scan(
            export_path,
            scan,
            vendor_registry_path=self.registry,
        )
        self.assertEqual("pass", assurance["status"])

        tampered = copy.deepcopy(scan)
        for row in tampered["coverage_ledger"]:
            if row["area_id"] in {"AREA-20", "AREA-23"}:
                row["source_count"] = 0
                row["applicability"] = "source_counted_zero"
        assurance = assure_scan(
            export_path,
            tampered,
            vendor_registry_path=self.registry,
        )
        check = next(
            row
            for row in assurance["checks"]
            if row["check_id"] == "raw_scope_area_applicability"
        )
        self.assertEqual("mismatch", check["status"])

    def test_duplicate_settings_names_remain_ambiguous_without_losing_candidates(self) -> None:
        export = rich_export()
        export["containerVersion"]["variable"].append(
            {
                "variableId": "199",
                "name": "Google - Configuration Settings",
                "type": "gtcs",
                "parameter": [
                    table_parameter(
                        "configSettingsTable",
                        [("transport_url", "https://second.example.test")],
                    )
                ],
            }
        )
        export_path = self.root / "duplicate-settings-name.json"
        export_path.write_text(json.dumps(export), encoding="utf-8")
        scan = build_canonical_scan(export_path)["canonical_scan"]
        surface = next(
            row
            for row in scan["optimization_facts"]["effective_google_settings"]
            if row["object_key"] == "tag:301"
            and row["settings_scope"] == "configuration"
        )
        self.assertEqual([], surface["resolved_settings_variable_keys"])
        ambiguity = surface["ambiguous_settings_variable_references"]
        self.assertEqual(1, len(ambiguity))
        self.assertEqual(
            ["variable:101", "variable:199"],
            ambiguity[0]["candidate_object_keys"],
        )
        self.assertEqual(
            {"variable:101", "variable:199"},
            {
                row["candidate_object_key"]
                for row in surface["candidate_inherited_settings"]
            },
        )
        topology = next(
            row
            for row in scan["optimization_facts"]["tag_control_topology"]
            if row["object_key"] == "tag:301"
        )
        self.assertEqual(
            ["collect.example.test", "second.example.test"],
            topology["server_route_hosts"],
        )
        assurance = assure_scan(
            export_path,
            scan,
            vendor_registry_path=self.registry,
        )
        self.assertEqual("pass", assurance["status"])

        tampered = copy.deepcopy(scan)
        tampered_surface = next(
            row
            for row in tampered["optimization_facts"]["effective_google_settings"]
            if row["object_key"] == "tag:301"
            and row["settings_scope"] == "configuration"
        )
        tampered_surface["candidate_inherited_settings"] = [
            row
            for row in tampered_surface["candidate_inherited_settings"]
            if row["candidate_object_key"] != "variable:199"
        ]
        assurance = assure_scan(
            export_path,
            tampered,
            vendor_registry_path=self.registry,
        )
        check = next(
            row
            for row in assurance["checks"]
            if row["check_id"] == "effective_google_settings"
        )
        self.assertEqual("mismatch", check["status"])

    def test_context_contract_has_no_legacy_unresolved_question_channel(self) -> None:
        model = build_context_model(self.export)
        self.assertIn("intake_questions", model)
        self.assertIn("intake_status", model)
        self.assertNotIn("unresolved_questions", model)
        with self.assertRaisesRegex(ValueError, "unsupported fields"):
            build_context_model(
                self.export,
                provided_context={"unresolved_questions": ["legacy question"]},
            )

    def test_server_consent_owner_is_unconfirmed_until_exact_host_is_approved(self) -> None:
        default_tag = next(
            row for row in self.scan["objects"] if row["object_key"] == "tag:301"
        )
        default_route = default_tag["effective_consent_route"]
        self.assertEqual(
            "unconfirmed",
            default_route["server_consent_gating_ownership_status"],
        )
        self.assertEqual(
            ["collect.example.test"],
            default_route["unconfirmed_server_consent_gating_hosts"],
        )

        approved_scan = build_canonical_scan(
            self.export,
            provided_context={
                "server_consent_gating_hosts": [
                    "https://collect.example.test"
                ]
            },
        )["canonical_scan"]
        approved_tag = next(
            row
            for row in approved_scan["objects"]
            if row["object_key"] == "tag:301"
        )
        approved_route = approved_tag["effective_consent_route"]
        self.assertEqual(
            "approved_context",
            approved_route["server_consent_gating_ownership_status"],
        )
        self.assertEqual(
            ["collect.example.test"],
            approved_route["approved_server_consent_gating_hosts"],
        )
        self.assertEqual(
            [],
            approved_route["unconfirmed_server_consent_gating_hosts"],
        )

    def test_advanced_mode_requires_typed_scoped_approval_and_visible_writers(self) -> None:
        for server_routed, transport_scope, route_host in (
            (False, "direct_browser", ""),
            (True, "client_to_server", "collect.example.test"),
        ):
            with self.subTest(server_routed=server_routed):
                export = self.root / f"advanced-{server_routed}.json"
                export.write_text(
                    json.dumps(self.advanced_mode_export(server_routed=server_routed)),
                    encoding="utf-8",
                )
                scan = build_canonical_scan(
                    export,
                    provided_context={
                        "advanced_consent_mode_approvals": [
                            {
                                "destination_id": "G-TEST",
                                "transport_scope": transport_scope,
                                "route_host": route_host,
                                "approval_status": "approved",
                                "evidence": "Owner approval ticket CMP-42",
                            }
                        ]
                    },
                )["canonical_scan"]
                topology = {
                    row["object_key"]: row
                    for row in scan["optimization_facts"]["tag_control_topology"]
                }
                evidence = topology["tag:301"][
                    "advanced_consent_mode_evidence"
                ]
                self.assertTrue(evidence["scoped_approval_complete"])
                self.assertTrue(evidence["source_visible_defaults_present"])
                self.assertTrue(evidence["source_visible_updates_present"])
                self.assertTrue(
                    evidence["source_visible_default_update_coherence"]
                )
                self.assertTrue(
                    evidence["confirmed_advanced_mode_evidence_complete"]
                )
                self.assertEqual(
                    route_host,
                    evidence["required_approval_scopes"][0]["route_host"],
                )

        incomplete = self.advanced_mode_export(server_routed=False)
        incomplete["containerVersion"]["tag"] = [
            row
            for row in incomplete["containerVersion"]["tag"]
            if row.get("tagId") != "306"
        ]
        incomplete_path = self.root / "advanced-missing-update.json"
        incomplete_path.write_text(json.dumps(incomplete), encoding="utf-8")
        scan = build_canonical_scan(
            incomplete_path,
            provided_context={
                "advanced_consent_mode_approvals": [
                    {
                        "destination_id": "G-TEST",
                        "transport_scope": "direct_browser",
                        "route_host": "",
                        "approval_status": "approved",
                        "evidence": "Owner approval ticket CMP-42",
                    }
                ]
            },
        )["canonical_scan"]
        tag = next(
            row
            for row in scan["optimization_facts"]["tag_control_topology"]
            if row["object_key"] == "tag:301"
        )
        self.assertFalse(
            tag["advanced_consent_mode_evidence"][
                "confirmed_advanced_mode_evidence_complete"
            ]
        )

        incomplete_ads = self.advanced_mode_export(server_routed=False)
        google_tag = next(
            row
            for row in incomplete_ads["containerVersion"]["tag"]
            if row.get("tagId") == "301"
        )
        next(
            parameter
            for parameter in google_tag["parameter"]
            if parameter.get("key") == "tagId"
        )["value"] = "AW-123456"
        ads_path = self.root / "advanced-incomplete-ads-types.json"
        ads_path.write_text(json.dumps(incomplete_ads), encoding="utf-8")
        ads_scan = build_canonical_scan(
            ads_path,
            provided_context={
                "advanced_consent_mode_approvals": [
                    {
                        "destination_id": "AW-123456",
                        "transport_scope": "direct_browser",
                        "route_host": "",
                        "approval_status": "approved",
                        "evidence": "Owner approval ticket CMP-84",
                    }
                ]
            },
        )["canonical_scan"]
        ads_evidence = next(
            row
            for row in ads_scan["optimization_facts"]["tag_control_topology"]
            if row["object_key"] == "tag:301"
        )["advanced_consent_mode_evidence"]
        self.assertFalse(ads_evidence["required_consent_types_visible"])
        self.assertFalse(
            ads_evidence["confirmed_advanced_mode_evidence_complete"]
        )

        with self.assertRaisesRegex(ValueError, "closed approval schema"):
            build_canonical_scan(
                incomplete_path,
                provided_context={
                    "advanced_consent_mode_approvals": [
                        {
                            "destination_id": "G-TEST",
                            "transport_scope": "direct_browser",
                            "route_host": "",
                            "approval_status": "approved",
                            "evidence": "Owner approval ticket CMP-42",
                            "foreign_context": "advanced",
                        }
                    ]
                },
            )

    def test_consent_area_applicability_and_vendor_topology_are_route_exact(self) -> None:
        payload = rich_export()
        cv = payload["containerVersion"]
        cv["variable"][0]["parameter"] = [
            table_parameter(
                "configSettingsTable",
                [("consent_state", "{{Consent State}}"), ("language", "en")],
            )
        ]
        vendor_tag = next(row for row in cv["tag"] if row["tagId"] == "304")
        vendor_tag["parameter"][0]["value"] = (
            "<script>fbq('track', 'PageView');</script>"
        )
        export = self.root / "direct-consent-topology.json"
        export.write_text(json.dumps(payload), encoding="utf-8")
        scan = build_canonical_scan(export)["canonical_scan"]
        topology = {
            row["object_key"]: row
            for row in scan["optimization_facts"]["tag_control_topology"]
        }
        self.assertIn("Meta", topology["tag:304"]["direct_vendor_signals"])
        self.assertTrue(
            topology["tag:304"]["consent_applicability"][
                "direct_non_advanced_browser_vendor"
            ]
        )
        self.assertFalse(
            topology["tag:304"]["consent_applicability"][
                "client_to_server_transport"
            ]
        )
        coverage = {row["area_id"]: row for row in scan["coverage_ledger"]}
        self.assertEqual("applicable", coverage["AREA-09"]["applicability"])
        self.assertEqual("applicable", coverage["AREA-10"]["applicability"])
        self.assertEqual("applicable", coverage["AREA-11"]["applicability"])
        self.assertEqual(
            "source_counted_zero", coverage["AREA-12"]["applicability"]
        )
        assurance = assure_scan(
            export,
            scan,
            vendor_registry_path=self.registry,
        )
        ledger = build_obligation_ledger(scan, assurance)
        routed_area_12 = [
            row
            for row in ledger["obligations"]
            if row["area_id"] == "AREA-12" and row["subject_keys"]
        ]
        self.assertEqual([], routed_area_12)

    def test_destination_linked_gtag_config_route_is_effective_and_assured(self) -> None:
        inherited = rich_export()
        cv = inherited["containerVersion"]
        cv["variable"][0]["parameter"] = [
            table_parameter(
                "configSettingsTable",
                [
                    ("consent_state", "{{Consent State}}"),
                    ("language", "en"),
                ],
            )
        ]
        cv["gtagConfig"] = [
            {
                "gtagConfigId": "401",
                "name": "Google destination settings",
                "type": "googtag",
                "parameter": [
                    {
                        "type": "TEMPLATE",
                        "key": "tagId",
                        "value": "G-TEST",
                    },
                    {
                        "type": "TEMPLATE",
                        "key": "transport_url",
                        "value": "https://collect.example.test",
                    },
                ],
            }
        ]
        export = self.root / "inherited-gtag-config.json"
        export.write_text(json.dumps(inherited), encoding="utf-8")
        scan = build_canonical_scan(export)["canonical_scan"]

        topology = {
            row["object_key"]: row
            for row in scan["optimization_facts"]["tag_control_topology"]
        }
        self.assertEqual(
            ["collect.example.test"],
            topology["tag:301"]["server_route_hosts"],
        )
        shared_tag = next(
            row for row in scan["objects"] if row["object_key"] == "tag:301"
        )
        self.assertEqual(
            ["collect.example.test"],
            shared_tag["effective_consent_route"]["server_routing_hosts"],
        )
        coverage = {
            row["area_id"]: row for row in scan["coverage_ledger"]
        }
        self.assertEqual("applicable", coverage["AREA-12"]["applicability"])
        self.assertEqual("applicable", coverage["AREA-13"]["applicability"])
        assurance = assure_scan(
            export,
            scan,
            vendor_registry_path=self.registry,
        )
        self.assertEqual(
            [],
            [row for row in assurance["checks"] if row["status"] != "pass"],
        )

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
