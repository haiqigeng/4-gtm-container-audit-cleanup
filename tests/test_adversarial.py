from __future__ import annotations

import collections
import copy
import json
import tempfile
import unittest
from pathlib import Path

from tests.review_helpers import complete_review_attestation
from tests.test_pipeline import (
    complete_architecture,
    complete_configuration,
    complete_operational,
    sample_export,
)

from gtm_architecture_review import validate_review as validate_architecture
from gtm_audit_package_build import build_package
from gtm_baseline_audit import audit_export, ua_style_signals
from gtm_configuration_facts import code_line_facts
from gtm_configuration_review import scaffold_review as scaffold_configuration
from gtm_configuration_review import validate_review as validate_configuration
from gtm_consent_model import server_route_hosts
from gtm_context_model import build_context_model
from gtm_future_state_check import prior_finding_covers
from gtm_lib import refs
from gtm_operation_compile import (
    decision_ledger,
    validate_cross_run_reconciliation,
    validate_mutation_conflicts,
)
from gtm_operational_review import validate_review as validate_operational
from gtm_relationships import relationship_candidates
from gtm_review_shards import check_shard, merge_review, split_review
from gtm_three_run_gate import run_gate
from gtm_vendor_registry import vendor_records


class AdversarialAuditTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.export = self.root / "container.json"
        self.export.write_text(json.dumps(sample_export()), encoding="utf-8")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_json(self, name: str, payload: dict) -> Path:
        path = self.root / name
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def test_fixture_manifest_covers_every_regression_family(self) -> None:
        manifest = json.loads(
            (Path(__file__).parent / "fixtures" / "analyst_cases.json").read_text(
                encoding="utf-8"
            )
        )
        case_ids = {row["id"] for row in manifest["cases"]}
        self.assertEqual(71, len(case_ids))
        self.assertIn("single_member_trigger_group", case_ids)
        self.assertIn("dynamic_ga4_purchase_contract", case_ids)
        self.assertIn("worsened_future_finding", case_ids)
        self.assertIn("ambiguous_source_identity", case_ids)
        self.assertIn("zone_and_google_tag_config_coverage", case_ids)
        self.assertIn("behavior_change_architecture_conflict", case_ids)
        self.assertIn("duplicate_reference_name_ambiguity", case_ids)
        self.assertIn("nested_control_shape_corruption", case_ids)
        self.assertIn("mixed_route_blocker_conservatism", case_ids)
        self.assertIn("zone_gtag_change_log", case_ids)
        self.assertIn("javascript_parser_fallback_visibility", case_ids)
        self.assertIn("mixed_vendor_unknown_host", case_ids)
        self.assertIn("export_metadata_duplicate_resilience", case_ids)
        self.assertIn("exact_once_branch_ownership", case_ids)
        self.assertIn("custom_template_section_separation", case_ids)
        self.assertIn("vendor_research_single_owner", case_ids)
        self.assertIn("vendor_aware_ua_detection", case_ids)
        self.assertIn("consent_control_evidence_boundaries", case_ids)
        self.assertIn("dependency_trace_cross_object_coverage", case_ids)
        self.assertIn("reachability_context_and_gateway_separation", case_ids)
        self.assertIn("architecture_verdict_coherence", case_ids)
        self.assertIn("transaction_id_contract_presence", case_ids)
        self.assertIn("custom_code_representation_safety", case_ids)
        self.assertIn("same_payload_different_route", case_ids)
        self.assertIn("same_contract_consent_collision", case_ids)
        self.assertIn("consumed_delete_remap_coverage", case_ids)
        self.assertIn("deterministic_configuration_contradiction", case_ids)
        self.assertIn("exact_parser_fallback_attestation", case_ids)
        self.assertIn("opaque_custom_template_boundary", case_ids)
        self.assertIn("browser_server_consent_dedup_family", case_ids)
        self.assertIn("unsafe_architecture_retention", case_ids)
        self.assertIn("visible_relationship_evidence_boundary", case_ids)
        self.assertIn("dependency_safe_remap_semantics", case_ids)
        self.assertIn("final_layer_name_uniqueness", case_ids)
        self.assertIn("configuration_obligation_identity_and_polarity", case_ids)
        self.assertIn("exact_once_configuration_rows", case_ids)
        self.assertIn("parser_segment_semantic_coverage", case_ids)
        self.assertIn("unknown_vendor_source_registry_boundary", case_ids)
        self.assertIn("destination_peer_inheritance_boundary", case_ids)
        self.assertIn("architecture_operation_candidate_binding", case_ids)
        self.assertIn("discovered_unsafe_policy_attribution", case_ids)
        self.assertIn("architecture_negative_runtime_claims", case_ids)
        self.assertIn("material_context_preflight", case_ids)
        self.assertIn("independent_run_input_boundary", case_ids)
        self.assertIn("incremental_shard_completion_check", case_ids)
        self.assertIn("decision_first_human_output", case_ids)
        self.assertIn("semantic_release_invariant", case_ids)
        self.assertIn("missing_setup_peer_repair", case_ids)
        self.assertIn("ua_label_ga4_consumer", case_ids)
        self.assertIn("source_ranked_canonical_default", case_ids)
        self.assertIn("metadata_only_vendor_noise", case_ids)
        self.assertIn("identical_code_disposition_consistency", case_ids)
        self.assertIn("independent_reasoning_context_identity", case_ids)
        self.assertIn("runtime_test_contract_grouping", case_ids)
        self.assertIn("action_incomplete_blocked_draft", case_ids)

    def test_provided_context_is_reproducible_and_tamper_evident(self) -> None:
        context_path = self.write_json(
            "context-input.json",
            {
                "website_url": "https://example.test/",
                "business_model": "lead_generation",
                "cmp": ["OneTrust"],
            },
        )
        package = self.root / "package"
        build_package(self.export, package, pretty=True, context_path=context_path)
        packaged_review = json.loads(
            (package / "operational_review.json").read_text(encoding="utf-8")
        )
        completed = complete_operational(self.export)
        for field in (
            "shared_facts_sha256",
            "context_sha256",
            "audit_context",
            "inferred_context",
            "provided_context",
            "provided_context_fields",
            "unresolved_context_questions",
            "input_contract",
        ):
            completed[field] = copy.deepcopy(packaged_review[field])
        completed["completion_attestation"] = complete_review_attestation(
            completed, decision_authoring_method="independent_test_fixture_review"
        )
        review_path = self.write_json("contextual-operational.json", completed)
        errors, _ = validate_operational(self.export, review_path)
        self.assertEqual([], errors)

        context = json.loads((package / "context.json").read_text(encoding="utf-8"))
        context["unresolved_questions"].append("Fabricated question")
        (package / "context.json").write_text(json.dumps(context), encoding="utf-8")
        report = run_gate(self.export, package)
        self.assertEqual("fail", report["status"])
        self.assertTrue(any("context" in error for error in report["errors"]))

    def test_intake_preflight_separates_evidence_without_adding_a_package_gate(self) -> None:
        inferred = build_context_model(self.export)
        self.assertEqual(
            "high_confidence_inferred",
            inferred["context_evidence"]["container_type"]["status"],
        )
        self.assertEqual(
            "audit_and_cleanup_plan", inferred["context"]["requested_deliverable"]
        )
        self.assertFalse(
            any(
                row["field"] == "requested_deliverable"
                for row in inferred["intake_questions"]
            )
        )
        self.assertEqual("confirmation_required", inferred["intake_status"])

        package = self.root / "preflight-package"
        manifest = build_package(self.export, package, pretty=True)
        self.assertEqual("pass", manifest["status"])
        self.assertEqual("confirmation_required", manifest["intake"]["status"])
        self.assertNotIn(
            "confirmed material audit context", manifest["required_next_artifacts"]
        )
        self.assertTrue(
            any("nonblocking owner decisions" in note for note in manifest["notes"])
        )

        provided = self.write_json(
            "complete-intake.json",
            {
                "website_url": "https://example.test/",
                "business_model": "ecommerce",
                "cmp": [],
                "server_routing_hosts": inferred["context"]["server_routing_hosts"],
                "requested_deliverable": "audit and cleanup plan",
            },
        )
        confirmed = build_context_model(self.export, provided)
        self.assertEqual(
            "audit_and_cleanup_plan", confirmed["context"]["requested_deliverable"]
        )
        self.assertEqual("provided", confirmed["context_evidence"]["cmp"]["status"])
        self.assertFalse(
            any(row["material"] for row in confirmed["intake_questions"]),
            confirmed["intake_questions"],
        )
        self.assertEqual("ready", confirmed["intake_status"])

        no_consent = sample_export()
        container = no_consent["containerVersion"]
        for layer in ("tag", "trigger", "variable"):
            container[layer] = []
        no_consent_export = self.write_json("no-consent-context.json", no_consent)
        non_blocking = build_context_model(
            no_consent_export,
            provided_context={
                "website_url": "https://example.test/",
                "business_model": "lead_generation",
                "server_routing_hosts": [],
                "requested_deliverable": "audit and cleanup plan",
            },
        )
        cmp_question = next(
            row for row in non_blocking["intake_questions"] if row["field"] == "cmp"
        )
        self.assertFalse(cmp_question["material"])
        self.assertEqual([], non_blocking["unresolved_questions"])
        self.assertEqual("ready", non_blocking["intake_status"])

        malformed_cmp = build_context_model(
            no_consent_export,
            provided_context={
                "website_url": "https://example.test/",
                "business_model": "lead_generation",
                "cmp": "none",
                "server_routing_hosts": [],
                "requested_deliverable": "audit and cleanup plan",
            },
        )
        self.assertEqual([], malformed_cmp["context"]["cmp"])
        self.assertEqual(
            "unresolved", malformed_cmp["context_evidence"]["cmp"]["status"]
        )
        self.assertTrue(
            any(row["field"] == "cmp" for row in malformed_cmp["intake_questions"])
        )

    def test_repeated_custom_code_lines_keep_distinct_source_identity(self) -> None:
        variable = {
            "variableId": "900",
            "name": "CJS - Nested closures",
            "type": "jsm",
            "parameter": [
                {
                    "key": "javascript",
                    "type": "TEMPLATE",
                    "value": "function() {\nif (true) {\nreturn 1;\n}\n}\n}",
                }
            ],
        }
        facts = code_line_facts("variable", variable)
        closing_hashes = [row["line_hash"] for row in facts if row["line_preview"] == "}"]
        self.assertEqual(3, len(closing_hashes))
        self.assertEqual(3, len(set(closing_hashes)))

    def test_dynamic_purchase_name_requires_ga4_ecommerce_contract(self) -> None:
        data = sample_export()
        data["containerVersion"]["variable"].append(
            {
                "variableId": "901",
                "name": "Const - Purchase",
                "type": "c",
                "parameter": [{"key": "value", "type": "TEMPLATE", "value": "purchase"}],
            }
        )
        data["containerVersion"]["tag"][0]["parameter"][0]["value"] = (
            "{{Const - Purchase}}"
        )
        export = self.write_json("dynamic-purchase.json", data)
        scaffold = scaffold_configuration(export)
        tag = next(row for row in scaffold["rows"] if row["object_key"] == "tag:1")
        topics = {row["topic"] for row in tag["required_contract_topics"]}
        self.assertIn("ecommerce_event_contract", topics)
        self.assertIn("transaction_value_currency_and_quantity", topics)

    def test_basic_and_semantic_overlap_scans_find_known_cases(self) -> None:
        findings = audit_export(self.export)["findings"]
        self.assertTrue(
            any(row.get("finding_type") == "single_member_trigger_group" for row in findings)
        )
        candidates = relationship_candidates(sample_export()["containerVersion"])
        funnel = next(
            row
            for row in candidates
            if set(row["candidate_object_names"])
            == {"Funnel question 1", "Funnel step impression Q1"}
        )
        self.assertIn("shared_business_scope", funnel["comparison_types"])

    def test_same_logic_for_different_consent_purposes_is_mandatory_comparison(self) -> None:
        data = sample_export()
        logic = {
            "type": "jsm",
            "parameter": [
                {
                    "key": "javascript",
                    "type": "TEMPLATE",
                    "value": "function() { return {{OneTrust Groups}}.indexOf('2') >= 0; }",
                }
            ],
        }
        data["containerVersion"]["variable"].extend(
            [
                {"variableId": "910", "name": "CJS - analytics_storage", **logic},
                {"variableId": "911", "name": "CJS - ad_storage", **logic},
            ]
        )
        candidates = relationship_candidates(data["containerVersion"])
        collision = next(
            row
            for row in candidates
            if "different_consent_purposes_same_logic" in row["comparison_types"]
        )
        self.assertEqual({"variable:910", "variable:911"}, set(collision["candidate_object_keys"]))

    def test_undeclared_exception_and_missing_d3_checks_are_rejected(self) -> None:
        operational = complete_operational(self.export)
        operational["findings"][0].update(
            {
                "disposition": "documented_exception",
                "rationale": "This source-specific configuration is intentionally retained by its owner.",
                "owner_question": "",
            }
        )
        errors, _ = validate_operational(
            self.export, self.write_json("bad-exception.json", operational)
        )
        self.assertTrue(any("known_owner_exceptions" in error for error in errors))

        configuration = complete_configuration(self.export)
        configuration["rows"][0]["logic_cross_checks"] = []
        errors, _ = validate_configuration(
            self.export, self.write_json("missing-d3.json", configuration)
        )
        self.assertTrue(any("D3 logic checks" in error for error in errors))

    def test_declared_owner_exception_is_accepted_only_with_its_locked_reason(self) -> None:
        baseline = complete_operational(self.export)
        finding = baseline["findings"][0]
        reason = "The measurement owner approved this retained legacy route until migration."
        context_path = self.write_json(
            "exception-context.json",
            {
                "known_owner_exceptions": [
                    {"finding_id": finding["finding_id"], "reason": reason}
                ]
            },
        )
        package = self.root / "exception-package"
        build_package(self.export, package, context_path=context_path)
        contextual = json.loads(
            (package / "operational_review.json").read_text(encoding="utf-8")
        )
        for field in (
            "shared_facts_sha256",
            "context_sha256",
            "audit_context",
            "inferred_context",
            "provided_context",
            "provided_context_fields",
            "unresolved_context_questions",
            "input_contract",
        ):
            baseline[field] = copy.deepcopy(contextual[field])
        baseline["completion_attestation"] = complete_review_attestation(
            baseline, decision_authoring_method="independent_test_fixture_review"
        )
        baseline["findings"][0].update(
            {
                "disposition": "documented_exception",
                "rationale": (
                    f"{reason} The source evidence "
                    f"{' and '.join(finding['rationale_evidence_terms'][:2])} is retained."
                ),
                "owner_question": "",
            }
        )
        errors, _ = validate_operational(
            self.export, self.write_json("declared-exception.json", baseline)
        )
        self.assertEqual([], errors)

    def test_unknown_vendor_placeholder_documentation_is_rejected(self) -> None:
        data = sample_export()
        data["containerVersion"]["tag"].append(
            {
                "tagId": "920",
                "name": "Unknown partner loader",
                "type": "html",
                "parameter": [
                    {
                        "key": "html",
                        "type": "TEMPLATE",
                        "value": '<script src="https://unknown-cdn.example/widget.js"></script>',
                    }
                ],
                "firingTriggerId": ["10"],
            }
        )
        export = self.write_json("unknown-vendor-placeholder.json", data)
        review = complete_configuration(export)
        partner = next(row for row in review["rows"] if row["object_key"] == "tag:920")
        research_check = next(
            check
            for check, topic in zip(
                partner["contract_checks"],
                partner["required_contract_topics"],
                strict=True,
            )
            if topic.get("research_required")
        )
        valid_research_status = research_check["research_status"]
        research_check["research_status"] = (
            "No authoritative vendor identity or official source is visible in the export."
        )
        errors, _ = validate_configuration(
            export, self.write_json("unresearched-contract.json", review)
        )
        self.assertTrue(any("attempted official-source research" in error for error in errors))
        research_check["research_status"] = valid_research_status
        research_check["source"] = "https://vendor.example.com/official/setup"
        errors, _ = validate_configuration(
            export, self.write_json("placeholder-contract.json", review)
        )
        self.assertTrue(any("placeholder" in error for error in errors))

        research_check["source"] = "https://metricsvendor.unrelated.org/official/setup"
        errors, _ = validate_configuration(
            export, self.write_json("spoofed-contract.json", review)
        )
        self.assertTrue(any("unregistered vendor source" in error for error in errors))

    def test_mixed_vendor_tag_keeps_every_vendor_and_unknown_host_obligation(self) -> None:
        data = sample_export()
        data["containerVersion"]["tag"][1]["tagManagerUrl"] = (
            "https://metadata.example/container/tag/2"
        )
        html_parameter = data["containerVersion"]["tag"][1]["parameter"][0]
        html_parameter["value"] = (
            "<script src='https://mystery.example/sdk.js'></script>"
            "<script>fbq('track', 'Purchase'); ttq.track('CompletePayment');</script>"
        )
        export = self.write_json("mixed-vendor.json", data)
        scaffold = scaffold_configuration(export)
        row = next(item for item in scaffold["rows"] if item["object_key"] == "tag:2")
        context_names = {item["vendor"] for item in row["vendor_contexts"]}
        self.assertTrue({"Meta", "TikTok"}.issubset(context_names))
        self.assertIn(
            "Unclassified external integration (mystery.example)", context_names
        )
        self.assertNotIn(
            "Unclassified external integration (metadata.example)", context_names
        )
        self.assertNotIn("metadata.example", scaffold["audit_context"]["external_hosts"])
        unknown_topics = [
            item
            for item in row["required_contract_topics"]
            if item["category"] == "unknown_vendor"
        ]
        self.assertTrue(unknown_topics)
        self.assertEqual(
            ["vendor_identity_and_official_setup"],
            [item["topic"] for item in unknown_topics if item["research_required"]],
        )
        self.assertEqual(
            1,
            len({item["research_dependency_key"] for item in unknown_topics}),
        )
        self.assertEqual(
            {"Meta", "TikTok"},
            {item["name"] for item in vendor_records(html_parameter["value"])},
        )

    def test_unknown_host_research_has_one_owner_and_reusable_dependencies(self) -> None:
        data = sample_export()
        for tag_id, name in (("91", "Partner one"), ("92", "Partner two")):
            data["containerVersion"]["tag"].append(
                {
                    "tagId": tag_id,
                    "name": name,
                    "type": "html",
                    "parameter": [
                        {
                            "key": "html",
                            "value": (
                                "<script src='https://shared-vendor.example.test/sdk.js'>"
                                "</script>"
                            ),
                        }
                    ],
                    "firingTriggerId": ["10"],
                }
            )
        scaffold = scaffold_configuration(self.write_json("shared-host.json", data))
        topics = [
            topic
            for row in scaffold["rows"]
            for topic in row["required_contract_topics"]
            if topic.get("research_dependency_key")
            == "vendor-research:Unclassified external integration (shared-vendor.example.test)"
        ]
        self.assertTrue(topics)
        self.assertEqual(1, sum(bool(topic["research_required"]) for topic in topics))
        self.assertEqual(1, len({topic["research_owner_object_key"] for topic in topics}))

    def test_branch_ownership_is_exact_once_while_dependency_context_survives(self) -> None:
        scaffold = scaffold_configuration(self.export)
        branch_paths = [
            branch["json_path"]
            for row in scaffold["rows"]
            for branch in row["required_branch_reviews"]
        ]
        self.assertTrue(branch_paths)
        self.assertTrue(
            all(count == 1 for count in collections.Counter(branch_paths).values())
        )
        value_row = next(
            row for row in scaffold["rows"] if row["object_key"] == "variable:24"
        )
        dependency_paths = {
            fact["json_path"] for fact in value_row["consumer_dependency_facts"]
        }
        self.assertTrue(dependency_paths)
        self.assertTrue(
            dependency_paths.isdisjoint(
                {fact["json_path"] for fact in value_row["required_branch_reviews"]}
            )
        )
        self.assertTrue(
            dependency_paths.issubset(set(value_row["available_evidence_anchors"]))
        )

    def test_context_uses_exported_domain_and_rejects_acronym_cmp_publisher_noise(self) -> None:
        data = sample_export()
        data["containerVersion"]["container"].update(
            {"name": "FR - Example - Web", "domainName": ["https://www.example.fr"]}
        )
        data["containerVersion"]["tag"][1]["name"] = "AW - DC - ID"
        data["containerVersion"]["tag"][1]["parameter"][0]["value"] += (
            "<!-- advertising cookieconsent documentation -->"
            "<script>window.OptanonActiveGroups = ',C0002,';</script>"
        )
        export = self.write_json("context-noise.json", data)
        context = build_context_model(export)["context"]
        self.assertEqual("https://www.example.fr", context["website_url"])
        self.assertEqual(["FR"], context["markets"])
        self.assertEqual(["OneTrust"], context["cmp"])
        self.assertNotIn("publisher", context["business_model"])

    def test_server_routes_are_extracted_only_from_route_fields(self) -> None:
        obj = {
            "name": "Tracking endpoint helper",
            "parameter": [
                {
                    "key": "endpoint",
                    "value": "https://tracking.example.test/collect",
                },
                {
                    "key": "server_container_url",
                    "value": "https://collect.example.test",
                },
                {
                    "key": "help",
                    "value": (
                        "Set transport_url if needed; see "
                        "https://docs.example.test/server-routing"
                    ),
                },
                {
                    "key": "settingsTable",
                    "map": [
                        {"key": "parameter", "value": "transport_url"},
                        {
                            "key": "parameterValue",
                            "value": "https://table-route.example.test",
                        },
                    ],
                },
            ],
        }
        self.assertEqual(
            ["collect.example.test", "table-route.example.test"],
            server_route_hosts(obj),
        )

    def test_custom_template_reviews_only_executable_sections(self) -> None:
        template = {
            "templateId": "900",
            "name": "Sectioned template",
            "templateData": (
                "___INFO___\n{\"description\":\"https://github.com/vendor/docs\"}\n"
                "___SANDBOXED_JS_FOR_WEB_TEMPLATE___\n"
                "const send = require('sendPixel');\n"
                "send('https://collect.vendor.test/' + data.id, data.gtmOnSuccess);\n"
                "___TESTS___\n[{\"name\":\"{{init: pixel.init, send: pixel.send}}\"}]\n"
            ),
        }
        lines = code_line_facts("customTemplate", template)
        previews = " ".join(line["line_preview"] for line in lines)
        self.assertIn("sendPixel", previews)
        self.assertNotIn("github.com", previews)
        self.assertNotIn("pixel.init", previews)
        self.assertEqual(set(), refs(template))
        data = sample_export()
        data["containerVersion"]["customTemplate"] = [template]
        export = self.write_json("sectioned-template.json", data)
        row = next(
            item
            for item in scaffold_configuration(export)["rows"]
            if item["object_key"] == "customTemplate:900"
        )
        self.assertNotIn(
            "Unclassified external integration (github.com)",
            {context["vendor"] for context in row["vendor_contexts"]},
        )

    def test_media_events_and_false_enhanced_ecommerce_do_not_imply_ua(self) -> None:
        media_tag = {
            "tagId": "900",
            "name": "Meta - AddToCart - All",
            "type": "cvt_123_456",
            "parameter": [
                {"key": "eventName", "value": "AddToCart"},
                {"key": "enhancedEcommerce", "value": "false"},
            ],
        }
        self.assertEqual([], ua_style_signals("tag", media_tag))

    def test_unconfirmed_naming_policy_is_one_batched_owner_decision(self) -> None:
        data = sample_export()
        for index, tag in enumerate(data["containerVersion"]["tag"], start=1):
            tag["name"] = f"ArbitraryTag{index}"
        export = self.write_json("unconfirmed-naming.json", data)
        scan = audit_export(export)
        naming = [
            row
            for row in scan["findings"]
            if row["module_name"] == "naming_architecture_standardization"
            and row["finding_type"] != "zero_findings"
        ]
        self.assertEqual(1, len(naming))
        self.assertEqual("naming_policy_confirmation_required", naming[0]["finding_type"])

    def test_exact_duplicate_cannot_be_silently_kept(self) -> None:
        architecture = complete_architecture(self.export)
        duplicate = next(
            row
            for row in architecture["comparisons"]
            if "exact_configuration" in row.get("comparison_types", [])
        )
        duplicate.update(
            {
                "relationship_verdict": "Intentional variant",
                "disposition": "keep",
                "owner_question": "",
            }
        )
        errors, _ = validate_architecture(
            self.export, self.write_json("silent-duplicate.json", architecture)
        )
        self.assertTrue(any("identical source configuration" in error for error in errors))

    def test_mutation_conflicts_cover_rename_overlap_and_allow_distinct_appends(self) -> None:
        rename = {
            "operation_key": "rename",
            "creations": [],
            "additions": [],
            "changes": [],
            "remaps": [],
            "renames": [{"object_key": "tag:1", "before": "A", "after": "B"}],
            "deletions": [],
        }
        name_change = {
            "operation_key": "change",
            "creations": [],
            "additions": [],
            "changes": [
                {"object_key": "tag:1", "json_path": "$.name", "before": "A", "after": "C"}
            ],
            "remaps": [],
            "renames": [],
            "deletions": [],
        }
        self.assertTrue(validate_mutation_conflicts([rename, name_change]))

        first = copy.deepcopy(rename)
        first.update(
            {
                "operation_key": "append-a",
                "renames": [],
                "additions": [
                    {
                        "object_key": "tag:1",
                        "json_path": "$.parameter",
                        "mode": "append",
                        "value": {"key": "a"},
                    }
                ],
            }
        )
        second = copy.deepcopy(first)
        second["operation_key"] = "append-b"
        second["additions"][0]["value"] = {"key": "b"}
        self.assertEqual([], validate_mutation_conflicts([first, second]))

        parent = copy.deepcopy(name_change)
        parent["operation_key"] = "parent-write"
        parent["changes"][0]["json_path"] = "$.parameter"
        child = copy.deepcopy(parent)
        child["operation_key"] = "child-write"
        child["changes"][0]["json_path"] = "$.parameter[0].value"
        self.assertTrue(validate_mutation_conflicts([parent, child]))

        duplicate_rename = copy.deepcopy(rename)
        duplicate_rename["operation_key"] = "rename-again"
        self.assertTrue(validate_mutation_conflicts([rename, duplicate_rename]))

        remap = copy.deepcopy(rename)
        remap.update(
            {
                "operation_key": "remap-a",
                "renames": [],
                "remaps": [
                    {
                        "from_object_key": "trigger:10",
                        "to_object_key": "trigger:11",
                        "consumer_object_keys": ["tag:1"],
                    }
                ],
            }
        )
        remap_again = copy.deepcopy(remap)
        remap_again["operation_key"] = "remap-b"
        self.assertTrue(validate_mutation_conflicts([remap, remap_again]))

    def test_keep_or_unresolved_architecture_blocks_single_destructive_mutation(self) -> None:
        architecture = {
            "comparisons": [
                {
                    "comparison_id": "REL-KEEP",
                    "candidate_object_keys": ["tag:1", "tag:2"],
                    "relationship_verdict": "Intentional variant",
                    "disposition": "keep",
                }
            ],
            "families": [],
        }
        operation = {
            "operation_key": "delete-one",
            "source_references": [],
            "source_runs": ["configuration_correctness"],
            "creations": [],
            "additions": [],
            "changes": [],
            "remaps": [],
            "renames": [],
            "deletions": [{"object_key": "tag:1"}],
        }
        errors = validate_cross_run_reconciliation(
            {"findings": []}, architecture, [operation]
        )
        self.assertTrue(any("says to keep" in error for error in errors))

    def test_source_bound_non_destructive_repair_uses_completed_family_coverage(self) -> None:
        operation = {
            "operation_key": "repair-tag-endpoint",
            "source_references": ["tag:1"],
            "source_runs": ["configuration_correctness"],
            "creations": [],
            "additions": [],
            "changes": [
                {
                    "object_key": "tag:1",
                    "json_path": "$.containerVersion.tag[0].parameter[0].value",
                    "before": "http://collector.example.test",
                    "after": "https://collector.example.test",
                }
            ],
            "remaps": [],
            "renames": [],
            "deletions": [],
        }
        architecture = {
            "comparisons": [],
            "families": [
                {
                    "family_id": "FAM-ENDPOINT",
                    "review_status": "complete",
                    "member_object_keys": ["tag:1"],
                    "chain_object_keys": ["tag:1", "trigger:10"],
                    "relationship_verdict": "Complementary",
                    "disposition": "keep",
                }
            ],
        }
        self.assertEqual(
            [], validate_cross_run_reconciliation({"findings": []}, architecture, [operation])
        )
        self.assertEqual(["FAM-ENDPOINT"], operation["architecture_supporting_family_ids"])

    def test_source_bound_operational_repair_uses_completed_family_coverage(self) -> None:
        operation = {
            "operation_key": "remove-ineffective-blocker",
            "source_references": ["BASE-INEFFECTIVE_BLOCKING_TRIGGER-001"],
            "source_runs": ["operational_sanitation"],
            "creations": [],
            "additions": [],
            "changes": [
                {
                    "object_key": "tag:1",
                    "json_path": "$.containerVersion.tag[0].blockingTriggerId",
                    "before": ["10"],
                    "after": [],
                }
            ],
            "remaps": [],
            "renames": [],
            "deletions": [],
        }
        operational = {
            "findings": [
                {
                    "finding_id": "BASE-INEFFECTIVE_BLOCKING_TRIGGER-001",
                    "finding_class": "deterministic_defect",
                    "disposition": "cleanup_operation",
                }
            ]
        }
        architecture = {
            "comparisons": [],
            "families": [
                {
                    "family_id": "FAM-BLOCKER",
                    "review_status": "complete",
                    "member_object_keys": ["tag:1"],
                    "chain_object_keys": ["tag:1", "trigger:10"],
                    "relationship_verdict": "Complementary",
                    "disposition": "keep",
                }
            ],
        }
        self.assertEqual([], validate_cross_run_reconciliation(operational, architecture, [operation]))
        self.assertEqual(["FAM-BLOCKER"], operation["architecture_supporting_family_ids"])

    def test_paused_tag_retirement_is_outside_active_behavior_alignment(self) -> None:
        operation = {
            "operation_key": "retire-paused-tag",
            "source_references": ["CFG-00001"],
            "source_runs": ["configuration_correctness"],
            "creations": [],
            "additions": [],
            "changes": [],
            "remaps": [],
            "renames": [],
            "deletions": [{"object_key": "tag:9", "reason": "Paused legacy tag."}],
        }
        operational = {
            "findings": [
                {
                    "finding_id": "BASE-PAUSED_TAGS-001",
                    "finding_type": "paused_objects_for_lifecycle_review",
                    "object_type": "tag",
                    "object_ids": ["9"],
                }
            ]
        }
        self.assertEqual(
            [],
            validate_cross_run_reconciliation(
                operational, {"comparisons": [], "families": []}, [operation]
            ),
        )

    def test_lifecycle_retention_and_folder_taxonomy_are_business_decisions(self) -> None:
        from gtm_baseline_audit import operational_finding_class

        for finding_type in (
            "used_only_by_paused_tags",
            "unfiled_objects",
            "overloaded_folder",
        ):
            self.assertEqual("business_decision", operational_finding_class(finding_type))

    def test_projected_benign_candidate_requires_source_reviewed_deletion_subset(self) -> None:
        from gtm_future_state_check import (
            retained_architecture_comparisons,
            retention_coverage_decision,
        )

        keys = ["trigger:1", "trigger:2", "trigger:3"]
        source_keys = [*keys, "trigger:4"]
        operations = {
            "decision_ledger": [
                {
                    "decision_id": "REL-RETAINED",
                    "source_run": "business_architecture",
                    "comparison_types": ["shared_business_scope"],
                    "disposition": "keep",
                    "verdict": "Intentional variant",
                    # The compiled ledger retains only surviving members.
                    "source_object_keys": keys,
                }
            ]
        }
        source_architecture = {
            "comparisons": [
                {
                    "comparison_id": "REL-RETAINED",
                    "candidate_object_keys": source_keys,
                    "comparison_types": ["shared_business_scope"],
                }
            ]
        }
        retained = retained_architecture_comparisons(operations, source_architecture)
        candidate = {
            "candidate_object_keys": keys,
            "comparison_types": ["shared_business_scope"],
        }
        self.assertEqual(
            "REL-RETAINED",
            retention_coverage_decision(candidate, retained, {"trigger:4"}, set()),
        )
        self.assertEqual(
            "",
            retention_coverage_decision(candidate, retained, set(), set()),
        )
        self.assertEqual(
            "",
            retention_coverage_decision(
                {**candidate, "comparison_types": ["same_payload_different_route"]},
                retained,
                {"trigger:4"},
                set(),
            ),
        )

    def test_exact_architecture_cleanup_resolves_weaker_candidate_rows(self) -> None:
        operation = {
            "operation_key": "remove-duplicate-trigger",
            "source_references": ["REL-EXACT:operation:1"],
            "source_runs": ["business_architecture"],
            "creations": [],
            "additions": [],
            "changes": [],
            "remaps": [],
            "renames": [],
            "deletions": [{"object_key": "trigger:10", "reason": "Exact duplicate."}],
        }
        architecture = {
            "comparisons": [
                {
                    "comparison_id": "REL-EXACT",
                    "candidate_object_keys": ["trigger:10", "trigger:11"],
                    "relationship_verdict": "Exact duplicate",
                    "disposition": "cleanup_operation",
                    "operations": [copy.deepcopy(operation)],
                },
                {
                    "comparison_id": "REL-WEAKER",
                    "candidate_object_keys": ["trigger:10", "trigger:12"],
                    "relationship_verdict": "Owner decision",
                    "disposition": "owner_decision_needed",
                },
            ],
            "families": [],
        }
        self.assertEqual(
            [], validate_cross_run_reconciliation({"findings": []}, architecture, [operation])
        )

    def test_reconciliation_ignores_deletion_explanations_not_mutations(self) -> None:
        from gtm_operation_compile import merge_compatible_operations, normalized_operation

        first = normalized_operation(
            {
                "operation_key": "remove-orphan-a",
                "area": "GTM hygiene",
                "problem_type": "Unused object",
                "canonical_object_key": "",
                "deletions": [{"object_key": "variable:20", "reason": "Unused."}],
            },
            "operational_sanitation",
            "BASE-UNUSED_VARIABLES-001",
            ["variable:20"],
        )
        second = normalized_operation(
            {
                "operation_key": "remove-orphan-b",
                "area": "GTM hygiene",
                "problem_type": "Unused object",
                "canonical_object_key": "variable:21",
                "deletions": [
                    {
                        "object_key": "variable:20",
                        "reason": "Delete the unused duplicate path.",
                    }
                ],
            },
            "business_architecture",
            "REL-ORPHAN:operation:1",
            ["variable:20", "variable:21"],
        )
        errors: list[str] = []
        merged = merge_compatible_operations([first, second], errors)
        self.assertEqual([], errors)
        self.assertEqual(1, len(merged))
        self.assertEqual(
            ["business_architecture", "operational_sanitation"], merged[0]["source_runs"]
        )

    def test_architecture_keep_blocks_behavior_change_but_not_metadata_maintenance(self) -> None:
        architecture = {
            "comparisons": [],
            "families": [
                {
                    "family_id": "FAM-KEEP",
                    "chain_object_keys": ["tag:1", "trigger:10"],
                    "relationship_verdict": "Intentional variant",
                    "disposition": "keep",
                }
            ],
        }
        operation = {
            "operation_key": "change-event",
            "source_references": [],
            "source_runs": ["configuration_correctness"],
            "creations": [],
            "additions": [],
            "changes": [
                {
                    "object_key": "tag:1",
                    "json_path": "$.containerVersion.tag[0].parameter[0].value",
                    "before": "purchase",
                    "after": "generate_lead",
                }
            ],
            "remaps": [],
            "renames": [],
            "deletions": [],
        }
        errors = validate_cross_run_reconciliation(
            {"findings": []}, architecture, [operation]
        )
        self.assertTrue(any("changes behavior" in error for error in errors))

        uncovered_errors = validate_cross_run_reconciliation(
            {"findings": []}, {"comparisons": [], "families": []}, [operation]
        )
        self.assertTrue(
            any("without an aligned business-architecture" in error for error in uncovered_errors)
        )

        aligned = copy.deepcopy(operation)
        aligned["source_runs"].append("business_architecture")
        self.assertEqual(
            [],
            validate_cross_run_reconciliation(
                {"findings": []}, {"comparisons": [], "families": []}, [aligned]
            ),
        )

        metadata = copy.deepcopy(operation)
        metadata["operation_key"] = "update-notes"
        metadata["changes"][0].update(
            {
                "json_path": "$.containerVersion.tag[0].notes",
                "before": "old owner note",
                "after": "current owner note",
            }
        )
        metadata_errors = validate_cross_run_reconciliation(
            {"findings": []}, architecture, [metadata]
        )
        self.assertEqual([], metadata_errors)

        creation = copy.deepcopy(operation)
        creation["operation_key"] = "create-helper"
        creation["changes"] = []
        creation["creations"] = [
            {
                "layer": "variable",
                "object": {"variableId": "999", "name": "Constant - EUR", "type": "c"},
            }
        ]
        creation_errors = validate_cross_run_reconciliation(
            {"findings": []}, architecture, [creation]
        )
        self.assertTrue(any("without an aligned" in error for error in creation_errors))

    def test_future_state_does_not_hide_a_worsened_numeric_finding(self) -> None:
        before = {
            "module_name": "trigger_condition_lint",
            "finding_type": "excessive_conditions",
            "object_type": "trigger",
            "object_ids": ["10"],
            "deterministic_evidence": "Trigger has 5 conditions.",
        }
        after = {**before, "deterministic_evidence": "Trigger has 10 conditions."}
        improved = {**before, "deterministic_evidence": "Trigger has 3 conditions."}
        self.assertFalse(prior_finding_covers(before, after))
        self.assertTrue(prior_finding_covers(before, improved))

    def test_context_questions_are_visible_owner_decisions(self) -> None:
        operational = complete_operational(self.export)
        configuration = complete_configuration(self.export)
        architecture = complete_architecture(self.export)
        ledger = decision_ledger(operational, configuration, architecture)
        context_rows = [row for row in ledger if row["source_run"] == "audit_context"]
        self.assertEqual(
            len(operational["unresolved_context_questions"]), len(context_rows)
        )
        self.assertTrue(all(row["disposition"] == "owner_decision_needed" for row in context_rows))

    def test_large_code_object_keeps_exact_coverage_without_micro_shards(self) -> None:
        data = sample_export()
        body = "function() {\n" + "\n".join(
            f"var value{i} = {i};" for i in range(75)
        ) + "\nreturn value74;\n}"
        data["containerVersion"]["variable"].append(
            {
                "variableId": "999",
                "name": "CJS - Large deterministic fixture",
                "type": "jsm",
                "parameter": [{"key": "javascript", "type": "TEMPLATE", "value": body}],
            }
        )
        export = self.write_json("large-code.json", data)
        review = scaffold_configuration(export)
        review_path = self.write_json("large-review.json", review)
        shard_dir = self.root / "shards"
        manifest = split_review(
            review_path,
            shard_dir,
            max_items=20,
            max_obligations=10,
        )
        self.assertEqual([], manifest["obligation_shards"])
        overlay = next(
            row
            for shard in manifest["shards"]
            for row in json.loads(
                (shard_dir / shard["filename"]).read_text(encoding="utf-8")
            )["items"]
            if row["object_key"] == "variable:999"
        )
        large_row = next(
            row for row in review["rows"] if row["object_key"] == "variable:999"
        )
        self.assertNotIn("required_code_line_hashes", overlay)
        self.assertNotIn("behavior_review_groups", overlay)
        self.assertTrue(overlay["source_row_sha256"])
        expected_hashes = set(large_row["required_code_line_hashes"])
        grouped_hashes = [
            value
            for group in large_row["behavior_review_groups"]
            for value in group["code_line_hashes"]
        ]
        self.assertGreaterEqual(len(expected_hashes), 75)
        self.assertEqual(expected_hashes, set(grouped_hashes))
        self.assertEqual(len(grouped_hashes), len(set(grouped_hashes)))
        self.assertLessEqual(
            large_row["configuration_coverage_metrics"]["authored_work_units"],
            10,
        )

    def test_completed_shards_fail_early_on_pending_or_missing_obligations(self) -> None:
        completed = complete_configuration(self.export)
        # Schema-3 packages retain the legacy micro-shard reader so an older,
        # already-started audit remains resumable after this release.
        completed["schema_version"] = 3
        review_path = self.write_json("completed-configuration.json", completed)
        shard_dir = self.root / "checked-shards"
        manifest = split_review(review_path, shard_dir, max_items=3, max_obligations=10)

        primary_name = manifest["shards"][0]["filename"]
        primary_report = check_shard(review_path, shard_dir, primary_name)
        self.assertEqual("pass", primary_report["status"])

        obligation_manifest = next(
            row
            for row in manifest["obligation_shards"]
            if row["source_field"] != "code_line_facts" and len(row["source_ids"]) > 1
        )
        obligation_name = obligation_manifest["filename"]
        obligation_report = check_shard(review_path, shard_dir, obligation_name)
        self.assertEqual("pass", obligation_report["status"])

        obligation_path = shard_dir / obligation_name
        obligation = json.loads(obligation_path.read_text(encoding="utf-8"))
        obligation["completed_items"].reverse()
        obligation_path.write_text(json.dumps(obligation), encoding="utf-8")
        reordered_report = check_shard(review_path, shard_dir, obligation_name)
        self.assertEqual("pass", reordered_report["status"])
        obligation["completed_items"] = obligation["completed_items"][:-1]
        obligation_path.write_text(json.dumps(obligation), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "cover every source obligation"):
            check_shard(review_path, shard_dir, obligation_name)

        code_name = next(
            row["filename"]
            for row in manifest["obligation_shards"]
            if row["source_field"] == "code_line_facts"
        )
        code_report = check_shard(review_path, shard_dir, code_name)
        self.assertEqual("pass", code_report["status"])
        code_path = shard_dir / code_name
        code = json.loads(code_path.read_text(encoding="utf-8"))
        code["completed_items"][0]["line_hashes"] = code["completed_items"][0][
            "line_hashes"
        ][:-1]
        code_path.write_text(json.dumps(code), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "every source line"):
            check_shard(review_path, shard_dir, code_name)

        primary_path = shard_dir / primary_name
        primary = json.loads(primary_path.read_text(encoding="utf-8"))
        primary["items"][0]["review_status"] = "pending"
        primary_path.write_text(json.dumps(primary), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "pending items"):
            check_shard(review_path, shard_dir, primary_name)
        with self.assertRaises(ValueError) as merge_error:
            merge_review(
                review_path,
                shard_dir,
                self.root / "should-not-merge.json",
            )
        self.assertIn(primary_name, str(merge_error.exception))
        self.assertIn(
            "repair only this declared shard, rerun check, then resume merge",
            str(merge_error.exception),
        )

    def test_shard_manifest_cannot_escape_its_directory(self) -> None:
        review = complete_operational(self.export)
        review_path = self.write_json("safe-review.json", review)
        shard_dir = self.root / "safe-shards"
        split_review(review_path, shard_dir, max_items=10)
        manifest_path = shard_dir / "shard_manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["shards"][0]["filename"] = "../outside.json"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "unsafe shard filename"):
            merge_review(review_path, shard_dir, self.root / "merged.json")


if __name__ == "__main__":
    unittest.main()
