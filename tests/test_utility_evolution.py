from __future__ import annotations

import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

from gtm_configuration_review import (  # noqa: E402
    required_contract_topics,
)
from gtm_configuration_review import (  # noqa: E402
    scaffold_review as scaffold_configuration,
)
from gtm_context_model import build_context_model  # noqa: E402
from gtm_custom_code_extract import extract_export  # noqa: E402
from gtm_execution_guard import execution_preflight  # noqa: E402
from gtm_future_state_check import configured_activation_risk  # noqa: E402
from gtm_operation_compile import packetize_operations  # noqa: E402
from gtm_relationships import (  # noqa: E402
    near_event_name,
    relationship_candidates,
)
from gtm_skill_identity import (  # noqa: E402
    declared_identity_errors,
    verify_identity,
    write_manifest,
)
from gtm_vendor_registry import load_registry  # noqa: E402


def condition(operator: str, left: str, right: str) -> dict:
    return {
        "type": operator,
        "parameter": [
            {"type": "TEMPLATE", "key": "arg0", "value": left},
            {"type": "TEMPLATE", "key": "arg1", "value": right},
        ],
    }


def minimal_export() -> dict:
    return {
        "exportFormatVersion": 2,
        "containerVersion": {
            "accountId": "1",
            "containerId": "2",
            "containerVersionId": "3",
            "container": {"publicId": "GTM-UTILITY", "usageContext": ["WEB"]},
            "tag": [],
            "trigger": [],
            "variable": [],
        },
    }


class UtilityEvolutionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_export(self, data: dict, name: str = "container.json") -> Path:
        path = self.root / name
        path.write_text(json.dumps(data), encoding="utf-8")
        return path

    def test_runtime_identity_detects_installed_tree_drift(self) -> None:
        expected = self.root / "expected"
        actual = self.root / "actual"
        for target in (expected, actual):
            (target / "scripts").mkdir(parents=True)
            (target / "SKILL.md").write_text("# Skill\n", encoding="utf-8")
            (target / "pyproject.toml").write_text(
                '[project]\nname="x"\nversion="1.0.0"\n',
                encoding="utf-8",
            )
            (target / "scripts" / "run.py").write_text("VALUE = 1\n", encoding="utf-8")
            write_manifest(target)

        report, errors = verify_identity(expected, actual)
        self.assertEqual([], errors)
        self.assertEqual("pass", report["status"])

        (actual / "scripts" / "run.py").write_text("VALUE = 2\n", encoding="utf-8")
        report, errors = verify_identity(expected, actual)
        self.assertEqual("fail", report["status"])
        self.assertTrue(any("runtime files differ" in value for value in errors))
        self.assertTrue(any("manifest" in value for value in errors))

    def test_clean_git_checkout_is_an_exact_manifest_free_identity(self) -> None:
        checkout = self.root / "checkout"
        (checkout / "scripts").mkdir(parents=True)
        (checkout / "SKILL.md").write_text("# Skill\n", encoding="utf-8")
        (checkout / "pyproject.toml").write_text(
            '[project]\nname="x"\nversion="1.0.0"\n',
            encoding="utf-8",
        )
        runtime_script = checkout / "scripts" / "run.py"
        runtime_script.write_text("VALUE = 1\n", encoding="utf-8")
        subprocess.run(["git", "init", "-q"], cwd=checkout, check=True)
        subprocess.run(["git", "add", "."], cwd=checkout, check=True)
        subprocess.run(
            [
                "git",
                "-c",
                "user.name=Identity Test",
                "-c",
                "user.email=identity-test.invalid",
                "commit",
                "-q",
                "-m",
                "identity fixture",
            ],
            cwd=checkout,
            check=True,
        )

        report, errors = declared_identity_errors(checkout)
        self.assertEqual([], errors)
        self.assertEqual("clean_git_checkout", report["identity_basis"])

        runtime_script.write_text("VALUE = 2\n", encoding="utf-8")
        report, errors = declared_identity_errors(checkout)
        self.assertEqual("fail", report["status"])
        self.assertTrue(any("source checkout is dirty" in error for error in errors))

    def test_extended_intake_is_source_locked_and_execution_ready(self) -> None:
        export = self.write_export(minimal_export())
        provided = self.root / "provided.json"
        provided.write_text(
            json.dumps(
                {
                    "spa": "yes",
                    "canonical_ids": ["G-PRIMARY"],
                    "staging_hosts": ["staging.example.test"],
                    "do_not_touch": ["tag:17"],
                    "naming_policy": "Vendor - Event - Scope",
                }
            ),
            encoding="utf-8",
        )
        context = build_context_model(export, provided)
        self.assertEqual("yes", context["context"]["spa"])
        self.assertEqual(["tag:17"], context["context"]["do_not_touch"])
        self.assertEqual(
            "provided",
            context["context_evidence"]["naming_policy"]["status"],
        )

    def test_custom_code_detectors_have_legitimate_neighbors(self) -> None:
        data = minimal_export()
        data["containerVersion"]["tag"] = [
            {
                "tagId": "1",
                "name": "Risk code",
                "type": "html",
                "parameter": [
                    {
                        "type": "TEMPLATE",
                        "key": "html",
                        "value": (
                            "document.write('<div>legacy</div>');"
                            "window.dataLayer.hide={start:1};"
                            "var client_secret='not-a-real-secret-but-long';"
                            "new MutationObserver(function(){});"
                            "var encoded=btoa('public');"
                            "var cb=Date.now();"
                        ),
                    }
                ],
            },
            {
                "tagId": "2",
                "name": "Legitimate HTML neighbor",
                "type": "html",
                "parameter": [
                    {
                        "type": "TEMPLATE",
                        "key": "html",
                        "value": "<div data-component='banner'>Static markup</div>",
                    }
                ],
            },
        ]
        data["containerVersion"]["variable"] = [
            {
                "variableId": "3",
                "name": "Async CMP variable",
                "type": "jsm",
                "parameter": [
                    {
                        "type": "TEMPLATE",
                        "key": "javascript",
                        "value": (
                            "function(){var result;__tcfapi('getTCData',2,"
                            "function(tc){result=tc;});return result;}"
                        ),
                    }
                ],
            }
        ]
        rows = extract_export(self.write_export(data))["rows"]
        risk = next(row for row in rows if row["object_id"] == "1")
        neighbor = next(row for row in rows if row["object_id"] == "2")
        cmp_variable = next(row for row in rows if row["object_id"] == "3")
        self.assertTrue(risk["document_write_calls"])
        self.assertTrue(risk["javascript_without_script_wrapper"])
        self.assertTrue(risk["optimize_or_antiflicker_signals"])
        self.assertIn("literal_client_secret", risk["secret_like_credential_signals"])
        self.assertTrue(risk["mutation_observer_signals"])
        self.assertTrue(risk["base64_signals"])
        self.assertTrue(risk["cache_buster_signals"])
        self.assertTrue(cmp_variable["async_cmp_callback_candidate"])
        self.assertFalse(neighbor["javascript_without_script_wrapper"])
        self.assertFalse(neighbor["document_write_calls"])

    def test_configuration_locks_document_write_consent_init_and_secrets(self) -> None:
        data = minimal_export()
        data["containerVersion"]["tag"] = [
            {
                "tagId": "1",
                "name": "Legacy writer",
                "type": "html",
                "parameter": [
                    {
                        "type": "TEMPLATE",
                        "key": "html",
                        "value": "<script>document.write('<p>x</p>');</script>",
                    }
                ],
            },
            {
                "tagId": "2",
                "name": "Ordinary analytics bootstrap",
                "type": "html",
                "parameter": [
                    {
                        "type": "TEMPLATE",
                        "key": "html",
                        "value": "<script>window.analyticsReady=true;</script>",
                    }
                ],
                "firingTriggerId": ["2147479593"],
            },
            {
                "tagId": "3",
                "name": "Embedded credential",
                "type": "html",
                "parameter": [
                    {
                        "type": "TEMPLATE",
                        "key": "html",
                        "value": "<script>void(0);</script>",
                    },
                    {
                        "type": "TEMPLATE",
                        "key": "client_secret",
                        "value": "redacted-long-secret-value",
                    },
                ],
            },
        ]
        data["containerVersion"]["variable"] = [
            {
                "variableId": "4",
                "name": "Constant - Client Secret",
                "type": "c",
                "parameter": [
                    {
                        "type": "TEMPLATE",
                        "key": "value",
                        "value": "redacted-secret-in-a-constant",
                    }
                ],
            },
            {
                "variableId": "5",
                "name": "Constant - Public API Key",
                "type": "c",
                "parameter": [
                    {
                        "type": "TEMPLATE",
                        "key": "value",
                        "value": "browser-public-key-candidate",
                    }
                ],
            },
        ]
        export = self.write_export(data)
        review = scaffold_configuration(export)
        obligations = {
            row["object_key"]: {
                item["obligation_key"]
                for item in row["required_configuration_obligations"]
            }
            for row in review["rows"]
        }
        secret_constant_row = next(
            row for row in review["rows"] if row["object_key"] == "variable:4"
        )
        secret_previews = json.dumps(
            [
                fact.get("value_preview")
                for fact in secret_constant_row["source_facts"]
            ]
        )
        self.assertNotIn("redacted-secret-in-a-constant", secret_previews)
        self.assertIn("redacted secret-like container value", secret_previews)
        self.assertIn("document_write_support_missing", obligations["tag:1"])
        self.assertIn("consent_initialization_non_consent_tag", obligations["tag:2"])
        self.assertTrue(
            any(key.startswith("embedded_secret:") for key in obligations["tag:3"])
        )
        self.assertTrue(
            any(
                key.startswith("embedded_secret:")
                for key in obligations["variable:4"]
            )
        )
        self.assertTrue(
            any(
                key.startswith("embedded_public_key_candidate:")
                for key in obligations["variable:5"]
            )
        )

    def test_relationships_find_only_reviewable_push_and_spa_risks(self) -> None:
        self.assertEqual((False, 1.0), near_event_name("purchase", "purchase"))
        self.assertEqual((True, 0.99), near_event_name("Purchase", "purchase"))
        data = minimal_export()
        data["containerVersion"]["tag"] = [
            {
                "tagId": "1",
                "name": "Push checkout event",
                "type": "html",
                "parameter": [
                    {
                        "type": "TEMPLATE",
                        "key": "html",
                        "value": "<script>dataLayer.push({event:'checkout_start'});</script>",
                    }
                ],
            },
            {
                "tagId": "2",
                "name": "GA4 virtual page view",
                "type": "gaawe",
                "parameter": [
                    {"type": "TEMPLATE", "key": "eventName", "value": "page_view"},
                    {"type": "TEMPLATE", "key": "measurementId", "value": "G-TEST"},
                ],
                "firingTriggerId": ["11"],
            },
            {
                "tagId": "3",
                "name": "Google tag",
                "type": "googtag",
                "parameter": [
                    {"type": "TEMPLATE", "key": "tagId", "value": "G-TEST"}
                ],
                "firingTriggerId": ["2147479553"],
            },
        ]
        data["containerVersion"]["trigger"] = [
            {
                "triggerId": "10",
                "name": "Checkout listener typo",
                "type": "CUSTOM_EVENT",
                "customEventFilter": [
                    condition("EQUALS", "{{_event}}", "chekout_start")
                ],
            },
            {
                "triggerId": "11",
                "name": "History",
                "type": "HISTORY_CHANGE",
            },
        ]
        rows = relationship_candidates(data["containerVersion"])
        types = {
            value
            for row in rows
            for value in row.get("comparison_types", [])
        }
        self.assertIn("data_layer_push_listener_near_miss", types)
        self.assertIn("spa_history_send_page_view_review", types)
        self.assertTrue(
            all(
                row["comparison_origin"] == "deterministic"
                and any(
                    term in " ".join(row["candidate_basis"]).lower()
                    for term in ("confirm", "before changing")
                )
                for row in rows
                if {
                    "data_layer_push_listener_near_miss",
                    "spa_history_send_page_view_review",
                }
                & set(row.get("comparison_types", []))
            )
        )

    def test_meta_and_google_contract_gaps_are_precise_not_blanket_defects(self) -> None:
        registry = load_registry()
        meta = next(item for item in registry["vendors"] if item["name"] == "Meta")
        meta_context = {
            **meta,
            "vendor": "Meta",
            "detection_evidence": ["fbq call"],
        }
        missing = {
            "tagId": "1",
            "type": "html",
            "parameter": [
                {
                    "type": "TEMPLATE",
                    "key": "html",
                    "value": "<script>fbq('track','Purchase',{content_ids:['1']});</script>",
                }
            ],
        }
        complete = copy.deepcopy(missing)
        complete["parameter"][0]["value"] = (
            "<script>fbq('track','Purchase',{value:12.5,currency:'EUR'});</script>"
        )
        cv = {"tag": [missing, complete]}
        missing_topic = next(
            topic
            for topic in required_contract_topics(
                cv, "tag", missing, [meta_context], {}
            )
            if topic["topic"] == "registry_contract_purchase"
        )
        complete_topic = next(
            topic
            for topic in required_contract_topics(
                cv, "tag", complete, [meta_context], {}
            )
            if topic["topic"] == "registry_contract_purchase"
        )
        self.assertEqual("known_noncompliant", missing_topic["deterministic_contract_state"])
        self.assertEqual("source_check_required", complete_topic["deterministic_contract_state"])

        google_ads = next(
            item for item in registry["vendors"] if item["name"] == "Google Ads"
        )
        ads_context = {
            **google_ads,
            "vendor": "Google Ads",
            "detection_evidence": ["AW destination"],
        }
        ads = {
            "tagId": "4",
            "type": "awct",
            "parameter": [
                {"type": "TEMPLATE", "key": "conversionId", "value": "AW-123"},
                {"type": "BOOLEAN", "key": "url_passthrough", "value": "true"},
                {
                    "type": "TEMPLATE",
                    "key": "transport_url",
                    "value": "https://example-tagging.run.app",
                },
            ],
        }
        topics = {
            topic["topic"]: topic
            for topic in required_contract_topics(
                {"tag": [ads]},
                "tag",
                ads,
                [ads_context],
                {"server_routing_hosts": ["example-tagging.run.app"]},
            )
        }
        self.assertIn("url_passthrough_and_ads_data_redaction", topics)
        self.assertIn("conversion_linking_coverage", topics)
        self.assertIn("first_party_server_domain_review", topics)
        self.assertEqual(
            "source_check_required",
            topics["first_party_server_domain_review"][
                "deterministic_contract_state"
            ],
        )

    def test_operation_safety_and_execution_guard_are_risk_specific(self) -> None:
        catalog = {
            "tag:1": {
                "layer": "tag",
                "object_name": "Server conversion",
                "config_hash": "abc",
                "reachability": "active",
                "server_route_hosts": ["collect.example.test"],
            }
        }
        operation = {
            "operation_key": "delete-server-tag",
            "title": "Retire duplicate route",
            "area": "GTM hygiene",
            "problem_type": "Exact duplicate",
            "problem": "The active route is duplicated.",
            "why_it_matters": "It can duplicate delivery.",
            "expected_clean_state": "One route remains.",
            "exact_proposed_action": "Quarantine and then delete tag:1.",
            "preconditions": "Confirm the surviving route.",
            "qa_steps": "Read back and test the route.",
            "rollback": "Restore the source export.",
            "priority": "High",
            "confidence": "High",
            "execution_readiness": "approval_required",
            "source_runs": ["business_architecture"],
            "source_references": ["ARCH-1"],
            "source_object_keys": ["tag:1"],
            "affected_object_keys": ["tag:1"],
            "deletions": [{"object_key": "tag:1", "reason": "duplicate"}],
        }
        packet = packetize_operations([operation], "Direct", catalog)[0]
        safety = packet["execution_safety"]
        self.assertTrue(safety["server_coupled"])
        self.assertFalse(safety["configured_activation_risk"]["flag"])
        self.assertEqual("individual_operation", safety["approval"]["scope"])
        self.assertTrue(safety["decommission"]["required"])

        activation_operation = {
            **operation,
            "operation_key": "change-firing-scope",
            "deletions": [],
            "changes": [
                {
                    "object_key": "tag:1",
                    "json_path": "$.containerVersion.tag[0].firingTriggerId",
                    "before": ["10"],
                    "after": ["11"],
                }
            ],
        }
        activation_packet = packetize_operations(
            [activation_operation],
            "Direct",
            catalog,
        )[0]
        self.assertTrue(
            activation_packet["execution_safety"]["configured_activation_risk"]["flag"]
        )

        low_packet = packetize_operations(
            [
                {
                    **operation,
                    "operation_key": "delete-inactive-variable",
                    "priority": "Low",
                    "title": "Delete unused variable",
                    "problem_type": "Unused object",
                    "problem": "The variable is inactive, unused, and unreferenced.",
                    "why_it_matters": "It adds maintenance clutter.",
                    "exact_proposed_action": "Delete variable:9.",
                    "source_object_keys": ["variable:9"],
                    "affected_object_keys": ["variable:9"],
                    "deletions": [
                        {"object_key": "variable:9", "reason": "unused"}
                    ],
                }
            ],
            "Direct",
            {
                "variable:9": {
                    "layer": "variable",
                    "object_name": "Unused",
                    "config_hash": "def",
                    "reachability": "inactive_or_unreferenced",
                    "server_route_hosts": [],
                }
            },
        )[0]
        self.assertEqual(
            "bulk_eligible_exact_low_risk_bundle",
            low_packet["execution_safety"]["approval"]["scope"],
        )
        self.assertFalse(low_packet["execution_safety"]["decommission"]["required"])

        operations = {
            "source_sha256": "source",
            "operations": [packet],
        }
        future = {
            "source_sha256": "source",
            "status": "pass",
            "configured_activation_risk": {
                "flag": True,
                "candidate_operation_ids": [packet["operation_id"]],
            },
        }
        blocked = execution_preflight(
            operations,
            {
                "context": {"do_not_touch": ["tag:1"]},
                "context_evidence": {"do_not_touch": {"status": "provided"}},
            },
            future,
            {packet["operation_id"]},
            {packet["operation_id"]},
            {packet["operation_id"]},
            {packet["operation_id"]},
        )
        self.assertEqual("fail", blocked["status"])
        self.assertTrue(any("do_not_touch" in value for value in blocked["errors"]))

        unresolved = execution_preflight(
            operations,
            {
                "context": {"do_not_touch": []},
                "context_evidence": {"do_not_touch": {"status": "unresolved"}},
            },
            future,
            {packet["operation_id"]},
            {packet["operation_id"]},
            {packet["operation_id"]},
            {packet["operation_id"]},
        )
        self.assertEqual("fail", unresolved["status"])
        self.assertTrue(
            any("explicitly confirmed" in value for value in unresolved["errors"])
        )

        allowed = execution_preflight(
            operations,
            {
                "context": {"do_not_touch": []},
                "context_evidence": {"do_not_touch": {"status": "provided"}},
            },
            future,
            {packet["operation_id"]},
            {packet["operation_id"]},
            {packet["operation_id"]},
            {packet["operation_id"]},
        )
        self.assertEqual("pass", allowed["status"])

    def test_future_state_reports_static_new_reachability_only(self) -> None:
        before = {
            "tag": [
                {
                    "tagId": "1",
                    "name": "Paused event",
                    "type": "html",
                    "paused": True,
                    "parameter": [
                        {
                            "type": "TEMPLATE",
                            "key": "html",
                            "value": "<script>void(0);</script>",
                        }
                    ],
                    "firingTriggerId": ["2147479553"],
                }
            ]
        }
        after = copy.deepcopy(before)
        after["tag"][0]["paused"] = False
        report = configured_activation_risk(
            before,
            after,
            {
                "operations": [
                    {
                        "operation_id": "OP-0001",
                        "operation_key": "unpause",
                        "execution_safety": {
                            "configured_activation_risk": {"flag": True}
                        },
                    }
                ]
            },
        )
        self.assertTrue(report["flag"])
        self.assertEqual(["tag:1"], report["newly_active_tag_keys"])
        self.assertIn("not evidence of live firing", report["scope"])


if __name__ == "__main__":
    unittest.main()
