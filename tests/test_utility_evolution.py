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

from gtm_approval_response import (  # noqa: E402
    CLEANUP_PACKET_SCHEMA_VERSION,
    approval_contract,
    response_template,
    validate_response,
)
from gtm_architecture_review import scaffold_review as scaffold_architecture  # noqa: E402
from gtm_audit_delta import build_delta  # noqa: E402
from gtm_audit_package_build import build_package  # noqa: E402
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
from gtm_operation_compile import (  # noqa: E402
    cleanup_closure_operations,
    dependency_order_operations,
    packetize_operations,
)
from gtm_relationships import (  # noqa: E402
    near_event_name,
    relationship_candidates,
)
from gtm_requirement_evidence import build_requirement_evidence  # noqa: E402
from gtm_review_common import object_consumer_map_from_data  # noqa: E402
from gtm_shared_facts import build_shared_facts  # noqa: E402
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


def cleanup_packet(rows: list[dict], source_sha256: str = "source") -> dict:
    packet = {
        "kind": "gtm_reconciled_operations",
        "schema_version": CLEANUP_PACKET_SCHEMA_VERSION,
        "source_sha256": source_sha256,
        "plan_status": "complete",
        "operations": rows,
    }
    packet["approval_contract"] = approval_contract(packet)
    return packet


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

    def test_approval_response_is_row_complete_and_packet_locked(self) -> None:
        operation = {
            "operation_id": "OP-0001",
            "title": "Repair route",
            "deletions": [],
            "execution_safety": {
                "server_coupled": True,
                "configured_activation_risk": {"flag": False},
                "decommission": {"required": False},
            },
        }
        packet = {
            "kind": "gtm_reconciled_operations",
            "schema_version": CLEANUP_PACKET_SCHEMA_VERSION,
            "source_sha256": "a" * 64,
            "shared_facts_sha256": "b" * 64,
            "context_sha256": "c" * 64,
            "route": "Direct",
            "plan_status": "complete",
            "projected_object_counts": {},
            "measurement_preservation": {},
            "target_organization": {},
            "decision_ledger": [],
            "operations": [operation],
        }
        packet["approval_contract"] = approval_contract(packet)
        response = response_template(packet)
        response["responses"][0].update(
            {
                "decision": "Approve",
                "confirm_server_coupled": True,
            }
        )
        selection, errors = validate_response(packet, response)
        self.assertEqual([], errors)
        self.assertEqual(["OP-0001"], selection["approved_operation_ids"])
        self.assertEqual(["OP-0001"], selection["server_confirmed_operation_ids"])

        response["responses"][0]["operation_sha256"] = "tampered"
        _selection, errors = validate_response(packet, response)
        self.assertTrue(any("content hash" in error for error in errors))

        packet["approval_contract"]["operation_ids"] = []
        _selection, errors = validate_response(packet, response_template(packet))
        self.assertTrue(any("approval contract" in error for error in errors))

        packet["approval_contract"] = approval_contract(packet)
        non_boolean = response_template(packet)
        non_boolean["responses"][0]["decision"] = "Approve"
        non_boolean["responses"][0]["confirm_server_coupled"] = "false"
        _selection, errors = validate_response(packet, non_boolean)
        self.assertTrue(any("must be true or false" in error for error in errors))

        legacy_packet = copy.deepcopy(packet)
        legacy_packet["schema_version"] = 4
        legacy_packet["approval_contract"] = approval_contract(legacy_packet)
        legacy_response = response_template(legacy_packet)
        legacy_response["responses"][0].update(
            {"decision": "Approve", "confirm_server_coupled": True}
        )
        _selection, errors = validate_response(legacy_packet, legacy_response)
        self.assertTrue(any("schema version" in error for error in errors))

    def test_audit_delta_compares_fresh_artifacts_without_carrying_verdicts(self) -> None:
        def artifacts(source_hash: str, object_hash: str, defect: str) -> dict:
            return {
                "manifest": {
                    "source_file": "container.json",
                    "source_sha256": source_hash,
                },
                "shared": {
                    "objects": [
                        {
                            "object_key": "tag:1",
                            "layer": "tag",
                            "object_name": "GA4 - Lead",
                            "configuration_hash": object_hash,
                        }
                    ]
                },
                "operational": {"findings": []},
                "configuration": {
                    "rows": [
                        {
                            "review_id": "CFG-1",
                            "object_key": "tag:1",
                            "defects": (
                                [
                                    {
                                        "defect_id": "D-1",
                                        "statement": defect,
                                        "evidence_anchors": ["$.tag[0].parameter[0]"],
                                    }
                                ]
                                if defect
                                else []
                            ),
                        }
                    ]
                },
                "architecture": {"families": [], "comparisons": []},
                "operations": {},
            }

        previous = artifacts("a" * 64, "before", "Wrong destination")
        current = artifacts("b" * 64, "after", "")
        delta = build_delta(previous, current)
        self.assertEqual(["tag:1"], [row["object_key"] for row in delta["objects"]["changed"]])
        self.assertEqual(1, len(delta["findings"]["resolved"]))
        self.assertEqual([], delta["findings"]["recurring"])
        self.assertIn("no prior semantic verdict", delta["comparison_policy"])

        reworded = artifacts("c" * 64, "after", "Destination is configured incorrectly")
        recurring = build_delta(previous, reworded)
        self.assertEqual(1, len(recurring["findings"]["recurring"]))
        self.assertEqual(1, len(recurring["findings"]["changed"]))

    def test_approved_tracking_plan_is_distinct_exact_match_evidence(self) -> None:
        data = minimal_export()
        data["containerVersion"]["tag"] = [
            {
                "tagId": "1",
                "name": "GA4 - generate_lead",
                "type": "gaawe",
                "parameter": [
                    {"type": "TEMPLATE", "key": "eventName", "value": "generate_lead"}
                ],
                "firingTriggerId": ["2147479553"],
            }
        ]
        export_path = self.write_export(data)
        requirements_path = self.root / "approved-plan.csv"
        requirements_path.write_text(
            "Event name,Tag name,Description\n"
            "generate_lead,GA4 - generate_lead,Approved lead event\n",
            encoding="utf-8",
        )
        requirements = build_requirement_evidence(requirements_path)
        shared = build_shared_facts(export_path)
        self.assertIn("never container evidence", requirements["evidence_role"])

        configuration = scaffold_configuration(
            export_path,
            shared_facts=shared,
            requirement_evidence=requirements,
        )
        config_tag = next(row for row in configuration["rows"] if row["object_key"] == "tag:1")
        self.assertTrue(config_tag["approved_requirement_links"])
        self.assertEqual(
            ["exact_object_name", "exact_event_value"],
            config_tag["approved_requirement_links"][0]["match_types"],
        )
        self.assertNotIn("approved_requirement_evidence", shared)
        architecture = scaffold_architecture(
            export_path,
            shared_facts=shared,
            requirement_evidence=requirements,
        )
        self.assertTrue(
            any(family["approved_requirement_links"] for family in architecture["families"])
        )

        package_dir = self.root / "requirements-package"
        manifest = build_package(
            export_path,
            package_dir,
            requirements_path=requirements_path,
        )
        self.assertEqual(1, manifest["counts"]["approved_requirement_rows"])
        packaged_shared = json.loads(
            (package_dir / "shared_facts.json").read_text(encoding="utf-8")
        )
        packaged_operational = json.loads(
            (package_dir / "operational_review.json").read_text(encoding="utf-8")
        )
        self.assertNotIn("approved_requirement_evidence", packaged_shared)
        self.assertNotIn("approved_requirement_evidence", packaged_operational)
        for run in ("configuration_correctness", "business_architecture"):
            self.assertTrue(
                (
                    package_dir
                    / "review-bundles"
                    / run
                    / "approved_requirements.json"
                ).is_file()
            )
        self.assertFalse(
            (
                package_dir
                / "review-bundles"
                / "operational_sanitation"
                / "approved_requirements.json"
            ).exists()
        )

    def test_approved_xlsx_discovers_headers_after_title_rows(self) -> None:
        try:
            from openpyxl import Workbook
        except ImportError:
            self.skipTest("openpyxl is not installed")

        requirements_path = self.root / "approved-plan.xlsx"
        workbook = Workbook()
        sheet = workbook.active
        sheet.title = "Event plan"
        sheet.append(["Approved measurement plan"])
        sheet.append(["Website rebuild — final scope"])
        sheet.append(["Nom de l'événement", "Nom de la balise", "Description"])
        sheet.append(["generate_lead", "GA4 - generate_lead", "Approved lead event"])
        workbook.save(requirements_path)

        evidence = build_requirement_evidence(requirements_path)
        self.assertEqual(1, evidence["counts"]["rows"])
        row = evidence["requirements"][0]
        self.assertEqual("Event plan", row["source_sheet"])
        self.assertEqual(4, row["source_row"])
        self.assertEqual("generate_lead", row["event_name"])
        self.assertEqual("GA4 - generate_lead", row["object_name"])

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

    def test_configuration_detects_consent_timing_and_nullable_dlv_semantics(self) -> None:
        data = minimal_export()
        data["containerVersion"].update(
            {
                "trigger": [
                    {"triggerId": "10", "name": "CMP ready", "type": "CUSTOM_EVENT"},
                    {
                        "triggerId": "11",
                        "name": "Consent init - regional host",
                        "type": "CONSENT_INIT",
                        "filter": [
                            {
                                "type": "CONTAINS",
                                "parameter": [
                                    {"key": "arg0", "value": "{{Page Hostname}}"},
                                    {"key": "arg1", "value": "example.be"},
                                ],
                            }
                        ],
                    },
                ],
                "tag": [
                    {
                        "tagId": "1",
                        "name": "Consent default too late",
                        "type": "html",
                        "firingTriggerId": ["10"],
                        "parameter": [
                            {
                                "key": "html",
                                "type": "TEMPLATE",
                                "value": "<script>gtag('consent','default',{});</script>",
                            }
                        ],
                    },
                    {
                        "tagId": "2",
                        "name": "Consent default on initialization",
                        "type": "cvt_1_99",
                        "firingTriggerId": ["2147479593"],
                        "parameter": [
                            {"key": "command", "type": "TEMPLATE", "value": "default"}
                        ],
                    },
                    {
                        "tagId": "3",
                        "name": "Consent default with generic template type",
                        "type": "html",
                        "firingTriggerId": ["2147479593"],
                        "parameter": [
                            {"key": "command", "type": "TEMPLATE", "value": "default"}
                        ],
                    },
                    {
                        "tagId": "4",
                        "name": "Consent call in a string only",
                        "type": "html",
                        "firingTriggerId": ["2147479593"],
                        "parameter": [
                            {
                                "key": "html",
                                "type": "TEMPLATE",
                                "value": (
                                    "<script>var note=\"gtag('consent','default',{})\";"
                                    "</script>"
                                ),
                            }
                        ],
                    },
                    {
                        "tagId": "5",
                        "name": "Consent API imported but not invoked",
                        "type": "cvt_1_100",
                        "firingTriggerId": ["2147479593"],
                    },
                    {
                        "tagId": "6",
                        "name": "Consent default on filtered regional initialization",
                        "type": "cvt_1_99",
                        "firingTriggerId": ["11"],
                        "parameter": [
                            {"key": "command", "type": "TEMPLATE", "value": "default"}
                        ],
                    },
                ],
                "customTemplate": [
                    {
                        "accountId": "1",
                        "templateId": "99",
                        "name": "Consent template",
                        "templateData": (
                            "___SANDBOXED_JS_FOR_WEB_TEMPLATE___\n"
                            "const setDefaultConsentState = "
                            "require('setDefaultConsentState');\n"
                            "setDefaultConsentState({ad_storage:'denied'});"
                        ),
                    },
                    {
                        "accountId": "1",
                        "templateId": "100",
                        "name": "Import-only template",
                        "templateData": (
                            "___SANDBOXED_JS_FOR_WEB_TEMPLATE___\n"
                            "const setDefaultConsentState = "
                            "require('setDefaultConsentState');\n"
                            "data.gtmOnSuccess();"
                        ),
                    },
                ],
                "variable": [
                    {
                        "variableId": "10",
                        "name": "Consent purposes",
                        "type": "v",
                        "parameter": [
                            {"key": "name", "type": "TEMPLATE", "value": "purposes"},
                            {
                                "key": "setDefaultValue",
                                "type": "BOOLEAN",
                                "value": "false",
                            },
                        ],
                    },
                    {
                        "variableId": "11",
                        "name": "Unsafe consent mapping",
                        "type": "jsm",
                        "parameter": [
                            {
                                "key": "javascript",
                                "type": "TEMPLATE",
                                "value": (
                                    "function(){var p={{Consent purposes}};"
                                    "return p.includes(',1,')?'granted':'denied';}"
                                ),
                            }
                        ],
                    },
                    {
                        "variableId": "12",
                        "name": "Guarded consent mapping",
                        "type": "jsm",
                        "parameter": [
                            {
                                "key": "javascript",
                                "type": "TEMPLATE",
                                "value": (
                                    "function(){var p={{Consent purposes}};if(!p)return 'denied';"
                                    "return p.includes(',1,')?'granted':'denied';}"
                                ),
                            }
                        ],
                    },
                    {
                        "variableId": "13",
                        "name": "Type-guarded consent mapping",
                        "type": "jsm",
                        "parameter": [
                            {
                                "key": "javascript",
                                "type": "TEMPLATE",
                                "value": (
                                    "function(){var p={{Consent purposes}};"
                                    "if(typeof p !== 'string'){return 'denied';}"
                                    "return p.includes(',1,')?'granted':'denied';}"
                                ),
                            }
                        ],
                    },
                    {
                        "variableId": "14",
                        "name": "Array-normalised consent mapping",
                        "type": "jsm",
                        "parameter": [
                            {
                                "key": "javascript",
                                "type": "TEMPLATE",
                                "value": (
                                    "function(){var p={{Consent purposes}};"
                                    "if(typeof p !== 'string'&&!Array.isArray(p)){p=[];}"
                                    "return p.includes(',1,')?'granted':'denied';}"
                                ),
                            }
                        ],
                    },
                    {
                        "variableId": "15",
                        "name": "Conditionally guarded consent mapping",
                        "type": "jsm",
                        "parameter": [
                            {
                                "key": "javascript",
                                "type": "TEMPLATE",
                                "value": (
                                    "function(){var p={{Consent purposes}};"
                                    "if(window.ready){if(typeof p !== 'string'){return 'denied';}}"
                                    "return p.includes(',1,')?'granted':'denied';}"
                                ),
                            }
                        ],
                    },
                    {
                        "variableId": "16",
                        "name": "Nested unused guard consent mapping",
                        "type": "jsm",
                        "parameter": [
                            {
                                "key": "javascript",
                                "type": "TEMPLATE",
                                "value": (
                                    "function(){var p={{Consent purposes}};"
                                    "function unused(){if(typeof p !== 'string'){return;}}"
                                    "return p.includes(',1,')?'granted':'denied';}"
                                ),
                            }
                        ],
                    },
                    {
                        "variableId": "17",
                        "name": "One unsafe call after a guarded call",
                        "type": "jsm",
                        "parameter": [
                            {
                                "key": "javascript",
                                "type": "TEMPLATE",
                                "value": (
                                    "function(){var p={{Consent purposes}};"
                                    "var first=p&&p.includes(',1,');"
                                    "return p.includes(',2,')||first;}"
                                ),
                            }
                        ],
                    },
                    {
                        "variableId": "18",
                        "name": "Guard invalidated before includes",
                        "type": "jsm",
                        "parameter": [
                            {
                                "key": "javascript",
                                "type": "TEMPLATE",
                                "value": (
                                    "function(){var p={{Consent purposes}};"
                                    "if(typeof p !== 'string'){return 'denied';}"
                                    "p=undefined;return p.includes(',1,');}"
                                ),
                            }
                        ],
                    },
                ],
            }
        )
        review = scaffold_configuration(self.write_export(data, "semantic-risks.json"))
        obligations = {
            row["object_key"]: {
                str(item.get("obligation_key") or "")
                for item in row["required_configuration_obligations"]
            }
            for row in review["rows"]
        }
        self.assertIn(
            "consent_default_wrong_initialization_trigger", obligations["tag:1"]
        )
        self.assertNotIn(
            "consent_default_wrong_initialization_trigger", obligations["tag:2"]
        )
        self.assertNotIn(
            "consent_default_wrong_initialization_trigger", obligations["tag:6"]
        )
        late_row = next(row for row in review["rows"] if row["object_key"] == "tag:1")
        late_obligation = next(
            item
            for item in late_row["required_configuration_obligations"]
            if item["obligation_key"]
            == "consent_default_wrong_initialization_trigger"
        )
        self.assertNotIn("source_known_repair", late_obligation)
        self.assertIn(
            "consent_initialization_non_consent_tag", obligations["tag:3"]
        )
        self.assertIn(
            "consent_initialization_non_consent_tag", obligations["tag:4"]
        )
        self.assertIn(
            "consent_initialization_non_consent_tag", obligations["tag:5"]
        )
        self.assertTrue(
            any(
                key.startswith("nullable_dlv_includes:")
                for key in obligations["variable:11"]
            )
        )
        self.assertFalse(
            any(
                key.startswith("nullable_dlv_includes:")
                for key in obligations["variable:12"]
            )
        )
        self.assertFalse(
            any(
                key.startswith("nullable_dlv_includes:")
                for key in obligations["variable:13"]
            )
        )
        self.assertFalse(
            any(
                key.startswith("nullable_dlv_includes:")
                for key in obligations["variable:14"]
            )
        )
        for object_key in (
            "variable:15",
            "variable:16",
            "variable:17",
            "variable:18",
        ):
            self.assertTrue(
                any(
                    key.startswith("nullable_dlv_includes:")
                    for key in obligations[object_key]
                ),
                object_key,
            )

    def test_relationship_discovery_covers_loaders_and_consent_writers_stably(self) -> None:
        cv = minimal_export()["containerVersion"]
        cv["tag"] = [
            {
                "tagId": "1",
                "name": "Vendor loader one",
                "type": "html",
                "parameter": [
                    {
                        "key": "html",
                        "value": "<script src='https://cdn.vendor.example/sdk.js'></script>",
                    }
                ],
            },
            {
                "tagId": "2",
                "name": "Vendor loader two",
                "type": "html",
                "parameter": [
                    {
                        "key": "html",
                        "value": (
                            "<script>var s=document.createElement('script');"
                            "s.src='https://cdn.vendor.example/sdk.js';</script>"
                        ),
                    }
                ],
            },
            {
                "tagId": "3",
                "name": "Consent default",
                "type": "cvt_consent",
                "firingTriggerId": ["2147479593"],
                "parameter": [{"key": "command", "value": "default"}],
            },
            {
                "tagId": "4",
                "name": "Consent update",
                "type": "cvt_consent",
                "firingTriggerId": ["20"],
                "parameter": [{"key": "command", "value": "update"}],
            },
        ]
        rows = relationship_candidates(cv)
        comparison_types = {
            comparison_type
            for row in rows
            for comparison_type in row["comparison_types"]
        }
        self.assertIn("duplicate_vendor_loader_review", comparison_types)
        self.assertIn("consent_writer_sequence_review", comparison_types)

        reversed_rows = relationship_candidates({**cv, "tag": list(reversed(cv["tag"]))})

        def signature(candidates: list[dict]) -> set[tuple[tuple[str, ...], tuple[str, ...]]]:
            return {
                (
                    tuple(row["candidate_object_keys"]),
                    tuple(row["comparison_types"]),
                )
                for row in candidates
            }

        self.assertEqual(signature(rows), signature(reversed_rows))
        one_loader = {**cv, "tag": [cv["tag"][0]]}
        self.assertNotIn(
            "duplicate_vendor_loader_review",
            {
                comparison_type
                for row in relationship_candidates(one_loader)
                for comparison_type in row["comparison_types"]
            },
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

        operations = cleanup_packet([packet])
        future = {
            "source_sha256": "source",
            "status": "pass",
            "configured_activation_risk": {
                "flag": True,
                "candidate_operation_ids": [packet["operation_id"]],
            },
        }
        preflight_source = {
            "containerVersion": {
                "publicId": "GTM-PREFLIGHT-TEST",
                "tag": [
                    {
                        "tagId": "1",
                        "name": "Server conversion",
                        "type": "html",
                    }
                ]
            }
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
            source_export=preflight_source,
            live_readback=copy.deepcopy(preflight_source),
            source_export_sha256="source",
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
            source_export=preflight_source,
            live_readback=copy.deepcopy(preflight_source),
            source_export_sha256="source",
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
            source_export=preflight_source,
            live_readback=copy.deepcopy(preflight_source),
            source_export_sha256="source",
        )
        self.assertEqual("pass", allowed["status"])

        legacy_operations = copy.deepcopy(operations)
        legacy_operations["schema_version"] = 4
        legacy_operations["approval_contract"] = approval_contract(
            legacy_operations
        )
        legacy = execution_preflight(
            legacy_operations,
            {
                "context": {"do_not_touch": []},
                "context_evidence": {"do_not_touch": {"status": "provided"}},
            },
            future,
            {packet["operation_id"]},
            {packet["operation_id"]},
            {packet["operation_id"]},
            {packet["operation_id"]},
            source_export=preflight_source,
            live_readback=copy.deepcopy(preflight_source),
            source_export_sha256="source",
        )
        self.assertEqual("fail", legacy["status"])
        self.assertTrue(any("schema version" in value for value in legacy["errors"]))

    def test_cleanup_closure_is_separate_approvable_and_dependency_ordered(self) -> None:
        source_operation = {
            "operation_key": "replace-trigger",
            "deletions": [],
            "creations": [],
            "additions": [],
            "changes": [
                {
                    "object_key": "tag:1",
                    "json_path": "$.containerVersion.tag[0].firingTriggerId",
                    "before": ["10"],
                    "after": ["11"],
                }
            ],
            "remaps": [],
            "renames": [],
        }
        catalog = {
            "tag:1": {"layer": "tag", "object_name": "Legacy tag"},
            "trigger:10": {"layer": "trigger", "object_name": "Legacy event"},
            "trigger:11": {"layer": "trigger", "object_name": "New event"},
            "variable:20": {"layer": "variable", "object_name": "Legacy value"},
        }
        consumers = {
            "tag:1": set(),
            "trigger:10": {"tag:1"},
            "trigger:11": set(),
            "variable:20": {"trigger:10"},
        }

        closure, decisions = cleanup_closure_operations(
            [source_operation], catalog, consumers
        )

        self.assertEqual(
            ["trigger:10", "variable:20"],
            [row["deletions"][0]["object_key"] for row in closure],
        )
        self.assertEqual(2, len(decisions))
        ordered, errors = dependency_order_operations(
            [*closure, source_operation], consumers
        )
        self.assertEqual([], errors)
        self.assertEqual(
            [
                "replace-trigger",
                closure[0]["operation_key"],
                closure[1]["operation_key"],
            ],
            [row["operation_key"] for row in ordered],
        )
        packets = packetize_operations(ordered, "Direct", catalog)
        self.assertEqual([], packets[0]["depends_on_operation_ids"])
        self.assertEqual(["OP-0001"], packets[1]["depends_on_operation_ids"])
        self.assertEqual(["OP-0002"], packets[2]["depends_on_operation_ids"])

    def test_cleanup_closure_uses_indexed_edits_and_future_graph(self) -> None:
        source = minimal_export()
        source["containerVersion"].update(
            {
                "tag": [
                    {
                        "tagId": "1",
                        "name": "Event tag",
                        "type": "html",
                        "firingTriggerId": ["10"],
                    }
                ],
                "trigger": [
                    {
                        "triggerId": "10",
                        "name": "Legacy event",
                        "type": "CUSTOM_EVENT",
                        "customEventFilter": [
                            condition("EQUALS", "{{Legacy value}}", "yes")
                        ],
                    },
                    {"triggerId": "11", "name": "New event", "type": "CUSTOM_EVENT"},
                ],
                "variable": [
                    {"variableId": "20", "name": "Legacy value", "type": "v"}
                ],
            }
        )
        operation = {
            "operation_key": "replace-indexed-trigger",
            "creations": [],
            "additions": [],
            "changes": [
                {
                    "object_key": "tag:1",
                    "json_path": "$.containerVersion.tag[0].firingTriggerId[0]",
                    "before": "10",
                    "after": "11",
                }
            ],
            "remaps": [],
            "renames": [],
            "deletions": [],
        }
        consumers = object_consumer_map_from_data(source)
        catalog = {
            "tag:1": {"layer": "tag", "object_name": "Event tag"},
            "trigger:10": {"layer": "trigger", "object_name": "Legacy event"},
            "trigger:11": {"layer": "trigger", "object_name": "New event"},
            "variable:20": {"layer": "variable", "object_name": "Legacy value"},
        }

        closure, _decisions = cleanup_closure_operations(
            [operation], catalog, consumers, source
        )

        self.assertEqual(
            ["trigger:10", "variable:20"],
            [row["deletions"][0]["object_key"] for row in closure],
        )
        self.assertEqual(
            ["replace-indexed-trigger"],
            closure[0]["prerequisite_operation_keys"],
        )

    def test_cleanup_closure_preserves_dependency_used_by_a_creation(self) -> None:
        source = minimal_export()
        source["containerVersion"].update(
            {
                "tag": [
                    {
                        "tagId": "1",
                        "name": "Existing consumer",
                        "type": "html",
                        "parameter": [
                            {"key": "html", "value": "{{Legacy value}}"}
                        ],
                    }
                ],
                "variable": [
                    {"variableId": "20", "name": "Legacy value", "type": "v"}
                ],
            }
        )
        operation = {
            "operation_key": "move-consumer",
            "creations": [
                {
                    "layer": "tag",
                    "object": {
                        "tagId": "2",
                        "name": "New consumer",
                        "type": "html",
                        "parameter": [
                            {"key": "html", "value": "{{Legacy value}}"}
                        ],
                    },
                }
            ],
            "additions": [],
            "changes": [
                {
                    "object_key": "tag:1",
                    "json_path": "$.containerVersion.tag[0].parameter",
                    "before": [{"key": "html", "value": "{{Legacy value}}"}],
                    "after": [{"key": "html", "value": "no reference"}],
                }
            ],
            "remaps": [],
            "renames": [],
            "deletions": [],
        }
        catalog = {
            "tag:1": {"layer": "tag", "object_name": "Existing consumer"},
            "variable:20": {"layer": "variable", "object_name": "Legacy value"},
        }

        closure, _decisions = cleanup_closure_operations(
            [operation],
            catalog,
            object_consumer_map_from_data(source),
            source,
        )

        self.assertEqual([], closure)

    def test_cleanup_closure_covers_groups_zones_and_custom_templates(self) -> None:
        source = minimal_export()
        source["containerVersion"].update(
            {
                "tag": [
                    {
                        "tagId": "1",
                        "name": "Grouped tag",
                        "type": "html",
                        "firingTriggerId": ["20"],
                    },
                    {
                        "tagId": "2",
                        "name": "Template tag",
                        "type": "cvt_1_99",
                    },
                ],
                "trigger": [
                    {"triggerId": "10", "name": "Member", "type": "CUSTOM_EVENT"},
                    {"triggerId": "11", "name": "Replacement", "type": "CUSTOM_EVENT"},
                    {
                        "triggerId": "20",
                        "name": "Legacy group",
                        "type": "TRIGGER_GROUP",
                        "parameter": [
                            {
                                "key": "triggerIds",
                                "type": "LIST",
                                "list": [{"type": "TRIGGER_REFERENCE", "value": "10"}],
                            }
                        ],
                    },
                ],
                "zone": [
                    {
                        "zoneId": "40",
                        "name": "Legacy zone route",
                        "boundary": {"customEvaluationTriggerId": ["10"]},
                    }
                ],
                "customTemplate": [
                    {
                        "accountId": "1",
                        "templateId": "99",
                        "name": "Legacy template",
                        "templateData": "___SANDBOXED_JS_FOR_WEB_TEMPLATE___\ndata.gtmOnSuccess();",
                    }
                ],
            }
        )
        operations = [
            {
                "operation_key": "replace-routes",
                "creations": [],
                "additions": [],
                "changes": [
                    {
                        "object_key": "tag:1",
                        "json_path": "$.containerVersion.tag[0].firingTriggerId[0]",
                        "before": "20",
                        "after": "11",
                    },
                    {
                        "object_key": "zone:40",
                        "json_path": (
                            "$.containerVersion.zone[0].boundary."
                            "customEvaluationTriggerId[0]"
                        ),
                        "before": "10",
                        "after": "11",
                    },
                ],
                "remaps": [],
                "renames": [],
                "deletions": [],
            },
            {
                "operation_key": "delete-template-tag",
                "creations": [],
                "additions": [],
                "changes": [],
                "remaps": [],
                "renames": [],
                "deletions": [{"object_key": "tag:2"}],
            },
        ]
        catalog = {
            "tag:1": {"layer": "tag", "object_name": "Grouped tag"},
            "tag:2": {"layer": "tag", "object_name": "Template tag"},
            "trigger:10": {"layer": "trigger", "object_name": "Member"},
            "trigger:11": {"layer": "trigger", "object_name": "Replacement"},
            "trigger:20": {"layer": "trigger", "object_name": "Legacy group"},
            "zone:40": {"layer": "zone", "object_name": "Legacy zone route"},
            "customTemplate:99": {
                "layer": "customTemplate",
                "object_name": "Legacy template",
            },
        }

        closure, _decisions = cleanup_closure_operations(
            operations,
            catalog,
            object_consumer_map_from_data(source),
            source,
        )

        self.assertEqual(
            {"customTemplate:99", "trigger:20", "trigger:10"},
            {row["deletions"][0]["object_key"] for row in closure},
        )

    def test_inactive_consent_named_trigger_uses_structural_deletion_risk(self) -> None:
        packet = packetize_operations(
            [
                {
                    "operation_key": "delete-unused-consent-trigger",
                    "area": "GTM hygiene",
                    "problem_type": "Unused object",
                    "problem": "Old Consent Trigger has no configured consumer.",
                    "why_it_matters": "It is obsolete container clutter.",
                    "priority": "Medium",
                    "confidence": "High",
                    "execution_readiness": "approval_required",
                    "source_object_keys": ["trigger:9"],
                    "affected_object_keys": ["trigger:9"],
                    "creations": [],
                    "additions": [],
                    "changes": [],
                    "remaps": [],
                    "renames": [],
                    "deletions": [{"object_key": "trigger:9"}],
                }
            ],
            "Direct",
            {
                "trigger:9": {
                    "layer": "trigger",
                    "object_name": "Old Consent Trigger",
                    "config_hash": "abc",
                    "reachability": "inactive_or_unreferenced",
                    "server_route_hosts": [],
                }
            },
        )[0]

        self.assertIn("consent_privacy", packet["priority_basis"]["impact_classes"])
        self.assertEqual(
            "bulk_eligible_exact_low_risk_bundle",
            packet["execution_safety"]["approval"]["scope"],
        )
        self.assertFalse(packet["execution_safety"]["decommission"]["required"])

    def test_execution_guard_requires_prerequisites_and_an_unchanged_live_readback(
        self,
    ) -> None:
        source = {
            "containerVersion": {
                "publicId": "GTM-GUARD-TEST",
                "tag": [{"tagId": "1", "name": "Legacy", "type": "html"}],
                "trigger": [
                    {"triggerId": "10", "name": "Legacy event", "type": "CUSTOM_EVENT"}
                ],
            }
        }
        operations = cleanup_packet(
            [
                {
                    "operation_id": "OP-0001",
                    "execution_order": 1,
                    "depends_on_operation_ids": [],
                },
                {
                    "operation_id": "OP-0002",
                    "execution_order": 2,
                    "depends_on_operation_ids": ["OP-0001"],
                },
            ]
        )
        context = {
            "context": {"do_not_touch": []},
            "context_evidence": {"do_not_touch": {"status": "provided"}},
        }
        missing_prerequisite = execution_preflight(
            operations,
            context,
            {"status": "pass", "source_sha256": "source", "operation_count": 1},
            {"OP-0002"},
            set(),
            set(),
            set(),
            source_export=source,
            live_readback=copy.deepcopy(source),
            source_export_sha256="source",
        )
        self.assertEqual("fail", missing_prerequisite["status"])
        self.assertTrue(
            any("prerequisite" in error for error in missing_prerequisite["errors"])
        )

        drifted = copy.deepcopy(source)
        drifted["containerVersion"]["tag"][0]["name"] = "Changed after audit"
        drift = execution_preflight(
            operations,
            context,
            {"status": "pass", "source_sha256": "source", "operation_count": 2},
            {"OP-0001", "OP-0002"},
            set(),
            set(),
            set(),
            source_export=source,
            live_readback=drifted,
            source_export_sha256="source",
        )
        self.assertEqual("fail", drift["status"])
        self.assertIn(
            "tag:1",
            drift["live_readback_binding"]["configuration_differences"][
                "changed_object_keys"
            ],
        )

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
