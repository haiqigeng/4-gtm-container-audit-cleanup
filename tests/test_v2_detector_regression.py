from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

from gtm_baseline_audit import audit_export  # noqa: E402
from gtm_canonical_scan import build_canonical_scan  # noqa: E402
from gtm_custom_code_extract import (  # noqa: E402
    code_hash,
    cookie_write_facts,
    javascript_ast_facts,
    returned_value_type,
    technical_code_review,
)
from gtm_lib import param_value, refs, safe_scalar_preview, source_integrity_findings  # noqa: E402


def condition(operator: str, left: str, right: str) -> dict:
    return {
        "type": operator,
        "parameter": [
            {"type": "TEMPLATE", "key": "arg0", "value": left},
            {"type": "TEMPLATE", "key": "arg1", "value": right},
        ],
    }


def detector_fixture() -> dict:
    return {
        "exportFormatVersion": 2,
        "exportTime": "2026-09-01 09:00:00",
        "containerVersion": {
            "path": "accounts/1/containers/2/versions/3",
            "accountId": "1",
            "containerId": "2",
            "containerVersionId": "3",
            "container": {
                "accountId": "1",
                "containerId": "2",
                "publicId": "GTM-DETECTOR-TEST",
                "usageContext": ["WEB"],
            },
            "tag": [
                {
                    "tagId": "1",
                    "name": "GA4 - Purchase",
                    "type": "gaawe",
                    "parameter": [
                        {"key": "eventName", "value": "purchase"},
                        {"key": "items", "value": "{{DLV - Items}}"},
                    ],
                    "firingTriggerId": ["10"],
                    "blockingTriggerId": ["13"],
                }
            ],
            "trigger": [
                {
                    "triggerId": "10",
                    "name": "Purchase",
                    "type": "CUSTOM_EVENT",
                    "customEventFilter": [condition("EQUALS", "{{_event}}", "purchase")],
                },
                {
                    "triggerId": "11",
                    "name": "Purchase copy",
                    "type": "CUSTOM_EVENT",
                    "customEventFilter": [condition("EQUALS", "{{_event}}", "purchase")],
                },
                {
                    "triggerId": "12",
                    "name": "Single-member group",
                    "type": "TRIGGER_GROUP",
                    "parameter": [
                        {
                            "key": "triggerIds",
                            "type": "LIST",
                            "list": [{"type": "TEMPLATE", "value": "10"}],
                        }
                    ],
                },
                {
                    "triggerId": "13",
                    "name": "Impossible page-view blocker",
                    "type": "CUSTOM_EVENT",
                    "customEventFilter": [condition("EQUALS", "{{_event}}", "page_view")],
                },
                {
                    "triggerId": "14",
                    "name": "Invalid regex",
                    "type": "LINK_CLICK",
                    "filter": [condition("MATCH_REGEX", "{{Click URL}}", "(")],
                },
            ],
            "variable": [
                {
                    "variableId": "20",
                    "name": "DLV - Items",
                    "type": "v",
                    "parameter": [{"key": "name", "value": "ecommerce.items"}],
                },
                {
                    "variableId": "21",
                    "name": "DLV - Items copy",
                    "type": "v",
                    "parameter": [{"key": "name", "value": "ecommerce.items"}],
                },
                {
                    "variableId": "22",
                    "name": "CJS - Page URL Mirror",
                    "type": "jsm",
                    "parameter": [
                        {"key": "javascript", "value": "function(){return {{Page URL}};}"}
                    ],
                },
            ],
            "folder": [],
            "builtInVariable": [
                {"name": "Page URL", "type": "PAGE_URL"},
                {"name": "Click URL", "type": "CLICK_URL"},
            ],
        },
    }


class V2DetectorRegressionTests(unittest.TestCase):
    def test_retained_cleanup_detectors_keep_known_positive_families(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            export = Path(directory) / "container.json"
            export.write_text(json.dumps(detector_fixture()), encoding="utf-8")
            findings = audit_export(export)["findings"]
        finding_types = {row["finding_type"] for row in findings}
        self.assertTrue(
            {
                "duplicate_configuration",
                "duplicate_variable_path",
                "single_member_trigger_group",
                "invalid_trigger_regex",
                "ineffective_blocking_trigger",
                "variable_mirrors_builtin",
                "unused_object",
            }
            <= finding_types
        )

    def test_source_identity_and_redaction_stay_fail_closed(self) -> None:
        self.assertEqual(set(), refs({"name": "{{Metadata only}}"}))
        self.assertEqual(
            {"Executable"},
            refs(
                {
                    "templateId": "template-test",
                    "name": "Template fixture",
                    "templateData": (
                        "___INFO___\nDocumentation {{Example}}\n"
                        "___SANDBOXED_JS_FOR_WEB_TEMPLATE___\n"
                        "const value='{{Executable}}';"
                    )
                }
            ),
        )
        malformed = {
            "containerVersion": {
                "tag": [{"tagId": "1", "name": "Bad", "parameter": ["bad-entry"]}]
            }
        }
        findings = source_integrity_findings(malformed)
        self.assertTrue(
            any(row["finding_type"] == "incomplete_container_identity" for row in findings)
        )
        self.assertTrue(
            any(row["finding_type"] == "invalid_parameter_entry_shape" for row in findings)
        )
        self.assertIsNone(param_value(malformed["containerVersion"]["tag"][0], "value"))
        self.assertEqual(
            "<redacted secret-like container value>",
            safe_scalar_preview("secret {{Debug}}", field_name="api_secret"),
        )

        partial = {"containerVersion": {"tag": []}}
        partial_findings = source_integrity_findings(partial)
        self.assertTrue(
            any(row["finding_type"] == "incomplete_container_identity" for row in partial_findings)
        )
        self.assertTrue(
            any(row["finding_type"] == "partial_equivalent_source" for row in partial_findings)
        )
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "partial.json"
            source.write_text(json.dumps(partial), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "source identity"):
                build_canonical_scan(source)

        server = detector_fixture()
        server["containerVersion"]["container"]["usageContext"] = ["SERVER"]
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "server-container.json"
            source.write_text(json.dumps(server), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "WEB container"):
                build_canonical_scan(source)

        for layer in ("client", "transformation"):
            with self.subTest(server_layer=layer):
                web_with_server_object = detector_fixture()
                web_with_server_object["containerVersion"][layer] = []
                findings = source_integrity_findings(web_with_server_object)
                self.assertTrue(
                    any(
                        row["finding_type"] == "unmodelled_entity_layer"
                        and row.get("layer") == layer
                        for row in findings
                    )
                )

        web_with_server_template = detector_fixture()
        web_with_server_template["containerVersion"]["customTemplate"] = [
            {
                "templateId": "99",
                "name": "Server template",
                "templateData": (
                    "___SANDBOXED_JS_FOR_SERVER_TEMPLATE___\n"
                    "return data.gtmOnSuccess();"
                ),
            }
        ]
        findings = source_integrity_findings(web_with_server_template)
        self.assertTrue(
            any(
                row["finding_type"] == "unsupported_server_template_section"
                for row in findings
            )
        )

    def test_custom_code_detectors_preserve_exactness_and_safe_neighbors(self) -> None:
        self.assertNotEqual(code_hash("return 'a  b';"), code_hash("return 'a b';"))
        self.assertEqual(code_hash("return 1;\r\n"), code_hash("return 1;\n"))
        self.assertEqual(
            "string_or_template_string",
            returned_value_type("function(){return 'true';}"),
        )
        parser = javascript_ast_facts("variable", "function(){return true;}")
        self.assertIn("javascript_parser_version", parser)

        deletion = cookie_write_facts("document.cookie='consent=; Max-Age=0; path=/';")
        self.assertEqual("delete", deletion[0]["operation"])
        deletion_findings = technical_code_review(
            "tag", "document.cookie='consent=; Max-Age=0; path=/';", ["cookie write"]
        )["technical_code_security_findings"]
        self.assertNotIn("set/update omits", " ".join(deletion_findings))

        fragile = technical_code_review(
            "tag",
            "window.addEventListener('load',handler,{once:true});",
            ["event listener"],
        )["technical_code_health_findings"]
        self.assertIn("does not prevent duplicate registrations", " ".join(fragile))
        guarded = technical_code_review(
            "tag",
            (
                "if(document.readyState==='complete'){handler();}"
                "else if(!window.bound){window.bound=true;"
                "window.addEventListener('load',handler,{once:true});}"
            ),
            ["event listener"],
        )["technical_code_health_findings"]
        self.assertNotIn("does not prevent duplicate registrations", " ".join(guarded))

        weak_message = technical_code_review(
            "tag",
            (
                "window.addEventListener('message',function(event){"
                "if(event.origin.indexOf('trusted.example')===-1)return;"
                "dataLayer.push(event.data.payload);});"
            ),
            ["event listener", "dataLayer push"],
        )["technical_code_security_findings"]
        self.assertIn("origin with substring matching", " ".join(weak_message))


if __name__ == "__main__":
    unittest.main()
