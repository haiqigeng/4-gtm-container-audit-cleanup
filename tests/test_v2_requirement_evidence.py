from __future__ import annotations

import builtins
import io
import json
import sys
import tempfile
import types
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

import gtm_requirement_evidence as requirement_evidence  # noqa: E402


class RequirementEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_json_csv_and_normalization_are_deterministic(self) -> None:
        json_path = self.root / "requirements.json"
        json_path.write_text(
            json.dumps(
                {
                    "requirements": [
                        {
                            "Nom de l’événement": "  purchase  ",
                            "Balise": "GA4 - Purchase",
                            "Measurement ID": "G-TEST",
                            "Description": "Approved purchase event",
                            "Statut": True,
                        },
                        {},
                    ]
                }
            ),
            encoding="utf-8",
        )
        first = requirement_evidence.build_requirement_evidence(json_path)
        second = requirement_evidence.build_requirement_evidence(json_path)
        self.assertEqual(first, second)
        self.assertEqual(
            {
                "rows": 1,
                "rows_with_event_name": 1,
                "rows_with_object_name": 1,
                "rows_with_destination": 1,
            },
            first["counts"],
        )
        row = first["requirements"][0]
        self.assertEqual("purchase", row["event_name"])
        self.assertEqual("GA4 - Purchase", row["object_name"])
        self.assertEqual("G-TEST", row["destination"])
        self.assertEqual("true", row["status"])
        self.assertEqual(64, len(row["source_row_sha256"]))

        csv_path = self.root / "requirements.csv"
        csv_path.write_text(
            "Event,Tag,Measurement ID,Description,Status\n"
            "login,GA4 - Login,G-TEST,Approved login,approved\n",
            encoding="utf-8",
        )
        csv_payload = requirement_evidence.build_requirement_evidence(csv_path)
        self.assertEqual("login", csv_payload["requirements"][0]["event_name"])
        self.assertEqual(2, csv_payload["requirements"][0]["source_row"])

        with self.assertRaisesRegex(ValueError, "unique identities"):
            requirement_evidence.normalized_requirement_rows(
                [
                    ("Sheet", 2, {"Event": "login"}),
                    ("Sheet", 2, {"Event": "login"}),
                ],
                "a" * 64,
            )
        scalar_json = self.root / "scalar.json"
        scalar_json.write_text("42", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "object or array"):
            requirement_evidence.json_rows(scalar_json)
        unsupported = self.root / "requirements.txt"
        unsupported.write_text("event=login", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "JSON, CSV, XLSX, or XLSM"):
            requirement_evidence.build_requirement_evidence(unsupported)

    def test_xlsx_header_discovery_uses_the_existing_runtime_contract(self) -> None:
        class FakeSheet:
            def __init__(self, title: str, rows: list[tuple[object, ...]]) -> None:
                self.title = title
                self.rows = rows

            def iter_rows(self, *, values_only: bool) -> object:
                self.assert_values_only = values_only
                return iter(self.rows)

        class FakeWorkbook:
            def __init__(self) -> None:
                self.worksheets = [
                    FakeSheet("Empty", [(None, None)]),
                    FakeSheet(
                        "Plan",
                        [
                            ("Tracking plan", None, None),
                            ("Event", "Tag", "Tag"),
                            ("purchase", "GA4 - Purchase", "Duplicate heading value"),
                        ],
                    ),
                ]
                self.closed = False

            def close(self) -> None:
                self.closed = True

        workbook = FakeWorkbook()
        fake_openpyxl = types.ModuleType("openpyxl")
        fake_openpyxl.load_workbook = lambda *args, **kwargs: workbook
        with patch.dict(sys.modules, {"openpyxl": fake_openpyxl}):
            rows = requirement_evidence.xlsx_rows(self.root / "plan.xlsx")
        self.assertTrue(workbook.closed)
        self.assertEqual(1, len(rows))
        sheet, row_number, fields = rows[0]
        self.assertEqual("Plan", sheet)
        self.assertEqual(3, row_number)
        self.assertEqual("purchase", fields["Event"])
        self.assertEqual("Duplicate heading value", fields["Tag [2]"])

        original_import = builtins.__import__

        def reject_openpyxl(name: str, *args: object, **kwargs: object) -> object:
            if name == "openpyxl":
                raise ImportError("not installed")
            return original_import(name, *args, **kwargs)

        with (
            patch("builtins.__import__", side_effect=reject_openpyxl),
            self.assertRaisesRegex(RuntimeError, "openpyxl is required"),
        ):
            requirement_evidence.xlsx_rows(self.root / "missing-runtime.xlsx")

    def test_object_links_are_exact_candidates_not_semantic_inferences(self) -> None:
        evidence = {
            "requirements": [
                {
                    "requirement_id": "REQ-ONE",
                    "source_sheet": "Plan",
                    "source_row": 2,
                    "event_name": "purchase",
                    "object_name": "GA4 - Purchase",
                    "destination": "G-TEST",
                    "requirement": "Approved purchase",
                    "source_row_sha256": "a" * 64,
                },
                {
                    "requirement_id": "REQ-TWO",
                    "source_sheet": "Plan",
                    "source_row": 3,
                    "event_name": "view_item",
                    "object_name": "Different tag",
                    "destination": "G-OTHER",
                    "requirement": "Different requirement",
                    "source_row_sha256": "b" * 64,
                },
            ]
        }
        obj = {
            "parameter": [
                {"key": "eventName", "value": "purchase"},
                {"key": "measurementId", "value": "G-TEST"},
            ]
        }
        links = requirement_evidence.object_requirement_links(
            obj, "GA4 - Purchase", evidence
        )
        self.assertEqual(1, len(links))
        self.assertEqual(
            ["exact_object_name", "exact_event_value", "exact_destination_value"],
            links[0]["match_types"],
        )
        self.assertIn("Exact text/value match only", links[0]["interpretation_boundary"])
        self.assertEqual([], requirement_evidence.object_requirement_links(obj, "Tag", None))

    def test_cli_success_and_failure_paths(self) -> None:
        source = self.root / "requirements.json"
        output = self.root / "requirements-evidence.json"
        source.write_text('[{"event": "login"}]', encoding="utf-8")
        with patch.object(sys, "argv", ["gtm_requirement_evidence.py", str(source), str(output)]):
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                self.assertEqual(0, requirement_evidence.main())
        self.assertTrue(output.is_file())
        self.assertEqual("pass", json.loads(stdout.getvalue())["status"])

        invalid = self.root / "requirements.txt"
        invalid.write_text("invalid", encoding="utf-8")
        with patch.object(sys, "argv", ["gtm_requirement_evidence.py", str(invalid), str(output)]):
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                self.assertEqual(1, requirement_evidence.main())
        self.assertIn("approved requirements must be", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
