"""Display localisation tests; the synthetic canonical fixture is not an audit."""
from __future__ import annotations

import copy
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from gtm_delivery_mapper import (  # noqa: E402
    create_delivery_map,
    display_prose_defaults,
    display_prose_errors,
    seal_editorial,
    validate_editorial,
)
from gtm_delivery_reviews import _expected_fidelity_input  # noqa: E402
from gtm_lib import file_sha256, stable_hash, write_json  # noqa: E402


def canonical_fixture():
    decisions = [{
        "canonical_decision_id": identity, "area_id": "AREA-26",
        "area_title": "Business architecture", "subject_keys": ["tag:1"],
        "human_decision_label": "Appropriate as configured",
        "decision": {
            "decision_class": "justified_as_is", "priority": "None", "confidence": "High",
            "criteria_assessment": "Le nom purchase et la destination G-DEMO restent inchangés.",
        },
    } for identity in ("CD-ONE", "CD-CODE")]
    return {
        "canonical_record_sha256": "synthetic-localisation-fixture",
        "source": {"scope_boundary": "Exemple statique de localisation, sans modification GTM.",
                   "container_identity": {"public_id": "GTM-DEMO"},
                   "object_directory": [{"object_key": "tag:1", "object_name": "GA4 - purchase"}]},
        "audit_decisions": decisions, "operations": [], "decision_to_operation": {},
        "owner_decision_ids": [], "custom_code_decision_ids": ["CD-CODE"],
        "summary": {"decision_counts": {"justified_as_is": 2}, "priority_counts": {"None": 2}},
    }


def french_display(display):
    result = copy.deepcopy(display)
    result.update(navigation_prefix="Sections — utilisez les onglets :",
                  navigation_current="actuel", focus_label="Objet")
    titles = ["Audit et optimisation GTM", "Recommandations", "Décisions attendues", "Audit complet", "Analyse du code"]
    headers = [None,
        ["Action + ID", "Domaine", "Type + priorité", "Périmètre", "État actuel", "Enjeu", "Cible", "Transmission", "Vérification / retour"],
        ["ID décision", "Domaine", "Priorité", "Question", "Motif", "Recommandation", "Périmètre", "Suite possible"],
        ["ID audit", "Domaine", "Objet détaillé", "Périmètre", "Décision", "Constat", "Suite / action", "Priorité", "Confiance"],
        ["ID audit", "Domaine", "Code concerné", "État actuel", "Décision", "Constat", "Cible", "Action liée", "Priorité", "Confiance statique"],
    ]
    for index, sheet in enumerate(result["sheets"].values()):
        sheet["title"] = titles[index]
        if index:
            sheet["headers"] = headers[index]
            sheet["subtitle"] = "Exemple de localisation ; les identifiants techniques sont conservés."
            sheet["empty_message"] = "Aucun élément dans cette section."
    result["overview"] = {
        "decision_headers": ["Type de décision", "Nombre", "Interprétation"],
        "priority_headers": ["Priorité", "Nombre", "Ordre de lecture"],
        "summary_labels": ["Actions prioritaires", "Couverture", "Architecture cible", "Configuration conservée", "Décisions et limites", "Prochaine étape"],
        "delta_headers": ["Évolution des objets", "Source", "Cible", "Écart"],
        "empty_deltas": "Aucune variation du nombre d’objets.",
        "no_actions": "Aucune",
        "coverage_summary": "2 constats : 04 Full Audit (1) et 05 Custom Code (1). 03 Decisions Needed (0) ; 02 Recommendations (0).",
    }
    return result


class WorkbookLocalisationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="gtm-localisation-")
        self.addCleanup(self.temporary.cleanup)
        self.package = Path(self.temporary.name)
        # Only upstream audit qualification is mocked; delivery reconstruction,
        # editorial validation/sealing and workbook commands remain production code.
        gate = patch("gtm_delivery_mapper.canonical_record_seal_errors", return_value=[])
        gate.start()
        self.addCleanup(gate.stop)
        write_json(self.package / "locked-source.json", {
            "containerVersion": {"tag": [{"tagId": "1", "name": "GA4 - purchase"}]}
        })
        canonical = canonical_fixture()
        canonical["source"]["source_sha256"] = file_sha256(self.package / "locked-source.json")
        write_json(self.package / "canonical-record.json", canonical)
        create_delivery_map(self.package, "French")
        self.map = json.loads((self.package / "delivery/delivery-map.json").read_text(encoding="utf-8"))
        self.editorial_path = self.package / "delivery/editorial.json"
        self.editorial = json.loads(self.editorial_path.read_text(encoding="utf-8"))
        self.editorial["status"] = "complete"
        self.editorial["completion_attestation"].update(
            technical_identifiers_preserved=True, conclusion="Identifiants conservés.")

    def test_english_defaults_and_french_closed_display_schema(self):
        english = display_prose_defaults(self.map)
        self.assertEqual("Recommendations", english["sheets"]["02 Recommendations"]["title"])
        self.assertEqual("Action + operation ID", english["sheets"]["02 Recommendations"]["headers"][0])
        self.assertEqual(english, self.editorial["display_prose"])
        french = french_display(english)
        self.assertEqual([], display_prose_errors(french, english))
        for mutation in ("rename_sheet", "drop_column", "blank", "nontext", "duplicate"):
            invalid = copy.deepcopy(french)
            sheet = invalid["sheets"]["02 Recommendations"]
            if mutation == "rename_sheet":
                invalid["sheets"]["02 Recommandations"] = invalid["sheets"].pop("02 Recommendations")
            elif mutation == "drop_column":
                sheet["headers"].pop()
            elif mutation == "blank":
                sheet["subtitle"] = " "
            elif mutation == "duplicate":
                sheet["headers"][1] = sheet["headers"][0]
            else:
                sheet["title"] = {"formula": "=1"}
            with self.subTest(mutation=mutation):
                self.assertTrue(display_prose_errors(invalid, english))

    def test_editorial_validation_and_fidelity_keep_canonical_identity(self):
        original_map = copy.deepcopy(self.map)
        self.editorial["display_prose"] = french_display(self.editorial["display_prose"])
        write_json(self.editorial_path, self.editorial)
        self.assertEqual([], validate_editorial(self.package))
        manifest = {"workbook_file_sha256": "fixture", "normalized_model": {"sheets": []}}
        fidelity = _expected_fidelity_input(self.package, manifest)
        self.assertEqual(display_prose_defaults(self.map), fidelity["display_prose_canonical"])
        self.assertEqual(self.editorial["display_prose"], fidelity["display_prose_delivered"])
        self.assertEqual(fidelity["fidelity_input_sha256"], stable_hash(
            {key: value for key, value in fidelity.items() if key != "fidelity_input_sha256"}, 64))
        for field in ("display_prose_canonical", "display_prose_delivered"):
            changed = copy.deepcopy(fidelity)
            changed[field]["sheets"]["02 Recommendations"]["headers"][0] = "Changed meaning"
            self.assertNotEqual(fidelity["fidelity_input_sha256"], stable_hash(
                {key: value for key, value in changed.items() if key != "fidelity_input_sha256"}, 64))
        self.editorial["display_prose"]["sheets"]["02 Recommendations"]["title"] = "Actions proposées"
        write_json(self.editorial_path, self.editorial)
        reconstructed = _expected_fidelity_input(self.package, manifest)
        self.assertNotEqual(fidelity["fidelity_input_sha256"], reconstructed["fidelity_input_sha256"])
        self.assertEqual(fidelity["display_prose_canonical"], reconstructed["display_prose_canonical"])
        self.assertEqual(fidelity["rows"], reconstructed["rows"])
        for field in ("workbook_file_sha256", "canonical_record_sha256", "delivery_map_sha256"):
            self.assertEqual(fidelity[field], reconstructed[field])
        self.assertEqual([row["locked"] for row in self.map["rows"]],
                         [row["canonical_locked_fields"] for row in fidelity["rows"]])
        self.assertEqual(original_map, json.loads((self.package / "delivery/delivery-map.json").read_text(encoding="utf-8")))
        self.editorial["language"] = "English"
        write_json(self.editorial_path, self.editorial)
        self.assertIn("editorial language differs from the delivery map", validate_editorial(self.package))

    @unittest.skipUnless(os.environ.get("CODEX_NODE") and os.environ.get("CODEX_ARTIFACT_NODE_MODULES"),
                         "bundled spreadsheet runtime paths were not supplied")
    def test_french_build_reimport_and_display_binding(self):
        self.editorial["display_prose"] = french_display(self.editorial["display_prose"])
        write_json(self.editorial_path, self.editorial)
        seal_editorial(self.package)
        for script in ("gtm_workbook_build.mjs", "gtm_workbook_verify.mjs"):
            run = subprocess.run([os.environ["CODEX_NODE"], str(ROOT / "scripts" / script), str(self.package)],
                                 capture_output=True, text=True, encoding="utf-8", timeout=120)
            self.assertEqual(0, run.returncode, run.stdout + run.stderr)
        build = self.package / "delivery/builds/build-000"
        manifest = json.loads((build / "workbook-build-manifest.json").read_text(encoding="utf-8"))
        model = manifest["normalized_model"]
        self.assertEqual(self.map["visible_sheets"], model["visible_sheets"])
        for sheet in model["sheets"]:
            self.assertIn("Sections — utilisez les onglets :", sheet["nav"])
            self.assertIn(f"{sheet['name']} (actuel)", sheet["nav"])
            if sheet.get("headers"):
                self.assertEqual(self.editorial["display_prose"]["sheets"][sheet["name"]]["headers"], sheet["headers"])
        rows = {row["row_id"]: row for sheet in model["sheets"] for row in sheet.get("rows", [])}
        for row in self.map["rows"]:
            self.assertEqual(row["locked"], rows[row["row_id"]]["locked"])
        report = json.loads((build / "technical-verification.json").read_text(encoding="utf-8"))
        self.assertEqual("pass", report["status"])
        example = os.environ.get("GTM_LOCALISATION_EXAMPLE")
        if example:
            shutil.copytree(build, example)
            print(f"French heading example: {example}")
        # A changed display artifact cannot reuse the verified build.
        self.editorial["display_prose"]["sheets"]["02 Recommendations"]["title"] = "Autre titre"
        write_json(self.editorial_path, self.editorial)
        run = subprocess.run([os.environ["CODEX_NODE"], str(ROOT / "scripts/gtm_workbook_verify.mjs"), str(self.package)],
                             capture_output=True, text=True, encoding="utf-8", timeout=120)
        self.assertNotEqual(0, run.returncode)
        self.assertIn("display prose differs", run.stdout)


if __name__ == "__main__":
    unittest.main()
