"""A repeated scaffold command must not damage existing reconciliation work."""

import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from gtm_reconciliation import scaffold_reconciliation


class ReconciliationPreservationTests(unittest.TestCase):
    def test_existing_draft_is_rejected_before_any_reconstruction_or_write(self):
        for name in ("reconciliation-scaffold.json", "reconciliation-seal.json",
                     "reconciliation-units", "reconciliation-completion.json"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                package = Path(temporary)
                target = package / name
                if name == "reconciliation-units":
                    target.mkdir()
                    target = target / "authored.json"
                target.write_text('{"authored": true}\n', encoding="utf-8")
                before = {p.relative_to(package): p.read_bytes()
                          for p in package.rglob("*") if p.is_file()}
                with mock.patch("gtm_reconciliation._reconciliation_scaffold_payloads") as build:
                    with self.assertRaisesRegex(FileExistsError, "preserve completed work"):
                        scaffold_reconciliation(package)
                    build.assert_not_called()
                after = {p.relative_to(package): p.read_bytes()
                         for p in package.rglob("*") if p.is_file()}
                self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()
