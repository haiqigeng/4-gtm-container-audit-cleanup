from __future__ import annotations

# Local script imports follow the explicit test path setup.
# ruff: noqa: E402
import contextlib
import io
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))

from test_v2_workflow import (
    build_package,
    complete_audit,
    complete_base_reconciliation,
    complete_checkpoint,
    complete_sharded_work_units,
    create_directory_redirect,
    minimal_export,
    remove_directory_redirect,
    write_audit_amendment,
)

import gtm_audit_repair as repair
from gtm_canonical_record import build_canonical_record, canonical_record_seal_errors
from gtm_cleanroom_audit import seal_audit, sealed_audit_errors
from gtm_lib import stable_hash, write_json
from gtm_target_synthesis import compile_operation_packet
from gtm_target_validation import validate_target


class AuditRepairTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.fixture_temp = tempfile.TemporaryDirectory()
        cls.fixture_root = Path(cls.fixture_temp.name)
        cls.fixture = cls.fixture_root / "sealed"
        source = cls.fixture_root / "source.json"
        write_json(source, minimal_export())
        build_package(source, cls.fixture)
        for audit_id in ("audit-a", "audit-b"):
            complete_checkpoint(cls.fixture, audit_id, f"fixture-{audit_id}-source-context")
            complete_audit(cls.fixture, audit_id)
        complete_base_reconciliation(cls.fixture)
        compile_operation_packet(cls.fixture)
        validate_target(cls.fixture)
        build_canonical_record(cls.fixture)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.fixture_temp.cleanup()

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.package = self.root / "predecessor"
        self.output = self.root / "successor"
        shutil.copytree(self.fixture, self.package)
        self.canonical = repair._load(self.package / "canonical-record.json")["audit_decisions"][0]
        self.canonical_id = self.canonical["canonical_decision_id"]
        self.reason = "Correct the exact owning decision after a concrete delivery wording defect."

    def reopen(self, ids: list[str] | None = None) -> dict:
        return repair.reopen_audit(self.package, self.output, ids or [self.canonical_id], self.reason)

    def test_postcanonical_copy_preserves_every_retained_byte_and_all_seals(self) -> None:
        write_json(self.package / "delivery" / "delivery-map.json", {"old": "generated output"})
        write_json(self.package / "analyst-notes.json", {"keep": "unrelated material"})
        before = repair._inventory(self.package)
        receipt = self.reopen()
        self.assertEqual(before, repair._inventory(self.package))
        for name, digest in before.items():
            path = self.output / name
            if name.split("/")[0] in repair.DOWNSTREAM:
                self.assertFalse(path.exists(), name)
            elif digest is not None:
                self.assertEqual((self.package / name).read_bytes(), path.read_bytes(), name)
        self.assertEqual([], sealed_audit_errors(self.output))
        self.assertEqual(receipt, repair._load(self.output / receipt["receipt_path"]))
        self.assertEqual([self.canonical_id], receipt["requested_decision_ids"])
        self.assertEqual(self.reason, receipt["reason"])
        self.assertEqual(before, receipt["predecessor_inventory"])
        self.assertEqual({"audit-a", "audit-b"}, {
            row["audit_id"] for row in receipt["requests"][0]["owning_decisions"]
        })

    def test_existing_amendment_path_changes_only_the_exact_decision(self) -> None:
        before = repair._inventory(self.package)
        audit_before = repair._load(self.package / "audits" / "audit-a.json")
        owner = next(row for row in audit_before["decisions"]
                     if row["obligation_id"] == self.canonical["obligation_id"])
        receipt = self.reopen([owner["decision_id"]])
        self.assertEqual(["audit-a"], [
            row["audit_id"] for row in receipt["requests"][0]["owning_decisions"]
        ])
        prior = repair._load(self.output / "audit-seals" / "audit-a.json")
        write_audit_amendment(
            self.output, "audit-a", parent_seal_sha256=prior["audit_seal_sha256"],
            context_id="repair-source-context", agent_id="repair-source-agent",
        )
        path = self.output / "audit-bundles" / "audit-a" / "audit.json"
        audit = repair._load(path)
        for row in audit["decisions"]:
            if row["decision_id"] == owner["decision_id"]:
                row["criteria_assessment"] += " This exact source absence was checked for the repair."
        write_json(path, audit)
        seal_audit(self.output, "audit-a", amendment_of=prior["audit_seal_sha256"])
        self.assertEqual([], sealed_audit_errors(self.output))
        current = repair._load(self.output / "audits" / "audit-a.json")
        for previous, amended in zip(audit_before["decisions"], current["decisions"], strict=True):
            if previous["decision_id"] != owner["decision_id"]:
                self.assertEqual(previous, amended)
        self.assertEqual((self.package / "audits" / "audit-b.json").read_bytes(),
                         (self.output / "audits" / "audit-b.json").read_bytes())
        self.assertEqual(before, repair._inventory(self.package))
        # The old unit tree must be absent so the ordinary scaffold can run.
        complete_base_reconciliation(self.output, agent_id="repair-reconciler", context_id="repair-reconciliation")
        self.assertTrue((self.output / "reconciliation-units" / "manifest.json").is_file())
        compile_operation_packet(self.output)
        validate_target(self.output)
        build_canonical_record(self.output)
        self.assertEqual([], canonical_record_seal_errors(self.output))

    def test_precanonical_target_failure_can_reopen_by_obligation(self) -> None:
        for name in ("canonical-record.json", "canonical-record-manifest.json", "canonical-record-seal.json"):
            (self.package / name).unlink()
        write_json(self.package / "target-validation" / "failure.json", {"status": "fail"})
        receipt = self.reopen([self.canonical["obligation_id"]])
        self.assertEqual([self.canonical["obligation_id"]], receipt["requests"][0]["obligation_ids"])
        self.assertFalse((self.output / "target-validation").exists())

    def test_invalid_request_never_creates_output(self) -> None:
        before = repair._inventory(self.package)
        for ids, reason in (([], self.reason), (["missing"], self.reason),
                            ([self.canonical_id] * 2, self.reason),
                            ([self.canonical_id], " "), ([" "], self.reason)):
            with self.subTest(ids=ids, reason=reason), self.assertRaises(ValueError):
                repair.reopen_audit(self.package, self.output, ids, reason)
            self.assertFalse(self.output.exists())
        self.assertEqual(before, repair._inventory(self.package))

    def test_changed_source_and_rehashed_root_manifest_are_rejected(self) -> None:
        source = self.package / "locked-source.json"
        payload = repair._load(source)
        payload["containerVersion"]["container"]["name"] = "Substituted source"
        write_json(source, payload)
        with self.assertRaisesRegex(ValueError, "changed"):
            self.reopen()
        manifest_path = self.package / "audit-package-manifest.json"
        manifest = repair._load(manifest_path)
        manifest["source_sha256"] = repair.file_sha256(source)
        for row in manifest["artifacts"]:
            if row["path"] == "locked-source.json":
                row["sha256"] = manifest["source_sha256"]
        manifest["package_manifest_sha256"] = stable_hash({
            key: value for key, value in manifest.items() if key != "package_manifest_sha256"
        }, 64)
        write_json(manifest_path, manifest)
        with self.assertRaisesRegex(ValueError, "differs"):
            self.reopen()
        self.assertFalse(self.output.exists())

    def test_nested_existing_and_redirected_destinations_are_rejected(self) -> None:
        for output in (self.package, self.package / "nested", self.root):
            with self.subTest(output=output), self.assertRaises(ValueError):
                repair.reopen_audit(self.package, output, [self.canonical_id], self.reason)
        self.output.mkdir()
        with self.assertRaises(FileExistsError):
            self.reopen()
        redirect = self.root / "redirect"
        create_directory_redirect(redirect, self.package)
        try:
            with self.assertRaisesRegex(ValueError, "reparse"):
                repair.reopen_audit(self.package, redirect / "nested", [self.canonical_id], self.reason)
        finally:
            remove_directory_redirect(redirect)

    def test_redirect_anywhere_in_source_is_rejected(self) -> None:
        redirect = self.package / "delivery"
        create_directory_redirect(redirect, self.root)
        try:
            with self.assertRaisesRegex(ValueError, "reparse"):
                self.reopen()
            self.assertFalse(self.output.exists())
        finally:
            remove_directory_redirect(redirect)

    def test_copy_and_receipt_failures_leave_no_partial_successor(self) -> None:
        before = repair._inventory(self.package)
        for target in ("copytree", "write_json"):
            owner = repair.shutil if target == "copytree" else repair
            with (
                self.subTest(target=target),
                mock.patch.object(owner, target, side_effect=OSError("injected")),
                self.assertRaisesRegex(OSError, "injected"),
            ):
                self.reopen()
            self.assertFalse(self.output.exists())
            self.assertEqual([], list(self.root.glob(".audit-repair-*")))
            self.assertEqual(before, repair._inventory(self.package))

    def test_old_fixed_point_package_is_not_migrated(self) -> None:
        (self.package / "fixed-point").mkdir()
        with self.assertRaisesRegex(ValueError, "cannot be reopened or migrated"):
            self.reopen()
        self.assertFalse(self.output.exists())

    def test_cli_errors_are_structured_and_exit_two(self) -> None:
        arguments = ["gtm_audit_repair.py", str(self.package), str(self.output),
                     "--decision-id", self.canonical_id, "--reason", self.reason]
        for failure in (OSError("copy failed"), ValueError("invalid source"),
                        KeyError("decision_id"), TypeError("invalid record")):
            stdout = io.StringIO()
            with (self.subTest(failure=failure), mock.patch.object(sys, "argv", arguments),
                  mock.patch.object(repair, "reopen_audit", side_effect=failure),
                  contextlib.redirect_stdout(stdout)):
                self.assertEqual(2, repair.main())
            self.assertEqual({"status": "blocked", "errors": [str(failure)]},
                             json.loads(stdout.getvalue()))
            self.assertFalse(self.output.exists())

    def test_discovery_owner_uses_nested_decision_id_or_discovery_id(self) -> None:
        original_load = repair._load
        for nested_id in ("AUDIT-A-DEC-DISCOVERY", ""):
            discovery_id = "AUDIT-A-DISC-EXACT"

            def load_with_discovery(
                path: Path, discovery_id=discovery_id, nested_id=nested_id,
            ) -> dict:
                payload = original_load(path)
                if path == self.package / "audits" / "audit-a.json":
                    payload["open_discoveries"] = [{
                        "discovery_id": discovery_id,
                        "area_id": "02", "scope_level": "relationship",
                        "subject_keys": [], "family_ids": [], "source_coordinates": [],
                        "decision": {"decision_id": nested_id},
                    }]
                return payload

            with self.subTest(nested_id=nested_id), mock.patch.object(repair, "_load", side_effect=load_with_discovery):
                requests = repair._requested_owners(self.package, [nested_id or discovery_id])
            self.assertEqual([discovery_id], requests[0]["obligation_ids"])
            self.assertEqual(nested_id or discovery_id, requests[0]["owning_decisions"][0]["decision_id"])
            self.assertEqual("audit-a", requests[0]["owning_decisions"][0]["audit_id"])

    def test_sharded_audit_history_and_prior_repair_receipts_survive(self) -> None:
        source = self.root / "sharded-source.json"
        package = self.root / "sharded-package"
        write_json(source, minimal_export())
        build_package(source, package)
        with mock.patch("gtm_audit_work_units.MAX_SINGLE_OBLIGATIONS", 1):
            for audit_id in ("audit-a", "audit-b"):
                complete_checkpoint(package, audit_id, f"sharded-{audit_id}-context")
                complete_sharded_work_units(package, audit_id)
                complete_audit(package, audit_id)
            seal = repair._load(package / "audit-seals" / "audit-a.json")
            write_audit_amendment(
                package, "audit-a", parent_seal_sha256=seal["audit_seal_sha256"],
                context_id="sharded-amendment-context", agent_id="sharded-amendment-agent",
            )
            seal_audit(package, "audit-a", amendment_of=seal["audit_seal_sha256"])
            decision_id = repair._load(package / "audits" / "audit-a.json")["decisions"][0]["decision_id"]
            first = repair.reopen_audit(package, self.output, [decision_id], self.reason)
            second_output = self.root / "second-successor"
            second = repair.reopen_audit(self.output, second_output, [decision_id], self.reason)
            self.assertEqual([], sealed_audit_errors(second_output))
            self.assertEqual(first, repair._load(second_output / first["receipt_path"]))
            self.assertNotEqual(first["receipt_path"], second["receipt_path"])
            for path in (package / "audit-seals").rglob("*"):
                if path.is_file():
                    self.assertEqual(path.read_bytes(), (second_output / path.relative_to(package)).read_bytes())


if __name__ == "__main__":
    unittest.main()
