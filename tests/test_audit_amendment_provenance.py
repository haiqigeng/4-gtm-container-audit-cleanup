"""Amendment provenance is projected by apply, never manually into audit JSON."""

from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from test_v2_workflow import (
    build_package,
    complete_checkpoint,
    minimal_export,
    write_fixture_audit_plan,
)

from gtm_audit_plan import apply_plan, main
from gtm_cleanroom_audit import _sealed_audit_record_errors, seal_audit, validate_audit


class AuditAmendmentProvenanceTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        source = self.root / "synthetic.json"
        source.write_text(json.dumps(minimal_export()), encoding="utf-8")
        self.package = self.root / "package"
        build_package(source, self.package)
        self.bundle = self.package / "audit-bundles" / "audit-a"

    def prepare(self, *, seal: bool = True) -> dict:
        complete_checkpoint(self.package, "audit-a", "initial-context")
        self.plan = write_fixture_audit_plan(self.package, "audit-a")
        before = self.read_audit()
        apply_plan(self.bundle, self.plan)
        after = self.read_audit()
        for field in ("independent_agent_id", "independent_context_id", "input_manifest_sha256"):
            self.assertEqual(before[field], after[field])
        self.assertNotIn("amendment_parent_seal_sha256", after)
        self.assertEqual([], validate_audit(self.package, "audit-a"))
        return seal_audit(self.package, "audit-a") if seal else {}

    def read_audit(self) -> dict:
        return json.loads((self.bundle / "audit.json").read_text(encoding="utf-8"))

    def snapshot(self) -> dict:
        return {
            path.relative_to(self.package): path.read_bytes()
            for path in self.package.rglob("*") if path.is_file()
        }

    def test_cli_projects_only_provenance_and_normal_seal_succeeds(self) -> None:
        for sharded in (False, True):
            with self.subTest(sharded=sharded), mock.patch(
                "gtm_audit_work_units.MAX_SINGLE_OBLIGATIONS", 1 if sharded else 100000
            ):
                if sharded:
                    # A second isolated synthetic package exercises the merge path.
                    self.package = self.root / "sharded"
                    build_package(self.root / "synthetic.json", self.package)
                    self.bundle = self.package / "audit-bundles" / "audit-a"
                previous = self.prepare()
                before = self.read_audit()
                argv = [
                    "gtm_audit_plan.py", "apply", str(self.bundle), str(self.plan),
                    "--amendment-of", previous["audit_seal_sha256"],
                    "--agent-id", "amending-agent", "--context-id", "amending-context",
                ]
                with mock.patch.object(sys, "argv", argv), contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(0, main())
                self.assertEqual({
                    **before,
                    "amendment_parent_seal_sha256": previous["audit_seal_sha256"],
                    "independent_agent_id": "amending-agent",
                    "independent_context_id": "amending-context",
                }, self.read_audit())
                self.assertEqual([], validate_audit(
                    self.package, "audit-a", amendment_of=previous["audit_seal_sha256"]
                ))
                sealed = seal_audit(
                    self.package, "audit-a", amendment_of=previous["audit_seal_sha256"]
                )
                self.assertEqual(1, sealed["amendment_sequence"])
                self.assertEqual([], _sealed_audit_record_errors(self.package, "audit-a"))
                snapshot = self.snapshot()
                with self.assertRaisesRegex(ValueError, "current audit seal"):
                    apply_plan(
                        self.bundle, self.plan, amendment_of=previous["audit_seal_sha256"],
                        agent_id="another-agent", context_id="another-context",
                    )
                self.assertEqual(snapshot, self.snapshot())

    def test_invalid_arguments_and_reused_identities_fail_before_any_write(self) -> None:
        previous = self.prepare()
        complete_checkpoint(self.package, "audit-b", "peer-context")
        peer_plan = write_fixture_audit_plan(self.package, "audit-b")
        apply_plan(self.package / "audit-bundles" / "audit-b", peer_plan)
        peer = seal_audit(self.package, "audit-b")
        valid = {
            "amendment_of": previous["audit_seal_sha256"],
            "agent_id": "new-agent", "context_id": "new-context",
        }
        cases = [{}]
        for field in valid:
            cases.extend({**valid, field: value} for value in (None, "", " ", 42))
        cases.append({**valid, "amendment_of": "0" * 64})
        assurance = json.loads((self.package / "scan-assurance.json").read_text(encoding="utf-8"))
        for identity in (previous, peer, assurance):
            for argument, field in (
                ("agent_id", "independent_agent_id"),
                ("context_id", "independent_context_id"),
            ):
                cases.append({**valid, argument: f" {identity[field]} "})
        before = self.snapshot()
        for arguments in cases:
            with self.subTest(arguments=arguments), self.assertRaises(ValueError):
                apply_plan(self.bundle, self.plan, **arguments)
            self.assertEqual(before, self.snapshot())

    def test_missing_parent_fails_before_writes(self) -> None:
        self.prepare(seal=False)
        before = self.snapshot()
        with self.assertRaisesRegex(ValueError, "prior audit seal"):
            apply_plan(self.bundle, self.plan, amendment_of="0" * 64,
                       agent_id="new-agent", context_id="new-context")
        self.assertEqual(before, self.snapshot())

    def test_amendment_provenance_does_not_bypass_semantic_plan_gate(self) -> None:
        previous = self.prepare()
        plan = json.loads(self.plan.read_text(encoding="utf-8"))
        plan["decision_profiles"] = []
        self.plan.write_text(json.dumps(plan), encoding="utf-8")
        before = self.snapshot()
        with self.assertRaisesRegex(ValueError, "unassigned"):
            apply_plan(
                self.bundle, self.plan, amendment_of=previous["audit_seal_sha256"],
                agent_id="new-agent", context_id="new-context",
            )
        self.assertEqual(before, self.snapshot())

    def test_broken_parent_and_closed_canonical_gate_fail_before_writes(self) -> None:
        previous = self.prepare()
        arguments = {
            "amendment_of": previous["audit_seal_sha256"],
            "agent_id": "new-agent", "context_id": "new-context",
        }
        seal_path = self.package / "audit-seals" / "audit-a.json"
        original = seal_path.read_bytes()
        changed = {**previous, "input_manifest_sha256": "tampered"}
        seal_path.write_text(json.dumps(changed), encoding="utf-8")
        before = self.snapshot()
        with self.assertRaisesRegex(ValueError, "provenance gate"):
            apply_plan(self.bundle, self.plan, **arguments)
        self.assertEqual(before, self.snapshot())
        seal_path.write_bytes(original)
        (self.package / "canonical-record-seal.json").write_text("{}", encoding="utf-8")
        before = self.snapshot()
        with self.assertRaisesRegex(ValueError, "closed after canonical"):
            apply_plan(self.bundle, self.plan, **arguments)
        self.assertEqual(before, self.snapshot())


if __name__ == "__main__":
    unittest.main()
