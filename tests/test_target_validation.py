"""Behavioral fixtures for deterministic validation, never real audit judgments."""

from __future__ import annotations

# Local script imports follow the explicit test path setup.
# ruff: noqa: E402
import copy
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from test_v2_workflow import (
    actionable_priority_export,
    build_package,
    complete_audit,
    complete_base_reconciliation,
    complete_checkpoint,
    create_directory_redirect,
    finalize_audit,
    remove_directory_redirect,
)

import gtm_target_validation as target_validation
from gtm_canonical_record import build_canonical_record, canonical_record_seal_errors
from gtm_cleanroom_audit import seal_audit
from gtm_lib import file_sha256, stable_hash, write_json
from gtm_operation_model import operation_packet_sha256
from gtm_target_synthesis import compile_operation_packet

TARGET_FILES = (
    "projected-container.json",
    "canonical-scan.json",
    "scan-assurance.json",
    "validation-proof.json",
    "validation-seal.json",
)
SELF_HASH_FIELDS = {
    "operation-packet.json": "operation_record_sha256",
    "canonical-scan.json": "canonical_scan_sha256",
    "scan-assurance.json": "scan_assurance_sha256",
    "validation-proof.json": "validation_proof_sha256",
    "validation-seal.json": "validation_seal_sha256",
}


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def file_snapshot(root):
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in root.rglob("*") if path.is_file()
    }


def rehash(payload, field):
    payload[field] = stable_hash({k: v for k, v in payload.items() if k != field}, 64)


def prepare_graph_fixture(root, source_payload, extra_actions=None):
    """Seal synthetic source judgments before exercising graph validation."""
    source = root / "source.json"
    package = root / "package"
    write_json(source, source_payload)
    build_package(source, package)
    for owner in ("audit-a", "audit-b"):
        complete_checkpoint(package, owner, owner + "-source-context")
        finalize_audit(package, owner, actionable_priority=True)
        if extra_actions:
            audit_path = package / "audit-bundles" / owner / "audit.json"
            audit = read_json(audit_path)
            row = next(r for r in audit["decisions"] if r["fact_kind"] == "explicit_firing_priority")
            proposal = row["operation_proposal"]
            proposal.update(copy.deepcopy(extra_actions))
            proposal["operation_family"] = "Exercise graph safety"
            row["target_direction"] = proposal["exact_target_state"] = (
                "Apply exactly the synthetic fixture actions to exercise the target graph gate."
            )
            write_json(audit_path, audit)
        seal_audit(package, owner)
    complete_base_reconciliation(package)
    compile_operation_packet(package)
    return package


def rebind_forged_artifacts(paths, changed_path, mutation):
    """Forge all dependent hashes so rejection must come from reconstruction."""
    replacements = {}

    def replace_hashes(value):
        if isinstance(value, dict):
            return {key: replace_hashes(item) for key, item in value.items()}
        if isinstance(value, list):
            return [replace_hashes(item) for item in value]
        return replacements.get(value, value) if isinstance(value, str) else value

    for path in paths:
        old = read_json(path)
        old_file_hash = file_sha256(path)
        updated = replace_hashes(old)
        if path == changed_path:
            mutation(updated)
        if path.name == "operation-packet.json":
            updated["operation_packet_sha256"] = operation_packet_sha256(updated["operations"])
            replacements[old["operation_packet_sha256"]] = updated["operation_packet_sha256"]
        field = SELF_HASH_FIELDS.get(path.name)
        if field:
            rehash(updated, field)
            replacements[old[field]] = updated[field]
        write_json(path, updated)
        replacements[stable_hash(old, 64)] = stable_hash(updated, 64)
        replacements[old_file_hash] = file_sha256(path)


class TargetValidationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.package = self.root / "package"
        source = self.root / "source.json"
        write_json(source, actionable_priority_export())
        build_package(source, self.package)
        for owner in ("audit-a", "audit-b"):
            complete_checkpoint(self.package, owner, owner + "-source-context")
            complete_audit(self.package, owner, actionable_priority=True)
        complete_base_reconciliation(self.package)
        compile_operation_packet(self.package)
        self.target = self.package / "target-validation"

    def validate(self):
        result = target_validation.validate_target(self.package)
        self.assertEqual("pass", result["status"])
        self.assertEqual([], target_validation.target_validation_seal_errors(self.package))
        return result

    def assert_cannot_deliver(self):
        self.assertTrue(target_validation.target_validation_seal_errors(self.package))
        with self.assertRaises(ValueError):
            build_canonical_record(self.package)
        self.assertFalse((self.package / "canonical-record-seal.json").exists())

    def test_source_pass_produces_only_five_target_artifacts_without_semantic_queues(self):
        before = file_snapshot(self.package)
        packet = read_json(self.package / "operation-packet.json")
        self.assertEqual("ready_for_target_validation", packet["status"])
        self.assertFalse((self.package / "projected-container.json").exists())
        self.validate()
        after = file_snapshot(self.package)
        self.assertEqual(before, {name: after[name] for name in before})
        self.assertEqual(
            {"target-validation/" + name for name in TARGET_FILES}, set(after) - set(before)
        )
        self.assertEqual(set(TARGET_FILES), {p.name for p in self.target.iterdir()})
        for obsolete in ("fixed-point", "projection-scratch", "projection-decisions.json"):
            self.assertFalse((self.package / obsolete).exists())
        self.assertFalse(list(self.package.rglob("cycle-*")))
        proof = read_json(self.target / "validation-proof.json")
        self.assertEqual("pass", proof["status"])
        for key in ("max_cycles", "current_cycle", "cycle_history", "canonical_decisions"):
            self.assertNotIn(key, proof)

    def test_target_is_exact_and_preserves_every_unmodified_source_field(self):
        source = read_json(self.package / "locked-source.json")
        expected = copy.deepcopy(source)
        expected["containerVersion"]["tag"][0].pop("priority")
        self.validate()
        self.assertEqual(expected, read_json(self.target / "projected-container.json"))
        self.assertEqual(source, read_json(self.package / "locked-source.json"))

    def test_equivalent_packages_produce_byte_identical_validation_and_readonly_replay(self):
        duplicate = self.root / "duplicate-package"
        shutil.copytree(self.package, duplicate)
        self.validate()
        result = target_validation.validate_target(duplicate)
        self.assertEqual("pass", result["status"])
        self.assertEqual(file_snapshot(self.target), file_snapshot(duplicate / "target-validation"))
        before = file_snapshot(self.package)
        self.assertEqual([], target_validation.target_validation_seal_errors(self.package))
        self.assertEqual(before, file_snapshot(self.package))
        with self.assertRaisesRegex(ValueError, "already exist"):
            target_validation.validate_target(self.package)
        self.assertEqual(before, file_snapshot(self.package))

    def test_canonical_decisions_are_exactly_the_source_reconciled_set(self):
        original = (self.package / "reconciled-decisions.json").read_bytes()
        self.validate()
        build_canonical_record(self.package)
        record = read_json(self.package / "canonical-record.json")
        reconciled = json.loads(original)["canonical_decisions"]
        self.assertEqual(
            {row["canonical_decision_id"]: row["decision"] for row in reconciled},
            {row["canonical_decision_id"]: row["decision"] for row in record["audit_decisions"]},
        )
        self.assertEqual(len(reconciled), len(record["audit_decisions"]))
        self.assertTrue(all(
            row["record_owner"]["owner_kind"] == "source_audit_and_reconciliation"
            for row in record["audit_decisions"]
        ))
        self.assertEqual(original, (self.package / "reconciled-decisions.json").read_bytes())
        self.assertEqual("pass", record["target_validation"]["status"])
        self.assertNotIn("fixed_point", record)

    def test_rehashed_historical_decision_cannot_be_appended_to_canonical_record(self):
        self.validate()
        build_canonical_record(self.package)
        path = self.package / "canonical-record.json"
        record = read_json(path)
        history = copy.deepcopy(record["audit_decisions"][0])
        history["canonical_decision_id"] = "PCD-C01-FORGED-HISTORY"
        record["audit_decisions"].append(history)
        rehash(record, "canonical_record_sha256")
        write_json(path, record)
        self.assertTrue(any(
            "deterministic reconstruction" in error
            for error in canonical_record_seal_errors(self.package)
        ))

    def test_rehashed_target_forgery_is_rejected(self):
        self.validate()
        path = self.target / "projected-container.json"

        def forge(payload):
            payload["containerVersion"]["tag"][0]["name"] = "Unsupported target"

        rebind_forged_artifacts([self.target / name for name in TARGET_FILES], path, forge)
        self.assert_cannot_deliver()

    def test_rehashed_packet_forgery_cannot_author_new_target_semantics(self):
        self.validate()
        path = self.package / "operation-packet.json"

        def forge(payload):
            payload["operations"][0]["exact_target_state"] = "Delete every tag without source support."

        rebind_forged_artifacts(
            [path] + [self.target / name for name in TARGET_FILES], path, forge
        )
        self.assert_cannot_deliver()

    def test_rehashed_scan_assurance_and_proof_forgery_are_rejected(self):
        self.validate()
        original = file_snapshot(self.target)
        for name in ("canonical-scan.json", "scan-assurance.json", "validation-proof.json"):
            with self.subTest(artifact=name):
                for filename, content in original.items():
                    (self.target / filename).write_bytes(content)
                rebind_forged_artifacts(
                    [self.target / filename for filename in TARGET_FILES],
                    self.target / name,
                    lambda payload: payload.update(unsupported_claim="Injected after source reconciliation"),
                )
                self.assert_cannot_deliver()

    def test_incomplete_or_malformed_validation_artifacts_fail_closed(self):
        self.validate()
        for name in TARGET_FILES:
            path = self.target / name
            original = path.read_bytes()
            for malformed in (b"[]", b"{", b"null"):
                with self.subTest(artifact=name, malformed=malformed):
                    path.write_bytes(malformed)
                    self.assert_cannot_deliver()
            path.unlink()
            self.assert_cannot_deliver()
            path.write_bytes(original)

    def test_scan_failure_preserves_all_source_artifacts_and_leaves_no_seal(self):
        before = file_snapshot(self.package)
        with (
            mock.patch.object(target_validation, "build_canonical_scan",
                              side_effect=ValueError("injected scan failure")),
            self.assertRaisesRegex(ValueError, "injected scan failure"),
        ):
            target_validation.validate_target(self.package)
        self.assertEqual(before, file_snapshot(self.package))
        self.assert_cannot_deliver()
        self.validate()

    def test_failed_assurance_cannot_seal_a_target_or_change_source_judgments(self):
        before = file_snapshot(self.package)
        with (
            mock.patch.object(target_validation, "assure_scan",
                              return_value={"status": "blocked", "checks": []}),
            self.assertRaises(ValueError),
        ):
            target_validation.validate_target(self.package)
        self.assertEqual(before, file_snapshot(self.package))
        self.assert_cannot_deliver()
        self.validate()

    def test_failed_artifact_commit_leaves_validation_retryable(self):
        for filename in ("validation-proof.json", "validation-seal.json"):
            with self.subTest(filename=filename):
                before = file_snapshot(self.package)

                def fail_write(path, payload, filename=filename):
                    if Path(path).name == filename:
                        raise OSError("injected artifact write failure")
                    return write_json(path, payload)

                with (
                    mock.patch.object(target_validation, "write_json", side_effect=fail_write),
                    self.assertRaisesRegex((OSError, ValueError), "injected artifact write failure"),
                ):
                    target_validation.validate_target(self.package)
                self.assertEqual(before, file_snapshot(self.package))
                self.assertFalse(self.target.exists())
                self.assert_cannot_deliver()
        self.validate()

    def test_replay_drift_fails_before_any_target_is_committed(self):
        before = file_snapshot(self.package)
        replay = read_json(self.package / "locked-source.json")
        replay["containerVersion"]["tag"][0]["name"] = "Divergent replay"
        with (
            mock.patch.object(target_validation, "apply_operations", return_value=replay),
            self.assertRaisesRegex(ValueError, "replay differs"),
        ):
            target_validation.validate_target(self.package)
        self.assertEqual(before, file_snapshot(self.package))
        self.assert_cannot_deliver()

    def test_failed_directory_commit_preserves_source_and_leaves_no_partial_target(self):
        before = file_snapshot(self.package)
        original_rename = Path.rename

        def fail_commit(path, destination):
            if Path(destination) == self.target:
                raise OSError("injected directory commit failure")
            return original_rename(path, destination)

        with (
            mock.patch.object(Path, "rename", autospec=True, side_effect=fail_commit),
            self.assertRaisesRegex((OSError, ValueError), "injected directory commit failure"),
        ):
            target_validation.validate_target(self.package)
        self.assertEqual(before, file_snapshot(self.package))
        self.assertFalse(self.target.exists())
        self.assert_cannot_deliver()
        self.validate()

    def test_target_directory_redirect_cannot_escape_package(self):
        external = self.root / "external-target"
        external.mkdir()
        write_json(external / "sentinel.json", {"must_remain": "unchanged"})
        before = file_snapshot(external)
        create_directory_redirect(self.target, external)
        try:
            with self.assertRaises(ValueError):
                target_validation.validate_target(self.package)
            self.assertTrue(target_validation.target_validation_seal_errors(self.package))
            self.assertEqual(before, file_snapshot(external))
        finally:
            remove_directory_redirect(self.target)


class TargetGraphSafetyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def test_additional_broken_occurrence_in_existing_consumer_is_blocked(self):
        for kind in ("variable", "trigger"):
            with self.subTest(kind=kind):
                source = actionable_priority_export()
                tag = source["containerVersion"]["tag"][0]
                if kind == "variable":
                    tag["parameter"].append({
                        "key": "existing", "type": "TEMPLATE", "value": "{{Missing Variable}}",
                    })
                    actions = {"changes": [{
                        "object_key": "tag:1", "json_path": "$.parameter[0].value",
                        "before": "purchase", "after": "{{Missing Variable}}",
                    }]}
                else:
                    tag["firingTriggerId"] = ["999"]
                    actions = {"changes": [{
                        "object_key": "tag:1", "json_path": "$.firingTriggerId",
                        "before": ["999"], "after": ["999", "999"],
                    }]}
                package = prepare_graph_fixture(self.root / kind, source, actions)
                before = file_snapshot(package)
                with self.assertRaisesRegex(ValueError, "target graph regression"):
                    target_validation.validate_target(package)
                self.assertEqual(before, file_snapshot(package))
                self.assertFalse((package / "target-validation").exists())

    def test_removing_earlier_parameter_does_not_create_a_broken_occurrence(self):
        source = actionable_priority_export()
        source["containerVersion"]["tag"][0]["parameter"].append({
            "key": "existing", "type": "TEMPLATE", "value": "{{Missing Variable}}",
        })
        parameters = source["containerVersion"]["tag"][0]["parameter"]
        package = prepare_graph_fixture(self.root, source, {"changes": [
            {"object_key": "tag:1", "json_path": "$.parameter",
             "before": parameters, "after": parameters[1:]},
        ]})
        self.assertEqual("pass", target_validation.validate_target(package)["status"])

    def test_unchanged_missing_references_and_cycles_preserve_source_dispositions(self):
        for kind in ("variable", "trigger", "template", "gallery_template", "cycle"):
            with self.subTest(kind=kind):
                source = actionable_priority_export()
                cv = source["containerVersion"]
                if kind == "variable":
                    cv["tag"][0]["parameter"].append(
                        {"key": "fixture", "type": "TEMPLATE", "value": "{{Missing Variable}}"}
                    )
                elif kind == "trigger":
                    cv["tag"][0]["firingTriggerId"] = ["999"]
                elif kind == "template":
                    cv["tag"].append({"tagId": "2", "name": "Missing template", "type": "cvt_1_999"})
                elif kind == "gallery_template":
                    cv["tag"].append({"tagId": "2", "name": "Missing gallery template", "type": "cvt_999"})
                else:
                    cv["variable"] = [
                        {"variableId": "20", "name": "Loop A", "type": "c", "parameter": [
                            {"key": "value", "type": "TEMPLATE", "value": "{{Loop B}}"}
                        ]},
                        {"variableId": "21", "name": "Loop B", "type": "c", "parameter": [
                            {"key": "value", "type": "TEMPLATE", "value": "{{Loop A}}"}
                        ]},
                    ]
                package = prepare_graph_fixture(self.root / kind, source)
                original = (package / "reconciled-decisions.json").read_bytes()
                self.assertEqual("pass", target_validation.validate_target(package)["status"])
                proof = read_json(package / "target-validation/validation-proof.json")
                self.assertTrue(proof["preserved_source_graph_issues"])
                self.assertEqual(original, (package / "reconciled-decisions.json").read_bytes())
                self.assertEqual([], target_validation.target_validation_seal_errors(package))

    def test_new_broken_references_and_dependency_cycles_are_blocked(self):
        for kind in ("new_consumer", "deleted_trigger", "deleted_gallery_template", "ambiguous_gallery_template", "new_cycle"):
            with self.subTest(kind=kind):
                source = actionable_priority_export()
                if kind == "new_consumer":
                    source["containerVersion"]["variable"].append({
                        "variableId": "20", "name": "Existing broken consumer", "type": "c",
                        "parameter": [{"key": "value", "type": "TEMPLATE", "value": "{{Missing Variable}}"}],
                    })
                    actions = {"changes": [{
                        "object_key": "tag:1", "json_path": "$.parameter[0].value",
                        "before": "purchase", "after": "{{Missing Variable}}",
                    }]}
                elif kind == "deleted_trigger":
                    actions = {"deletions": [{"object_key": "trigger:10"}]}
                elif kind in ("deleted_gallery_template", "ambiguous_gallery_template"):
                    source["containerVersion"]["tag"].append({
                        "tagId": "2", "name": "Gallery template consumer", "type": "cvt_FIXTURE",
                    })
                    source["containerVersion"]["customTemplate"].append({
                        "templateId": "30", "name": "Fixture template",
                        "galleryReference": {"galleryTemplateId": "FIXTURE"},
                        "templateData": "___INFO___\n{\"displayName\": \"Fixture\", \"type\": \"TAG\"}\n___SANDBOXED_JS_FOR_WEB_TEMPLATE___\ndata.gtmOnSuccess();\n",
                    })
                    if kind == "deleted_gallery_template":
                        actions = {"deletions": [{"object_key": "customTemplate:30"}]}
                    else:
                        duplicate = copy.deepcopy(source["containerVersion"]["customTemplate"][0])
                        duplicate.update(templateId="31", name="Ambiguous gallery mapping")
                        actions = {"creations": [{"layer": "customTemplate", "object": duplicate}]}
                else:
                    source["containerVersion"]["variable"] = [
                        {"variableId": "20", "name": "Dependency A", "type": "c", "parameter": [
                            {"key": "value", "type": "TEMPLATE", "value": "constant"}
                        ]},
                        {"variableId": "21", "name": "Dependency B", "type": "c", "parameter": [
                            {"key": "value", "type": "TEMPLATE", "value": "{{Dependency A}}"}
                        ]},
                    ]
                    actions = {"changes": [{
                        "object_key": "variable:20", "json_path": "$.parameter[0].value",
                        "before": "constant", "after": "{{Dependency B}}",
                    }]}
                package = prepare_graph_fixture(self.root / kind, source, actions)
                packet = read_json(package / "operation-packet.json")
                operation = packet["operations"][0]
                before = file_snapshot(package)
                with self.assertRaisesRegex(ValueError, "target graph regression") as failure:
                    target_validation.validate_target(package)
                message = str(failure.exception)
                if kind in ("deleted_gallery_template", "ambiguous_gallery_template"):
                    # A gallery type name does not identify the operation that
                    # changed its mapping. Never claim the whole packet owns it.
                    self.assertIn("operation ownership unresolved", message)
                    self.assertNotIn("owning source decisions", message)
                else:
                    self.assertIn(operation["operation_id"], message)
                    for decision_id in operation["source_reconciled_decision_ids"]:
                        self.assertIn(decision_id, message)
                self.assertEqual(before, file_snapshot(package))
                self.assertTrue(target_validation.target_validation_seal_errors(package))

    def test_position_shift_and_dependency_rename_do_not_reclassify_existing_issues(self):
        source = actionable_priority_export()
        cv = source["containerVersion"]
        cv["tag"].insert(0, {"tagId": "99", "name": "Preceding fixture", "type": "gaawe"})
        cv["tag"][1]["parameter"].append(
            {"key": "fixture", "type": "TEMPLATE", "value": "{{Existing dependency}}"}
        )
        cv["variable"].append({
            "variableId": "20", "name": "Existing dependency", "type": "c",
            "parameter": [{"key": "value", "type": "TEMPLATE", "value": "{{Missing Variable}}"}],
        })
        package = prepare_graph_fixture(self.root, source, {
            "deletions": [{"object_key": "tag:99"}],
            "renames": [{"object_key": "variable:20", "before": "Existing dependency", "after": "Renamed dependency"}],
        })
        self.assertEqual("pass", target_validation.validate_target(package)["status"])
        proof = read_json(package / "target-validation/validation-proof.json")
        self.assertTrue(proof["preserved_source_graph_issues"])
        target = read_json(package / "target-validation/projected-container.json")
        self.assertEqual("1", target["containerVersion"]["tag"][0]["tagId"])
        self.assertEqual("Renamed dependency", target["containerVersion"]["variable"][0]["name"])


if __name__ == "__main__":
    unittest.main()
