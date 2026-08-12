#!/usr/bin/env python3
"""Gate a GTM cleanup plan on three complete independent review runs."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from gtm_approval_response import CLEANUP_PACKET_SCHEMA_VERSION
from gtm_architecture_review import validate_review as validate_architecture
from gtm_configuration_review import validate_review as validate_configuration
from gtm_context_model import build_context_model, context_content_hash
from gtm_future_state_check import check_future_state
from gtm_lib import load_json, source_descriptor
from gtm_operation_compile import compile_operations, source_object_catalog
from gtm_operational_review import validate_review as validate_operational
from gtm_review_common import (
    object_consumer_map,
    object_name_map,
    object_source_path_map,
)
from gtm_review_isolation import review_seal_errors
from gtm_shared_facts import build_shared_facts, shared_content_hash
from gtm_skill_identity import build_identity, declared_identity_errors

REQUIRED_PACKAGE_FILES = {
    "context": "context.json",
    "shared_facts": "shared_facts.json",
    "source_model": "source_model.json",
    "operational_scan": "operational_scan.json",
    "operational_review": "operational_review.json",
    "technical_code_findings": "technical_code_findings.json",
    "configuration_review": "configuration_review.json",
    "architecture_review": "architecture_review.json",
    "manifest": "audit_package_manifest.json",
}


def package_paths(package_dir: Path) -> dict[str, Path]:
    return {key: package_dir / name for key, name in REQUIRED_PACKAGE_FILES.items()}


def manifest_errors(
    manifest: dict[str, Any], paths: dict[str, Path], source_sha256: str
) -> list[str]:
    errors: list[str] = []
    if manifest.get("source_sha256") != source_sha256:
        errors.append("package manifest source hash differs from the export")
    if not str(manifest.get("shared_facts_coverage_gate") or "").startswith("pass"):
        errors.append("shared facts coverage gate is not pass")
    expected_files = manifest.get("files") or {}
    errors.extend(
        f"manifest file mapping for {key} is invalid"
        for key, filename in REQUIRED_PACKAGE_FILES.items()
        if str(expected_files.get(key) or "") != filename
    )
    for key, path in paths.items():
        if key != "manifest" and load_json(path).get("source_sha256") != source_sha256:
            errors.append(f"{path.name} source hash differs from the export")
    return errors


def context_integrity_errors(export: Path, context: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    recalculated = context_content_hash(
        str(context.get("source_sha256") or ""),
        context.get("context") or {},
        context.get("inferred_context") or {},
        context.get("provided_context") or {},
        context.get("provided_fields") or [],
        context.get("unresolved_questions") or [],
        context.get("context_evidence") or {},
        context.get("intake_questions") or [],
        str(context.get("intake_status") or ""),
    )
    if context.get("context_sha256") != recalculated:
        errors.append("context content does not match its recorded hash")
    rebuilt = build_context_model(export, provided_context=context.get("provided_context") or {})
    for field in (
        "context",
        "inferred_context",
        "provided_context",
        "provided_fields",
        "context_evidence",
        "intake_questions",
        "intake_status",
        "unresolved_questions",
        "context_sha256",
    ):
        if context.get(field) != rebuilt.get(field):
            errors.append(f"packaged context {field} differs from deterministic reconstruction")
    return errors


def shared_integrity_errors(
    export: Path,
    shared: dict[str, Any],
    context: dict[str, Any],
    manifest: dict[str, Any],
) -> list[str]:
    errors: list[str] = []
    if shared.get("shared_facts_sha256") != shared_content_hash(shared):
        errors.append("shared deterministic facts content does not match its recorded hash")
    rebuilt = build_shared_facts(export, context=context)
    if shared.get("shared_facts_sha256") != rebuilt.get("shared_facts_sha256"):
        errors.append("packaged shared facts differ from deterministic source reconstruction")
    if shared.get("shared_facts_sha256") != manifest.get("shared_facts_sha256"):
        errors.append("shared facts hash differs from the package manifest")
    if context.get("context_sha256") != manifest.get("context_sha256"):
        errors.append("context hash differs from the package manifest")
    return errors


def review_binding_errors(
    paths: dict[str, Path],
    shared: dict[str, Any],
    context: dict[str, Any],
    manifest: dict[str, Any],
) -> list[str]:
    errors: list[str] = []
    field_map = (
        ("audit_context", "context"),
        ("inferred_context", "inferred_context"),
        ("provided_context", "provided_context"),
        ("provided_context_fields", "provided_fields"),
        ("unresolved_context_questions", "unresolved_questions"),
    )
    contract_key_by_review = {
        "operational_review": "operational_sanitation",
        "configuration_review": "configuration_correctness",
        "architecture_review": "business_architecture",
    }
    contracts = manifest.get("run_input_contracts") or {}
    reasoning_contexts: dict[str, str] = {}
    for key in ("operational_review", "configuration_review", "architecture_review"):
        payload = load_json(paths[key])
        if payload.get("shared_facts_sha256") != shared.get("shared_facts_sha256"):
            errors.append(f"{paths[key].name} does not use the packaged shared facts")
        if payload.get("context_sha256") != context.get("context_sha256"):
            errors.append(f"{paths[key].name} does not use the packaged audit context")
        errors.extend(
            f"{paths[key].name} {review_field} differs from packaged context"
            for review_field, context_field in field_map
            if payload.get(review_field) != context.get(context_field)
        )
        expected_contract = contracts.get(contract_key_by_review[key])
        if payload.get("input_contract") != expected_contract:
            errors.append(f"{paths[key].name} input contract differs from the package manifest")
        attestation = payload.get("completion_attestation") or {}
        context_id = str(attestation.get("independent_review_context_id") or "")
        if context_id:
            reasoning_contexts[key] = context_id
    duplicate_contexts = sorted(
        {
            context_id
            for context_id in reasoning_contexts.values()
            if list(reasoning_contexts.values()).count(context_id) > 1
        }
    )
    if duplicate_contexts:
        errors.append(
            "the three semantic runs reuse an independent_review_context_id; "
            "each run must be completed in its own reasoning context"
        )
    return errors


def validate_package_structure(export: Path, package_dir: Path) -> list[str]:
    errors: list[str] = []
    descriptor = source_descriptor(export)
    paths = package_paths(package_dir)
    for key, path in paths.items():
        if not path.is_file():
            errors.append(f"missing package artifact {key}: {path.name}")
    if errors:
        return errors
    manifest = load_json(paths["manifest"])
    errors.extend(manifest_errors(manifest, paths, descriptor["source_sha256"]))
    skill_root = Path(__file__).resolve().parents[1]
    identity_report, identity_errors = declared_identity_errors(skill_root)
    errors.extend(f"runtime identity: {error}" for error in identity_errors)
    actual_identity = build_identity(skill_root)
    recorded_identity = manifest.get("skill_runtime_identity") or {}
    for field in (
        "project_version",
        "runtime_tree_sha256",
        "runtime_file_count",
    ):
        if recorded_identity.get(field) != actual_identity.get(field):
            errors.append(
                f"package runtime identity {field} differs from the executing skill"
            )
    declared_identity = identity_report.get("declared") or {}
    for field in ("source_git_commit", "source_git_dirty"):
        expected_provenance = declared_identity.get(field)
        if expected_provenance is None:
            expected_provenance = actual_identity.get(field)
        if recorded_identity.get(field) != expected_provenance:
            errors.append(f"package runtime provenance {field} differs from its source")
    shared = load_json(paths["shared_facts"])
    context = load_json(paths["context"])
    errors.extend(context_integrity_errors(export, context))
    errors.extend(shared_integrity_errors(export, shared, context, manifest))
    errors.extend(review_binding_errors(paths, shared, context, manifest))
    errors.extend(review_seal_errors(package_dir, manifest))
    return errors


def validate_three_runs(
    export: Path,
    operational_path: Path,
    configuration_path: Path,
    architecture_path: Path,
) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []
    validators = (
        ("operational", validate_operational, operational_path),
        ("configuration", validate_configuration, configuration_path),
        ("architecture", validate_architecture, architecture_path),
    )
    for label, validator, path in validators:
        review_errors, review_warnings = validator(export, path)
        errors.extend(f"{label}: {error}" for error in review_errors)
        warnings.extend(f"{label}: {warning}" for warning in review_warnings)
    return errors, warnings


def run_gate(
    export: Path,
    package_dir: Path,
    operations_path: Path | None = None,
) -> dict[str, Any]:
    errors = validate_package_structure(export, package_dir)
    warnings: list[str] = []
    if not errors:
        run_errors, run_warnings = validate_three_runs(
            export,
            package_dir / REQUIRED_PACKAGE_FILES["operational_review"],
            package_dir / REQUIRED_PACKAGE_FILES["configuration_review"],
            package_dir / REQUIRED_PACKAGE_FILES["architecture_review"],
        )
        errors.extend(run_errors)
        warnings.extend(run_warnings)
    future_state: dict[str, Any] | None = None
    if not operations_path and not errors:
        errors.append(
            "full completion requires reconciled cleanup actions and future-state simulation"
        )
    if operations_path and not errors:
        operations = load_json(operations_path)
        expected_hash = source_descriptor(export)["source_sha256"]
        if operations.get("source_sha256") != expected_hash:
            errors.append("operations source hash differs from the export")
        elif operations.get("schema_version") != CLEANUP_PACKET_SCHEMA_VERSION:
            errors.append(
                "operations schema_version must be "
                f"{CLEANUP_PACKET_SCHEMA_VERSION}"
            )
        elif set((operations.get("run_statuses") or {}).values()) != {"complete"}:
            errors.append("operations do not record three complete input runs")
        else:
            operational = load_json(package_dir / REQUIRED_PACKAGE_FILES["operational_review"])
            configuration = load_json(package_dir / REQUIRED_PACKAGE_FILES["configuration_review"])
            architecture = load_json(package_dir / REQUIRED_PACKAGE_FILES["architecture_review"])
            expected_operations, compile_errors = compile_operations(
                operational,
                configuration,
                architecture,
                str(operations.get("route") or ""),
                source_object_catalog(export),
                object_consumer_map(export),
                object_name_map(export),
                object_source_path_map(export),
                load_json(export),
            )
            errors.extend(f"operation recompile: {error}" for error in compile_errors)
            if not compile_errors and operations != expected_operations:
                errors.append(
                    "operations artifact differs from deterministic recompilation of the three reviews"
                )
            action_completeness = operations.get("action_completeness") or {}
            if action_completeness.get("status") != "pass":
                completeness_errors = [
                    str(value) for value in action_completeness.get("errors", []) if str(value)
                ]
                errors.extend(
                    "action completeness: " + value for value in completeness_errors
                )
                if not completeness_errors:
                    errors.append("action completeness: cleanup plan is incomplete")
            if not errors:
                future_state, future_errors = check_future_state(export, operations)
                errors.extend(f"future state: {error}" for error in future_errors)
    return {
        "kind": "gtm_three_run_completion_gate",
        "status": "pass" if not errors else "fail",
        "source_file": export.name,
        "package_dir": str(package_dir),
        "three_required_runs": [
            "operational_sanitation",
            "configuration_correctness",
            "business_architecture",
        ],
        "future_state": future_state,
        "completion_mode": "audit_and_cleanup_plan",
        "errors": errors,
        "warnings": warnings,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("export", type=Path)
    parser.add_argument("package_dir", type=Path)
    parser.add_argument("--operations", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()
    report = run_gate(args.export, args.package_dir, args.operations)
    rendered = json.dumps(report, ensure_ascii=False, indent=2 if args.pretty else None)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    if report["status"] != "pass":
        for error in report["errors"]:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
