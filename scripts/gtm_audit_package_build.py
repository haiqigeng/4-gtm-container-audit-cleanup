#!/usr/bin/env python3
"""Build the source-locked package for the dual clean-room GTM audit."""

from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path
from typing import Any

from gtm_canonical_scan import build_canonical_scan
from gtm_cleanroom_audit import prepare_audit_bundles
from gtm_lib import file_sha256, package_root_errors, stable_hash, write_json
from gtm_obligation_ledger import build_obligation_ledger
from gtm_scan_assurance import assure_scan
from gtm_skill_identity import build_identity, declared_identity_errors
from gtm_vendor_registry import validate_registry


def _ensure_empty_directory(path: Path) -> None:
    root_errors = package_root_errors(path)
    if root_errors:
        raise RuntimeError("; ".join(root_errors))
    if path.exists():
        if not path.is_dir() or any(path.iterdir()):
            raise RuntimeError(
                "audit package out-dir must be new or empty; evidence is never overwritten"
            )
    else:
        path.mkdir(parents=True)
    root_errors = package_root_errors(path)
    if root_errors:
        raise RuntimeError("; ".join(root_errors))


def _artifact_record(path: Path, role: str) -> dict[str, Any]:
    return {"role": role, "path": path.name, "sha256": file_sha256(path)}


def _manifest_hash(payload: dict[str, Any]) -> str:
    return stable_hash(
        {key: value for key, value in payload.items() if key != "package_manifest_sha256"},
        64,
    )


def build_package(
    export_path: Path,
    out_dir: Path,
    pretty: bool = False,
    context_path: Path | None = None,
    requirements_path: Path | None = None,
    scan_assurance_path: Path | None = None,
) -> dict[str, Any]:
    skill_root = Path(__file__).resolve().parents[1]
    identity_report, identity_errors = declared_identity_errors(skill_root)
    if identity_errors:
        raise RuntimeError(
            "runtime identity preflight failed before package creation: "
            + "; ".join(identity_errors)
        )
    if not export_path.is_file():
        raise RuntimeError(f"confirmed GTM source does not exist: {export_path}")
    if scan_assurance_path is None or not scan_assurance_path.is_file():
        raise RuntimeError(
            "package creation requires a separately produced scan-assurance artifact"
        )
    _ensure_empty_directory(out_dir)

    scan_result = build_canonical_scan(
        export_path,
        context_path=context_path,
        requirements_path=requirements_path,
    )
    scan = scan_result["canonical_scan"]
    contract = scan_result["audit_contract"]
    context = scan_result["context"]
    requirements = scan_result["approved_requirements"]
    registry_path = skill_root / "references" / "03-rules" / "vendor-registry.toml"
    registry_errors, registry_warnings = validate_registry(
        registry_path, online=False, max_age_days=365
    )
    if registry_errors or registry_warnings:
        raise RuntimeError(
            "locked vendor registry is invalid or stale: "
            + "; ".join([*registry_errors, *registry_warnings])
        )
    assurance = json.loads(scan_assurance_path.read_text(encoding="utf-8"))
    assurance_agent_id = str(assurance.get("independent_agent_id") or "").strip()
    assurance_context_id = str(assurance.get("independent_context_id") or "").strip()
    if not assurance_agent_id or not assurance_context_id:
        raise RuntimeError(
            "scan-assurance artifact requires fresh agent and context labels"
        )
    expected_assurance = assure_scan(
        export_path,
        scan,
        vendor_registry_path=registry_path,
        independent_agent_id=assurance_agent_id,
        independent_context_id=assurance_context_id,
    )
    if assurance != expected_assurance:
        raise RuntimeError(
            "scan-assurance artifact differs from independent raw-source reconstruction"
        )
    if assurance.get("status") != "pass":
        mismatch_ids = [
            str(row.get("check_id") or "unknown")
            for row in assurance.get("checks", [])
            if row.get("status") != "pass"
        ]
        raise RuntimeError(
            "independent scan assurance blocked semantic review: "
            + ", ".join(mismatch_ids)
        )
    ledger = build_obligation_ledger(
        scan,
        assurance,
        requirements,
    )

    locked_source_path = out_dir / "locked-source.json"
    context_output_path = out_dir / "context.json"
    contract_path = out_dir / "audit-contract.json"
    source_model_path = out_dir / "source-model.json"
    scan_path = out_dir / "canonical-scan.json"
    assurance_path = out_dir / "scan-assurance.json"
    ledger_path = out_dir / "obligation-ledger.json"
    registry_output_path = out_dir / "vendor-registry.toml"
    manifest_path = out_dir / "audit-package-manifest.json"
    shutil.copy2(export_path, locked_source_path)
    write_json(context_output_path, context)
    write_json(contract_path, contract)
    write_json(source_model_path, scan_result["source_model"])
    write_json(scan_path, scan)
    write_json(assurance_path, assurance)
    write_json(ledger_path, ledger)
    shutil.copy2(registry_path, registry_output_path)
    requirement_output_path: Path | None = None
    if requirements:
        requirement_output_path = out_dir / "approved-requirements.json"
        write_json(requirement_output_path, requirements)
    runtime_identity = build_identity(skill_root)
    declared = identity_report.get("declared") or {}
    if not runtime_identity.get("source_git_commit"):
        # A clean runtime bundle has no .git directory; in that explicit case,
        # preserve the source checkout identity recorded when the bundle was built.
        for field in ("source_git_commit", "source_git_dirty"):
            if declared.get(field) is not None:
                runtime_identity[field] = declared[field]
    artifact_records = [
        _artifact_record(locked_source_path, "raw_source"),
        _artifact_record(context_output_path, "locked_context"),
        _artifact_record(contract_path, "audit_contract"),
        _artifact_record(source_model_path, "source_identity_model"),
        _artifact_record(scan_path, "canonical_scan"),
        _artifact_record(assurance_path, "independent_scan_assurance"),
        _artifact_record(ledger_path, "semantic_obligation_ledger"),
        _artifact_record(registry_output_path, "locked_vendor_registry"),
    ]
    if requirement_output_path:
        artifact_records.append(
            _artifact_record(
                requirement_output_path,
                "approved_requirement_evidence_withheld_until_checkpoint",
            )
        )
    temporary_manifest = {
        "kind": "gtm_dual_audit_package_manifest",
        "schema_version": 1,
        "status": "building",
        "source_sha256": scan.get("source_sha256"),
    }
    temporary_manifest["package_manifest_sha256"] = _manifest_hash(
        temporary_manifest
    )
    write_json(manifest_path, temporary_manifest)
    audit_bundles = prepare_audit_bundles(
        locked_source_path,
        out_dir,
        scan=scan,
        assurance=assurance,
        ledger=ledger,
        context_path=context_output_path,
        contract_path=contract_path,
        registry_path=registry_output_path,
        requirements_path=requirement_output_path,
    )

    manifest = {
        "kind": "gtm_dual_audit_package_manifest",
        "schema_version": 1,
        "status": "ready_for_source_checkpoints",
        "source_file": export_path.name,
        "source_sha256": scan.get("source_sha256"),
        "container_identity": scan.get("container_identity", {}),
        "context_sha256": scan.get("context_sha256"),
        "audit_contract_sha256": scan.get("audit_contract_sha256"),
        "canonical_scan_sha256": scan.get("canonical_scan_sha256"),
        "scan_assurance_sha256": assurance.get("scan_assurance_sha256"),
        "obligation_ledger_sha256": ledger.get("obligation_ledger_sha256"),
        "vendor_registry_sha256": file_sha256(registry_output_path),
        "approved_requirements_sha256": scan.get("approved_requirements_sha256"),
        "skill_runtime_identity": {
            key: runtime_identity.get(key)
            for key in (
                "project_version",
                "runtime_tree_sha256",
                "runtime_file_count",
                "source_git_commit",
                "source_git_dirty",
            )
        },
        "artifacts": artifact_records,
        "audit_bundles": audit_bundles,
        "counts": {
            **scan.get("counts", {}),
            "semantic_obligations": ledger.get("counts", {}).get("obligations", 0),
            "source_only_obligations": ledger.get("counts", {}).get("source_only", 0),
            "post_checkpoint_obligations": ledger.get("counts", {}).get(
                "post_source_checkpoint", 0
            ),
        },
        "required_next_steps": [
            "Complete and seal the source-only checkpoint in audit-a.",
            "Independently complete and seal the candidate-blind source checkpoint in audit-b.",
            "Complete every released obligation with two separate fresh agents and contexts.",
            "Validate and seal both audits before reconciliation.",
        ],
        "phase_boundary": (
            "This package is read-only. The workflow ends at one validated analyst "
            "workbook and never mutates GTM, creates an import, version, or publication."
        ),
    }
    manifest["package_manifest_sha256"] = _manifest_hash(manifest)
    write_json(manifest_path, manifest)
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("export", type=Path)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--context", type=Path)
    parser.add_argument("--requirements", type=Path)
    parser.add_argument("--scan-assurance", type=Path, required=True)
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()
    try:
        result = build_package(
            args.export,
            args.out_dir,
            args.pretty,
            args.context,
            args.requirements,
            args.scan_assurance,
        )
    except (RuntimeError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"status": "blocked", "errors": [str(exc)]}))
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2 if args.pretty else None))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
