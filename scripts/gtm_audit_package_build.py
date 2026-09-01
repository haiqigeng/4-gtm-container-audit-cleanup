#!/usr/bin/env python3
"""Build the source-locked package for the dual clean-room GTM audit."""

from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path
from typing import Any

from gtm_audit_contract import CANONICAL_DECISION_FIELDS
from gtm_canonical_record import (
    CANONICAL_MANIFEST_FILE,
    CANONICAL_RECORD_FILE,
    CANONICAL_SEAL_FILE,
    canonical_record_seal_errors,
)
from gtm_canonical_scan import build_canonical_scan
from gtm_cleanroom_audit import prepare_audit_bundles
from gtm_lib import as_list, file_sha256, stable_hash, write_json
from gtm_obligation_ledger import build_obligation_ledger
from gtm_scan_assurance import assure_scan
from gtm_skill_identity import build_identity, declared_identity_errors
from gtm_vendor_registry import validate_registry

SEMANTIC_PREDECESSOR_FILES = {
    CANONICAL_RECORD_FILE: "superseded-canonical-record.json",
    CANONICAL_MANIFEST_FILE: "superseded-canonical-record-manifest.json",
    CANONICAL_SEAL_FILE: "superseded-canonical-record-seal.json",
}
REPAIRABLE_FIELDS = {
    *CANONICAL_DECISION_FIELDS,
    "operation_proposal",
    "evidence_citations",
    "reconciliation_rationale",
}


def _ensure_empty_directory(path: Path) -> None:
    if path.exists():
        if not path.is_dir() or any(path.iterdir()):
            raise RuntimeError(
                "audit package out-dir must be new or empty; evidence is never overwritten"
            )
    else:
        path.mkdir(parents=True)


def _artifact_record(path: Path, role: str) -> dict[str, Any]:
    return {"role": role, "path": path.name, "sha256": file_sha256(path)}


def _manifest_hash(payload: dict[str, Any]) -> str:
    return stable_hash(
        {key: value for key, value in payload.items() if key != "package_manifest_sha256"},
        64,
    )


def _semantic_successor_evidence(
    predecessor_record_path: Path | None,
    repair_brief_path: Path | None,
    source_sha256: str,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    if bool(predecessor_record_path) != bool(repair_brief_path):
        raise ValueError(
            "semantic successor creation requires both a predecessor canonical record "
            "and an approved semantic repair brief"
        )
    if predecessor_record_path is None or repair_brief_path is None:
        return None, None
    predecessor_record_path = predecessor_record_path.resolve()
    if predecessor_record_path.name != CANONICAL_RECORD_FILE:
        raise ValueError(
            f"semantic predecessor must be named {CANONICAL_RECORD_FILE}"
        )
    predecessor_package = predecessor_record_path.parent
    errors = canonical_record_seal_errors(predecessor_package)
    if errors:
        raise ValueError(
            "semantic predecessor canonical seal is invalid: " + "; ".join(errors)
        )
    predecessor = json.loads(predecessor_record_path.read_text(encoding="utf-8"))
    if predecessor.get("kind") != "gtm_container_audit_canonical_record":
        raise ValueError("semantic predecessor canonical record kind is invalid")
    predecessor_source_sha256 = str(
        (predecessor.get("source") or {}).get("source_sha256") or ""
    )
    if predecessor_source_sha256 != source_sha256:
        raise ValueError(
            "semantic successor must start from the predecessor's same locked source"
        )

    repair = json.loads(repair_brief_path.read_text(encoding="utf-8"))
    if not isinstance(repair, dict):
        raise ValueError("semantic repair brief must be a JSON object")
    if repair.get("kind") != "gtm_semantic_repair_brief" or repair.get(
        "schema_version"
    ) != 1:
        raise ValueError("semantic repair brief kind or schema_version is invalid")
    if repair.get("status") != "approved":
        raise ValueError("semantic repair brief status must be approved")
    if repair.get("canonical_record_sha256") != predecessor.get(
        "canonical_record_sha256"
    ):
        raise ValueError("semantic repair brief is bound to another canonical record")

    decision_rows = [
        row
        for row in as_list(predecessor.get("audit_decisions"))
        if isinstance(row, dict)
    ]
    decisions = {
        str(row.get("canonical_decision_id") or ""): (index, row)
        for index, row in enumerate(decision_rows)
        if str(row.get("canonical_decision_id") or "")
    }
    repair_records = [
        row for row in as_list(repair.get("repair_records")) if isinstance(row, dict)
    ]
    if not repair_records:
        raise ValueError("semantic repair brief must contain at least one repair record")
    repair_ids: set[str] = set()
    enriched_records = []
    for index, row in enumerate(repair_records):
        repair_id = str(row.get("repair_id") or "").strip()
        decision_id = str(row.get("canonical_decision_id") or "").strip()
        fields = {str(value) for value in as_list(row.get("fields"))}
        reason = str(row.get("reason") or "").strip()
        if len(repair_id) < 8 or repair_id in repair_ids:
            raise ValueError("semantic repair IDs must be strong and unique")
        repair_ids.add(repair_id)
        if decision_id not in decisions:
            raise ValueError(
                f"semantic repair {repair_id} names an unknown canonical decision"
            )
        if not fields or fields - REPAIRABLE_FIELDS:
            raise ValueError(
                f"semantic repair {repair_id} has missing or unsupported fields"
            )
        if len(reason.split()) < 8:
            raise ValueError(
                f"semantic repair {repair_id} requires an evidence-bound reason"
            )
        predecessor_index, predecessor_decision = decisions[decision_id]
        enriched_records.append(
            {
                **row,
                "repair_id": repair_id,
                "canonical_decision_id": decision_id,
                "fields": sorted(fields),
                "source_reference_path": (
                    f"$.repair_records[{index}]"
                ),
                "predecessor_source_reference_path": (
                    "$.audit_decisions["
                    f"{predecessor_index}]"
                ),
                "predecessor_decision": predecessor_decision,
            }
        )
    semantic_evidence = {**repair, "repair_records": enriched_records}
    predecessor_manifest = json.loads(
        (predecessor_package / CANONICAL_MANIFEST_FILE).read_text(encoding="utf-8")
    )
    predecessor_seal = json.loads(
        (predecessor_package / CANONICAL_SEAL_FILE).read_text(encoding="utf-8")
    )
    lineage = {
        "canonical_record_sha256": predecessor.get("canonical_record_sha256"),
        "canonical_record_file_sha256": file_sha256(predecessor_record_path),
        "canonical_manifest_sha256": predecessor_manifest.get(
            "canonical_manifest_sha256"
        ),
        "canonical_record_seal_sha256": predecessor_seal.get(
            "canonical_record_seal_sha256"
        ),
        "source_sha256": predecessor_source_sha256,
        "semantic_repair_brief_sha256": file_sha256(repair_brief_path),
        "repair_ids": sorted(repair_ids),
    }
    return lineage, semantic_evidence


def build_package(
    export_path: Path,
    out_dir: Path,
    pretty: bool = False,
    context_path: Path | None = None,
    requirements_path: Path | None = None,
    predecessor_record_path: Path | None = None,
    repair_brief_path: Path | None = None,
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
    assurance = assure_scan(
        export_path,
        scan,
        vendor_registry_path=registry_path,
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
    successor_lineage, semantic_repair = _semantic_successor_evidence(
        predecessor_record_path,
        repair_brief_path,
        str(scan.get("source_sha256") or ""),
    )
    ledger = build_obligation_ledger(
        scan,
        assurance,
        requirements,
        semantic_repair,
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
    repair_output_path: Path | None = None
    repair_evidence_output_path: Path | None = None
    predecessor_output_paths: list[Path] = []
    if (
        successor_lineage
        and semantic_repair
        and predecessor_record_path
        and repair_brief_path
    ):
        repair_output_path = out_dir / "semantic-repair-brief.json"
        shutil.copy2(repair_brief_path, repair_output_path)
        repair_evidence_output_path = out_dir / "semantic-repair-evidence.json"
        write_json(repair_evidence_output_path, semantic_repair)
        predecessor_package = predecessor_record_path.resolve().parent
        for source_name, target_name in SEMANTIC_PREDECESSOR_FILES.items():
            target = out_dir / target_name
            shutil.copy2(predecessor_package / source_name, target)
            predecessor_output_paths.append(target)

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
    if repair_output_path:
        artifact_records.append(
            _artifact_record(repair_output_path, "approved_semantic_repair_brief")
        )
        predecessor_roles = (
            "semantic_predecessor_canonical_record",
            "semantic_predecessor_canonical_manifest",
            "semantic_predecessor_canonical_seal",
        )
        artifact_records.extend(
            _artifact_record(path, role)
            for path, role in zip(
                predecessor_output_paths, predecessor_roles, strict=True
            )
        )
    if repair_evidence_output_path:
        artifact_records.append(
            _artifact_record(
                repair_evidence_output_path,
                "projection_stable_semantic_repair_evidence",
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
        "semantic_successor_of": successor_lineage,
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
            "Complete every released obligation in two host-scoped audit contexts.",
            "Validate and seal both audits before reconciliation.",
            *(
                [
                    "Disposition every approved semantic repair in both fresh audits and neutral reconciliation."
                ]
                if successor_lineage
                else []
            ),
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
    parser.add_argument("--supersedes-canonical-record", type=Path)
    parser.add_argument("--semantic-repair-brief", type=Path)
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()
    try:
        result = build_package(
            args.export,
            args.out_dir,
            args.pretty,
            args.context,
            args.requirements,
            args.supersedes_canonical_record,
            args.semantic_repair_brief,
        )
    except (RuntimeError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"status": "blocked", "errors": [str(exc)]}))
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2 if args.pretty else None))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
