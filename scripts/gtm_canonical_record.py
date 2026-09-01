#!/usr/bin/env python3
"""Seal the authoritative machine record after deterministic target closure."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any

from gtm_audit_contract import (
    ACTIONABLE_DECISION_CLASSES,
    AREA_BY_ID,
    CANONICAL_DECISION_FIELDS,
    HUMAN_DECISION_LABELS,
    semantic_contract_errors,
)
from gtm_fixed_point import fixed_point_seal_errors
from gtm_lib import (
    as_list,
    contained_relative_path,
    file_sha256,
    require_safe_package_root,
    stable_hash,
    write_json,
)
from gtm_operation_model import operation_action_identity, operation_packet_sha256
from gtm_reconciliation import reconciliation_seal_errors

CANONICAL_RECORD_FILE = "canonical-record.json"
CANONICAL_MANIFEST_FILE = "canonical-record-manifest.json"
CANONICAL_SEAL_FILE = "canonical-record-seal.json"
CANONICAL_INPUTS = (
    "audit-package-manifest.json",
    "canonical-scan.json",
    "scan-assurance.json",
    "obligation-ledger.json",
    "reconciled-decisions.json",
    "reconciliation-seal.json",
    "operation-packet.json",
    "fixed-point/fixed-point-proof.json",
    "fixed-point/fixed-point-seal.json",
    "fixed-point/projection-decisions.json",
    "fixed-point/replay/projected-container.json",
    "fixed-point/replay/canonical-scan.json",
    "fixed-point/replay/scan-assurance.json",
    "fixed-point/replay/obligation-ledger.json",
)


def _load(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"JSON artifact must be an object: {path}")
    return payload


def _hash_without(payload: dict[str, Any], *fields: str) -> str:
    return stable_hash(
        {key: value for key, value in payload.items() if key not in set(fields)},
        64,
    )


def _projection_decisions(package_dir: Path) -> list[dict[str, Any]]:
    path = package_dir / "fixed-point" / "projection-decisions.json"
    if not path.is_file():
        return []
    return as_list(_load(path).get("canonical_decisions"))


def _decision_owner(row: dict[str, Any]) -> dict[str, Any]:
    if row.get("owning_cycle"):
        return {
            "owner_kind": "projection_review_and_reconciliation",
            "owning_cycle": row.get("owning_cycle"),
            "owning_reviews": row.get("owning_reviews", []),
            "repair_rule": (
                "Reopen both focused projection reviews in fresh host-scoped contexts, "
                "repeat projection reconciliation and required neutral verification, "
                "then rerun fixed-point closure."
            ),
        }
    return {
        "owner_kind": "source_audit_and_reconciliation",
        "owning_audits": row.get("owning_audits", []),
        "repair_rule": (
            "Reopen the owning source audit in a fresh amendment context bound to its "
            "prior seal, repeat exact reconciliation and required neutral verification, "
            "then rerun fixed-point closure."
        ),
    }


def _code_object_keys(scan: dict[str, Any]) -> set[str]:
    keys: set[str] = set()
    for row in as_list((scan.get("code_evidence") or {}).get("rows")):
        if isinstance(row, dict) and str(row.get("object_key") or ""):
            keys.add(str(row["object_key"]))
    for row in as_list(scan.get("objects")):
        if not isinstance(row, dict):
            continue
        if row.get("layer") == "customTemplate" or as_list(row.get("code_line_facts")):
            keys.add(str(row.get("object_key") or ""))
    keys.discard("")
    return keys


def _canonical_decision_rows(package_dir: Path) -> list[dict[str, Any]]:
    original = as_list(
        _load(package_dir / "reconciled-decisions.json").get("canonical_decisions")
    )
    rows = [*original, *_projection_decisions(package_dir)]
    seen: set[str] = set()
    result = []
    errors = []
    for row in rows:
        decision_id = str(row.get("canonical_decision_id") or "")
        if not decision_id or decision_id in seen:
            errors.append("canonical decision IDs are blank or duplicated")
            continue
        seen.add(decision_id)
        decision = row.get("decision")
        if not isinstance(decision, dict):
            errors.append(f"{decision_id}: semantic decision is missing")
            continue
        errors.extend(semantic_contract_errors(decision, decision_id))
        missing = [
            field
            for field in CANONICAL_DECISION_FIELDS
            if field not in {"owner_question", "evidence_boundary"}
            and not str(decision.get(field) or "").strip()
        ]
        if missing:
            errors.append(
                f"{decision_id}: canonical delivery fields are missing: {', '.join(missing)}"
            )
        result.append(
            {
                **row,
                "human_decision_label": HUMAN_DECISION_LABELS.get(
                    str(decision.get("decision_class") or ""), "Unknown"
                ),
                "area_title": AREA_BY_ID.get(str(row.get("area_id") or ""), {}).get(
                    "title", "Unknown audit area"
                ),
                "record_owner": _decision_owner(row),
            }
        )
    if errors:
        raise ValueError("canonical decision completeness gate failed: " + "; ".join(errors))
    return sorted(result, key=lambda value: str(value["canonical_decision_id"]))


def _operation_errors(
    packet: dict[str, Any], decisions: list[dict[str, Any]]
) -> list[str]:
    errors = []
    operations = [row for row in as_list(packet.get("operations")) if isinstance(row, dict)]
    operation_ids = {str(row.get("operation_id") or "") for row in operations}
    if "" in operation_ids or len(operation_ids) != len(operations):
        errors.append("operation IDs are blank or duplicated")
    if packet.get("operation_packet_sha256") != operation_packet_sha256(operations):
        errors.append("operation packet hash is invalid")
    mapping = dict(packet.get("decision_to_operation") or {})
    by_decision = {
        str(row.get("canonical_decision_id") or ""): row for row in decisions
    }
    for decision_id, row in by_decision.items():
        decision_class = str((row.get("decision") or {}).get("decision_class") or "")
        mapped = str(mapping.get(decision_id) or "")
        if decision_class in ACTIONABLE_DECISION_CLASSES:
            if mapped not in operation_ids:
                errors.append(f"{decision_id}: actionable decision has no exact operation")
        elif mapped:
            errors.append(f"{decision_id}: non-actionable decision maps to an operation")
    valid_decisions = set(by_decision)
    for operation in operations:
        operation_id = str(operation.get("operation_id") or "")
        source_ids = {
            str(value)
            for value in as_list(operation.get("source_reconciled_decision_ids"))
        }
        if not source_ids or source_ids - valid_decisions:
            errors.append(f"{operation_id}: operation source decision set is invalid")
        if operation.get("action_payload_sha256") != operation_action_identity(operation):
            errors.append(f"{operation_id}: executable action identity is invalid")
        for field in (
            "exact_target_state",
            "preconditions",
            "static_verification",
            "rollback",
        ):
            if len(str(operation.get(field) or "").split()) < 4:
                errors.append(f"{operation_id}: {field} is incomplete")
    return errors


def _count_deltas(
    source_counts: dict[str, Any], target_counts: dict[str, Any]
) -> list[dict[str, Any]]:
    keys = sorted(set(source_counts) | set(target_counts))
    return [
        {
            "metric": key,
            "source": int(source_counts.get(key) or 0),
            "target": int(target_counts.get(key) or 0),
            "delta": int(target_counts.get(key) or 0) - int(source_counts.get(key) or 0),
        }
        for key in keys
        if int(source_counts.get(key) or 0) != int(target_counts.get(key) or 0)
    ]


def _object_directory(scan: dict[str, Any]) -> list[dict[str, Any]]:
    return sorted(
        [
            {
                "object_key": row.get("object_key"),
                "object_name": row.get("object_name"),
                "layer": row.get("layer"),
                "object_type": row.get("object_type"),
                "paused": row.get("paused"),
                "source_json_path": row.get("source_json_path"),
            }
            for row in as_list(scan.get("objects"))
            if isinstance(row, dict)
        ],
        key=lambda value: str(value.get("object_key") or ""),
    )


def build_canonical_record(
    package_dir: Path, *, _validate_only: bool = False
) -> dict[str, Any]:
    require_safe_package_root(package_dir)
    errors = reconciliation_seal_errors(package_dir)
    errors.extend(fixed_point_seal_errors(package_dir))
    if errors:
        raise ValueError("canonical seal prerequisites failed: " + "; ".join(errors))
    record_path = package_dir / CANONICAL_RECORD_FILE
    if record_path.exists() and not _validate_only:
        raise ValueError("canonical record already exists and is immutable")
    source_manifest = _load(package_dir / "audit-package-manifest.json")
    source_scan = _load(package_dir / "canonical-scan.json")
    source_assurance = _load(package_dir / "scan-assurance.json")
    source_ledger = _load(package_dir / "obligation-ledger.json")
    target_root = package_dir / "fixed-point" / "replay"
    target_scan = _load(target_root / "canonical-scan.json")
    target_assurance = _load(target_root / "scan-assurance.json")
    target_ledger = _load(target_root / "obligation-ledger.json")
    proof = _load(package_dir / "fixed-point" / "fixed-point-proof.json")
    packet = _load(package_dir / "operation-packet.json")
    decisions = _canonical_decision_rows(package_dir)
    operation_errors = _operation_errors(packet, decisions)
    if operation_errors:
        raise ValueError("canonical operation gate failed: " + "; ".join(operation_errors))
    code_keys = _code_object_keys(source_scan)
    decision_counts = Counter(
        str((row.get("decision") or {}).get("decision_class") or "")
        for row in decisions
    )
    priority_counts = Counter(
        str((row.get("decision") or {}).get("priority") or "") for row in decisions
    )
    operations = as_list(packet.get("operations"))
    record = {
        "kind": "gtm_container_audit_canonical_record",
        "schema_version": 2,
        "product_boundary": (
            "Read-only container audit and decision-ready workbook. This record is not "
            "execution approval, an import, a GTM version, or proof of mutation."
        ),
        "source": {
            "source_sha256": source_manifest.get("source_sha256"),
            "container_identity": source_manifest.get("container_identity", {}),
            "context_sha256": source_manifest.get("context_sha256"),
            "canonical_scan_sha256": source_scan.get("canonical_scan_sha256"),
            "scan_assurance_sha256": source_assurance.get("scan_assurance_sha256"),
            "obligation_ledger_sha256": source_ledger.get(
                "obligation_ledger_sha256"
            ),
            "scope_boundary": (
                "Conclusions are limited to complete static GTM container evidence and "
                "explicit approved context; runtime firing and vendor receipt are not proven."
            ),
            "source_layer_counts": source_scan.get("source_layer_counts", {}),
            "object_directory": _object_directory(source_scan),
        },
        "target": {
            "projected_container_sha256": file_sha256(
                target_root / "projected-container.json"
            ),
            "canonical_scan_sha256": target_scan.get("canonical_scan_sha256"),
            "scan_assurance_sha256": target_assurance.get("scan_assurance_sha256"),
            "obligation_ledger_sha256": target_ledger.get(
                "obligation_ledger_sha256"
            ),
            "source_layer_counts": target_scan.get("source_layer_counts", {}),
            "object_directory": _object_directory(target_scan),
            "material_count_deltas": _count_deltas(
                source_scan.get("source_layer_counts", {}),
                target_scan.get("source_layer_counts", {}),
            ),
        },
        "fixed_point": {
            "status": proof.get("status"),
            "stable_cycle": proof.get("stable_cycle"),
            "completed_cycles": proof.get("completed_cycles"),
            "stable_hashes": proof.get("stable_hashes", {}),
            "fixed_point_proof_sha256": proof.get("fixed_point_proof_sha256"),
        },
        "summary": {
            "decision_counts": dict(sorted(decision_counts.items())),
            "priority_counts": dict(sorted(priority_counts.items())),
            "operation_count": len(operations),
            "owner_decision_count": decision_counts.get("owner_decision", 0),
            "evidence_limit_count": decision_counts.get(
                "container_evidence_limit", 0
            ),
            "custom_code_decision_count": sum(
                bool(set(as_list(row.get("subject_keys"))) & code_keys)
                for row in decisions
            ),
        },
        "audit_decisions": decisions,
        "operations": operations,
        "decision_to_operation": packet.get("decision_to_operation", {}),
        "custom_code_decision_ids": [
            str(row.get("canonical_decision_id") or "")
            for row in decisions
            if set(as_list(row.get("subject_keys"))) & code_keys
        ],
        "owner_decision_ids": [
            str(row.get("canonical_decision_id") or "")
            for row in decisions
            if (row.get("decision") or {}).get("decision_class") == "owner_decision"
        ],
        "integrity_contract": {
            "one_primary_full_audit_row_per_decision": True,
            "one_primary_recommendation_row_per_operation": True,
            "one_primary_owner_row_per_owner_decision": True,
            "delivery_may_not_patch_canonical_fields": True,
        },
    }
    record["canonical_record_sha256"] = stable_hash(record, 64)
    if _validate_only:
        return record
    write_json(record_path, record)
    manifest = {
        "kind": "gtm_canonical_record_manifest",
        "schema_version": 1,
        "canonical_record_sha256": record["canonical_record_sha256"],
        "canonical_record_file_sha256": file_sha256(record_path),
        "inputs": [
            {
                "path": path,
                "sha256": file_sha256(package_dir / path),
            }
            for path in CANONICAL_INPUTS
        ],
        "record_counts": {
            "audit_decisions": len(decisions),
            "operations": len(operations),
            "owner_decisions": len(record["owner_decision_ids"]),
            "custom_code_decisions": len(record["custom_code_decision_ids"]),
        },
    }
    manifest["canonical_manifest_sha256"] = stable_hash(manifest, 64)
    manifest_path = package_dir / CANONICAL_MANIFEST_FILE
    write_json(manifest_path, manifest)
    seal = {
        "kind": "gtm_canonical_record_seal",
        "schema_version": 1,
        "canonical_record_sha256": record["canonical_record_sha256"],
        "canonical_record_file_sha256": file_sha256(record_path),
        "canonical_manifest_sha256": manifest["canonical_manifest_sha256"],
        "canonical_manifest_file_sha256": file_sha256(manifest_path),
        "validator_status": "pass",
    }
    seal["canonical_record_seal_sha256"] = _hash_without(
        seal, "canonical_record_seal_sha256"
    )
    write_json(package_dir / CANONICAL_SEAL_FILE, seal)
    return {
        "status": "pass",
        "canonical_record_sha256": record["canonical_record_sha256"],
        "decisions": len(decisions),
        "operations": len(operations),
        "canonical_record_seal_sha256": seal["canonical_record_seal_sha256"],
    }


def canonical_record_seal_errors(package_dir: Path) -> list[str]:
    require_safe_package_root(package_dir)
    record_path = package_dir / CANONICAL_RECORD_FILE
    manifest_path = package_dir / CANONICAL_MANIFEST_FILE
    seal_path = package_dir / CANONICAL_SEAL_FILE
    if not all(path.is_file() for path in (record_path, manifest_path, seal_path)):
        return ["canonical record, manifest, or seal is missing"]
    record = _load(record_path)
    manifest = _load(manifest_path)
    seal = _load(seal_path)
    errors: list[str] = []
    try:
        expected_record = build_canonical_record(package_dir, _validate_only=True)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return [f"canonical record reconstruction failed: {exc}"]
    if record != expected_record:
        errors.append("canonical record differs from deterministic reconstruction")
    if record.get("canonical_record_sha256") != _hash_without(
        record, "canonical_record_sha256"
    ):
        errors.append("canonical record content hash is invalid")
    if manifest.get("canonical_manifest_sha256") != _hash_without(
        manifest, "canonical_manifest_sha256"
    ):
        errors.append("canonical manifest content hash is invalid")
    if seal.get("canonical_record_seal_sha256") != _hash_without(
        seal, "canonical_record_seal_sha256"
    ):
        errors.append("canonical seal content hash is invalid")
    if seal.get("canonical_record_file_sha256") != file_sha256(record_path):
        errors.append("canonical record changed after sealing")
    if manifest.get("canonical_record_sha256") != record.get(
        "canonical_record_sha256"
    ):
        errors.append("canonical manifest is bound to another record")
    if manifest.get("canonical_record_file_sha256") != file_sha256(record_path):
        errors.append("canonical manifest record file hash is invalid")
    if seal.get("canonical_record_sha256") != record.get(
        "canonical_record_sha256"
    ):
        errors.append("canonical seal is bound to another record")
    if seal.get("canonical_manifest_sha256") != manifest.get(
        "canonical_manifest_sha256"
    ):
        errors.append("canonical seal is bound to another manifest")
    if seal.get("canonical_manifest_file_sha256") != file_sha256(manifest_path):
        errors.append("canonical manifest changed after sealing")
    input_rows = [
        item for item in as_list(manifest.get("inputs")) if isinstance(item, dict)
    ]
    input_paths = [str(item.get("path") or "") for item in input_rows]
    if input_paths != list(CANONICAL_INPUTS) or len(input_paths) != len(
        set(input_paths)
    ):
        errors.append("canonical manifest input inventory is not the exact closed set")
    for item in input_rows:
        try:
            path = contained_relative_path(
                package_dir,
                item.get("path"),
                "canonical manifest input path",
            )
        except ValueError as exc:
            errors.append(str(exc))
            continue
        if not path.is_file() or file_sha256(path) != item.get("sha256"):
            errors.append(f"canonical record input changed: {item.get('path')}")
    if seal.get("validator_status") != "pass":
        errors.append("canonical record validator did not pass")
    expected_manifest = {
        "kind": "gtm_canonical_record_manifest",
        "schema_version": 1,
        "canonical_record_sha256": expected_record.get("canonical_record_sha256"),
        "canonical_record_file_sha256": file_sha256(record_path),
        "inputs": [
            {"path": path, "sha256": file_sha256(package_dir / path)}
            for path in CANONICAL_INPUTS
        ],
        "record_counts": {
            "audit_decisions": len(as_list(expected_record.get("audit_decisions"))),
            "operations": len(as_list(expected_record.get("operations"))),
            "owner_decisions": len(as_list(expected_record.get("owner_decision_ids"))),
            "custom_code_decisions": len(
                as_list(expected_record.get("custom_code_decision_ids"))
            ),
        },
    }
    expected_manifest["canonical_manifest_sha256"] = stable_hash(
        expected_manifest, 64
    )
    if manifest != expected_manifest:
        errors.append("canonical manifest differs from exact reconstructed inventory")
    expected_seal = {
        "kind": "gtm_canonical_record_seal",
        "schema_version": 1,
        "canonical_record_sha256": expected_record.get("canonical_record_sha256"),
        "canonical_record_file_sha256": file_sha256(record_path),
        "canonical_manifest_sha256": expected_manifest.get(
            "canonical_manifest_sha256"
        ),
        "canonical_manifest_file_sha256": file_sha256(manifest_path),
        "validator_status": "pass",
    }
    expected_seal["canonical_record_seal_sha256"] = _hash_without(
        expected_seal, "canonical_record_seal_sha256"
    )
    if seal != expected_seal:
        errors.append("canonical seal differs from deterministic reconstruction")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("package_dir", type=Path)
    args = parser.parse_args()
    try:
        result = build_canonical_record(args.package_dir)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"status": "blocked", "errors": [str(exc)]}))
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
