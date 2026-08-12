#!/usr/bin/env python3
"""Compare two completed GTM audit packages without carrying verdicts forward."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from gtm_approval_response import CLEANUP_PACKET_SCHEMA_VERSION
from gtm_lib import as_list, load_json, stable_hash, write_json
from gtm_review_isolation import review_seal_errors

ACTION_FIELDS = ("creations", "additions", "changes", "remaps", "renames", "deletions")


def optional_json(path: Path) -> dict[str, Any]:
    return load_json(path) if path.is_file() else {}


def package_artifacts(
    package_dir: Path, operations_path: Path | None
) -> dict[str, dict[str, Any]]:
    if not package_dir.is_dir():
        raise ValueError(f"audit package directory does not exist: {package_dir}")
    artifact_paths = {
        "manifest": package_dir / "audit_package_manifest.json",
        "shared": package_dir / "shared_facts.json",
        "operational": package_dir / "operational_review.json",
        "configuration": package_dir / "configuration_review.json",
        "architecture": package_dir / "architecture_review.json",
    }
    missing = [str(path.name) for path in artifact_paths.values() if not path.is_file()]
    if missing:
        raise ValueError(
            "audit delta requires a complete package; missing: " + ", ".join(missing)
        )
    artifacts = {key: load_json(path) for key, path in artifact_paths.items()}
    manifest = artifacts["manifest"]
    if manifest.get("kind") != "gtm_audit_package_manifest" or manifest.get(
        "status"
    ) != "pass":
        raise ValueError("audit delta requires a passing audit package manifest")
    source_sha256 = str(manifest.get("source_sha256") or "")
    shared_sha256 = str(manifest.get("shared_facts_sha256") or "")
    context_sha256 = str(manifest.get("context_sha256") or "")
    if not source_sha256 or not shared_sha256 or not context_sha256:
        raise ValueError("audit delta package manifest is missing source locks")
    for key in ("shared", "operational", "configuration", "architecture"):
        if artifacts[key].get("source_sha256") != source_sha256:
            raise ValueError(f"audit delta {key} artifact uses another source")
    if artifacts["shared"].get("shared_facts_sha256") != shared_sha256:
        raise ValueError("audit delta shared facts differ from the package manifest")
    for key in ("operational", "configuration", "architecture"):
        if artifacts[key].get("shared_facts_sha256") != shared_sha256:
            raise ValueError(f"audit delta {key} artifact uses other shared facts")
        if artifacts[key].get("context_sha256") != context_sha256:
            raise ValueError(f"audit delta {key} artifact uses another context")
    incomplete_runs = [
        label
        for label, key in (
            ("operational_sanitation", "operational"),
            ("configuration_correctness", "configuration"),
            ("business_architecture", "architecture"),
        )
        if artifacts[key].get("run_status") != "complete"
    ]
    if incomplete_runs:
        raise ValueError(
            "audit delta requires freshly completed independent reviews: "
            + ", ".join(incomplete_runs)
        )
    seal_errors = review_seal_errors(package_dir, manifest)
    if seal_errors:
        raise ValueError(
            "audit delta requires three valid independent review seals: "
            + "; ".join(seal_errors)
        )
    if operations_path:
        resolved_operations = operations_path
    else:
        resolved_operations = next(
            (
                path
                for path in (
                    package_dir / "reconciled_operations.json",
                    package_dir / "operations.json",
                )
                if path.is_file()
            ),
            package_dir / "reconciled_operations.json",
        )
    artifacts["operations"] = optional_json(resolved_operations)
    if artifacts["operations"]:
        operations = artifacts["operations"]
        if (
            operations.get("kind") != "gtm_reconciled_operations"
            or operations.get("schema_version") != CLEANUP_PACKET_SCHEMA_VERSION
            or operations.get("plan_status") != "complete"
        ):
            raise ValueError(
                "audit delta operations must be a complete schema-"
                f"{CLEANUP_PACKET_SCHEMA_VERSION} packet"
            )
        for field, expected in (
            ("source_sha256", source_sha256),
            ("shared_facts_sha256", shared_sha256),
            ("context_sha256", context_sha256),
        ):
            if operations.get(field) != expected:
                raise ValueError(f"audit delta operations {field} differs from the package")
    return artifacts


def object_index(artifacts: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {
        str(row.get("object_key") or ""): {
            "object_key": str(row.get("object_key") or ""),
            "layer": str(row.get("layer") or ""),
            "object_name": str(row.get("object_name") or ""),
            "configuration_hash": str(row.get("configuration_hash") or ""),
        }
        for row in as_list(artifacts["shared"].get("objects"))
        if str(row.get("object_key") or "")
    }


def operational_findings(artifacts: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    result = {}
    for row in as_list(artifacts["operational"].get("findings")):
        finding_type = str(row.get("finding_type") or "")
        if not finding_type or finding_type == "zero_findings":
            continue
        identity = {
            "finding_type": finding_type,
            "object_keys": sorted(
                str(value)
                for value in as_list(
                    row.get("shared_fact_object_keys") or row.get("affected_object_keys")
                )
                if str(value)
            ),
            "evidence_paths": sorted(
                str(value)
                for value in as_list(row.get("evidence_paths"))
                if str(value)
            ),
            "repair": row.get("deterministic_repair") or {},
        }
        key = "OPS:" + stable_hash(identity, 32)
        result[key] = {
            "finding_key": key,
            "source_run": "operational_sanitation",
            "source_id": str(row.get("finding_id") or ""),
            "finding_type": finding_type,
            "object_keys": identity["object_keys"],
            "summary": str(row.get("summary") or row.get("rationale") or ""),
        }
    return result


def configuration_findings(
    artifacts: dict[str, dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    result = {}
    for row in as_list(artifacts["configuration"].get("rows")):
        object_key = str(row.get("object_key") or "")
        for defect in as_list(row.get("defects")):
            anchors = sorted(
                str(value)
                for value in as_list(defect.get("evidence_anchors"))
                if str(value)
            )
            line_hashes = sorted(
                str(value)
                for value in as_list(defect.get("code_line_hashes"))
                if str(value)
            )
            technical_keys = sorted(
                str(value)
                for value in as_list(defect.get("technical_finding_keys"))
                if str(value)
            )
            identity = {
                "object_key": object_key,
                "anchors": anchors,
                "line_hashes": line_hashes,
                "technical_finding_keys": technical_keys,
            }
            if not anchors and not line_hashes and not technical_keys:
                identity["statement_fallback"] = " ".join(
                    str(defect.get("statement") or "").casefold().split()
                )
            key = "CFG:" + stable_hash(identity, 32)
            existing = result.setdefault(
                key,
                {
                    "finding_key": key,
                    "source_run": "configuration_correctness",
                    "source_ids": [],
                    "finding_type": "configuration_defect",
                    "object_keys": [object_key] if object_key else [],
                    "evidence_anchors": anchors,
                    "code_line_hashes": line_hashes,
                    "technical_finding_keys": technical_keys,
                    "summaries": [],
                },
            )
            existing["source_ids"].append(
                f"{row.get('review_id')}:{defect.get('defect_id')}"
            )
            existing["summaries"].append(str(defect.get("statement") or ""))
    for finding in result.values():
        finding["source_ids"] = sorted(set(finding["source_ids"]))
        finding["summaries"] = sorted(set(finding["summaries"]))
    return result


def architecture_findings(
    artifacts: dict[str, dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    result = {}
    architecture = artifacts["architecture"]
    for collection, id_field, key_field in (
        ("families", "family_id", "chain_object_keys"),
        ("comparisons", "comparison_id", "candidate_object_keys"),
    ):
        for row in as_list(architecture.get(collection)):
            verdict = str(
                row.get("relationship_verdict")
                or row.get("disposition")
                or ""
            )
            if verdict in {"", "keep", "Intentional variant", "Complementary", "Unrelated"}:
                continue
            identity = {
                "collection": collection,
                "object_keys": sorted(
                    str(value) for value in as_list(row.get(key_field)) if str(value)
                ),
                "comparison_types": sorted(
                    str(value)
                    for value in as_list(row.get("comparison_types"))
                    if str(value)
                ),
            }
            key = "ARC:" + stable_hash(identity, 32)
            result[key] = {
                "finding_key": key,
                "source_run": "business_architecture",
                "source_id": str(row.get(id_field) or ""),
                "finding_type": str(
                    row.get("comparison_type") or row.get("disposition") or verdict
                ),
                "object_keys": identity["object_keys"],
                "summary": str(
                    row.get("analyst_rationale")
                    or row.get("family_purpose")
                    or row.get("target_architecture")
                    or ""
                ),
            }
    return result


def finding_index(artifacts: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {
        **operational_findings(artifacts),
        **configuration_findings(artifacts),
        **architecture_findings(artifacts),
    }


def operation_index(artifacts: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    result = {}
    for operation in as_list(artifacts["operations"].get("operations")):
        mutation = {field: as_list(operation.get(field)) for field in ACTION_FIELDS}
        key = "OP:" + stable_hash(mutation, 32)
        result[key] = {
            "operation_key": key,
            "source_operation_id": str(operation.get("operation_id") or ""),
            "title": str(operation.get("title") or ""),
            "priority": str(operation.get("priority") or ""),
            "affected_object_keys": sorted(
                str(value)
                for value in as_list(operation.get("affected_object_keys"))
                if str(value)
            ),
            "mutation_sha256": stable_hash(mutation, 64),
        }
    return result


def decision_index(artifacts: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {
        str(row.get("decision_id") or ""): {
            "decision_id": str(row.get("decision_id") or ""),
            "source_run": str(row.get("source_run") or ""),
            "disposition": str(row.get("disposition") or ""),
            "compiled_operation_ids": sorted(
                str(value)
                for value in as_list(row.get("compiled_operation_ids"))
                if str(value)
            ),
            "summary": str(row.get("summary") or ""),
        }
        for row in as_list(artifacts["operations"].get("decision_ledger"))
        if str(row.get("decision_id") or "")
    }


def family_index(artifacts: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {
        str(row.get("family_id") or ""): row
        for row in as_list(
            (artifacts["operations"].get("measurement_preservation") or {}).get(
                "families"
            )
        )
        if str(row.get("family_id") or "")
    }


def classified_delta(
    previous: dict[str, dict[str, Any]], current: dict[str, dict[str, Any]]
) -> dict[str, list[dict[str, Any]]]:
    previous_keys = set(previous)
    current_keys = set(current)
    return {
        "new": [current[key] for key in sorted(current_keys - previous_keys)],
        "resolved": [previous[key] for key in sorted(previous_keys - current_keys)],
        "recurring": [current[key] for key in sorted(previous_keys & current_keys)],
        "changed": changed_records(previous, current),
    }


def changed_records(
    previous: dict[str, dict[str, Any]], current: dict[str, dict[str, Any]]
) -> list[dict[str, Any]]:
    return [
        {
            "identity": key,
            "previous": previous[key],
            "current": current[key],
        }
        for key in sorted(set(previous) & set(current))
        if stable_hash(previous[key], 64) != stable_hash(current[key], 64)
    ]


def build_delta(
    previous: dict[str, dict[str, Any]], current: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    previous_objects = object_index(previous)
    current_objects = object_index(current)
    object_membership = classified_delta(previous_objects, current_objects)
    changed_objects = [
        {
            "object_key": key,
            "previous_name": previous_objects[key]["object_name"],
            "current_name": current_objects[key]["object_name"],
            "previous_configuration_hash": previous_objects[key]["configuration_hash"],
            "current_configuration_hash": current_objects[key]["configuration_hash"],
        }
        for key in sorted(set(previous_objects) & set(current_objects))
        if previous_objects[key]["configuration_hash"]
        != current_objects[key]["configuration_hash"]
    ]
    previous_findings = finding_index(previous)
    current_findings = finding_index(current)
    previous_operations = operation_index(previous)
    current_operations = operation_index(current)
    previous_decisions = decision_index(previous)
    current_decisions = decision_index(current)
    previous_families = family_index(previous)
    current_families = family_index(current)
    return {
        "kind": "gtm_audit_delta",
        "schema_version": 1,
        "status": "pass",
        "comparison_policy": (
            "Objective artifact comparison only. Both audits must be freshly completed "
            "with all three independent scans; no prior semantic verdict, disposition, "
            "or confidence is carried into the current audit."
        ),
        "previous": {
            "source_file": previous["manifest"].get("source_file"),
            "source_sha256": previous["manifest"].get("source_sha256"),
        },
        "current": {
            "source_file": current["manifest"].get("source_file"),
            "source_sha256": current["manifest"].get("source_sha256"),
        },
        "objects": {
            "added": object_membership["new"],
            "removed": object_membership["resolved"],
            "changed": changed_objects,
            "unchanged_count": len(object_membership["recurring"]) - len(changed_objects),
        },
        "findings": classified_delta(previous_findings, current_findings),
        "operations": classified_delta(previous_operations, current_operations),
        "changed_decisions": changed_records(previous_decisions, current_decisions),
        "added_decisions": [
            current_decisions[key]
            for key in sorted(set(current_decisions) - set(previous_decisions))
        ],
        "resolved_decisions": [
            previous_decisions[key]
            for key in sorted(set(previous_decisions) - set(current_decisions))
        ],
        "changed_measurement_families": changed_records(
            previous_families, current_families
        ),
        "count_delta": {
            "objects": len(current_objects) - len(previous_objects),
            "findings": len(current_findings) - len(previous_findings),
            "operations": len(current_operations) - len(previous_operations),
            "decisions": len(current_decisions) - len(previous_decisions),
            "measurement_families": len(current_families) - len(previous_families),
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("previous_package", type=Path)
    parser.add_argument("current_package", type=Path)
    parser.add_argument("--previous-operations", type=Path)
    parser.add_argument("--current-operations", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()
    try:
        previous = package_artifacts(
            args.previous_package, args.previous_operations
        )
        current = package_artifacts(args.current_package, args.current_operations)
        result = build_delta(previous, current)
        write_json(args.output, result, args.pretty)
        print(json.dumps(result, ensure_ascii=False, indent=2 if args.pretty else None))
        return 0
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
