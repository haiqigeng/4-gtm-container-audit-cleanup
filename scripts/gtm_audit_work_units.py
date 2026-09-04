#!/usr/bin/env python3
"""Plan and merge family-complete work units inside one clean-room audit."""

from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

from gtm_audit_contract import CANONICAL_DECISION_FIELDS, OPERATION_ACTION_FIELDS
from gtm_lib import (
    as_list,
    contained_relative_path,
    require_safe_package_root,
    stable_hash,
    write_json,
)

WORK_UNIT_DIRECTORY = "work-units"
WORK_UNIT_MANIFEST = "work-unit-manifest.json"
MAX_SINGLE_OBLIGATIONS = 420
MAX_SINGLE_ESTIMATED_TOKENS = 180_000
MAX_FAMILY_OBLIGATIONS = 700
MAX_SHARED_AREA_OBLIGATIONS = 60
WORK_UNIT_MANIFEST_IDENTITY_FIELDS = (
    "kind",
    "schema_version",
    "audit_id",
    "source_sha256",
    "obligation_ledger_sha256",
    "strategy",
    "workload_estimate",
    "work_units",
)
WORK_UNIT_IDENTITY_FIELDS = (
    "kind",
    "schema_version",
    "audit_id",
    "source_sha256",
    "obligation_ledger_sha256",
    "work_unit_id",
    "owner_family_id",
    "shared_infrastructure_unit",
    "decision_ids",
    "obligation_ids",
)
WORK_UNIT_MANIFEST_FIELDS = {
    *WORK_UNIT_MANIFEST_IDENTITY_FIELDS,
    "work_unit_manifest_sha256",
}
WORK_UNIT_RECORD_FIELDS = {
    "work_unit_id",
    "owner_family_id",
    "filename",
    "work_unit_identity_sha256",
    "obligation_ids",
}
WORK_UNIT_FIELDS = {
    *WORK_UNIT_IDENTITY_FIELDS,
    "decisions",
    "open_discoveries",
    "unit_closure",
    "work_unit_identity_sha256",
}
WORK_UNIT_COMPLETION_FIELDS = {
    "status",
    "strategy",
    "work_unit_manifest_sha256",
    "completed_units",
    "merged_decisions_sha256",
    "merged_discoveries_sha256",
    "work_unit_completion_sha256",
}
COMPLETED_UNIT_FIELDS = {
    "work_unit_id",
    "completed_work_unit_sha256",
}
WORKLOAD_ESTIMATE_FIELDS = {
    "object_count",
    "obligation_count",
    "relationship_count",
    "custom_code_segment_count",
    "shared_dependency_count",
    "estimated_authored_tokens",
    "schema_ceiling",
}
SCHEMA_CEILING_FIELDS = {
    "single_obligations",
    "single_estimated_tokens",
    "family_obligations",
}
SEMANTIC_AUDIT_DECISION_FIELDS = {
    "decision_id",
    "obligation_id",
    "obligation_sha256",
    "area_id",
    "scope_level",
    "audit_mechanism",
    "fact_kind",
    "subject_keys",
    "family_ids",
    "candidate_id",
    "source_coordinates",
    "applicability",
    "material_verification_triggers",
    "status",
    *CANONICAL_DECISION_FIELDS,
    "operation_proposal",
    "evidence_citations",
}
DISCOVERY_FIELDS = {
    "discovery_id",
    "area_id",
    "scope_level",
    "subject_keys",
    "family_ids",
    "source_coordinates",
    "decision",
}
DISCOVERY_DECISION_FIELDS = {
    "decision_id",
    *CANONICAL_DECISION_FIELDS,
    "operation_proposal",
    "evidence_citations",
}
OPERATION_PROPOSAL_FIELDS = {
    "operation_id",
    "source_decision_id",
    "operation_family",
    "exact_target_state",
    "preconditions",
    "static_verification",
    "rollback",
    "depends_on",
    *OPERATION_ACTION_FIELDS,
}
OPERATION_ACTION_ROW_FIELDS = {
    "creations": {"layer", "object"},
    "additions": {"object_key", "json_path", "value"},
    "changes": {"object_key", "json_path", "before_source_sha256", "after"},
    "removals": {"object_key", "json_path", "before_source_sha256"},
    "remaps": {"from_object_key", "to_object_key", "consumer_object_keys"},
    "renames": {"object_key", "before", "after"},
    "pauses": {"object_key", "before", "after"},
    "deletions": {"object_key"},
}


def _closed_object_list_errors(
    value: Any,
    fields: set[str],
    label: str,
) -> tuple[list[dict[str, Any]], list[str]]:
    errors: list[str] = []
    if not isinstance(value, list):
        return [], [f"{label} must be an exact object list"]
    rows: list[dict[str, Any]] = []
    for index, row in enumerate(value, start=1):
        if not isinstance(row, dict):
            errors.append(f"{label} row {index} is not an object")
            continue
        if set(row) != fields:
            errors.append(f"{label} row {index} fields differ from their closed schema")
        rows.append(row)
    return rows, errors


def operation_proposal_schema_errors(
    proposal: Any,
    label: str,
) -> list[str]:
    if proposal == {}:
        return []
    if not isinstance(proposal, dict):
        return [f"{label}: operation_proposal must be an object"]
    errors: list[str] = []
    if set(proposal) != OPERATION_PROPOSAL_FIELDS:
        errors.append(f"{label}: operation_proposal fields differ from its closed schema")
    if not isinstance(proposal.get("depends_on"), list) or any(
        not isinstance(value, str) for value in as_list(proposal.get("depends_on"))
    ):
        errors.append(f"{label}: operation depends_on must be a string list")
    for field, fields in OPERATION_ACTION_ROW_FIELDS.items():
        _rows, row_errors = _closed_object_list_errors(
            proposal.get(field), fields, f"{label}: operation {field}"
        )
        errors.extend(row_errors)
        if field in {"changes", "removals"}:
            for row in _rows:
                if not isinstance(row.get("before_source_sha256"), str) or not re.fullmatch(r"[0-9a-f]{64}", row["before_source_sha256"]):
                    errors.append(f"{label}: operation {field} requires a full source SHA-256")
    return errors


def semantic_audit_decision_schema_errors(
    decision: Any,
    label: str,
) -> list[str]:
    if not isinstance(decision, dict):
        return [f"{label}: decision is not an object"]
    errors: list[str] = []
    if set(decision) != SEMANTIC_AUDIT_DECISION_FIELDS:
        errors.append(f"{label}: decision fields differ from its closed schema")
    for field in (
        "subject_keys",
        "family_ids",
        "source_coordinates",
        "material_verification_triggers",
        "evidence_citations",
    ):
        if not isinstance(decision.get(field), list) or any(
            not isinstance(value, str) for value in as_list(decision.get(field))
        ):
            errors.append(f"{label}: {field} must be a string list")
    errors.extend(
        operation_proposal_schema_errors(decision.get("operation_proposal"), label)
    )
    return errors


def discovery_schema_errors(discovery: Any, label: str) -> list[str]:
    if not isinstance(discovery, dict):
        return [f"{label}: discovery is not an object"]
    errors: list[str] = []
    if set(discovery) != DISCOVERY_FIELDS:
        errors.append(f"{label}: discovery fields differ from its closed schema")
    for field in ("subject_keys", "family_ids", "source_coordinates"):
        if not isinstance(discovery.get(field), list) or any(
            not isinstance(value, str) for value in as_list(discovery.get(field))
        ):
            errors.append(f"{label}: {field} must be a string list")
    decision = discovery.get("decision")
    if not isinstance(decision, dict):
        errors.append(f"{label}: semantic decision must be an object")
    else:
        if set(decision) != DISCOVERY_DECISION_FIELDS:
            errors.append(
                f"{label}: discovery decision fields differ from its closed schema"
            )
        if not isinstance(decision.get("evidence_citations"), list) or any(
            not isinstance(value, str)
            for value in as_list(decision.get("evidence_citations"))
        ):
            errors.append(f"{label}: discovery evidence_citations must be a string list")
        errors.extend(
            operation_proposal_schema_errors(
                decision.get("operation_proposal"), f"{label}: discovery decision"
            )
        )
    return errors


def workload_estimate_schema_errors(estimate: Any) -> list[str]:
    if not isinstance(estimate, dict):
        return ["workload estimate must be an object"]
    errors: list[str] = []
    if set(estimate) != WORKLOAD_ESTIMATE_FIELDS:
        errors.append("workload estimate fields differ from its closed schema")
    for field in WORKLOAD_ESTIMATE_FIELDS - {"schema_ceiling"}:
        value = estimate.get(field)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            errors.append(f"workload estimate {field} must be a non-negative integer")
    ceiling = estimate.get("schema_ceiling")
    if not isinstance(ceiling, dict):
        errors.append("workload estimate schema_ceiling must be an object")
    else:
        if set(ceiling) != SCHEMA_CEILING_FIELDS:
            errors.append("workload schema ceiling fields differ from its closed schema")
        for field in SCHEMA_CEILING_FIELDS:
            value = ceiling.get(field)
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                errors.append(f"workload schema ceiling {field} must be a positive integer")
    return errors


def deterministic_workload_errors(
    manifest: dict[str, Any],
    scan: dict[str, Any],
    assurance: dict[str, Any],
    audit: dict[str, Any],
) -> list[str]:
    errors = workload_estimate_schema_errors(manifest.get("workload_estimate"))
    if not errors:
        reconstructed = workload_estimate(scan, assurance, audit)
        if manifest.get("workload_estimate") != reconstructed:
            errors.append(
                "workload estimate is not the exact deterministic reconstruction"
            )
        expected_strategy = (
            "family_sharded"
            if reconstructed["obligation_count"] > MAX_SINGLE_OBLIGATIONS
            or reconstructed["estimated_authored_tokens"]
            > MAX_SINGLE_ESTIMATED_TOKENS
            else "single_file"
        )
        if manifest.get("strategy") != expected_strategy:
            errors.append("work-unit strategy differs from deterministic workload")
    return errors


def workload_estimate(
    scan: dict[str, Any],
    assurance: dict[str, Any],
    audit: dict[str, Any],
) -> dict[str, Any]:
    obligations = len(as_list(audit.get("decisions")))
    objects = int((scan.get("counts") or {}).get("objects") or 0)
    relationships = int((scan.get("counts") or {}).get("relationships") or 0)
    code_segments = len(
        as_list(
            (assurance.get("recomputed_invariants") or {}).get(
                "custom_code_segments"
            )
        )
    )
    shared_dependencies = sum(
        len(as_list(row.get("execution_dependency_traces")))
        for row in as_list(scan.get("objects"))
    )
    candidate_count = min(
        obligations,
        int((scan.get("counts") or {}).get("operational_candidates") or 0),
    )
    # Exact-ID decision groups carry each obligation identity once while sharing
    # genuinely identical prose. Candidate decisions retain the full per-finding
    # allowance because their targets and evidence commonly differ.
    estimated_tokens = candidate_count * 90 + (obligations - candidate_count) * 16
    return {
        "object_count": objects,
        "obligation_count": obligations,
        "relationship_count": relationships,
        "custom_code_segment_count": code_segments,
        "shared_dependency_count": shared_dependencies,
        "estimated_authored_tokens": estimated_tokens,
        "schema_ceiling": {
            "single_obligations": MAX_SINGLE_OBLIGATIONS,
            "single_estimated_tokens": MAX_SINGLE_ESTIMATED_TOKENS,
            "family_obligations": MAX_FAMILY_OBLIGATIONS,
        },
    }


def _family_members(scan: dict[str, Any]) -> dict[str, set[str]]:
    result: dict[str, set[str]] = {}
    for family in as_list(
        (scan.get("architecture_evidence") or {}).get("families")
    ):
        if not isinstance(family, dict):
            continue
        family_id = str(family.get("family_id") or "")
        if family_id:
            result[family_id] = {
                str(value)
                for value in [
                    *as_list(family.get("member_object_keys")),
                    *as_list(family.get("chain_object_keys")),
                ]
                if str(value)
            }
    return result


def _decision_owner_family(
    decision: dict[str, Any],
    families: dict[str, set[str]],
) -> str:
    explicit = [str(value) for value in as_list(decision.get("family_ids")) if str(value)]
    if len(explicit) == 1 and explicit[0] in families:
        return explicit[0]
    subjects = {
        str(value) for value in as_list(decision.get("subject_keys")) if str(value)
    }
    if not subjects or decision.get("scope_level") in {"coverage", "container"}:
        return "shared-infrastructure"
    owners = [
        family_id
        for family_id, members in families.items()
        if subjects <= members
    ]
    return sorted(owners)[0] if len(owners) == 1 else "shared-infrastructure"


def work_unit_identity_hash(payload: dict[str, Any]) -> str:
    """Hash only the explicit immutable fields for this artifact kind."""

    kind = payload.get("kind")
    if kind == "gtm_cleanroom_work_unit_manifest":
        fields = WORK_UNIT_MANIFEST_IDENTITY_FIELDS
    elif kind == "gtm_cleanroom_family_work_unit":
        fields = WORK_UNIT_IDENTITY_FIELDS
    else:
        return ""
    return stable_hash({field: payload.get(field) for field in fields}, 64)


def declared_work_unit_files(
    manifest: dict[str, Any],
) -> tuple[set[str], list[str]]:
    """Return the only files permitted in one generated work-unit directory."""

    expected = {WORK_UNIT_MANIFEST}
    errors: list[str] = []
    if set(manifest) != WORK_UNIT_MANIFEST_FIELDS:
        errors.append("work-unit manifest fields differ from its closed schema")
    errors.extend(workload_estimate_schema_errors(manifest.get("workload_estimate")))
    raw_records = manifest.get("work_units")
    if not isinstance(raw_records, list):
        records: list[Any] = []
        errors.append("work-unit manifest work_units must be an exact object list")
    else:
        records = raw_records
    strategy = manifest.get("strategy")
    if strategy == "single_file":
        if records:
            errors.append("single-file manifest unexpectedly declares work units")
        return expected, errors
    if strategy != "family_sharded":
        errors.append("work-unit manifest strategy is invalid")
        return expected, errors
    if not records:
        errors.append("family-sharded manifest declares no work units")
    seen_work_unit_ids: set[str] = set()
    seen_filenames: set[str] = set()
    for record in records:
        if not isinstance(record, dict):
            errors.append("work-unit manifest record is malformed")
            continue
        if set(record) != WORK_UNIT_RECORD_FIELDS:
            errors.append("work-unit manifest record fields differ from their schema")
        work_unit_id = str(record.get("work_unit_id") or "")
        if not work_unit_id or work_unit_id in seen_work_unit_ids:
            errors.append("work-unit manifest work_unit_id is blank or duplicated")
        seen_work_unit_ids.add(work_unit_id)
        obligation_ids = record.get("obligation_ids")
        if not isinstance(obligation_ids, list) or any(
            not isinstance(value, str) or not value for value in as_list(obligation_ids)
        ):
            errors.append("work-unit manifest obligation_ids must be a non-blank string list")
        elif len(set(obligation_ids)) != len(obligation_ids):
            errors.append("work-unit manifest obligation_ids contain duplicates")
        filename = str(record.get("filename") or "")
        relative = Path(filename)
        if (
            not filename
            or relative.is_absolute()
            or len(relative.parts) != 1
            or relative.as_posix() != filename
            or filename in expected
            or filename in seen_filenames
        ):
            errors.append("work-unit manifest filename is invalid or duplicated")
            continue
        seen_filenames.add(filename)
        expected.add(filename)
    return expected, errors


def work_unit_contract_errors(
    unit: dict[str, Any],
    record: dict[str, Any],
    manifest: dict[str, Any],
) -> list[str]:
    """Recompute immutable identity and prove one unit belongs to its manifest."""

    errors: list[str] = []
    if set(unit) != WORK_UNIT_FIELDS:
        errors.append("work-unit fields differ from their closed schema")
    checks = (
        ("kind", "gtm_cleanroom_family_work_unit"),
        ("schema_version", 1),
        ("audit_id", manifest.get("audit_id")),
        ("source_sha256", manifest.get("source_sha256")),
        (
            "obligation_ledger_sha256",
            manifest.get("obligation_ledger_sha256"),
        ),
        ("work_unit_id", record.get("work_unit_id")),
        ("owner_family_id", record.get("owner_family_id")),
        (
            "shared_infrastructure_unit",
            record.get("owner_family_id") == "shared-infrastructure",
        ),
    )
    for field, expected in checks:
        if unit.get(field) != expected:
            errors.append(f"immutable field {field} differs from its manifest")
    declared_obligations = [
        str(value) for value in as_list(record.get("obligation_ids"))
    ]
    if [str(value) for value in as_list(unit.get("obligation_ids"))] != (
        declared_obligations
    ):
        errors.append("immutable obligation membership differs from its manifest")
    raw_decisions = unit.get("decisions")
    if not isinstance(raw_decisions, list) or any(
        not isinstance(row, dict) for row in raw_decisions
    ):
        errors.append("decisions must be a declared-only object list")
        decisions = []
    else:
        decisions = raw_decisions
        for index, decision in enumerate(decisions, start=1):
            errors.extend(
                semantic_audit_decision_schema_errors(
                    decision, f"work-unit decision {index}"
                )
            )
    if [str(row.get("obligation_id") or "") for row in decisions] != (
        declared_obligations
    ):
        errors.append("decision obligation membership differs from its manifest")
    if [str(row.get("decision_id") or "") for row in decisions] != [
        str(value) for value in as_list(unit.get("decision_ids"))
    ]:
        errors.append("decision identity membership differs from its immutable list")
    raw_discoveries = unit.get("open_discoveries")
    if not isinstance(raw_discoveries, list) or any(
        not isinstance(row, dict) for row in raw_discoveries
    ):
        errors.append("open discoveries must be a declared-only object list")
    else:
        for index, discovery in enumerate(raw_discoveries, start=1):
            errors.extend(
                discovery_schema_errors(discovery, f"work-unit discovery {index}")
            )
    embedded_identity = str(unit.get("work_unit_identity_sha256") or "")
    if embedded_identity != str(record.get("work_unit_identity_sha256") or ""):
        errors.append("embedded identity differs from its manifest")
    if embedded_identity != work_unit_identity_hash(unit):
        errors.append("immutable identity does not match the unit content")
    return errors


def build_work_units(
    bundle: Path,
    audit: dict[str, Any],
    scan: dict[str, Any],
    assurance: dict[str, Any],
) -> dict[str, Any]:
    estimate = workload_estimate(scan, assurance, audit)
    sharded = bool(
        estimate["obligation_count"] > MAX_SINGLE_OBLIGATIONS
        or estimate["estimated_authored_tokens"] > MAX_SINGLE_ESTIMATED_TOKENS
    )
    directory = bundle / WORK_UNIT_DIRECTORY
    directory.mkdir(exist_ok=True)
    manifest = {
        "kind": "gtm_cleanroom_work_unit_manifest",
        "schema_version": 1,
        "audit_id": audit.get("audit_id"),
        "source_sha256": audit.get("source_sha256"),
        "obligation_ledger_sha256": audit.get("obligation_ledger_sha256"),
        "strategy": "family_sharded" if sharded else "single_file",
        "workload_estimate": estimate,
        "work_units": [],
    }
    if not sharded:
        manifest["work_unit_manifest_sha256"] = work_unit_identity_hash(manifest)
        write_json(directory / WORK_UNIT_MANIFEST, manifest)
        return manifest

    families = _family_members(scan)
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for decision in as_list(audit.get("decisions")):
        if not isinstance(decision, dict):
            continue
        grouped[_decision_owner_family(decision, families)].append(decision)
    unit_specs: list[tuple[str, str, list[dict[str, Any]]]] = []
    for owner in sorted(key for key in grouped if key != "shared-infrastructure"):
        unit_specs.append((owner, owner, grouped[owner]))
    shared_by_area: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for decision in grouped.get("shared-infrastructure", []):
        shared_by_area[str(decision.get("area_id") or "AREA-UNKNOWN")].append(decision)
    for area_id in sorted(shared_by_area):
        decisions = sorted(
            shared_by_area[area_id],
            key=lambda row: str(row.get("obligation_id") or ""),
        )
        for offset in range(0, len(decisions), MAX_SHARED_AREA_OBLIGATIONS):
            part = offset // MAX_SHARED_AREA_OBLIGATIONS + 1
            unit_specs.append(
                (
                    "shared-infrastructure",
                    f"shared-infrastructure-{area_id}-part-{part:02d}",
                    decisions[offset : offset + MAX_SHARED_AREA_OBLIGATIONS],
                )
            )
    for index, (owner, unit_label, unsorted_decisions) in enumerate(unit_specs, start=1):
        decisions = sorted(
            unsorted_decisions,
            key=lambda row: str(row.get("obligation_id") or ""),
        )
        if owner != "shared-infrastructure" and len(decisions) > MAX_FAMILY_OBLIGATIONS:
            raise ValueError(
                f"{owner} exceeds the fixed complete-family schema ceiling; "
                "the audit is blocked rather than split into incomplete micro-shards"
            )
        filename_owner = re.sub(r"[^A-Za-z0-9_-]+", "-", unit_label).strip("-")
        filename = f"unit-{index:03d}-{filename_owner}.json"
        work_unit = {
            "kind": "gtm_cleanroom_family_work_unit",
            "schema_version": 1,
            "audit_id": audit.get("audit_id"),
            "source_sha256": audit.get("source_sha256"),
            "obligation_ledger_sha256": audit.get("obligation_ledger_sha256"),
            "work_unit_id": f"WU-{index:03d}",
            "owner_family_id": owner,
            "shared_infrastructure_unit": owner == "shared-infrastructure",
            "decision_ids": [str(row.get("decision_id") or "") for row in decisions],
            "obligation_ids": [str(row.get("obligation_id") or "") for row in decisions],
            "decisions": decisions,
            "open_discoveries": [],
            "unit_closure": "",
        }
        work_unit["work_unit_identity_sha256"] = work_unit_identity_hash(work_unit)
        write_json(directory / filename, work_unit)
        manifest["work_units"].append(
            {
                "work_unit_id": work_unit["work_unit_id"],
                "owner_family_id": owner,
                "filename": filename,
                "work_unit_identity_sha256": work_unit[
                    "work_unit_identity_sha256"
                ],
                "obligation_ids": work_unit["obligation_ids"],
            }
        )
    manifest["work_unit_manifest_sha256"] = work_unit_identity_hash(manifest)
    write_json(directory / WORK_UNIT_MANIFEST, manifest)
    return manifest


def merge_work_units(bundle: Path) -> dict[str, Any]:
    guard_root = (
        bundle.parent.parent
        if bundle.parent.name == "audit-bundles"
        else bundle
    )
    require_safe_package_root(guard_root)
    directory = bundle / WORK_UNIT_DIRECTORY
    manifest_path = directory / WORK_UNIT_MANIFEST
    audit_path = bundle / "audit.json"
    scan_path = bundle / "canonical-scan.json"
    assurance_path = bundle / "scan-assurance.json"
    if not all(
        path.is_file()
        for path in (manifest_path, audit_path, scan_path, assurance_path)
    ):
        raise ValueError(
            "work-unit manifest, audit, canonical scan, or scan assurance is missing"
        )
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("work_unit_manifest_sha256") != work_unit_identity_hash(manifest):
        raise ValueError("work-unit manifest identity changed")
    if manifest.get("strategy") != "family_sharded":
        raise ValueError("single-file audit has no work units to merge")
    _, declared_file_errors = declared_work_unit_files(manifest)
    if declared_file_errors:
        raise ValueError("; ".join(declared_file_errors))
    base = json.loads(audit_path.read_text(encoding="utf-8"))
    scan = json.loads(scan_path.read_text(encoding="utf-8"))
    assurance = json.loads(assurance_path.read_text(encoding="utf-8"))
    workload_errors = deterministic_workload_errors(
        manifest, scan, assurance, base
    )
    if workload_errors:
        raise ValueError("; ".join(workload_errors))
    expected = {
        str(row.get("obligation_id") or "")
        for row in as_list(base.get("decisions"))
    }
    merged: dict[str, dict[str, Any]] = {}
    discoveries = []
    completed_units = []
    for record in as_list(manifest.get("work_units")):
        path = contained_relative_path(
            directory,
            record.get("filename"),
            "work-unit manifest filename",
        )
        if not path.is_file():
            raise ValueError(f"work unit is missing: {path.name}")
        unit = json.loads(path.read_text(encoding="utf-8"))
        contract_errors = work_unit_contract_errors(unit, record, manifest)
        if contract_errors:
            raise ValueError(
                f"work unit contract changed: {path.name}: "
                + "; ".join(contract_errors)
            )
        if not str(unit.get("unit_closure") or "").strip():
            raise ValueError(f"work unit is not closed: {path.name}")
        declared = [str(value) for value in as_list(record.get("obligation_ids"))]
        decisions = [
            row for row in as_list(unit.get("decisions")) if isinstance(row, dict)
        ]
        actual = [str(row.get("obligation_id") or "") for row in decisions]
        if actual != declared:
            raise ValueError(f"work unit decision membership changed: {path.name}")
        for row in decisions:
            obligation_id = str(row.get("obligation_id") or "")
            if obligation_id in merged:
                raise ValueError(f"obligation appears in multiple work units: {obligation_id}")
            merged[obligation_id] = row
        discoveries.extend(as_list(unit.get("open_discoveries")))
        completed_units.append(
            {
                "work_unit_id": record.get("work_unit_id"),
                "completed_work_unit_sha256": stable_hash(unit, 64),
            }
        )
    if set(merged) != expected:
        raise ValueError("merged work units do not cover the complete audit")
    base["decisions"] = [merged[key] for key in sorted(merged)]
    base["open_discoveries"] = discoveries
    completion = {
        "status": "complete",
        "strategy": "family_sharded",
        "work_unit_manifest_sha256": manifest.get("work_unit_manifest_sha256"),
        "completed_units": completed_units,
        "merged_decisions_sha256": stable_hash(base["decisions"], 64),
        "merged_discoveries_sha256": stable_hash(discoveries, 64),
    }
    completion["work_unit_completion_sha256"] = stable_hash(completion, 64)
    base["work_unit_completion"] = completion
    require_safe_package_root(guard_root)
    write_json(audit_path, base)
    return {
        "status": "pass",
        "audit_file": str(audit_path),
        "merged_decisions": len(merged),
        "merged_discoveries": len(discoveries),
        "work_unit_completion_sha256": completion["work_unit_completion_sha256"],
    }


def work_unit_completion_errors(
    bundle: Path,
    audit: dict[str, Any],
    manifest: dict[str, Any],
    *,
    work_unit_directory: Path | None = None,
) -> list[str]:
    """Prove a sharded audit was merged from every closed declared unit."""

    errors: list[str] = []
    scan_path = bundle / "canonical-scan.json"
    assurance_path = bundle / "scan-assurance.json"
    if not scan_path.is_file() or not assurance_path.is_file():
        errors.append("deterministic workload source artifacts are missing")
    else:
        try:
            scan = json.loads(scan_path.read_text(encoding="utf-8"))
            assurance = json.loads(assurance_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            errors.append("deterministic workload source artifacts are malformed")
        else:
            errors.extend(
                deterministic_workload_errors(manifest, scan, assurance, audit)
            )
    if manifest.get("strategy") != "family_sharded":
        if audit.get("work_unit_completion"):
            errors.append("single-file audit cannot claim sharded work-unit completion")
        return errors
    completion = audit.get("work_unit_completion")
    if not isinstance(completion, dict):
        errors.append("family-sharded audit must be merged before validation")
        return errors
    if set(completion) != WORK_UNIT_COMPLETION_FIELDS:
        errors.append("work-unit completion fields differ from their closed schema")
    unsigned = {
        key: value
        for key, value in completion.items()
        if key != "work_unit_completion_sha256"
    }
    if completion.get("work_unit_completion_sha256") != stable_hash(unsigned, 64):
        errors.append("work-unit completion identity is invalid")
    if completion.get("status") != "complete":
        errors.append("work-unit completion status must be complete")
    if completion.get("strategy") != "family_sharded":
        errors.append("work-unit completion strategy differs from its manifest")
    if completion.get("work_unit_manifest_sha256") != manifest.get(
        "work_unit_manifest_sha256"
    ):
        errors.append("work-unit completion uses another manifest")
    manifest_records = as_list(manifest.get("work_units"))
    expected_units = {
        str(row.get("work_unit_id") or ""): row
        for row in manifest_records
        if isinstance(row, dict)
    }
    if len(expected_units) != len(manifest_records):
        errors.append("work-unit manifest contains duplicate work-unit identities")
    raw_completed_units = completion.get("completed_units")
    if not isinstance(raw_completed_units, list):
        errors.append("completed unit proof must be an exact object list")
        completed_unit_records: list[dict[str, Any]] = []
    else:
        completed_unit_records = []
        for row in raw_completed_units:
            if not isinstance(row, dict):
                errors.append("completed unit proof contains a non-object row")
                continue
            if set(row) != COMPLETED_UNIT_FIELDS:
                errors.append("completed unit proof row fields differ from their schema")
            completed_unit_records.append(row)
    actual_units = {
        str(row.get("work_unit_id") or ""): row for row in completed_unit_records
    }
    if len(actual_units) != len(completed_unit_records):
        errors.append("completed unit proof contains duplicate identities")
    if "" in expected_units or set(actual_units) != set(expected_units):
        errors.append("work-unit completion does not cover every declared unit exactly once")
    directory = work_unit_directory or bundle / WORK_UNIT_DIRECTORY
    reconstructed_decisions: dict[str, dict[str, Any]] = {}
    reconstructed_discoveries: list[Any] = []
    reconstructed_completed_units: list[dict[str, str]] = []
    for work_unit_id, record in expected_units.items():
        try:
            unit_path = contained_relative_path(
                directory,
                record.get("filename"),
                "work-unit manifest filename",
            )
        except ValueError as exc:
            errors.append(str(exc))
            continue
        if not unit_path.is_file():
            errors.append(f"completed work unit is missing: {work_unit_id}")
            continue
        unit = json.loads(unit_path.read_text(encoding="utf-8"))
        errors.extend(
            f"completed work unit {work_unit_id}: {error}"
            for error in work_unit_contract_errors(unit, record, manifest)
        )
        if not str(unit.get("unit_closure") or "").strip():
            errors.append(f"completed work unit {work_unit_id}: closure is missing")
        for decision in as_list(unit.get("decisions")):
            if not isinstance(decision, dict):
                continue
            obligation_id = str(decision.get("obligation_id") or "")
            if obligation_id in reconstructed_decisions:
                errors.append(
                    f"completed work unit {work_unit_id}: obligation is duplicated"
                )
            else:
                reconstructed_decisions[obligation_id] = decision
        reconstructed_discoveries.extend(as_list(unit.get("open_discoveries")))
        completed_unit_sha256 = stable_hash(unit, 64)
        reconstructed_completed_units.append(
            {
                "work_unit_id": work_unit_id,
                "completed_work_unit_sha256": completed_unit_sha256,
            }
        )
        if completed_unit_sha256 != (actual_units.get(work_unit_id) or {}).get(
            "completed_work_unit_sha256"
        ):
            errors.append(f"completed work unit changed after merge: {work_unit_id}")
    reconstructed_rows = [
        reconstructed_decisions[key] for key in sorted(reconstructed_decisions)
    ]
    if as_list(audit.get("decisions")) != reconstructed_rows:
        errors.append("audit decisions are not the exact deterministic work-unit merge")
    if as_list(audit.get("open_discoveries")) != reconstructed_discoveries:
        errors.append("audit discoveries are not the exact deterministic work-unit merge")
    merged_decisions_sha256 = stable_hash(reconstructed_rows, 64)
    merged_discoveries_sha256 = stable_hash(reconstructed_discoveries, 64)
    if completion.get("merged_decisions_sha256") != merged_decisions_sha256:
        errors.append("merged decision proof differs from reconstructed work units")
    if completion.get("merged_discoveries_sha256") != merged_discoveries_sha256:
        errors.append("merged discovery proof differs from reconstructed work units")
    reconstructed_completion: dict[str, Any] = {
        "status": "complete",
        "strategy": "family_sharded",
        "work_unit_manifest_sha256": manifest.get("work_unit_manifest_sha256"),
        "completed_units": reconstructed_completed_units,
        "merged_decisions_sha256": merged_decisions_sha256,
        "merged_discoveries_sha256": merged_discoveries_sha256,
    }
    reconstructed_completion["work_unit_completion_sha256"] = stable_hash(
        reconstructed_completion, 64
    )
    if completion != reconstructed_completion:
        errors.append("work-unit completion is not the exact reconstructed proof")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path)
    args = parser.parse_args()
    try:
        result = merge_work_units(args.bundle)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"status": "blocked", "errors": [str(exc)]}))
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
