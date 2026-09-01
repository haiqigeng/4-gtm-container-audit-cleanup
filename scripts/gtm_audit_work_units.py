#!/usr/bin/env python3
"""Plan and merge family-complete work units inside one clean-room audit."""

from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

from gtm_lib import as_list, stable_hash, write_json

WORK_UNIT_DIRECTORY = "work-units"
WORK_UNIT_MANIFEST = "work-unit-manifest.json"
MAX_SINGLE_OBLIGATIONS = 420
MAX_SINGLE_ESTIMATED_TOKENS = 180_000
MAX_FAMILY_OBLIGATIONS = 700
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
    # The estimate is deliberately simple and fixed. It is used only to choose
    # the schema shape, never to reduce audit scope or reviewer count.
    estimated_tokens = (
        obligations * 240
        + objects * 120
        + relationships * 180
        + code_segments * 320
        + shared_dependencies * 100
    )
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
    records = as_list(manifest.get("work_units"))
    strategy = manifest.get("strategy")
    if strategy == "single_file":
        if records:
            errors.append("single-file manifest unexpectedly declares work units")
        return expected, errors
    if strategy != "family_sharded":
        return expected, ["work-unit manifest strategy is invalid"]
    if not records:
        errors.append("family-sharded manifest declares no work units")
    for record in records:
        if not isinstance(record, dict):
            errors.append("work-unit manifest record is malformed")
            continue
        if set(record) != WORK_UNIT_RECORD_FIELDS:
            errors.append("work-unit manifest record fields differ from their schema")
        filename = str(record.get("filename") or "")
        relative = Path(filename)
        if (
            not filename
            or relative.is_absolute()
            or len(relative.parts) != 1
            or relative.as_posix() != filename
            or filename in expected
        ):
            errors.append("work-unit manifest filename is invalid or duplicated")
            continue
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
    decisions = [
        row for row in as_list(unit.get("decisions")) if isinstance(row, dict)
    ]
    if [str(row.get("obligation_id") or "") for row in decisions] != (
        declared_obligations
    ):
        errors.append("decision obligation membership differs from its manifest")
    if [str(row.get("decision_id") or "") for row in decisions] != [
        str(value) for value in as_list(unit.get("decision_ids"))
    ]:
        errors.append("decision identity membership differs from its immutable list")
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
    ordered_owners = [
        *sorted(key for key in grouped if key != "shared-infrastructure"),
        *( ["shared-infrastructure"] if "shared-infrastructure" in grouped else [] ),
    ]
    for index, owner in enumerate(ordered_owners, start=1):
        decisions = sorted(
            grouped[owner], key=lambda row: str(row.get("obligation_id") or "")
        )
        if owner != "shared-infrastructure" and len(decisions) > MAX_FAMILY_OBLIGATIONS:
            raise ValueError(
                f"{owner} exceeds the fixed complete-family schema ceiling; "
                "the audit is blocked rather than split into incomplete micro-shards"
            )
        filename_owner = re.sub(r"[^A-Za-z0-9_-]+", "-", owner).strip("-")
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
    directory = bundle / WORK_UNIT_DIRECTORY
    manifest_path = directory / WORK_UNIT_MANIFEST
    audit_path = bundle / "audit.json"
    if not manifest_path.is_file() or not audit_path.is_file():
        raise ValueError("work-unit manifest or bundle-local audit is missing")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("work_unit_manifest_sha256") != work_unit_identity_hash(manifest):
        raise ValueError("work-unit manifest identity changed")
    if manifest.get("strategy") != "family_sharded":
        raise ValueError("single-file audit has no work units to merge")
    _, declared_file_errors = declared_work_unit_files(manifest)
    if declared_file_errors:
        raise ValueError("; ".join(declared_file_errors))
    base = json.loads(audit_path.read_text(encoding="utf-8"))
    expected = {
        str(row.get("obligation_id") or "")
        for row in as_list(base.get("decisions"))
    }
    merged: dict[str, dict[str, Any]] = {}
    discoveries = []
    completed_units = []
    for record in as_list(manifest.get("work_units")):
        path = directory / str(record.get("filename") or "")
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

    if manifest.get("strategy") != "family_sharded":
        return [] if not audit.get("work_unit_completion") else [
            "single-file audit cannot claim sharded work-unit completion"
        ]
    completion = audit.get("work_unit_completion")
    if not isinstance(completion, dict):
        return ["family-sharded audit must be merged before validation"]
    errors = []
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
    expected_units = {
        str(row.get("work_unit_id") or ""): row
        for row in as_list(manifest.get("work_units"))
    }
    if len(expected_units) != len(as_list(manifest.get("work_units"))):
        errors.append("work-unit manifest contains duplicate work-unit identities")
    actual_units = {
        str(row.get("work_unit_id") or ""): row
        for row in as_list(completion.get("completed_units"))
        if isinstance(row, dict)
    }
    if "" in expected_units or set(actual_units) != set(expected_units):
        errors.append("work-unit completion does not cover every declared unit exactly once")
    directory = work_unit_directory or bundle / WORK_UNIT_DIRECTORY
    reconstructed_decisions: dict[str, dict[str, Any]] = {}
    reconstructed_discoveries: list[Any] = []
    for work_unit_id, record in expected_units.items():
        unit_path = directory / str(record.get("filename") or "")
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
        if stable_hash(unit, 64) != (actual_units.get(work_unit_id) or {}).get(
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
    if completion.get("merged_decisions_sha256") != stable_hash(
        reconstructed_rows, 64
    ):
        errors.append("merged decision proof differs from reconstructed work units")
    if completion.get("merged_discoveries_sha256") != stable_hash(
        reconstructed_discoveries, 64
    ):
        errors.append("merged discovery proof differs from reconstructed work units")
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
