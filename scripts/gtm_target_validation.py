#!/usr/bin/env python3
"""Validate and exactly replay one source-reconciled static target packet."""

from __future__ import annotations

import argparse
import json
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any

from gtm_canonical_scan import build_canonical_scan
from gtm_lib import (
    as_list,
    container_version,
    custom_template_ids,
    custom_template_type_index,
    file_sha256,
    require_safe_package_root,
    stable_hash,
    write_json,
)
from gtm_operation_model import apply_operations, object_catalog
from gtm_scan_assurance import assure_scan
from gtm_target_synthesis import build_operation_packet_payloads, operation_error_context

TARGET_VALIDATION_ROOT = "target-validation"
PROOF_FILE = "validation-proof.json"
SEAL_FILE = "validation-seal.json"
EVIDENCE_FILES = ("projected-container.json", "canonical-scan.json", "scan-assurance.json")
ARTIFACT_FILES = (*EVIDENCE_FILES, PROOF_FILE, SEAL_FILE)
INPUT_FILES = (
    "audit-package-manifest.json",
    "locked-source.json",
    "context.json",
    "vendor-registry.toml",
    "canonical-scan.json",
    "scan-assurance.json",
    "obligation-ledger.json",
    "reconciled-decisions.json",
    "reconciliation-seal.json",
    "operation-packet.json",
)
BOUNDARY = (
    "Single-pass static validation of the source-reconciled operation packet. "
    "Checks exact actions, protected objects, dependencies, conflicts, consent ownership, "
    "new graph regressions, scan assurance and deterministic replay. Unchanged source "
    "issues retain their reconciled dispositions. No projected semantic review, "
    "convergence, absence of future optimisations, or runtime behavior is proven."
)


def _load(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"JSON artifact must be an object: {path}")
    return payload


def _input_hashes(package_dir: Path) -> dict[str, str]:
    paths = [*INPUT_FILES]
    if (package_dir / "approved-requirements.json").is_file():
        paths.append("approved-requirements.json")
    return {name: file_sha256(package_dir / name) for name in paths}


def _graph_issues(source: dict[str, Any], scan: dict[str, Any]) -> Counter[str]:
    """Count broken dependency occurrences without treating array shifts as changes."""
    issues: Counter[str] = Counter()
    names: dict[tuple[str, str], list[str]] = {}
    for row in as_list(scan.get("objects")):
        names.setdefault((row["layer"], row["object_name"]), []).append(row["object_key"])

    def reference_identity(relation: str, reference: str) -> str:
        layer = "tag" if relation in {"setupTag", "teardownTag"} else "variable"
        matches = names.get((layer, reference), []) if relation in {
            "setupTag", "teardownTag", "variable_reference"
        } else []
        return matches[0] if len(matches) == 1 else reference

    def visit(
        value: Any, owner: str, chain: tuple[str, ...] = (), occurrences: int = 1
    ) -> None:
        if isinstance(value, list):
            for child in value:
                visit(child, owner, chain, occurrences)
        elif isinstance(value, dict):
            # Variable traces group identical references across multiple source
            # fields. Preserve their multiplicity, not their unstable indices.
            if "relation" not in value:
                occurrences *= max(1, len(as_list(value.get("source_reference_paths"))))
            reference = str(value.get("reference") or "")
            relation = str(value.get("relation") or "variable_reference")
            if reference:
                chain = (*chain, f"{relation}:{reference_identity(relation, reference)}")
            state = value.get("resolution_state") or value.get("state")
            if state in {"missing", "ambiguous", "cycle", "malformed"}:
                issues[f"{owner}: {state} dependency {' -> '.join(chain) or relation}"] += occurrences
            for key in ("targets", "member_traces", "sequence_traces", "terminal_requirements"):
                if key in value:
                    visit(value[key], owner, chain, occurrences)

    for row in as_list(scan.get("objects")):
        owner = str(row["object_key"])
        visit(row.get("execution_dependency_traces", []), owner)
        visit(row.get("reference_trace_requirements", []), owner)

    cv = container_version(source)
    catalog = object_catalog(source)
    templates = as_list(cv.get("customTemplate"))
    template_types = custom_template_type_index(templates)
    for key, row in catalog.items():
        obj = row["object"]
        folder = str(obj.get("parentFolderId") or "")
        if folder and f"folder:{folder}" not in catalog:
            issues[f"{key}: missing folder reference {folder}"] += 1
        template_ids = custom_template_ids(obj, template_types)
        type_token = str(obj.get("type") or "")
        if type_token.startswith("cvt_") and not template_ids:
            issues[f"{key}: missing custom template type {type_token}"] += 1
        if len(template_ids) > 1:
            issues[f"{key}: ambiguous custom template type {type_token}"] += 1
        for template_id in template_ids:
            if template_id and f"customTemplate:{template_id}" not in catalog:
                issues[f"{key}: missing custom template reference {template_id}"] += 1
    return issues


def _build_target_evidence(
    package_dir: Path, output_dir: Path, projected: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, Any]]:
    projected_path = output_dir / "projected-container.json"
    write_json(projected_path, projected)
    context = _load(package_dir / "context.json")
    requirements_path = package_dir / "approved-requirements.json"
    result = build_canonical_scan(
        projected_path,
        provided_context=dict(context.get("provided_context") or {}),
        approved_requirements=_load(requirements_path) if requirements_path.is_file() else {},
    )
    scan = result["canonical_scan"]
    assurance = assure_scan(
        projected_path, scan,
        vendor_registry_path=package_dir / "vendor-registry.toml",
    )
    if assurance.get("status") != "pass":
        failed = [
            f"{row.get('check_id') or 'unknown'}: {json.dumps(row, sort_keys=True)}"
            for row in as_list(assurance.get("checks")) if row.get("status") != "pass"
        ]
        raise ValueError("target scan assurance failed: " + "; ".join(failed or ["status is not pass"]))
    write_json(output_dir / "canonical-scan.json", scan)
    write_json(output_dir / "scan-assurance.json", assurance)
    return scan, assurance


def _reconstruct(package_dir: Path, staging: Path) -> dict[str, Any]:
    """Build evidence and proof from authority, without changing the package."""
    inputs = _input_hashes(package_dir)
    packet, projected = build_operation_packet_payloads(package_dir)
    stored_packet = _load(package_dir / "operation-packet.json")
    operations = as_list(packet.get("operations"))
    if stored_packet != packet:
        raise ValueError("; ".join(operation_error_context(
            operations, ["operation packet differs from sealed source semantic reconstruction"]
        )))
    source = _load(package_dir / "locked-source.json")
    source_scan = _load(package_dir / "canonical-scan.json")
    output = staging / TARGET_VALIDATION_ROOT
    try:
        scan, assurance = _build_target_evidence(package_dir, output, projected)
        source_issues = _graph_issues(source, source_scan)
        target_issues = _graph_issues(projected, scan)
        regressions = sorted((target_issues - source_issues).elements())
        if regressions:
            raise ValueError("target graph regression: " + "; ".join(regressions))
        # This is an exact repeat from the original, never a new semantic cycle.
        replay = apply_operations(source, operations)
        if replay != projected:
            raise ValueError("target replay differs from source-reconciled projection")
        replay_dir = staging / "replay"
        replay_scan, replay_assurance = _build_target_evidence(package_dir, replay_dir, replay)
        if replay_scan != scan or replay_assurance != assurance:
            raise ValueError("target scan or assurance differs from exact replay")
        for name in EVIDENCE_FILES:
            if file_sha256(output / name) != file_sha256(replay_dir / name):
                raise ValueError(f"target artifact differs from exact replay: {name}")
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise ValueError("; ".join(operation_error_context(operations, [str(exc)]))) from exc
    if _input_hashes(package_dir) != inputs:
        raise ValueError("target validation inputs changed during reconstruction")
    proof = {
        "kind": "gtm_target_validation_proof",
        "schema_version": 1,
        "status": "pass",
        "inputs": inputs,
        "validated_hashes": {
            "projected_graph_sha256": stable_hash(projected, 64),
            "canonical_scan_sha256": scan["canonical_scan_sha256"],
            "scan_assurance_sha256": assurance["scan_assurance_sha256"],
            "operation_packet_sha256": packet["operation_packet_sha256"],
            "reconciled_record_sha256": packet["reconciled_record_sha256"],
        },
        "artifact_sha256": {name: file_sha256(output / name) for name in EVIDENCE_FILES},
        "preserved_source_graph_issues": sorted((target_issues & source_issues).elements()),
        "invariants": {
            "source_reconciled_packet_reconstructed": True,
            "exact_action_safety_passed": True,
            "consent_ownership_passed": True,
            "no_new_graph_reference_or_dependency_failures": True,
            "deterministic_scan_assurance_passed": True,
            "exact_replay_passed": True,
        },
        "boundary": BOUNDARY,
    }
    proof["validation_proof_sha256"] = stable_hash(proof, 64)
    write_json(output / PROOF_FILE, proof)
    seal = {
        "kind": "gtm_target_validation_seal",
        "schema_version": 1,
        "validator_status": "pass",
        "validation_proof_sha256": proof["validation_proof_sha256"],
        "artifacts": {
            name: file_sha256(output / name) for name in (*EVIDENCE_FILES, PROOF_FILE)
        },
    }
    seal["validation_seal_sha256"] = stable_hash(seal, 64)
    write_json(output / SEAL_FILE, seal)
    return proof


def validate_target(package_dir: Path) -> dict[str, Any]:
    require_safe_package_root(package_dir)
    target = package_dir / TARGET_VALIDATION_ROOT
    if target.exists():
        raise ValueError("target validation outputs already exist and are never overwritten")
    with tempfile.TemporaryDirectory(prefix=".target-validation-", dir=package_dir) as temporary:
        staging = Path(temporary)
        proof = _reconstruct(package_dir, staging)
        # Same-filesystem directory rename publishes all five artifacts together.
        (staging / TARGET_VALIDATION_ROOT).rename(target)
    return {
        "status": "pass",
        "validation_proof_sha256": proof["validation_proof_sha256"],
        "validated_hashes": proof["validated_hashes"],
    }


def target_validation_seal_errors(package_dir: Path) -> list[str]:
    try:
        require_safe_package_root(package_dir)
        target = package_dir / TARGET_VALIDATION_ROOT
        if not all((target / name).is_file() for name in ARTIFACT_FILES):
            return ["target validation evidence, proof, or seal is missing"]
        if {path.name for path in target.iterdir()} != set(ARTIFACT_FILES):
            return ["target validation artifact inventory differs from the exact closed set"]
        # Reconstruct separately; stored hashes never authorize their own contents.
        with tempfile.TemporaryDirectory(prefix="gtm-target-reconstruction-") as temporary:
            staging = Path(temporary)
            _reconstruct(package_dir, staging)
            return [
                f"target validation artifact differs from deterministic reconstruction: {name}"
                for name in ARTIFACT_FILES
                if (target / name).read_bytes()
                != (staging / TARGET_VALIDATION_ROOT / name).read_bytes()
            ]
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return [f"target validation reconstruction failed: {exc}"]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("package_dir", type=Path)
    args = parser.parse_args()
    try:
        result = validate_target(args.package_dir)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(json.dumps({"status": "blocked", "errors": [str(exc)]}))
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
