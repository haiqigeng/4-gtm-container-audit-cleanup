#!/usr/bin/env python3
"""Prepare isolated GTM review bundles and seal validated run outputs."""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

from gtm_lib import load_json, stable_hash
from gtm_skill_identity import sha256_file

BUNDLE_DIRECTORY = "review-bundles"
SEAL_DIRECTORY = "review-seals"

RUN_SPECS: dict[str, dict[str, Any]] = {
    "operational_sanitation": {
        "review_file": "operational_review.json",
        "rule_files": ["operational-sanitation.md"],
        "package_roles": {
            "audit_context": "context.json",
            "shared_facts": "shared_facts.json",
            "operational_scan": "operational_scan.json",
            "operational_review_scaffold": "operational_review.json",
        },
        "shard_directory": "operational-shards",
    },
    "configuration_correctness": {
        "review_file": "configuration_review.json",
        "rule_files": ["configuration-correctness.md", "domain-contracts.md"],
        "package_roles": {
            "audit_context": "context.json",
            "shared_facts": "shared_facts.json",
            "technical_code_facts": "technical_code_findings.json",
            "configuration_review_scaffold": "configuration_review.json",
        },
        "shard_directory": "configuration-shards",
    },
    "business_architecture": {
        "review_file": "architecture_review.json",
        "rule_files": ["business-architecture.md"],
        "package_roles": {
            "audit_context": "context.json",
            "shared_facts": "shared_facts.json",
            "architecture_review_scaffold": "architecture_review.json",
        },
        "shard_directory": "architecture-shards",
    },
}


def write_json(path: Path, payload: dict[str, Any], pretty: bool = True) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2 if pretty else None) + "\n",
        encoding="utf-8",
    )


def bundle_content_hash(payload: dict[str, Any]) -> str:
    content = {key: value for key, value in payload.items() if key != "bundle_sha256"}
    return stable_hash(content, 64)


def seal_content_hash(payload: dict[str, Any]) -> str:
    content = {key: value for key, value in payload.items() if key != "seal_sha256"}
    return stable_hash(content, 64)


def _copy_role(
    source: Path,
    target: Path,
    role: str,
    records: list[dict[str, Any]],
    *,
    mutable_output: bool = False,
) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, target)
    records.append(
        {
            "role": role,
            "path": target.name,
            "sha256": sha256_file(target),
            "mutable_output": mutable_output,
        }
    )


def prepare_review_bundles(
    export_path: Path,
    package_dir: Path,
    skill_root: Path,
    *,
    pretty: bool = True,
) -> dict[str, Any]:
    """Create one physical allowlisted input directory per semantic run."""

    bundle_root = package_dir / BUNDLE_DIRECTORY
    if bundle_root.exists():
        raise FileExistsError(
            "review-bundles already exists; build into a new empty audit package directory"
        )
    bundle_root.mkdir(parents=True)
    result: dict[str, Any] = {}
    for run_name, spec in RUN_SPECS.items():
        bundle_dir = bundle_root / run_name
        bundle_dir.mkdir()
        records: list[dict[str, Any]] = []
        _copy_role(export_path, bundle_dir / "source_export.json", "raw_export", records)
        for role, filename in spec["package_roles"].items():
            _copy_role(
                package_dir / filename,
                bundle_dir / filename,
                role,
                records,
                mutable_output=role.endswith("_review_scaffold"),
            )
        for filename in spec["rule_files"]:
            role = "domain_contracts" if filename == "domain-contracts.md" else "run_rules"
            _copy_role(
                skill_root / "references" / "03-rules" / filename,
                bundle_dir / filename,
                role,
                records,
            )
        if run_name == "configuration_correctness":
            _copy_role(
                skill_root / "references" / "03-rules" / "vendor-registry.toml",
                bundle_dir / "vendor-registry.toml",
                "vendor_registry",
                records,
            )
        if run_name in {"configuration_correctness", "business_architecture"}:
            requirement_path = package_dir / "approved_requirements.json"
            if requirement_path.is_file():
                _copy_role(
                    requirement_path,
                    bundle_dir / requirement_path.name,
                    "approved_requirement_evidence",
                    records,
                )
        instruction_path = bundle_dir / "RUN_INSTRUCTIONS.md"
        instruction_path.write_text(
            "# Isolated review run\n\n"
            f"Complete only `{spec['review_file']}` for `{run_name}`. Read only files "
            "inside this directory plus current official documentation when the input "
            "contract explicitly permits it. Do not read another run, reconciled output, "
            "future-state output, workbook, repository tests, or semantic completion helper. "
            "Use a fresh reasoning context, preserve every generated source field, and "
            "return the completed review to the root orchestrator for validation and sealing. "
            "If a shard declares `configuration_completion_overlay`, read the matching "
            "object row in the bundle-local base review as the exhaustive evidence ledger, "
            "edit only the overlay fields, check every shard, and merge all overlays back "
            "into that base review before sealing. Approved-requirement evidence, when "
            "present, is separately labelled context and is never container proof.\n",
            encoding="utf-8",
        )
        records.append(
            {
                "role": "run_instructions",
                "path": instruction_path.name,
                "sha256": sha256_file(instruction_path),
                "mutable_output": False,
            }
        )
        shard_source = package_dir / str(spec["shard_directory"])
        if shard_source.is_dir():
            shard_target = bundle_dir / str(spec["shard_directory"])
            shutil.copytree(shard_source, shard_target)
            work_unit_files = sorted(
                path.relative_to(shard_target).as_posix()
                for path in shard_target.rglob("*")
                if path.is_file()
            )
            records.append(
                {
                    "role": "review_work_units",
                    "path": shard_target.name,
                    "sha256": stable_hash(
                        {
                            path.relative_to(shard_target).as_posix(): sha256_file(path)
                            for path in sorted(shard_target.rglob("*"))
                            if path.is_file()
                        },
                        64,
                    ),
                    "allowed_output_files": work_unit_files,
                    "shard_manifest_sha256": sha256_file(shard_target / "shard_manifest.json"),
                    "mutable_output": True,
                }
            )
        review = load_json(bundle_dir / str(spec["review_file"]))
        manifest = {
            "kind": "gtm_isolated_review_bundle",
            "schema_version": 1,
            "review_run": run_name,
            "source_sha256": review.get("source_sha256"),
            "context_sha256": review.get("context_sha256"),
            "shared_facts_sha256": review.get("shared_facts_sha256"),
            "input_contract": review.get("input_contract"),
            "review_file": spec["review_file"],
            "input_files": records,
            "isolation_policy": (
                "This directory is the complete allowlisted input surface for one fresh "
                "semantic reasoning context. Foreign verdict artifacts are prohibited."
            ),
        }
        manifest["bundle_sha256"] = bundle_content_hash(manifest)
        write_json(bundle_dir / "bundle_manifest.json", manifest, pretty)
        result[run_name] = {
            "directory": f"{BUNDLE_DIRECTORY}/{run_name}",
            "manifest": f"{BUNDLE_DIRECTORY}/{run_name}/bundle_manifest.json",
            "bundle_sha256": manifest["bundle_sha256"],
            "review_file": spec["review_file"],
        }
    return result


def bundle_integrity_errors(bundle_dir: Path) -> tuple[dict[str, Any], list[str]]:
    manifest_path = bundle_dir / "bundle_manifest.json"
    if not manifest_path.is_file():
        return {}, ["isolated bundle manifest is missing"]
    manifest = load_json(manifest_path)
    errors: list[str] = []
    if manifest.get("kind") != "gtm_isolated_review_bundle":
        errors.append("isolated bundle kind is invalid")
    if manifest.get("bundle_sha256") != bundle_content_hash(manifest):
        errors.append("isolated bundle manifest content hash is invalid")
    declared_names = {
        str(record.get("path") or "")
        for record in manifest.get("input_files") or []
        if str(record.get("path") or "")
    }
    actual_names = {path.name for path in bundle_dir.iterdir()}
    unexpected = sorted(actual_names - declared_names - {"bundle_manifest.json"})
    if unexpected:
        errors.append(
            "isolated bundle contains undeclared top-level artifacts: " + ", ".join(unexpected)
        )
    for record in manifest.get("input_files") or []:
        path = bundle_dir / str(record.get("path") or "")
        if record.get("role") == "review_work_units":
            if not path.is_dir() or not (path / "shard_manifest.json").is_file():
                errors.append("isolated review work-unit directory is incomplete")
                continue
            if sha256_file(path / "shard_manifest.json") != record.get("shard_manifest_sha256"):
                errors.append("isolated shard manifest changed")
            shard_manifest = load_json(path / "shard_manifest.json")
            allowed_shards = {
                str(value) for value in record.get("allowed_output_files") or [] if str(value)
            }
            manifest_shards = {
                "shard_manifest.json",
                *[
                    str(item.get("filename") or "")
                    for field in ("shards", "obligation_shards")
                    for item in shard_manifest.get(field) or []
                    if str(item.get("filename") or "")
                ],
            }
            discovery = str(shard_manifest.get("discovery_shard") or "")
            if discovery:
                manifest_shards.add(discovery)
            if manifest_shards != allowed_shards:
                errors.append("isolated shard manifest file set differs from its bundle lock")
            actual_shards = {
                item.relative_to(path).as_posix() for item in path.rglob("*") if item.is_file()
            }
            if unexpected_shards := sorted(actual_shards - allowed_shards):
                errors.append(
                    "isolated review work units contain undeclared artifacts: "
                    + ", ".join(unexpected_shards)
                )
            if missing_shards := sorted(allowed_shards - actual_shards):
                errors.append(
                    "isolated review work units are missing declared artifacts: "
                    + ", ".join(missing_shards)
                )
            continue
        if record.get("mutable_output"):
            continue
        if not path.is_file():
            errors.append(f"isolated input is missing: {record.get('path')}")
        elif sha256_file(path) != record.get("sha256"):
            errors.append(f"isolated input changed: {record.get('path')}")
    return manifest, errors


def _validator(run_name: str) -> Callable[[Path, Path], tuple[list[str], list[str]]]:
    if run_name == "operational_sanitation":
        from gtm_operational_review import validate_review
    elif run_name == "configuration_correctness":
        from gtm_configuration_review import validate_review
    elif run_name == "business_architecture":
        from gtm_architecture_review import validate_review
    else:
        raise ValueError(f"Unsupported review run: {run_name}")
    return validate_review


def seal_review(
    export_path: Path,
    package_dir: Path,
    run_name: str,
    context_id: str,
    completed_review: Path | None = None,
    *,
    pretty: bool = True,
) -> dict[str, Any]:
    """Validate a bundle-local review, promote it, and seal its provenance."""

    if run_name not in RUN_SPECS:
        raise ValueError(f"Unsupported review run: {run_name}")
    if len(context_id.strip()) < 12:
        raise ValueError("context_id must identify one real fresh reasoning context")
    bundle_dir = (package_dir / BUNDLE_DIRECTORY / run_name).resolve()
    manifest, errors = bundle_integrity_errors(bundle_dir)
    package_manifest_path = package_dir / "audit_package_manifest.json"
    if not package_manifest_path.is_file():
        errors.append("audit package manifest is missing")
    else:
        package_manifest = load_json(package_manifest_path)
        expected_bundle_hash = (
            (package_manifest.get("review_bundles") or {}).get(run_name) or {}
        ).get("bundle_sha256")
        if not expected_bundle_hash or manifest.get("bundle_sha256") != expected_bundle_hash:
            errors.append("isolated bundle differs from the source-locked package manifest")
    review_path = (completed_review or bundle_dir / RUN_SPECS[run_name]["review_file"]).resolve()
    if not review_path.is_relative_to(bundle_dir):
        errors.append("completed review must come from its isolated bundle directory")
    if not review_path.is_file():
        errors.append("completed review is missing from its isolated bundle")
    if errors:
        raise ValueError("; ".join(errors))
    review = load_json(review_path)
    requirement_record = next(
        (
            record
            for record in manifest.get("input_files") or []
            if record.get("role") == "approved_requirement_evidence"
        ),
        None,
    )
    if requirement_record:
        requirement_payload = load_json(
            bundle_dir / str(requirement_record.get("path") or "")
        )
        if review.get("approved_requirement_evidence") != requirement_payload:
            raise ValueError(
                "review-approved requirement evidence differs from its bundle input"
            )
    elif review.get("approved_requirement_evidence"):
        raise ValueError("review introduced undeclared approved requirement evidence")
    attestation = review.get("completion_attestation") or {}
    if attestation.get("independent_review_context_id") != context_id:
        raise ValueError("review context ID differs from the orchestrator-supplied context ID")
    review_errors, review_warnings = _validator(run_name)(export_path, review_path)
    if review_errors:
        raise ValueError("review validator failed: " + "; ".join(review_errors))
    seal_dir = package_dir / SEAL_DIRECTORY
    for existing_path in seal_dir.glob("*.json") if seal_dir.is_dir() else []:
        existing = load_json(existing_path)
        if (
            existing.get("review_run") != run_name
            and existing.get("independent_review_context_id") == context_id
        ):
            raise ValueError("context_id is already sealed for another review run")
    canonical_path = package_dir / str(RUN_SPECS[run_name]["review_file"])
    shutil.copy2(review_path, canonical_path)
    seal = {
        "kind": "gtm_isolated_review_seal",
        "schema_version": 1,
        "review_run": run_name,
        "source_sha256": review.get("source_sha256"),
        "context_sha256": review.get("context_sha256"),
        "shared_facts_sha256": review.get("shared_facts_sha256"),
        "input_contract_sha256": (review.get("input_contract") or {}).get("contract_sha256"),
        "bundle_sha256": manifest.get("bundle_sha256"),
        "completed_review_sha256": sha256_file(canonical_path),
        "independent_review_context_id": context_id,
        "validator_status": "pass",
        "validator_warnings": review_warnings,
    }
    seal["seal_sha256"] = seal_content_hash(seal)
    seal_path = seal_dir / f"{run_name}.json"
    write_json(seal_path, seal, pretty)
    return seal


def review_seal_errors(package_dir: Path, manifest: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    bundle_records = manifest.get("review_bundles") or {}
    context_ids: list[str] = []
    for run_name, spec in RUN_SPECS.items():
        seal_path = package_dir / SEAL_DIRECTORY / f"{run_name}.json"
        if not seal_path.is_file():
            errors.append(f"missing isolated review seal for {run_name}")
            continue
        seal = load_json(seal_path)
        if seal.get("kind") != "gtm_isolated_review_seal":
            errors.append(f"{run_name} review seal kind is invalid")
        if seal.get("seal_sha256") != seal_content_hash(seal):
            errors.append(f"{run_name} review seal content hash is invalid")
        expected_bundle = (bundle_records.get(run_name) or {}).get("bundle_sha256")
        if not expected_bundle or seal.get("bundle_sha256") != expected_bundle:
            errors.append(f"{run_name} review seal uses another input bundle")
        review_path = package_dir / str(spec["review_file"])
        if not review_path.is_file() or seal.get("completed_review_sha256") != sha256_file(
            review_path
        ):
            errors.append(f"{run_name} review changed after it was sealed")
        review = load_json(review_path) if review_path.is_file() else {}
        if seal.get("source_sha256") != manifest.get("source_sha256"):
            errors.append(f"{run_name} review seal uses another source")
        if seal.get("context_sha256") != manifest.get("context_sha256"):
            errors.append(f"{run_name} review seal uses another context")
        if seal.get("shared_facts_sha256") != manifest.get("shared_facts_sha256"):
            errors.append(f"{run_name} review seal uses another shared fact layer")
        if seal.get("input_contract_sha256") != (review.get("input_contract") or {}).get(
            "contract_sha256"
        ):
            errors.append(f"{run_name} review seal uses another input contract")
        context_id = str(seal.get("independent_review_context_id") or "")
        if len(context_id) < 12:
            errors.append(f"{run_name} review seal has no strong context identity")
        else:
            context_ids.append(context_id)
        if seal.get("validator_status") != "pass":
            errors.append(f"{run_name} review seal is not validator-passing")
    if len(context_ids) != len(set(context_ids)):
        errors.append("isolated review seals reuse a reasoning context identity")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    seal = subparsers.add_parser("seal")
    seal.add_argument("export", type=Path)
    seal.add_argument("package_dir", type=Path)
    seal.add_argument("run_name", choices=sorted(RUN_SPECS))
    seal.add_argument("--context-id", required=True)
    seal.add_argument("--completed-review", type=Path)
    seal.add_argument("--pretty", action="store_true")
    args = parser.parse_args()
    try:
        result = seal_review(
            args.export,
            args.package_dir,
            args.run_name,
            args.context_id,
            args.completed_review,
            pretty=args.pretty,
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, indent=2 if args.pretty else None))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
