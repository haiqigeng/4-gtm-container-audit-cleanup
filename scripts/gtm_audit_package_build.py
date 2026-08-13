#!/usr/bin/env python3
"""Build the GTM audit evidence package.

This command is the deterministic first half of a full skill execution. It
creates the source model and the three independent cleanup lens artifacts that
must exist before a user-facing cleanup plan is compiled.
"""

from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path
from typing import Any

from gtm_architecture_review import scaffold_review as scaffold_architecture_review
from gtm_baseline_audit import audit_export
from gtm_configuration_review import scaffold_review as scaffold_configuration_review
from gtm_context_model import build_context_model
from gtm_custom_code_extract import extract_export
from gtm_lib import as_list, source_descriptor
from gtm_operational_review import scaffold_review as scaffold_operational_review
from gtm_requirement_evidence import build_requirement_evidence
from gtm_review_isolation import prepare_review_bundles
from gtm_review_shards import (
    DEFAULT_MAX_AUTHORED_WORK_UNITS,
    DEFAULT_MAX_ITEMS,
    DEFAULT_MAX_OBLIGATIONS,
    review_requires_sharding,
    review_workload,
    split_review,
)
from gtm_shared_facts import build_shared_facts
from gtm_skill_identity import build_identity, declared_identity_errors
from gtm_source_model import build_model


def write_json(path: Path, payload: dict[str, Any], pretty: bool) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2 if pretty else None),
        encoding="utf-8",
    )


def nonzero_findings(payload: dict[str, Any]) -> int:
    return sum(
        1
        for finding in payload.get("findings", [])
        if finding.get("finding_type") != "zero_findings"
    )


def build_review_work_units(
    out_dir: Path,
    files: dict[str, Path],
    reviews: dict[str, tuple[str, dict[str, Any], str]],
    pretty: bool,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "max_items_per_shard": DEFAULT_MAX_ITEMS,
        "max_configuration_obligations_per_shard": DEFAULT_MAX_OBLIGATIONS,
        "max_authored_work_units_per_shard": DEFAULT_MAX_AUTHORED_WORK_UNITS,
        "runs": {},
    }
    for run_name, (file_key, review, shard_directory) in reviews.items():
        workload = review_workload(review)
        run_result = {
            "review_file": files[file_key].name,
            "strategy": "single_file",
            **workload,
        }
        if review_requires_sharding(review):
            shard_dir = out_dir / shard_directory
            shard_manifest = split_review(
                files[file_key],
                shard_dir,
                max_items=DEFAULT_MAX_ITEMS,
                pretty=pretty,
                max_obligations=DEFAULT_MAX_OBLIGATIONS,
            )
            run_result.update(
                {
                    "strategy": "sharded",
                    "shard_directory": shard_directory,
                    "shard_manifest": f"{shard_directory}/shard_manifest.json",
                    "primary_shards": len(shard_manifest["shards"]),
                    "obligation_shards": len(shard_manifest["obligation_shards"]),
                    "discovery_shard": shard_manifest["discovery_shard"],
                }
            )
        result["runs"][run_name] = run_result
    return result


def build_package(
    export_path: Path,
    out_dir: Path,
    pretty: bool = False,
    context_path: Path | None = None,
    requirements_path: Path | None = None,
) -> dict[str, Any]:
    skill_root = Path(__file__).resolve().parents[1]
    identity_report, identity_errors = declared_identity_errors(skill_root)
    if identity_errors:
        raise RuntimeError(
            "runtime identity preflight failed after intake and before package creation: "
            + "; ".join(identity_errors)
        )
    if out_dir.exists():
        if not out_dir.is_dir() or any(out_dir.iterdir()):
            raise RuntimeError(
                "audit package out-dir must be a new or empty directory; existing "
                "artifacts are never overwritten"
            )
    else:
        out_dir.mkdir(parents=True)
    skill_identity = build_identity(skill_root)
    declared_identity = identity_report.get("declared") or {}
    for field in ("source_git_commit", "source_git_dirty"):
        if declared_identity.get(field) is not None:
            skill_identity[field] = declared_identity[field]

    source_model = build_model(export_path)
    if source_model.get("coverage_gate") == "blocked_source_integrity":
        source_path = out_dir / "source_model.json"
        manifest_path = out_dir / "audit_package_manifest.json"
        manifest = {
            **source_descriptor(export_path),
            "kind": "gtm_audit_package_manifest",
            "status": "blocked",
            "skill_runtime_identity": {
                key: skill_identity.get(key)
                for key in (
                    "project_version",
                    "runtime_tree_sha256",
                    "runtime_file_count",
                    "source_git_commit",
                    "source_git_dirty",
                )
            },
            "source_model_coverage_gate": source_model.get("coverage_gate"),
            "shared_facts_coverage_gate": "not_built",
            "counts": {
                "source_integrity_findings": len(
                    source_model.get("source_integrity_findings", [])
                ),
                "source_model_objects": sum(
                    len(source_model.get("objects", {}).get(key, []))
                    for key in (
                        "tags",
                        "triggers",
                        "variables",
                        "customTemplates",
                        "zones",
                        "clients",
                        "gtagConfigs",
                        "transformations",
                    )
                ),
            },
            "required_next_artifacts": [
                "corrected complete GTM ContainerVersion export"
            ],
            "files": {
                "source_model": source_path.name,
                "manifest": manifest_path.name,
            },
            "notes": [
                "Source integrity is blocking; no review scaffold or inferred context was built.",
                "Resolve every source_integrity_finding before starting the three independent runs.",
            ],
        }
        write_json(source_path, source_model, pretty)
        write_json(manifest_path, manifest, pretty)
        return manifest

    context = build_context_model(export_path, context_path)
    requirement_evidence = (
        build_requirement_evidence(requirements_path) if requirements_path else None
    )
    operational_scan = audit_export(export_path)
    technical = extract_export(export_path)
    shared_facts = build_shared_facts(
        export_path,
        context=context,
        technical=technical,
        navigation=source_model,
    )
    operational_review = scaffold_operational_review(export_path, shared_facts)
    configuration_review = scaffold_configuration_review(
        export_path,
        technical,
        shared_facts,
        requirement_evidence=requirement_evidence,
    )
    architecture_review = scaffold_architecture_review(
        export_path,
        shared_facts,
        requirement_evidence=requirement_evidence,
    )

    files = {
        "source_model": out_dir / "source_model.json",
        "context": out_dir / "context.json",
        "shared_facts": out_dir / "shared_facts.json",
        "operational_scan": out_dir / "operational_scan.json",
        "operational_review": out_dir / "operational_review.json",
        "technical_code_findings": out_dir / "technical_code_findings.json",
        "configuration_review": out_dir / "configuration_review.json",
        "architecture_review": out_dir / "architecture_review.json",
        "manifest": out_dir / "audit_package_manifest.json",
    }
    if requirement_evidence:
        files["approved_requirements"] = out_dir / "approved_requirements.json"

    manifest = {
        **source_descriptor(export_path),
        "kind": "gtm_audit_package_manifest",
        "skill_runtime_identity": {
            key: skill_identity.get(key)
            for key in (
                "project_version",
                "runtime_tree_sha256",
                "runtime_file_count",
                "source_git_commit",
                "source_git_dirty",
            )
        },
        "status": (
            "pass"
            if str(shared_facts.get("coverage_gate") or "").startswith("pass")
            else "blocked"
        ),
        "source_model_coverage_gate": source_model.get("coverage_gate"),
        "shared_facts_coverage_gate": shared_facts.get("coverage_gate"),
        "shared_facts_sha256": shared_facts.get("shared_facts_sha256"),
        "context_sha256": context.get("context_sha256"),
        "run_input_contracts": {
            "operational_sanitation": operational_review.get("input_contract"),
            "configuration_correctness": configuration_review.get("input_contract"),
            "business_architecture": architecture_review.get("input_contract"),
        },
        "intake": {
            "status": context.get("intake_status"),
            "material_questions": sum(
                1
                for item in context.get("intake_questions", [])
                if item.get("material")
            ),
            "unresolved_questions": len(context.get("intake_questions", [])),
            "provided_fields": context.get("provided_fields", []),
        },
        "counts": {
            "source_model_objects": sum(
                len(source_model.get("objects", {}).get(key, []))
                for key in (
                    "tags",
                    "triggers",
                    "variables",
                    "customTemplates",
                    "zones",
                    "clients",
                    "gtagConfigs",
                    "transformations",
                )
            ),
            "shared_fact_objects": shared_facts.get("counts", {}).get("objects", 0),
            "field_edges": source_model.get("counts", {}).get("field_edges", 0),
            "trigger_edges": source_model.get("counts", {}).get("trigger_edges", 0),
            "operational_findings": nonzero_findings(operational_scan),
            "operational_zero_finding_rows": sum(
                1
                for finding in operational_scan.get("findings", [])
                if finding.get("finding_type") == "zero_findings"
            ),
            "technical_code_rows": len(technical.get("rows", [])),
            "configuration_review_rows": len(configuration_review.get("rows", [])),
            "architecture_families": len(architecture_review.get("families", [])),
            "architecture_comparisons": len(architecture_review.get("comparisons", [])),
            "approved_requirement_rows": len(
                as_list((requirement_evidence or {}).get("requirements"))
            ),
        },
        "required_next_artifacts": [
            "completed operational_review.json",
            "completed configuration_review.json",
            "completed architecture_review.json",
            "three isolated review seals",
        ],
        "files": {key: path.name for key, path in files.items() if key != "manifest"},
        "notes": [
            "This package is evidence, not the user-facing cleanup plan.",
            (
                "Review scaffolds are generated and semantic review continues. Material "
                "context questions remain nonblocking owner decisions; they block only an "
                "affected mutation whose exact target cannot be selected from the export."
                if context.get("intake_status") == "confirmation_required"
                else "Intake has no unresolved material question; semantic review may start."
            ),
            "The three review artifacts are independent and all are mandatory.",
            "Complete each review only inside its physical review-bundles directory.",
            "All verdict engines use the same immutable shared facts and source hash.",
            "Unresolved references remain operational findings and do not stop other audit checks.",
            "Technical code findings support configuration review and do not replace it.",
            "Compile operations only after all three review validators pass.",
        ],
    }
    manifest["files"]["manifest"] = files["manifest"].name

    write_json(files["context"], context, pretty)
    write_json(files["source_model"], source_model, pretty)
    write_json(files["shared_facts"], shared_facts, pretty)
    write_json(files["operational_scan"], operational_scan, pretty)
    write_json(files["operational_review"], operational_review, pretty)
    write_json(files["technical_code_findings"], technical, pretty)
    if requirement_evidence:
        write_json(files["approved_requirements"], requirement_evidence, pretty)
    write_json(files["configuration_review"], configuration_review, pretty)
    write_json(files["architecture_review"], architecture_review, pretty)
    manifest["review_work_units"] = build_review_work_units(
        out_dir,
        files,
        {
            "operational_sanitation": (
                "operational_review",
                operational_review,
                "operational-shards",
            ),
            "configuration_correctness": (
                "configuration_review",
                configuration_review,
                "configuration-shards",
            ),
            "business_architecture": (
                "architecture_review",
                architecture_review,
                "architecture-shards",
            ),
        },
        pretty,
    )
    sharded_runs = [
        run_name
        for run_name, run in manifest["review_work_units"]["runs"].items()
        if run["strategy"] == "sharded"
    ]
    if sharded_runs:
        manifest["notes"].append(
            "Large reviews were automatically sharded for: "
            + ", ".join(sharded_runs)
            + ". Complete and check every declared shard, then merge each run "
            "back to its bundle-local review file before validation and sealing."
        )
    else:
        manifest["notes"].append(
            "All reviews are below the automatic shard limits; complete the "
            "bundle-local review files directly."
        )
    manifest["review_bundles"] = prepare_review_bundles(
        export_path,
        out_dir,
        skill_root,
        pretty=pretty,
    )
    for run_name, run in manifest["review_work_units"]["runs"].items():
        if run.get("strategy") != "sharded":
            continue
        staging_directory = str(run.get("shard_directory") or "")
        staging_path = (out_dir / staging_directory).resolve()
        if staging_path.parent != out_dir.resolve() or not staging_path.is_dir():
            raise RuntimeError(
                f"unsafe or missing staging shard directory for {run_name}"
            )
        shutil.rmtree(staging_path)
        bundle_directory = f"review-bundles/{run_name}/{staging_directory}"
        run["shard_directory"] = bundle_directory
        run["shard_manifest"] = f"{bundle_directory}/shard_manifest.json"
    manifest["notes"].append(
        "A root orchestrator must assign each review-bundles directory to a distinct "
        "fresh reasoning context, then validate and seal that bundle-local output."
    )
    artifact_files = [
        path
        for path in out_dir.rglob("*")
        if path.is_file() and path != files["manifest"]
    ]
    configuration_workload = manifest["review_work_units"]["runs"].get(
        "configuration_correctness", {}
    )
    artifact_bytes = sum(path.stat().st_size for path in artifact_files)
    manifest["scalability"] = {
        "contract": (
            "Evidence coverage must remain exhaustive while authored work and physical "
            "shards are measured by meaningful object/behavior units. These metrics are "
            "release-regression evidence, not a reduced audit mode."
        ),
        "source_bytes": export_path.stat().st_size,
        "artifact_files_excluding_manifest": len(artifact_files),
        "artifact_bytes_excluding_manifest": artifact_bytes,
        "artifact_to_source_bytes_ratio": round(
            artifact_bytes / max(1, export_path.stat().st_size), 3
        ),
        "configuration_evidence_obligations": int(
            configuration_workload.get("configuration_evidence_obligations")
            or configuration_workload.get("configuration_obligations")
            or 0
        ),
        "configuration_authored_work_units": int(
            configuration_workload.get("authored_behavior_work_units") or 0
        ),
        "obligation_to_authored_ratio": float(
            configuration_workload.get("obligation_to_authored_ratio") or 0
        ),
        "review_shards": sum(
            int(run.get("primary_shards") or 0)
            + int(run.get("obligation_shards") or 0)
            + int(bool(run.get("discovery_shard")))
            for run in manifest["review_work_units"]["runs"].values()
        ),
    }
    write_json(files["manifest"], manifest, pretty)
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("export", type=Path, help="Path to a GTM container export JSON")
    parser.add_argument(
        "--out-dir",
        type=Path,
        required=True,
        help="Directory where source/lens artifacts should be written",
    )
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON files")
    parser.add_argument(
        "--context",
        type=Path,
        help="Optional analyst-provided JSON context merged with deterministic inference",
    )
    parser.add_argument(
        "--requirements",
        type=Path,
        help="Optional analyst-approved JSON, CSV, XLSX, or XLSM tracking-plan evidence",
    )
    args = parser.parse_args()

    try:
        result = build_package(
            args.export,
            args.out_dir,
            args.pretty,
            args.context,
            args.requirements,
        )
    except (RuntimeError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"status": "blocked", "errors": [str(exc)]}))
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2 if args.pretty else None))
    return 0 if result["status"] == "pass" else 2


if __name__ == "__main__":
    raise SystemExit(main())
