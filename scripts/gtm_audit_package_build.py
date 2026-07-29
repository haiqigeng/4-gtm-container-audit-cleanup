#!/usr/bin/env python3
"""Build the GTM audit evidence package.

This command is the deterministic first half of a full skill execution. It
creates the source model and the three independent cleanup lens artifacts that
must exist before a user-facing cleanup plan is compiled.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from gtm_architecture_review import scaffold_review as scaffold_architecture_review
from gtm_baseline_audit import audit_export
from gtm_configuration_review import scaffold_review as scaffold_configuration_review
from gtm_context_model import build_context_model
from gtm_custom_code_extract import extract_export
from gtm_lib import source_descriptor
from gtm_operational_review import scaffold_review as scaffold_operational_review
from gtm_review_shards import (
    DEFAULT_MAX_ITEMS,
    DEFAULT_MAX_OBLIGATIONS,
    review_requires_sharding,
    review_workload,
    split_review,
)
from gtm_shared_facts import build_shared_facts
from gtm_skill_identity import build_identity
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
) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    skill_identity = build_identity(Path(__file__).resolve().parents[1])

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
    operational_scan = audit_export(export_path)
    technical = extract_export(export_path)
    shared_facts = build_shared_facts(
        export_path,
        context=context,
        technical=technical,
        navigation=source_model,
    )
    operational_review = scaffold_operational_review(export_path, shared_facts)
    configuration_review = scaffold_configuration_review(export_path, technical, shared_facts)
    architecture_review = scaffold_architecture_review(export_path, shared_facts)

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
        },
        "required_next_artifacts": [
            *(
                ["confirmed material audit context"]
                if context.get("intake_status") == "confirmation_required"
                else []
            ),
            "completed operational_review.json",
            "completed configuration_review.json",
            "completed architecture_review.json",
        ],
        "files": {key: path.name for key, path in files.items() if key != "manifest"},
        "notes": [
            "This package is evidence, not the user-facing cleanup plan.",
            (
                "Review scaffolds are generated, but material intake questions must be "
                "confirmed before semantic review."
                if context.get("intake_status") == "confirmation_required"
                else "Intake has no unresolved material question; semantic review may start."
            ),
            "The three review artifacts are independent and all are mandatory.",
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
            "back to its canonical review file before validation."
        )
    else:
        manifest["notes"].append(
            "All reviews are below the automatic shard limits; complete the "
            "canonical review files directly."
        )
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
    args = parser.parse_args()

    result = build_package(args.export, args.out_dir, args.pretty, args.context)
    print(json.dumps(result, ensure_ascii=False, indent=2 if args.pretty else None))
    return 0 if result["status"] == "pass" else 2


if __name__ == "__main__":
    raise SystemExit(main())
