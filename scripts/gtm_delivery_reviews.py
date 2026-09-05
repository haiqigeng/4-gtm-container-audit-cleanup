#!/usr/bin/env python3
"""Stage one fresh workbook-reader check, then seal delivery."""

from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path
from typing import Any

from gtm_delivery_mapper import (
    DELIVERY_ROOT,
    audience_brief_payload,
    editorial_seal_errors,
)
from gtm_lib import (
    as_list,
    contained_relative_path,
    file_sha256,
    require_safe_package_root,
    stable_hash,
    write_json,
)

REVIEW_ROOT = "reviews"
READER_BUNDLE = "reader"
READER_REVIEW_FILE = "reader-review.json"
DELIVERY_MANIFEST_FILE = "delivery-manifest.json"
DELIVERY_SEAL_FILE = "delivery-seal.json"
REVIEW_BUNDLE_MANIFEST_FILE = "bundle-manifest.json"


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


def _locked_file_records(root: Path, paths: list[Path]) -> list[dict[str, Any]]:
    return [
        {
            "path": path.relative_to(root).as_posix(),
            "sha256": file_sha256(path),
        }
        for path in sorted(paths)
    ]


def _review_manifest_payload(
    root: Path,
    *,
    review_kind: str,
    locked_paths: list[Path],
    mutable_output: str,
) -> dict[str, Any]:
    manifest = {
        "kind": "gtm_delivery_review_bundle_manifest",
        "schema_version": 1,
        "review_kind": review_kind,
        "locked_files": _locked_file_records(root, locked_paths),
        "mutable_output": mutable_output,
        "independence_contract": {
            "required": True,
            "boundary": (
                "Use one fresh agent and context. Review only the declared workbook, "
                "audience brief, and rendered previews."
            ),
        },
    }
    manifest["bundle_manifest_sha256"] = _hash_without(manifest, "bundle_manifest_sha256")
    return manifest


def _write_review_manifest(
    root: Path,
    *,
    review_kind: str,
    locked_paths: list[Path],
    mutable_output: str,
) -> dict[str, Any]:
    manifest = _review_manifest_payload(
        root,
        review_kind=review_kind,
        locked_paths=locked_paths,
        mutable_output=mutable_output,
    )
    write_json(root / REVIEW_BUNDLE_MANIFEST_FILE, manifest)
    return manifest


def _review_bundle_errors(root: Path) -> tuple[dict[str, Any], list[str]]:
    path = root / REVIEW_BUNDLE_MANIFEST_FILE
    if not path.is_file():
        return {}, [f"{root.name} review bundle manifest is missing"]
    manifest = _load(path)
    errors = []
    if manifest.get("bundle_manifest_sha256") != _hash_without(manifest, "bundle_manifest_sha256"):
        errors.append(f"{root.name} review bundle manifest hash is invalid")
    mutable_output = manifest.get("mutable_output")
    allowed = {REVIEW_BUNDLE_MANIFEST_FILE}
    try:
        mutable_path = contained_relative_path(
            root,
            mutable_output,
            f"{root.name} mutable review output path",
        )
    except ValueError as exc:
        errors.append(str(exc))
    else:
        allowed.add(mutable_path.relative_to(root.absolute()).as_posix())
    for record in as_list(manifest.get("locked_files")):
        relative = (record or {}).get("path")
        try:
            target = contained_relative_path(
                root,
                relative,
                f"{root.name} locked review input path",
            )
        except ValueError as exc:
            errors.append(str(exc))
            continue
        relative = target.relative_to(root.absolute()).as_posix()
        allowed.add(relative)
        if not target.is_file():
            errors.append(f"{root.name} locked review input is missing: {relative}")
        elif file_sha256(target) != (record or {}).get("sha256"):
            errors.append(f"{root.name} locked review input changed: {relative}")
    actual = {path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file()}
    unexpected = sorted(actual - allowed)
    if unexpected:
        errors.append(f"{root.name} review bundle has undeclared files: " + ", ".join(unexpected))
    return manifest, errors


def _review_provenance_errors(
    review: dict[str, Any], manifest: dict[str, Any], label: str
) -> list[str]:
    errors = []
    if not str(review.get("independent_agent_id") or "").strip():
        errors.append(f"{label} independent agent identity is missing")
    if not str(review.get("independent_context_id") or "").strip():
        errors.append(f"{label} independent context identity is missing")
    if review.get("input_manifest_sha256") != manifest.get("bundle_manifest_sha256"):
        errors.append(f"{label} is not bound to its review bundle")
    return errors


def _relative_file_hashes(root: Path) -> dict[str, str]:
    if not root.is_dir():
        return {}
    return {
        path.relative_to(root).as_posix(): file_sha256(path)
        for path in root.rglob("*")
        if path.is_file()
    }


def _expected_preview_hashes(
    package_dir: Path, build_dir: Path, manifest: dict[str, Any]
) -> tuple[dict[str, str], list[str]]:
    preview_root = (build_dir / "previews").absolute()
    expected: dict[str, str] = {}
    errors: list[str] = []
    for record in as_list(manifest.get("previews")):
        if not isinstance(record, dict):
            errors.append("workbook build preview record is malformed")
            continue
        try:
            target = contained_relative_path(
                package_dir,
                record.get("path"),
                "workbook build preview path",
            )
            relative = target.relative_to(preview_root).as_posix()
        except ValueError as exc:
            errors.append(str(exc))
            continue
        if relative in expected:
            errors.append("workbook build preview path is duplicated")
            continue
        expected[relative] = str(record.get("sha256") or "")
    return expected, errors


def _current_build(package_dir: Path) -> tuple[Path, dict[str, Any], list[str]]:
    delivery = package_dir / DELIVERY_ROOT
    current_path = delivery / "current-build.json"
    if not current_path.is_file():
        return delivery, {}, ["current workbook build pointer is missing"]
    current = _load(current_path)
    errors = []
    if current.get("current_build_sha256") != _hash_without(current, "current_build_sha256"):
        errors.append("current workbook build pointer hash is invalid")
    try:
        build_dir = contained_relative_path(
            delivery,
            current.get("build_path"),
            "current workbook build path",
        )
    except ValueError as exc:
        return delivery, {}, [*errors, str(exc)]
    manifest_path = build_dir / "workbook-build-manifest.json"
    if not manifest_path.is_file():
        return build_dir, {}, [*errors, "workbook build manifest is missing"]
    manifest = _load(manifest_path)
    if manifest.get("workbook_build_manifest_sha256") != _hash_without(
        manifest, "workbook_build_manifest_sha256"
    ):
        errors.append("workbook build manifest content hash is invalid")
    if current.get("workbook_build_manifest_sha256") != manifest.get(
        "workbook_build_manifest_sha256"
    ):
        errors.append("current pointer is bound to another build manifest")
    try:
        workbook = contained_relative_path(
            package_dir,
            manifest.get("workbook_path"),
            "workbook manifest path",
        )
    except ValueError as exc:
        errors.append(str(exc))
        return build_dir, manifest, errors
    if not workbook.is_file() or file_sha256(workbook) != manifest.get("workbook_file_sha256"):
        errors.append("workbook file is missing or changed")
    delivery = package_dir / DELIVERY_ROOT
    delivery_map = _load(delivery / "delivery-map.json")
    editorial_path = delivery / "editorial.json"
    editorial_seal = _load(delivery / "editorial-seal.json")
    if manifest.get("delivery_map_sha256") != delivery_map.get("delivery_map_sha256"):
        errors.append("workbook build is bound to another delivery map")
    if manifest.get("editorial_file_sha256") != file_sha256(editorial_path):
        errors.append("workbook build is bound to another editorial artifact")
    if manifest.get("editorial_seal_sha256") != editorial_seal.get("editorial_seal_sha256"):
        errors.append("workbook build is bound to another editorial seal")
    expected_rows = {
        str(row.get("row_id") or ""): row
        for row in as_list(delivery_map.get("rows"))
    }
    model_rows = [
        row
        for sheet in as_list((manifest.get("normalized_model") or {}).get("sheets"))
        for row in as_list((sheet or {}).get("rows"))
        if isinstance(row, dict)
    ]
    supplied_rows = {str(row.get("row_id") or ""): row for row in model_rows}
    if len(supplied_rows) != len(model_rows) or set(supplied_rows) != set(expected_rows):
        errors.append("workbook build rows differ from the canonical delivery map")
    else:
        for row_id, expected in expected_rows.items():
            delivered = supplied_rows[row_id]
            if delivered.get("locked") != expected.get("locked"):
                errors.append(f"{row_id}: workbook locked fields differ from the canonical delivery map")
    technical_path = build_dir / "technical-verification.json"
    if not technical_path.is_file():
        errors.append("workbook technical verification is missing")
    else:
        technical = _load(technical_path)
        if technical.get("technical_verification_sha256") != _hash_without(
            technical, "technical_verification_sha256"
        ):
            errors.append("technical verification content hash is invalid")
        if technical.get("status") != "pass":
            errors.append("workbook technical verification did not pass")
    return build_dir, manifest, errors


def scaffold_delivery_reviews(package_dir: Path) -> dict[str, Any]:
    require_safe_package_root(package_dir)
    # Editorial validation includes its canonical source and delivery projection.
    errors = editorial_seal_errors(package_dir)
    build_dir, manifest, build_errors = _current_build(package_dir)
    errors.extend(build_errors)
    if errors:
        raise ValueError("delivery review prerequisites failed: " + "; ".join(errors))
    reviews = build_dir / REVIEW_ROOT
    if reviews.exists():
        raise ValueError("delivery review bundles already exist for this build")
    reviews.mkdir()
    delivery = package_dir / DELIVERY_ROOT
    workbook_path = contained_relative_path(
        package_dir,
        manifest.get("workbook_path"),
        "workbook manifest path",
    )

    reader = reviews / READER_BUNDLE
    reader.mkdir()
    shutil.copy2(workbook_path, reader / "workbook.xlsx")
    shutil.copy2(delivery / "audience-brief.json", reader / "audience-brief.json")
    source_previews = build_dir / "previews"
    if source_previews.is_dir():
        shutil.copytree(source_previews, reader / "previews")
    reader_review = {
        "kind": "gtm_workbook_only_reader_review",
        "schema_version": 1,
        "status": "pending",
        "independent_agent_id": "",
        "independent_context_id": "",
        "input_manifest_sha256": "",
        "workbook_file_sha256": manifest.get("workbook_file_sha256"),
        "received_only_workbook_audience_brief_and_previews": False,
        "sheet_reviews": [
            {
                "sheet": sheet,
                "verdict": "pending",
                "standalone_and_clear": False,
                "next_action_clear": False,
                "wording_human_readable": False,
                "layout_legible": False,
                "navigation_usable": False,
                "issues": [],
            }
            for sheet in as_list(manifest.get("visible_sheets"))
        ],
        "cross_workbook_issues": [],
        "completion_attestation": "",
    }
    write_json(reader / READER_REVIEW_FILE, reader_review)
    reader_locked = [reader / "workbook.xlsx", reader / "audience-brief.json"]
    if (reader / "previews").is_dir():
        reader_locked.extend(path for path in (reader / "previews").rglob("*") if path.is_file())
    reader_manifest = _write_review_manifest(
        reader,
        review_kind="workbook_only_reader",
        locked_paths=reader_locked,
        mutable_output=READER_REVIEW_FILE,
    )
    reader_review["input_manifest_sha256"] = reader_manifest[
        "bundle_manifest_sha256"
    ]
    write_json(reader / READER_REVIEW_FILE, reader_review)
    return {
        "status": "ready_for_workbook_reader_review",
        "build_path": str(build_dir),
        "reader_sheets": len(as_list(manifest.get("visible_sheets"))),
    }


def _review_errors(package_dir: Path, build_dir: Path, manifest: dict[str, Any]) -> list[str]:
    reviews = build_dir / REVIEW_ROOT
    reader_dir = reviews / READER_BUNDLE
    reader_path = reader_dir / READER_REVIEW_FILE
    if not reader_path.is_file():
        return ["reader review artifact is missing"]
    reader = _load(reader_path)
    reader_manifest, errors = _review_bundle_errors(reader_dir)
    authoritative_workbook_sha256 = str(manifest.get("workbook_file_sha256") or "")
    copied_workbook = reader_dir / "workbook.xlsx"
    if (
        not copied_workbook.is_file()
        or file_sha256(copied_workbook) != authoritative_workbook_sha256
    ):
        errors.append("reader workbook copy differs from the authoritative workbook")
    delivery_map = _load(package_dir / DELIVERY_ROOT / "delivery-map.json")
    expected_audience = audience_brief_payload(
        str(delivery_map.get("language") or "English")
    )
    authoritative_audience = package_dir / DELIVERY_ROOT / "audience-brief.json"
    reader_audience = reader_dir / "audience-brief.json"
    if (
        not authoritative_audience.is_file()
        or _load(authoritative_audience) != expected_audience
        or not reader_audience.is_file()
        or _load(reader_audience) != expected_audience
    ):
        errors.append("reader audience brief differs from canonical reconstruction")
    expected_previews, preview_errors = _expected_preview_hashes(
        package_dir, build_dir, manifest
    )
    errors.extend(preview_errors)
    if _relative_file_hashes(build_dir / "previews") != expected_previews:
        errors.append("authoritative previews differ from the workbook build manifest")
    if _relative_file_hashes(reader_dir / "previews") != expected_previews:
        errors.append("reader previews differ from the authoritative rendered previews")
    reader_locked = [
        reader_dir / "workbook.xlsx",
        reader_dir / "audience-brief.json",
    ]
    if (reader_dir / "previews").is_dir():
        reader_locked.extend(
            path for path in (reader_dir / "previews").rglob("*") if path.is_file()
        )
    expected_reader_manifest = _review_manifest_payload(
        reader_dir,
        review_kind="workbook_only_reader",
        locked_paths=reader_locked,
        mutable_output=READER_REVIEW_FILE,
    )
    if reader_manifest != expected_reader_manifest:
        errors.append("reader bundle manifest differs from workbook reconstruction")
    errors.extend(_review_provenance_errors(reader, reader_manifest, "reader review"))
    if reader.get("status") != "complete":
        errors.append("reader review status must be complete")
    if reader.get("workbook_file_sha256") != manifest.get("workbook_file_sha256"):
        errors.append("reader review is bound to another workbook")
    if reader.get("received_only_workbook_audience_brief_and_previews") is not True:
        errors.append("reader review isolation attestation is missing")
    sheet_rows = [row for row in as_list(reader.get("sheet_reviews")) if isinstance(row, dict)]
    sheet_index = {str(row.get("sheet") or ""): row for row in sheet_rows}
    expected_sheets = set(as_list(manifest.get("visible_sheets")))
    if len(sheet_index) != len(sheet_rows) or set(sheet_index) != expected_sheets:
        errors.append("reader review must cover every visible sheet exactly once")
    for sheet, row in sheet_index.items():
        if row.get("verdict") != "pass":
            errors.append(f"{sheet}: reader verdict did not pass")
        for field in (
            "standalone_and_clear",
            "next_action_clear",
            "wording_human_readable",
            "layout_legible",
            "navigation_usable",
        ):
            if row.get(field) is not True:
                errors.append(f"{sheet}: reader check {field} did not pass")
        if as_list(row.get("issues")):
            errors.append(f"{sheet}: reader issues remain open")
    if as_list(reader.get("cross_workbook_issues")):
        errors.append("cross-workbook reader issues remain open")
    conclusion = reader.get("completion_attestation")
    if not isinstance(conclusion, str) or not conclusion.strip():
        errors.append("reader completion attestation must be a non-blank string")
    return errors


def seal_delivery(package_dir: Path) -> dict[str, Any]:
    require_safe_package_root(package_dir)
    build_dir, manifest, errors = _current_build(package_dir)
    errors.extend(editorial_seal_errors(package_dir))
    errors.extend(_review_errors(package_dir, build_dir, manifest))
    if errors:
        raise ValueError("final delivery gate failed: " + "; ".join(errors))
    technical_path = build_dir / "technical-verification.json"
    technical = _load(technical_path)
    delivery_map = _load(package_dir / DELIVERY_ROOT / "delivery-map.json")
    canonical = _load(package_dir / "canonical-record.json")
    coverage = delivery_map.get("coverage") or {}
    expected_operations = {
        str(row.get("operation_id") or "") for row in as_list(canonical.get("operations"))
    }
    expected_decisions = {
        str(row.get("canonical_decision_id") or "")
        for row in as_list(canonical.get("audit_decisions"))
    }
    expected_owner = set(as_list(canonical.get("owner_decision_ids")))
    expected_code = set(as_list(canonical.get("custom_code_decision_ids"))) - expected_owner
    expected_full = expected_decisions - expected_owner - expected_code
    coverage_errors = []
    if set(as_list(coverage.get("recommendation_operation_ids"))) != expected_operations:
        coverage_errors.append("recommendation coverage differs from canonical operations")
    delivered_full = set(as_list(coverage.get("full_audit_decision_ids")))
    delivered_owner = set(as_list(coverage.get("owner_decision_ids")))
    delivered_code = set(as_list(coverage.get("custom_code_decision_ids")))
    if delivered_full != expected_full:
        coverage_errors.append("full-audit ownership differs from canonical decisions")
    if delivered_owner != expected_owner:
        coverage_errors.append("owner-decision coverage differs from canonical record")
    if delivered_code != expected_code:
        coverage_errors.append("custom-code coverage differs from canonical record")
    primary_sets = (delivered_owner, delivered_code, delivered_full)
    if any(
        primary_sets[left] & primary_sets[right]
        for left in range(len(primary_sets))
        for right in range(left + 1, len(primary_sets))
    ):
        coverage_errors.append("one audit decision appears on multiple owning sheets")
    if set().union(*primary_sets) != expected_decisions:
        coverage_errors.append("primary owning sheets do not cover every audit decision")
    expected_owners = {
        **{decision_id: "03 Decisions Needed" for decision_id in expected_owner},
        **{decision_id: "05 Custom Code" for decision_id in expected_code},
        **{decision_id: "04 Full Audit" for decision_id in expected_full},
    }
    if coverage.get("primary_decision_owner") != expected_owners:
        coverage_errors.append("primary decision-owner map differs from canonical precedence")
    if coverage_errors:
        raise ValueError("delivery coverage gate failed: " + "; ".join(coverage_errors))
    delivery_manifest = {
        "kind": "gtm_analyst_workbook_delivery_manifest",
        "schema_version": 1,
        "status": "pass",
        "canonical_record_sha256": canonical.get("canonical_record_sha256"),
        "delivery_map_sha256": delivery_map.get("delivery_map_sha256"),
        "workbook_path": manifest.get("workbook_path"),
        "workbook_file_sha256": manifest.get("workbook_file_sha256"),
        "workbook_build_manifest_sha256": manifest.get("workbook_build_manifest_sha256"),
        "technical_verification_sha256": technical.get("technical_verification_sha256"),
        "reader_review_file_sha256": file_sha256(
            build_dir / REVIEW_ROOT / READER_BUNDLE / READER_REVIEW_FILE
        ),
        "visible_sheets": manifest.get("visible_sheets", []),
        "coverage_counts": {
            "operations": len(expected_operations),
            "audit_decisions": len(expected_decisions),
            "owner_decisions": len(as_list(canonical.get("owner_decision_ids"))),
            "custom_code_decisions": len(as_list(canonical.get("custom_code_decision_ids"))),
        },
        "phase_boundary": (
            "This workbook is decision-ready but is not execution authorisation, an "
            "import, a GTM version, or evidence that any change was applied."
        ),
    }
    delivery_manifest["delivery_manifest_sha256"] = stable_hash(delivery_manifest, 64)
    manifest_path = build_dir / DELIVERY_MANIFEST_FILE
    write_json(manifest_path, delivery_manifest)
    seal = {
        "kind": "gtm_analyst_workbook_delivery_seal",
        "schema_version": 1,
        "delivery_manifest_sha256": delivery_manifest["delivery_manifest_sha256"],
        "delivery_manifest_file_sha256": file_sha256(manifest_path),
        "workbook_file_sha256": manifest.get("workbook_file_sha256"),
        "reader_review_file_sha256": delivery_manifest[
            "reader_review_file_sha256"
        ],
        "validator_status": "pass",
    }
    seal["delivery_seal_sha256"] = _hash_without(seal, "delivery_seal_sha256")
    write_json(build_dir / DELIVERY_SEAL_FILE, seal)
    return {
        "status": "pass",
        "workbook": str(
            contained_relative_path(
                package_dir,
                manifest.get("workbook_path"),
                "workbook manifest path",
            )
        ),
        "delivery_seal_sha256": seal["delivery_seal_sha256"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    scaffold = subparsers.add_parser("scaffold")
    scaffold.add_argument("package_dir", type=Path)
    seal = subparsers.add_parser("seal")
    seal.add_argument("package_dir", type=Path)
    args = parser.parse_args()
    try:
        result = (
            scaffold_delivery_reviews(args.package_dir)
            if args.command == "scaffold"
            else seal_delivery(args.package_dir)
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"status": "blocked", "errors": [str(exc)]}))
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
