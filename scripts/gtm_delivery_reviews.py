#!/usr/bin/env python3
"""Stage independent fidelity and workbook-only reader checks, then seal delivery."""

from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path
from typing import Any

from gtm_canonical_record import canonical_record_seal_errors
from gtm_delivery_mapper import (
    DELIVERY_ROOT,
    audience_brief_payload,
    delivery_map_from_record,
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
FIDELITY_BUNDLE = "fidelity"
READER_BUNDLE = "reader"
FIDELITY_INPUT_FILE = "fidelity-input.json"
FIDELITY_REVIEW_FILE = "fidelity-review.json"
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
                "Use a fresh agent and context for this review and do not provide the "
                "peer review output before both reviews are complete."
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


def _expected_fidelity_input(
    package_dir: Path, manifest: dict[str, Any]
) -> dict[str, Any]:
    delivery = package_dir / DELIVERY_ROOT
    sealed_delivery_map = _load(delivery / "delivery-map.json")
    canonical = _load(package_dir / "canonical-record.json")
    delivery_map = delivery_map_from_record(
        canonical, str(sealed_delivery_map.get("language") or "English")
    )
    if delivery_map != sealed_delivery_map:
        raise ValueError("delivery map differs from canonical reconstruction")
    editorial = _load(delivery / "editorial.json")
    editorial_rows = {
        str(row.get("row_id") or ""): row
        for row in as_list(editorial.get("rows"))
    }
    row_locations = {
        str(row.get("row_id") or ""): row
        for sheet in as_list((manifest.get("normalized_model") or {}).get("sheets"))
        for row in as_list((sheet or {}).get("rows"))
    }
    rows = []
    for row in as_list(delivery_map.get("rows")):
        row_id = str(row.get("row_id") or "")
        delivered = editorial_rows.get(row_id) or {}
        location = row_locations.get(row_id) or {}
        rows.append(
            {
                "row_id": row_id,
                "primary_sheet": row.get("primary_sheet"),
                "workbook_row_number": location.get("row_number"),
                "binding_sha256": row.get("binding_sha256"),
                "canonical_locked_fields": row.get("locked", {}),
                "canonical_prose": row.get("canonical_prose", {}),
                "delivered_prose": delivered.get("prose", {}),
            }
        )
    payload = {
        "kind": "gtm_workbook_fidelity_input",
        "schema_version": 1,
        "workbook_file_sha256": manifest.get("workbook_file_sha256"),
        "canonical_record_sha256": canonical.get("canonical_record_sha256"),
        "delivery_map_sha256": delivery_map.get("delivery_map_sha256"),
        "rows": rows,
        "overview_canonical": delivery_map.get("overview", {}),
        "overview_delivered": editorial.get("overview_prose", {}),
        "review_contract": (
            "Reject changed meaning, missing caveats, overstated consequences, "
            "mismatched actions, or any visible row that no longer preserves its lock."
        ),
    }
    payload["fidelity_input_sha256"] = stable_hash(payload, 64)
    return payload


def scaffold_delivery_reviews(package_dir: Path) -> dict[str, Any]:
    require_safe_package_root(package_dir)
    errors = canonical_record_seal_errors(package_dir)
    errors.extend(editorial_seal_errors(package_dir))
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

    fidelity = reviews / FIDELITY_BUNDLE
    fidelity.mkdir()
    shutil.copy2(workbook_path, fidelity / "workbook.xlsx")
    fidelity_input = _expected_fidelity_input(package_dir, manifest)
    fidelity_rows = as_list(fidelity_input.get("rows"))
    write_json(fidelity / FIDELITY_INPUT_FILE, fidelity_input)
    fidelity_review = {
        "kind": "gtm_workbook_fidelity_review",
        "schema_version": 1,
        "status": "pending",
        "independent_agent_id": "",
        "independent_context_id": "",
        "input_manifest_sha256": "",
        "fidelity_input_sha256": fidelity_input["fidelity_input_sha256"],
        "overview_review": {
            "verdict": "pending",
            "meaning_preserved": False,
            "evidence_limits_preserved": False,
            "next_action_preserved": False,
            "issues": [],
        },
        "row_reviews": [
            {
                "row_id": row["row_id"],
                "binding_sha256": row["binding_sha256"],
                "verdict": "pending",
                "meaning_preserved": False,
                "caveats_preserved": False,
                "action_matches": False,
                "identifiers_preserved": False,
                "issues": [],
            }
            for row in fidelity_rows
        ],
        "completion_attestation": "",
    }
    write_json(fidelity / FIDELITY_REVIEW_FILE, fidelity_review)
    fidelity_manifest = _write_review_manifest(
        fidelity,
        review_kind="fidelity",
        locked_paths=[fidelity / "workbook.xlsx", fidelity / FIDELITY_INPUT_FILE],
        mutable_output=FIDELITY_REVIEW_FILE,
    )
    fidelity_review["input_manifest_sha256"] = fidelity_manifest[
        "bundle_manifest_sha256"
    ]
    write_json(fidelity / FIDELITY_REVIEW_FILE, fidelity_review)

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
        "status": "ready_for_parallel_delivery_reviews",
        "build_path": str(build_dir),
        "fidelity_rows": len(fidelity_rows),
        "reader_sheets": len(as_list(manifest.get("visible_sheets"))),
    }


def _review_errors(package_dir: Path, build_dir: Path, manifest: dict[str, Any]) -> list[str]:
    reviews = build_dir / REVIEW_ROOT
    fidelity_dir = reviews / FIDELITY_BUNDLE
    reader_dir = reviews / READER_BUNDLE
    input_path = fidelity_dir / FIDELITY_INPUT_FILE
    fidelity_path = fidelity_dir / FIDELITY_REVIEW_FILE
    reader_path = reader_dir / READER_REVIEW_FILE
    if not all(path.is_file() for path in (input_path, fidelity_path, reader_path)):
        return ["fidelity or reader review artifact is missing"]
    fidelity_input = _load(input_path)
    fidelity = _load(fidelity_path)
    reader = _load(reader_path)
    fidelity_manifest, errors = _review_bundle_errors(fidelity_dir)
    reader_manifest, reader_bundle_errors = _review_bundle_errors(reader_dir)
    errors.extend(reader_bundle_errors)
    authoritative_workbook_sha256 = str(manifest.get("workbook_file_sha256") or "")
    for copied_workbook, label in (
        (fidelity_dir / "workbook.xlsx", "fidelity workbook copy"),
        (reader_dir / "workbook.xlsx", "reader workbook copy"),
    ):
        if (
            not copied_workbook.is_file()
            or file_sha256(copied_workbook) != authoritative_workbook_sha256
        ):
            errors.append(f"{label} differs from the authoritative workbook")
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
    expected_fidelity_manifest = _review_manifest_payload(
        fidelity_dir,
        review_kind="fidelity",
        locked_paths=[fidelity_dir / "workbook.xlsx", input_path],
        mutable_output=FIDELITY_REVIEW_FILE,
    )
    if fidelity_manifest != expected_fidelity_manifest:
        errors.append("fidelity bundle manifest differs from canonical reconstruction")
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
    errors.extend(
        _review_provenance_errors(fidelity, fidelity_manifest, "fidelity review")
    )
    errors.extend(_review_provenance_errors(reader, reader_manifest, "reader review"))
    if fidelity_input.get("fidelity_input_sha256") != _hash_without(
        fidelity_input, "fidelity_input_sha256"
    ):
        errors.append("fidelity input content hash is invalid")
    try:
        expected_fidelity_input = _expected_fidelity_input(package_dir, manifest)
    except ValueError as exc:
        errors.append(f"fidelity input reconstruction failed: {exc}")
    else:
        if fidelity_input != expected_fidelity_input:
            errors.append("fidelity input differs from canonical reconstruction")
    if fidelity.get("status") != "complete":
        errors.append("fidelity review status must be complete")
    if fidelity.get("fidelity_input_sha256") != fidelity_input.get("fidelity_input_sha256"):
        errors.append("fidelity review is bound to another input")
    expected = {str(row.get("row_id") or ""): row for row in as_list(fidelity_input.get("rows"))}
    supplied_rows = [row for row in as_list(fidelity.get("row_reviews")) if isinstance(row, dict)]
    supplied = {str(row.get("row_id") or ""): row for row in supplied_rows}
    if len(supplied) != len(supplied_rows) or set(supplied) != set(expected):
        errors.append("fidelity review must cover every delivered row exactly once")
    for row_id, expected_row in expected.items():
        row = supplied.get(row_id)
        if not row:
            continue
        if row.get("binding_sha256") != expected_row.get("binding_sha256"):
            errors.append(f"{row_id}: fidelity binding changed")
        if row.get("verdict") != "pass":
            errors.append(f"{row_id}: fidelity verdict did not pass")
        for field in (
            "meaning_preserved",
            "caveats_preserved",
            "action_matches",
            "identifiers_preserved",
        ):
            if row.get(field) is not True:
                errors.append(f"{row_id}: fidelity check {field} did not pass")
        if as_list(row.get("issues")):
            errors.append(f"{row_id}: fidelity issues remain open")
    overview = fidelity.get("overview_review") or {}
    if overview.get("verdict") != "pass" or any(
        overview.get(field) is not True
        for field in (
            "meaning_preserved",
            "evidence_limits_preserved",
            "next_action_preserved",
        )
    ):
        errors.append("overview fidelity review did not pass")
    if as_list(overview.get("issues")):
        errors.append("overview fidelity issues remain open")
    if len(str(fidelity.get("completion_attestation") or "").split()) < 8:
        errors.append("fidelity completion attestation is incomplete")

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
    if len(str(reader.get("completion_attestation") or "").split()) < 8:
        errors.append("reader completion attestation is incomplete")
    if fidelity.get("independent_agent_id") == reader.get("independent_agent_id"):
        errors.append("fidelity and reader reviews must use different agents")
    if fidelity.get("independent_context_id") == reader.get("independent_context_id"):
        errors.append("fidelity and reader reviews must use different contexts")
    return errors


def seal_delivery(package_dir: Path) -> dict[str, Any]:
    require_safe_package_root(package_dir)
    build_dir, manifest, errors = _current_build(package_dir)
    errors.extend(canonical_record_seal_errors(package_dir))
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
        "fidelity_review_file_sha256": file_sha256(
            build_dir / REVIEW_ROOT / FIDELITY_BUNDLE / FIDELITY_REVIEW_FILE
        ),
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
        "fidelity_review_file_sha256": delivery_manifest[
            "fidelity_review_file_sha256"
        ],
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
