#!/usr/bin/env python3
"""Reopen exact source decisions in a same-source working audit successor.

This is an engineering repair, not a new discovery pass. The predecessor remains
read-only. Its complete decisions, audit seals, histories, bundles and source
checkpoints survive unchanged in the successor. Only generated downstream state
is excluded, allowing the existing seal_audit amendment protocol to operate.

A fresh reconciler may retain a predecessor neutral conclusion when the newly
scaffolded comparison (including both source decisions) AND neutral evidence row
equal their predecessor scaffolds exactly. Matching an ID or evidence hash alone
is insufficient. The reconciler owns changed rows and fresh completion provenance;
this helper neither transfers verdicts nor authors semantic changes.
"""

from __future__ import annotations

import argparse
import json
import shutil
import tempfile
from pathlib import Path
from typing import Any

from gtm_cleanroom_audit import AUDIT_IDS, sealed_audit_errors
from gtm_lib import (
    contained_relative_path,
    file_sha256,
    path_is_link_or_reparse,
    require_safe_package_root,
    stable_hash,
    write_json,
)
from gtm_reconciliation import _discovery_decisions

# Exact generated roots only: never glob away source or audit evidence.
DOWNSTREAM = frozenset({
    "reconciliation-scaffold.json", "neutral-verification-queue.json",
    "reconciliation-units", "reconciliation-completion.json",
    "reconciliation.json", "neutral-verification.json",
    "reconciled-decisions.json", "reconciliation-seal.json",
    "operation-packet.json", "target-validation",
    "canonical-record.json", "canonical-record-manifest.json",
    "canonical-record-seal.json", "delivery",
})


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def _safe_path(path: Path) -> Path:
    path = path.absolute()
    for part in (path, *path.parents):
        if path_is_link_or_reparse(part):
            raise ValueError(f"path is a link or reparse point: {part}")
    return path.resolve()


def _inventory(package: Path) -> dict[str, str | None]:
    require_safe_package_root(package)
    result: dict[str, str | None] = {}
    for path in sorted(package.rglob("*")):
        name = path.relative_to(package).as_posix()
        if path.is_dir():
            result[name] = None
        elif path.is_file():
            result[name] = file_sha256(path)
        else:
            raise ValueError(f"package contains a non-regular entry: {name}")
    return result


def _validate_source(package: Path) -> dict[str, Any]:
    require_safe_package_root(package)
    if (package / "fixed-point").exists():
        raise ValueError("old fixed-point packages cannot be reopened or migrated")
    manifest = _load(package / "audit-package-manifest.json")
    if (manifest.get("kind") != "gtm_dual_audit_package_manifest"
            or manifest.get("schema_version") != 1):
        raise ValueError("unsupported audit package manifest")
    expected_hash = stable_hash({
        key: value for key, value in manifest.items()
        if key != "package_manifest_sha256"
    }, 64)
    if manifest.get("package_manifest_sha256") != expected_hash:
        raise ValueError("audit package manifest changed")
    records = manifest.get("artifacts")
    if not isinstance(records, list) or not records:
        raise ValueError("locked artifact inventory is missing")
    names: set[str] = set()
    for record in records:
        if not isinstance(record, dict):
            raise ValueError("invalid locked artifact record")
        path = contained_relative_path(package, record.get("path"), "locked artifact")
        name = path.relative_to(package).as_posix()
        if name in names or name.split("/")[0] in DOWNSTREAM:
            raise ValueError("invalid or duplicated locked artifact identity")
        names.add(name)
        if not path.is_file() or file_sha256(path) != record.get("sha256"):
            raise ValueError(f"locked source artifact changed: {name}")
    required = {
        "locked-source.json", "context.json", "audit-contract.json",
        "source-model.json", "canonical-scan.json", "scan-assurance.json",
        "obligation-ledger.json", "vendor-registry.toml",
    }
    if not required <= names:
        raise ValueError("locked artifact inventory is incomplete")
    if manifest.get("source_sha256") != file_sha256(package / "locked-source.json"):
        raise ValueError("locked source changed")
    errors = sealed_audit_errors(package)
    if errors:
        raise ValueError("sealed source audit validation failed: " + "; ".join(errors))
    # Bind the root evidence to the independently sealed copies, even if someone
    # has rehashed a substituted root manifest. No scan or new audit is produced.
    for audit_id in AUDIT_IDS:
        bundle = package / "audit-bundles" / audit_id
        for name in required - {"source-model.json"}:
            if file_sha256(package / name) != file_sha256(bundle / name):
                raise ValueError(f"locked source differs from {audit_id}: {name}")
    return manifest


def _requested_owners(package: Path, decision_ids: list[str]) -> list[dict[str, Any]]:
    owners = []
    for audit_id in AUDIT_IDS:
        audit = _load(package / "audits" / f"{audit_id}.json")
        rows = list(audit["decisions"])
        rows.extend(_discovery_decisions(audit).values())
        seal = _load(package / "audit-seals" / f"{audit_id}.json")
        for row in rows:
            owners.append({
                "audit_id": audit_id,
                "decision_id": row["decision_id"],
                "obligation_id": row["obligation_id"],
                "audit_seal_sha256": seal["audit_seal_sha256"],
            })

    canonical_rows = []
    if (package / "canonical-record-seal.json").exists():
        from gtm_canonical_record import canonical_record_seal_errors

        errors = canonical_record_seal_errors(package)
        if errors:
            raise ValueError("predecessor canonical validation failed: " + "; ".join(errors))
        canonical_rows = _load(package / "canonical-record.json")["audit_decisions"]
    elif (package / "reconciliation-seal.json").exists():
        from gtm_reconciliation import reconciliation_seal_errors

        errors = reconciliation_seal_errors(package)
        if errors:
            raise ValueError("predecessor reconciliation validation failed: " + "; ".join(errors))
        canonical_rows = _load(package / "reconciled-decisions.json")["canonical_decisions"]

    requests = []
    for requested_id in decision_ids:
        canonical = [row for row in canonical_rows if row["canonical_decision_id"] == requested_id]
        matches = [owner for owner in owners if requested_id in (
            owner["decision_id"], owner["obligation_id"]
        ) or any(row["obligation_id"] == owner["obligation_id"] for row in canonical)]
        if not matches:
            raise ValueError(f"unknown requested canonical/obligation/decision ID: {requested_id}")
        obligations = {owner["obligation_id"] for owner in matches}
        requests.append({
            "requested_id": requested_id,
            "canonical_decision_ids": sorted({
                row["canonical_decision_id"] for row in canonical_rows
                if row["obligation_id"] in obligations
            }),
            "obligation_ids": sorted(obligations),
            "owning_decisions": matches,
        })
    return requests


def reopen_audit(
    package_dir: Path,
    out_dir: Path,
    decision_ids: list[str],
    reason: str,
) -> dict[str, Any]:
    """Atomically create a new working successor; return its persisted receipt.

    IDs are exact canonical, obligation, or source decision IDs. A source decision
    ID selects only its audit owner; an obligation/canonical ID selects its owners.
    The destination must not exist, must have an existing parent, and cannot be
    nested in the predecessor (or contain it). No predecessor file is modified.
    """
    if (not isinstance(decision_ids, list) or not decision_ids
            or any(not isinstance(value, str) or not value.strip() or value != value.strip()
                   for value in decision_ids)
            or len(set(decision_ids)) != len(decision_ids)):
        raise ValueError("decision_ids must be unique non-blank exact IDs")
    if not isinstance(reason, str) or not reason.strip():
        raise ValueError("a concrete repair reason is required")
    package = _safe_path(Path(package_dir))
    output = _safe_path(Path(out_dir))
    if output == package or output.is_relative_to(package) or package.is_relative_to(output):
        raise ValueError("repair destination must not overlap or nest with the predecessor")
    if output.exists():
        raise FileExistsError("repair destination must be new")
    if not package.is_dir() or not output.parent.is_dir():
        raise ValueError("predecessor and destination parent must be existing directories")
    before = _inventory(package)
    manifest = _validate_source(package)
    requests = _requested_owners(package, decision_ids)
    excluded = sorted(name for name in before if name.split("/")[0] in DOWNSTREAM)
    retained = {name: digest for name, digest in before.items()
                if name.split("/")[0] not in DOWNSTREAM}
    receipt = {
        "kind": "gtm_audit_repair_receipt",
        "schema_version": 1,
        "status": "reopened",
        "predecessor_package": str(package),
        "successor_package": str(output),
        "source_sha256": manifest["source_sha256"],
        "package_manifest_sha256": manifest["package_manifest_sha256"],
        "predecessor_inventory": before,
        "requested_decision_ids": decision_ids,
        "requests": requests,
        "reason": reason,
        "excluded_paths": excluded,
    }
    receipt_id = stable_hash(receipt, 64)
    receipt["receipt_path"] = f"repair-receipts/{receipt_id}.json"
    receipt["repair_receipt_sha256"] = stable_hash(receipt, 64)
    # Publish only after copy integrity and retained seals pass. TemporaryDirectory
    # owns only this newly allocated sibling and removes it on every failure.
    with tempfile.TemporaryDirectory(prefix=".audit-repair-", dir=output.parent) as temporary:
        staged = Path(temporary) / "package"

        def ignore(directory: str, names: list[str]) -> set[str]:
            return set(names) & DOWNSTREAM if Path(directory) == package else set()

        shutil.copytree(package, staged, ignore=ignore)
        if _inventory(staged) != retained:
            raise ValueError("successor copy differs from retained predecessor evidence")
        _validate_source(staged)
        receipt_path = staged / receipt["receipt_path"]
        if receipt_path.exists():
            raise ValueError("repair receipt already exists")
        write_json(receipt_path, receipt)
        if _inventory(package) != before:
            raise ValueError("predecessor changed during repair; successor was not published")
        _safe_path(output)
        if output.exists():
            raise FileExistsError("repair destination appeared during copy")
        staged.rename(output)
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("package_dir", type=Path)
    parser.add_argument("out_dir", type=Path)
    parser.add_argument("--decision-id", action="append", required=True, dest="decision_ids")
    parser.add_argument("--reason", required=True)
    args = parser.parse_args()
    try:
        result = reopen_audit(**vars(args))
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(json.dumps({"status": "blocked", "errors": [str(exc)]}, ensure_ascii=False, indent=2))
        return 2
    # The complete evidence inventory is persisted in the receipt. Return only
    # what the caller needs to continue, not thousands of repeated file hashes.
    print(json.dumps({key: result[key] for key in (
        "status", "successor_package", "requested_decision_ids",
        "receipt_path", "repair_receipt_sha256",
    )}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
