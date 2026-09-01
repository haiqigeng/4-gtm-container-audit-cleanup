#!/usr/bin/env python3
"""Prepare, checkpoint, validate, and seal the two clean-room GTM audits."""

from __future__ import annotations

import argparse
import copy
import json
import re
import shutil
import stat
import tempfile
from pathlib import Path
from typing import Any

from gtm_audit_contract import (
    ACTIONABLE_DECISION_CLASSES,
    AUDIT_METHODS,
    CANONICAL_DECISION_FIELDS,
    OPERATION_ACTION_FIELDS,
    SEMANTIC_AREA_IDS,
    semantic_contract_errors,
)
from gtm_audit_work_units import (
    WORK_UNIT_DIRECTORY,
    WORK_UNIT_MANIFEST,
    build_work_units,
    declared_work_unit_files,
    work_unit_completion_errors,
    work_unit_identity_hash,
)
from gtm_lib import as_list, file_sha256, stable_hash, write_json
from gtm_reasoning_identity import (
    collect_reasoning_identity_registry,
    reasoning_identity_reuse_errors,
    workflow_reasoning_identity_errors,
)

AUDIT_IDS = ("audit-a", "audit-b")
BUNDLE_DIRECTORY = "audit-bundles"
SEAL_DIRECTORY = "audit-seals"
SCRATCH_DIRECTORY = "audit-scratch"
HISTORY_DIRECTORY = "history"
CHECKPOINT_FILE = "source-checkpoint.json"
CHECKPOINT_SEAL_FILE = "source-checkpoint-seal.json"
AUDIT_FILE = "audit.json"
RELEASE_MANIFEST_FILE = "release-manifest.json"
BUNDLE_MANIFEST_FILE = "bundle-manifest.json"
WORK_UNIT_SNAPSHOT_ROOT = "work-unit-snapshots"
WORK_UNIT_SNAPSHOT_MANIFEST = "snapshot-manifest.json"
ISOLATION_MECHANISMS = {
    "orchestrator_scoped_context",
    "filesystem_acl_or_sandbox",
}

OBJECT_KEY_RE = re.compile(
    r"^(?:tag|trigger|variable|folder|builtInVariable|zone|customTemplate|client|"
    r"gtagConfig|transformation):.+$"
)


def _hash_without(payload: dict[str, Any], *fields: str) -> str:
    return stable_hash(
        {key: value for key, value in payload.items() if key not in set(fields)},
        64,
    )


def _path_is_link_or_reparse(path: Path) -> bool:
    """Reject symlinks and Windows reparse points, including NTFS junctions."""

    try:
        if path.is_symlink():
            return True
        attributes = int(getattr(path.lstat(), "st_file_attributes", 0))
    except OSError:
        return False
    return bool(
        attributes & int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))
    )


def _regular_tree_files(root: Path) -> tuple[list[Path], list[str]]:
    """Enumerate one tree without crossing any link or reparse boundary."""

    if _path_is_link_or_reparse(root):
        return [], [f"path is a link or reparse point: {root}"]
    files: list[Path] = []
    pending = [root]
    errors: list[str] = []
    while pending:
        directory = pending.pop()
        try:
            entries = sorted(directory.iterdir())
        except OSError as exc:
            errors.append(f"cannot enumerate protected tree {directory}: {exc}")
            continue
        for entry in entries:
            if _path_is_link_or_reparse(entry):
                errors.append(f"path is a link or reparse point: {entry}")
            elif entry.is_dir():
                pending.append(entry)
            elif entry.is_file():
                files.append(entry)
            else:
                errors.append(f"path is not a regular file or directory: {entry}")
    return sorted(files), errors


def _contained_child_errors(path: Path, parent: Path, label: str) -> list[str]:
    """Prove one package child is direct, regular, and not redirected."""

    errors: list[str] = []
    if _path_is_link_or_reparse(path):
        errors.append(f"{label} is a link or reparse point")
    try:
        if path.resolve().parent != parent.resolve():
            errors.append(f"{label} leaves its package parent")
    except OSError:
        errors.append(f"{label} cannot be resolved")
    return errors


def _copy_locked(source: Path, target: Path, role: str) -> dict[str, Any]:
    shutil.copy2(source, target)
    return {
        "role": role,
        "path": target.name,
        "sha256": file_sha256(target),
        "mutable": False,
    }


def _object_inventory(scan: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for obj in as_list(scan.get("objects")):
        if not isinstance(obj, dict):
            continue
        rows.append(
            {
                "object_key": obj.get("object_key"),
                "layer": obj.get("layer"),
                "object_id": obj.get("object_id"),
                "object_name": obj.get("object_name"),
                "object_type": obj.get("object_type"),
                "paused": obj.get("paused"),
                "source_json_path": obj.get("source_json_path"),
                "source_leaf_facts": obj.get("source_leaf_facts", []),
                "source_absence_facts": obj.get("source_absence_facts", []),
                "execution_dependency_traces": obj.get("execution_dependency_traces", []),
                "reference_trace_requirements": obj.get("reference_trace_requirements", []),
                "consumers": obj.get("consumers", []),
                "firing_trigger_ids": obj.get("firing_trigger_ids", []),
                "blocking_trigger_ids": obj.get("blocking_trigger_ids", []),
                "trigger_group_member_ids": obj.get("trigger_group_member_ids", []),
                "setup_tags": obj.get("setup_tags", []),
                "teardown_tags": obj.get("teardown_tags", []),
            }
        )
    return sorted(rows, key=lambda row: str(row["object_key"]))


def _blind_inventory(scan: dict[str, Any]) -> dict[str, Any]:
    payload = {
        "kind": "gtm_candidate_blind_source_inventory",
        "schema_version": 1,
        "source_sha256": scan.get("source_sha256"),
        "canonical_scan_sha256": scan.get("canonical_scan_sha256"),
        "objects": _object_inventory(scan),
        "boundary": (
            "This inventory intentionally omits generated relationship candidates, "
            "families, optimisation candidates, requirement evidence, and all verdicts."
        ),
    }
    payload["blind_inventory_sha256"] = stable_hash(payload, 64)
    return payload


def _checkpoint_scaffold(
    audit_id: str,
    source_sha256: str,
    inventory: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "kind": "gtm_cleanroom_source_checkpoint",
        "schema_version": 1,
        "audit_id": audit_id,
        "source_sha256": source_sha256,
        "status": "pending",
        "independent_context_id": "",
        "host_isolation_receipt": {
            "status": "pending",
            "receipt_id": "",
            "mechanism": "",
            "allowed_bundle_manifest_sha256": "",
            "other_audit_accessible": None,
            "prohibited_artifacts_accessible": None,
        },
        "candidate_blind_discovery": audit_id == "audit-b",
        "object_behavior_map": [
            {
                "object_key": row["object_key"],
                "source_json_path": row["source_json_path"],
                "configured_role": "",
                "current_configured_behavior": "",
                "evidence_coordinates": [],
            }
            for row in inventory
        ],
        "discovered_families": [],
        "discovered_relationships": [],
        "singleton_object_keys": [],
        "open_discoveries": [],
        "generated_candidate_ids_reviewed": [],
        "source_only_conclusion": "",
        "approved_requirement_ids_used": [],
    }


def prepare_audit_bundles(
    export_path: Path,
    package_dir: Path,
    *,
    scan: dict[str, Any],
    assurance: dict[str, Any],
    ledger: dict[str, Any],
    context_path: Path,
    contract_path: Path,
    registry_path: Path,
    requirements_path: Path | None = None,
) -> dict[str, Any]:
    bundles_root = package_dir / BUNDLE_DIRECTORY
    if bundles_root.exists():
        raise ValueError("clean-room audit bundles already exist")
    bundles_root.mkdir(parents=True)
    result: dict[str, Any] = {}
    inventory = _object_inventory(scan)
    for audit_id in AUDIT_IDS:
        bundle = bundles_root / audit_id
        bundle.mkdir()
        records = [
            _copy_locked(export_path, bundle / "locked-source.json", "raw_source"),
            _copy_locked(context_path, bundle / "context.json", "locked_context"),
            _copy_locked(contract_path, bundle / "audit-contract.json", "audit_contract"),
            _copy_locked(
                registry_path,
                bundle / "vendor-registry.toml",
                "locked_vendor_registry",
            ),
        ]
        if audit_id == "audit-a":
            scan_path = bundle / "canonical-scan.json"
            assurance_path = bundle / "scan-assurance.json"
            source_ledger_path = bundle / "source-obligations.json"
            write_json(scan_path, scan)
            write_json(assurance_path, assurance)
            source_ids = set((ledger.get("release_sets") or {}).get("source_only", []))
            source_obligations = []
            for row in as_list(ledger.get("obligations")):
                if row.get("obligation_id") not in source_ids:
                    continue
                source_row = copy.deepcopy(row)
                if as_list(source_row.pop("semantic_repair_records", [])):
                    source_row["source_coordinates"] = [
                        value
                        for value in as_list(source_row.get("source_coordinates"))
                        if not str(value).startswith(
                            ("$.repair_records[", "$.audit_decisions[")
                        )
                    ]
                    source_row["material_verification_triggers"] = [
                        value
                        for value in as_list(
                            source_row.get("material_verification_triggers")
                        )
                        if value != "semantic_repair"
                    ]
                    source_row["obligation_sha256"] = _hash_without(
                        source_row, "obligation_sha256"
                    )
                source_obligations.append(source_row)
            source_ledger = {
                **ledger,
                "obligations": source_obligations,
                "release_sets": {"source_only": sorted(source_ids)},
                "counts": {
                    **(ledger.get("counts") or {}),
                    "semantic_repairs": 0,
                },
            }
            source_ledger["obligation_ledger_sha256"] = _hash_without(
                source_ledger, "obligation_ledger_sha256"
            )
            write_json(source_ledger_path, source_ledger)
            records.extend(
                [
                    {
                        "role": "assured_canonical_scan",
                        "path": scan_path.name,
                        "sha256": file_sha256(scan_path),
                        "mutable": False,
                    },
                    {
                        "role": "scan_assurance",
                        "path": assurance_path.name,
                        "sha256": file_sha256(assurance_path),
                        "mutable": False,
                    },
                    {
                        "role": "source_only_obligations",
                        "path": source_ledger_path.name,
                        "sha256": file_sha256(source_ledger_path),
                        "mutable": False,
                    },
                ]
            )
        else:
            blind_path = bundle / "blind-inventory.json"
            write_json(blind_path, _blind_inventory(scan))
            records.append(
                {
                    "role": "candidate_blind_inventory",
                    "path": blind_path.name,
                    "sha256": file_sha256(blind_path),
                    "mutable": False,
                }
            )
        checkpoint_path = bundle / CHECKPOINT_FILE
        write_json(
            checkpoint_path,
            _checkpoint_scaffold(audit_id, str(scan.get("source_sha256") or ""), inventory),
        )
        records.append(
            {
                "role": "source_checkpoint_output",
                "path": CHECKPOINT_FILE,
                "mutable": True,
            }
        )
        manifest = {
            "kind": "gtm_cleanroom_audit_bundle_manifest",
            "schema_version": 1,
            "audit_id": audit_id,
            "source_sha256": scan.get("source_sha256"),
            "canonical_scan_sha256": scan.get("canonical_scan_sha256"),
            "scan_assurance_sha256": assurance.get("scan_assurance_sha256"),
            "obligation_ledger_sha256": ledger.get("obligation_ledger_sha256"),
            "requirements_present": bool(requirements_path),
            "phase": "source_checkpoint",
            "allowed_files": records,
            "prohibited_inputs": [
                "the other audit bundle or output",
                "reconciliation output",
                "neutral-verification output",
                "target-state operations",
                "workbook or editorial output",
                "test helpers or bulk semantic completion helpers",
            ],
            "isolation_contract": {
                "required": True,
                "scope": "this audit bundle and its declared released inputs only",
                "accepted_host_mechanisms": sorted(ISOLATION_MECHANISMS),
                "boundary": (
                    "The validator can prove bundle identity, context separation, and "
                    "receipt consistency. The execution host must enforce scoped access; "
                    "a self-declared context ID alone is not isolation evidence."
                ),
            },
        }
        manifest["bundle_manifest_sha256"] = _hash_without(manifest, "bundle_manifest_sha256")
        write_json(bundle / BUNDLE_MANIFEST_FILE, manifest)
        result[audit_id] = {
            "bundle_directory": f"{BUNDLE_DIRECTORY}/{audit_id}",
            "bundle_manifest_sha256": manifest["bundle_manifest_sha256"],
            "phase": "source_checkpoint",
        }
    return result


def _specific_text(value: Any, minimum_words: int = 5) -> bool:
    text = " ".join(str(value or "").split())
    return len(re.findall(r"\b[\w{}:./-]+\b", text)) >= minimum_words


def _host_isolation_receipt_errors(
    receipt: dict[str, Any],
    bundle_manifest_sha256: str,
    label: str,
    *,
    amendment_parent_seal_sha256: str | None = None,
) -> list[str]:
    errors: list[str] = []
    if receipt.get("status") != "enforced":
        errors.append(f"{label} requires an enforced host isolation receipt")
    if len(str(receipt.get("receipt_id") or "").strip()) < 12:
        errors.append(f"{label} host isolation receipt_id is missing or too weak")
    if receipt.get("mechanism") not in ISOLATION_MECHANISMS:
        errors.append(f"{label} host isolation mechanism is unsupported or absent")
    if receipt.get("allowed_bundle_manifest_sha256") != bundle_manifest_sha256:
        errors.append(f"{label} host isolation receipt is not bound to its audit bundle")
    if receipt.get("other_audit_accessible") is not False:
        errors.append(f"{label} must keep the other audit inaccessible")
    if receipt.get("prohibited_artifacts_accessible") is not False:
        errors.append(f"{label} must keep prohibited artifacts inaccessible")
    declared_parent = str(receipt.get("amendment_parent_seal_sha256") or "")
    if amendment_parent_seal_sha256 is None:
        if declared_parent:
            errors.append(f"{label} unexpectedly declares an amendment parent")
    elif declared_parent != amendment_parent_seal_sha256:
        errors.append(f"{label} host receipt is not bound to the prior audit seal")
    return errors


def _checkpoint_errors(
    checkpoint: dict[str, Any],
    audit_id: str,
    source_sha256: str,
    inventory: list[dict[str, Any]],
    generated_relationship_ids: set[str],
    bundle_manifest_sha256: str,
) -> list[str]:
    errors: list[str] = []
    if checkpoint.get("kind") != "gtm_cleanroom_source_checkpoint":
        errors.append("source checkpoint kind is invalid")
    if checkpoint.get("schema_version") != 1:
        errors.append("source checkpoint schema_version must be 1")
    if checkpoint.get("audit_id") != audit_id:
        errors.append("source checkpoint uses another audit identity")
    if checkpoint.get("source_sha256") != source_sha256:
        errors.append("source checkpoint uses another source")
    if checkpoint.get("status") != "complete":
        errors.append("source checkpoint status must be complete")
    context_id = str(checkpoint.get("independent_context_id") or "").strip()
    if len(context_id) < 12:
        errors.append("source checkpoint requires a strong independent_context_id")
    receipt = checkpoint.get("host_isolation_receipt") or {}
    errors.extend(
        _host_isolation_receipt_errors(
            receipt, bundle_manifest_sha256, "source checkpoint"
        )
    )
    expected_keys = {str(row["object_key"]) for row in inventory}
    behavior_rows = [
        row for row in as_list(checkpoint.get("object_behavior_map")) if isinstance(row, dict)
    ]
    behavior_by_key = {str(row.get("object_key") or ""): row for row in behavior_rows}
    if len(behavior_by_key) != len(behavior_rows) or "" in behavior_by_key:
        errors.append("object behavior map has blank or duplicate object keys")
    if set(behavior_by_key) != expected_keys:
        errors.append("object behavior map must cover every source object exactly once")
    source_path_by_key = {str(row["object_key"]): str(row["source_json_path"]) for row in inventory}
    for key, row in behavior_by_key.items():
        if row.get("source_json_path") != source_path_by_key.get(key):
            errors.append(f"{key}: source_json_path differs from locked inventory")
        if not _specific_text(row.get("configured_role"), 3):
            errors.append(f"{key}: configured_role is incomplete")
        if not _specific_text(row.get("current_configured_behavior"), 6):
            errors.append(f"{key}: current configured behavior is incomplete")
        coordinates = {
            str(value) for value in as_list(row.get("evidence_coordinates")) if str(value)
        }
        if not coordinates or not any(
            value.startswith(source_path_by_key.get(key, "__missing__")) for value in coordinates
        ):
            errors.append(f"{key}: evidence coordinates do not bind to its source object")

    allocated: list[str] = []
    family_ids: set[str] = set()
    for family in as_list(checkpoint.get("discovered_families")):
        if not isinstance(family, dict):
            errors.append("discovered family row is malformed")
            continue
        family_id = str(family.get("discovery_family_id") or "")
        if not family_id or family_id in family_ids:
            errors.append("discovered family IDs must be unique and nonblank")
        family_ids.add(family_id)
        members = [str(value) for value in as_list(family.get("member_object_keys"))]
        if not members or set(members) - expected_keys:
            errors.append(f"{family_id or 'family'}: members are empty or unknown")
        allocated.extend(members)
        if not _specific_text(family.get("configured_purpose"), 6):
            errors.append(f"{family_id or 'family'}: configured purpose is incomplete")
        if not as_list(family.get("evidence_coordinates")):
            errors.append(f"{family_id or 'family'}: evidence coordinates are missing")
    singleton_keys = [str(value) for value in as_list(checkpoint.get("singleton_object_keys"))]
    allocated.extend(singleton_keys)
    if set(allocated) != expected_keys or len(allocated) != len(set(allocated)):
        errors.append(
            "discovered families plus singleton_object_keys must allocate every object exactly once"
        )

    relationship_ids: set[str] = set()
    for relationship in as_list(checkpoint.get("discovered_relationships")):
        if not isinstance(relationship, dict):
            errors.append("discovered relationship row is malformed")
            continue
        relationship_id = str(relationship.get("discovery_relationship_id") or "")
        if not relationship_id or relationship_id in relationship_ids:
            errors.append("discovered relationship IDs must be unique and nonblank")
        relationship_ids.add(relationship_id)
        members = [str(value) for value in as_list(relationship.get("member_object_keys"))]
        if len(set(members)) < 2 or set(members) - expected_keys:
            errors.append(
                f"{relationship_id or 'relationship'}: requires at least two known members"
            )
        if not _specific_text(relationship.get("configured_relationship"), 6):
            errors.append(
                f"{relationship_id or 'relationship'}: configured relationship is incomplete"
            )
        if not as_list(relationship.get("evidence_coordinates")):
            errors.append(f"{relationship_id or 'relationship'}: evidence coordinates are missing")

    if audit_id == "audit-a":
        reviewed = {
            str(value) for value in as_list(checkpoint.get("generated_candidate_ids_reviewed"))
        }
        if reviewed != generated_relationship_ids:
            errors.append(
                "Audit A source checkpoint must attest every generated relationship candidate"
            )
    elif as_list(checkpoint.get("generated_candidate_ids_reviewed")):
        errors.append(
            "Audit B is candidate-blind at checkpoint and cannot claim generated candidate IDs"
        )
    if as_list(checkpoint.get("approved_requirement_ids_used")):
        errors.append("approved requirement evidence is prohibited before source checkpoint")
    if not _specific_text(checkpoint.get("source_only_conclusion"), 10):
        errors.append("source_only_conclusion is incomplete")
    return errors


def _bundle_manifest_errors(bundle: Path) -> tuple[dict[str, Any], list[str]]:
    manifest_path = bundle / BUNDLE_MANIFEST_FILE
    if not manifest_path.is_file():
        return {}, ["bundle manifest is missing"]
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    errors = []
    if manifest.get("bundle_manifest_sha256") != _hash_without(manifest, "bundle_manifest_sha256"):
        errors.append("bundle manifest content hash is invalid")
    declared = {
        str(row.get("path") or "")
        for row in as_list(manifest.get("allowed_files"))
        if str(row.get("path") or "")
    }
    actual = {path.name for path in bundle.iterdir() if path.is_file()}
    allowed_runtime = {
        BUNDLE_MANIFEST_FILE,
        CHECKPOINT_SEAL_FILE,
        RELEASE_MANIFEST_FILE,
        AUDIT_FILE,
    }
    release_path = bundle / RELEASE_MANIFEST_FILE
    if release_path.is_file():
        try:
            release = json.loads(release_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            errors.append("coverage release manifest is not valid JSON")
        else:
            allowed_runtime.update(
                str(row.get("path") or "")
                for row in as_list(release.get("released_files"))
                if str(row.get("path") or "")
            )
    unexpected = sorted(actual - declared - allowed_runtime)
    if unexpected:
        errors.append("bundle contains undeclared files: " + ", ".join(unexpected))
    for record in as_list(manifest.get("allowed_files")):
        if record.get("mutable"):
            continue
        path = bundle / str(record.get("path") or "")
        if not path.is_file():
            errors.append(f"locked bundle input is missing: {path.name}")
        elif file_sha256(path) != record.get("sha256"):
            errors.append(f"locked bundle input changed: {path.name}")
    return manifest, errors


def _audit_scaffold(
    audit_id: str,
    ledger: dict[str, Any],
    checkpoint_seal: dict[str, Any],
) -> dict[str, Any]:
    order = {
        scope: index
        for index, scope in enumerate(AUDIT_METHODS[audit_id.replace("-", "_")]["order"])
    }
    obligations = sorted(
        as_list(ledger.get("obligations")),
        key=lambda row: (
            order.get(str(row.get("scope_level") or ""), 99),
            str(row.get("obligation_id") or ""),
        ),
    )
    decisions = []
    for obligation in obligations:
        decisions.append(
            {
                "decision_id": f"{audit_id.upper()}-{obligation['obligation_id']}",
                "obligation_id": obligation["obligation_id"],
                "obligation_sha256": obligation["obligation_sha256"],
                "area_id": obligation["area_id"],
                "scope_level": obligation["scope_level"],
                "audit_mechanism": obligation["audit_mechanism"],
                "fact_kind": obligation["fact_kind"],
                "subject_keys": obligation["subject_keys"],
                "family_ids": obligation["family_ids"],
                "candidate_id": obligation["candidate_id"],
                "source_coordinates": obligation["source_coordinates"],
                "applicability": obligation["applicability"],
                "material_verification_triggers": obligation["material_verification_triggers"],
                "semantic_repair_records": obligation.get(
                    "semantic_repair_records", []
                ),
                "status": "pending",
                **{field: "" for field in CANONICAL_DECISION_FIELDS},
                "operation_proposal": {},
                "evidence_citations": [],
            }
        )
    return {
        "kind": "gtm_cleanroom_semantic_audit",
        "schema_version": 1,
        "audit_id": audit_id,
        "traversal_method": AUDIT_METHODS[audit_id.replace("-", "_")],
        "source_sha256": ledger.get("source_sha256"),
        "canonical_scan_sha256": ledger.get("canonical_scan_sha256"),
        "scan_assurance_sha256": ledger.get("scan_assurance_sha256"),
        "obligation_ledger_sha256": ledger.get("obligation_ledger_sha256"),
        "source_checkpoint_seal_sha256": checkpoint_seal.get("checkpoint_seal_sha256"),
        "status": "pending",
        "independent_context_id": checkpoint_seal.get("independent_context_id"),
        "host_isolation_receipt": checkpoint_seal.get("host_isolation_receipt"),
        "decisions": decisions,
        "open_discoveries": [],
        "coverage_closure": {
            "reviewed_obligation_ids": [],
            "reviewed_object_keys": [],
            "reviewed_family_ids": [],
            "reviewed_relationship_candidate_ids": [],
            "global_shared_infrastructure_review": "",
            "global_target_architecture_review": "",
        },
        "completion_attestation": {
            "status": "pending",
            "foreign_audit_artifacts_used": [],
            "test_or_bulk_semantic_helpers_used": [],
            "decision_authoring_method": "",
            "host_scope_preserved_through_completion": None,
        },
    }


def checkpoint_audit(
    package_dir: Path,
    audit_id: str,
    completed_checkpoint: Path | None = None,
) -> dict[str, Any]:
    if audit_id not in AUDIT_IDS:
        raise ValueError(f"unsupported audit identity: {audit_id}")
    bundle = (package_dir / BUNDLE_DIRECTORY / audit_id).resolve()
    if (bundle / CHECKPOINT_SEAL_FILE).is_file():
        raise ValueError("source checkpoint is already sealed and immutable")
    manifest, errors = _bundle_manifest_errors(bundle)
    package_manifest_path = package_dir / "audit-package-manifest.json"
    if not package_manifest_path.is_file():
        errors.append("audit package manifest is missing")
        package_manifest = {}
    else:
        package_manifest = json.loads(package_manifest_path.read_text(encoding="utf-8"))
    expected_bundle_hash = ((package_manifest.get("audit_bundles") or {}).get(audit_id) or {}).get(
        "bundle_manifest_sha256"
    )
    if expected_bundle_hash != manifest.get("bundle_manifest_sha256"):
        errors.append("bundle differs from the source-locked package manifest")
    checkpoint_path = (completed_checkpoint or bundle / CHECKPOINT_FILE).resolve()
    if checkpoint_path.parent != bundle:
        errors.append("completed checkpoint must be inside its own audit bundle")
    if not checkpoint_path.is_file():
        errors.append("completed source checkpoint is missing")
    if errors:
        raise ValueError("; ".join(errors))

    checkpoint = json.loads(checkpoint_path.read_text(encoding="utf-8"))
    scan_path = package_dir / "canonical-scan.json"
    ledger_path = package_dir / "obligation-ledger.json"
    assurance_path = package_dir / "scan-assurance.json"
    for path in (scan_path, ledger_path, assurance_path):
        if not path.is_file():
            raise ValueError(f"required package artifact is missing: {path.name}")
    scan = json.loads(scan_path.read_text(encoding="utf-8"))
    inventory = _object_inventory(scan)
    generated_relationship_ids = {
        str(row.get("comparison_id") or "")
        for row in as_list((scan.get("architecture_evidence") or {}).get("relationships"))
        if str(row.get("comparison_id") or "")
    }
    errors = _checkpoint_errors(
        checkpoint,
        audit_id,
        str(scan.get("source_sha256") or ""),
        inventory,
        generated_relationship_ids,
        str(manifest.get("bundle_manifest_sha256") or ""),
    )
    context_id = str(checkpoint.get("independent_context_id") or "")
    receipt_id = str(
        (checkpoint.get("host_isolation_receipt") or {}).get("receipt_id") or ""
    )
    errors.extend(
        reasoning_identity_reuse_errors(
            collect_reasoning_identity_registry(package_dir),
            owner=f"source-audit:{audit_id}:0",
            label=f"{audit_id} source checkpoint",
            context_id=context_id,
            receipt_id=receipt_id,
        )
    )
    if errors:
        raise ValueError("; ".join(errors))

    canonical_checkpoint_path = bundle / CHECKPOINT_FILE
    if checkpoint_path != canonical_checkpoint_path:
        shutil.copy2(checkpoint_path, canonical_checkpoint_path)
    checkpoint_sha = file_sha256(canonical_checkpoint_path)
    seal = {
        "kind": "gtm_cleanroom_source_checkpoint_seal",
        "schema_version": 1,
        "audit_id": audit_id,
        "source_sha256": scan.get("source_sha256"),
        "checkpoint_sha256": checkpoint_sha,
        "independent_context_id": context_id,
        "host_isolation_receipt": checkpoint.get("host_isolation_receipt"),
        "candidate_blind_discovery": audit_id == "audit-b",
        "validator_status": "pass",
    }
    seal["checkpoint_seal_sha256"] = _hash_without(seal, "checkpoint_seal_sha256")
    write_json(bundle / CHECKPOINT_SEAL_FILE, seal)

    release_records = []
    release_sources = (
        (scan_path, "canonical-scan.json", "assured_canonical_scan"),
        (assurance_path, "scan-assurance.json", "scan_assurance"),
        (ledger_path, "obligation-ledger.json", "complete_obligation_ledger"),
    )
    for source, filename, role in release_sources:
        target = bundle / filename
        if target.is_file():
            if file_sha256(target) != file_sha256(source):
                raise ValueError(f"released immutable artifact changed: {filename}")
        else:
            shutil.copy2(source, target)
        release_records.append({"role": role, "path": filename, "sha256": file_sha256(target)})
    requirements_path = package_dir / "approved-requirements.json"
    if requirements_path.is_file():
        target = bundle / requirements_path.name
        shutil.copy2(requirements_path, target)
        release_records.append(
            {
                "role": "approved_requirement_evidence",
                "path": target.name,
                "sha256": file_sha256(target),
            }
        )
    repair_path = package_dir / "semantic-repair-brief.json"
    if repair_path.is_file():
        target = bundle / repair_path.name
        shutil.copy2(repair_path, target)
        release_records.append(
            {
                "role": "approved_semantic_successor_repair",
                "path": target.name,
                "sha256": file_sha256(target),
            }
        )
        predecessor_path = package_dir / "superseded-canonical-record.json"
        if not predecessor_path.is_file():
            raise ValueError(
                "semantic repair brief exists without its sealed predecessor record"
            )
        predecessor_target = bundle / predecessor_path.name
        shutil.copy2(predecessor_path, predecessor_target)
        release_records.append(
            {
                "role": "semantic_predecessor_canonical_record",
                "path": predecessor_target.name,
                "sha256": file_sha256(predecessor_target),
            }
        )
    ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
    audit = _audit_scaffold(audit_id, ledger, seal)
    write_json(bundle / AUDIT_FILE, audit)
    work_units = build_work_units(
        bundle, audit, scan, json.loads(assurance_path.read_text(encoding="utf-8"))
    )
    release_manifest = {
        "kind": "gtm_cleanroom_coverage_release_manifest",
        "schema_version": 1,
        "audit_id": audit_id,
        "source_checkpoint_seal_sha256": seal["checkpoint_seal_sha256"],
        "released_files": release_records,
        "mutable_output": AUDIT_FILE,
        "work_units": {
            "strategy": work_units.get("strategy"),
            "manifest": f"{WORK_UNIT_DIRECTORY}/{WORK_UNIT_MANIFEST}",
            "work_unit_manifest_sha256": work_units.get("work_unit_manifest_sha256"),
        },
        "phase": "semantic_audit",
    }
    release_manifest["release_manifest_sha256"] = _hash_without(
        release_manifest, "release_manifest_sha256"
    )
    write_json(bundle / RELEASE_MANIFEST_FILE, release_manifest)
    return {
        "status": "pass",
        "audit_id": audit_id,
        "checkpoint_seal_sha256": seal["checkpoint_seal_sha256"],
        "release_manifest_sha256": release_manifest["release_manifest_sha256"],
        "audit_file": f"{BUNDLE_DIRECTORY}/{audit_id}/{AUDIT_FILE}",
    }


def operation_proposal_errors(
    proposal: dict[str, Any],
    decision: dict[str, Any],
    operation_ids: set[str],
    label: str,
) -> list[str]:
    errors: list[str] = []
    operation_id = str(proposal.get("operation_id") or "")
    if not re.fullmatch(r"OP-[A-Z0-9][A-Z0-9_-]{5,80}", operation_id):
        errors.append(f"{label}: operation_id must use the stable OP-* form")
    elif operation_id in operation_ids:
        errors.append(f"{label}: operation_id is duplicated")
    else:
        operation_ids.add(operation_id)
    if proposal.get("source_decision_id") != decision.get("decision_id"):
        errors.append(f"{label}: operation source_decision_id is not exact")
    action_count = 0
    for field in OPERATION_ACTION_FIELDS:
        value = proposal.get(field)
        if not isinstance(value, list):
            errors.append(f"{label}: operation {field} must be a list")
            continue
        action_count += len(value)
    if not action_count:
        errors.append(f"{label}: actionable operation contains no structured action")
    for field in (
        "operation_family",
        "exact_target_state",
        "preconditions",
        "static_verification",
        "rollback",
    ):
        if not _specific_text(proposal.get(field), 4):
            errors.append(f"{label}: operation {field} is incomplete")
    dependencies = proposal.get("depends_on")
    if not isinstance(dependencies, list) or any(
        not str(value).startswith("OP-") for value in dependencies
    ):
        errors.append(f"{label}: operation depends_on must be a list of OP-* IDs")
    return errors


def _locked_decision_fields(obligation: dict[str, Any]) -> dict[str, Any]:
    return {
        "obligation_id": obligation["obligation_id"],
        "obligation_sha256": obligation["obligation_sha256"],
        "area_id": obligation["area_id"],
        "scope_level": obligation["scope_level"],
        "audit_mechanism": obligation["audit_mechanism"],
        "fact_kind": obligation["fact_kind"],
        "subject_keys": obligation["subject_keys"],
        "family_ids": obligation["family_ids"],
        "candidate_id": obligation["candidate_id"],
        "source_coordinates": obligation["source_coordinates"],
        "applicability": obligation["applicability"],
        "material_verification_triggers": obligation["material_verification_triggers"],
        "semantic_repair_records": obligation.get("semantic_repair_records", []),
    }


def _discovery_errors(
    discoveries: list[Any],
    valid_object_keys: set[str],
    audit_id: str,
) -> list[str]:
    errors: list[str] = []
    ids: set[str] = set()
    for index, discovery in enumerate(discoveries, start=1):
        label = f"open discovery {index}"
        if not isinstance(discovery, dict):
            errors.append(f"{label}: row is malformed")
            continue
        discovery_id = str(discovery.get("discovery_id") or "")
        if not re.fullmatch(rf"{audit_id.upper()}-DISC-[A-Z0-9_-]+", discovery_id):
            errors.append(f"{label}: discovery_id is invalid")
        elif discovery_id in ids:
            errors.append(f"{label}: discovery_id is duplicated")
        ids.add(discovery_id)
        if discovery.get("area_id") not in SEMANTIC_AREA_IDS:
            errors.append(f"{label}: area_id is invalid")
        subjects = {str(value) for value in as_list(discovery.get("subject_keys"))}
        if not subjects or subjects - valid_object_keys:
            errors.append(f"{label}: subject_keys must be known source objects")
        if not as_list(discovery.get("source_coordinates")):
            errors.append(f"{label}: source_coordinates are missing")
        decision = discovery.get("decision")
        if not isinstance(decision, dict):
            errors.append(f"{label}: semantic decision is missing")
        else:
            errors.extend(semantic_contract_errors(decision, label))
    return errors


def _work_unit_snapshot_relative_path(audit_id: str, sequence: int) -> str:
    return f"{WORK_UNIT_SNAPSHOT_ROOT}/{audit_id}/sequence-{sequence:03d}"


def _work_unit_snapshot_manifest(
    bundle: Path, audit_id: str, sequence: int
) -> dict[str, Any]:
    work_units = bundle / WORK_UNIT_DIRECTORY
    manifest_path = work_units / WORK_UNIT_MANIFEST
    if not manifest_path.is_file():
        raise ValueError("work-unit manifest is missing before audit sealing")
    files, tree_errors = _regular_tree_files(work_units)
    if tree_errors:
        raise ValueError(
            "work-unit snapshot source is not a self-contained regular tree: "
            + "; ".join(tree_errors)
        )
    work_unit_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    declared_files, declared_errors = declared_work_unit_files(work_unit_manifest)
    actual_files = {
        path.relative_to(work_units).as_posix() for path in files
    }
    if declared_errors or actual_files != declared_files:
        raise ValueError(
            "work-unit snapshot source differs from its declared files: "
            + "; ".join(declared_errors or ["unexpected or missing files"])
        )
    snapshot = {
        "kind": "gtm_cleanroom_work_unit_snapshot_manifest",
        "schema_version": 1,
        "audit_id": audit_id,
        "amendment_sequence": sequence,
        "work_unit_manifest_sha256": work_unit_manifest.get(
            "work_unit_manifest_sha256"
        ),
        "files": [
            {
                "path": path.relative_to(work_units).as_posix(),
                "sha256": file_sha256(path),
            }
            for path in files
        ],
    }
    snapshot["work_unit_snapshot_sha256"] = _hash_without(
        snapshot, "work_unit_snapshot_sha256"
    )
    return snapshot


def _sealed_work_unit_snapshot(
    package_dir: Path,
    audit_id: str,
    sealed_seal: dict[str, Any],
) -> tuple[Path, dict[str, Any], list[str]]:
    errors: list[str] = []
    try:
        sequence = int(sealed_seal.get("amendment_sequence") or 0)
    except (TypeError, ValueError):
        sequence = 0
        errors.append("sealed work-unit snapshot sequence is invalid")
    expected_relative = _work_unit_snapshot_relative_path(audit_id, sequence)
    if sealed_seal.get("work_unit_snapshot_path") != expected_relative:
        errors.append("sealed audit work-unit snapshot path is invalid")
    seal_dir = package_dir / SEAL_DIRECTORY
    snapshot_root = seal_dir / WORK_UNIT_SNAPSHOT_ROOT
    snapshot_audit_root = snapshot_root / audit_id
    snapshot_dir = snapshot_audit_root / f"sequence-{sequence:03d}"
    containment_checks = (
        (snapshot_root, seal_dir),
        (snapshot_audit_root, snapshot_root),
        (snapshot_dir, snapshot_audit_root),
    )
    for path, expected_parent in containment_checks:
        if _path_is_link_or_reparse(path):
            errors.append("sealed work-unit snapshot path is a link or reparse point")
        try:
            if path.resolve().parent != expected_parent.resolve():
                errors.append("sealed work-unit snapshot path leaves its sealed root")
        except OSError:
            errors.append("sealed work-unit snapshot path cannot be resolved")
    if errors:
        return snapshot_dir, {}, errors
    manifest_path = snapshot_dir / WORK_UNIT_SNAPSHOT_MANIFEST
    if not manifest_path.is_file():
        return snapshot_dir, {}, [*errors, "sealed work-unit snapshot is missing"]
    snapshot_files, tree_errors = _regular_tree_files(snapshot_dir)
    if tree_errors:
        return snapshot_dir, {}, [
            *errors,
            *(
                "sealed work-unit snapshot is not self-contained: " + error
                for error in tree_errors
            ),
        ]
    snapshot = json.loads(manifest_path.read_text(encoding="utf-8"))
    if snapshot.get("work_unit_snapshot_sha256") != _hash_without(
        snapshot, "work_unit_snapshot_sha256"
    ):
        errors.append("sealed work-unit snapshot manifest hash is invalid")
    if sealed_seal.get("work_unit_snapshot_sha256") != snapshot.get(
        "work_unit_snapshot_sha256"
    ):
        errors.append("audit seal is bound to another work-unit snapshot")
    if (
        snapshot.get("kind") != "gtm_cleanroom_work_unit_snapshot_manifest"
        or snapshot.get("schema_version") != 1
        or snapshot.get("audit_id") != audit_id
        or snapshot.get("amendment_sequence") != sequence
    ):
        errors.append("sealed work-unit snapshot identity is invalid")
    supplied_records = [
        row for row in as_list(snapshot.get("files")) if isinstance(row, dict)
    ]
    supplied = {
        str(row.get("path") or ""): str(row.get("sha256") or "")
        for row in supplied_records
    }
    actual = {
        path.relative_to(snapshot_dir).as_posix(): file_sha256(path)
        for path in snapshot_files
        if path != manifest_path
    }
    if (
        len(supplied) != len(supplied_records)
        or "" in supplied
        or supplied != actual
    ):
        errors.append("sealed work-unit snapshot files differ from their manifest")
    work_unit_manifest_path = snapshot_dir / WORK_UNIT_MANIFEST
    if not work_unit_manifest_path.is_file():
        errors.append("sealed work-unit manifest is missing from its snapshot")
        return snapshot_dir, {}, errors
    work_unit_manifest = json.loads(
        work_unit_manifest_path.read_text(encoding="utf-8")
    )
    if snapshot.get("work_unit_manifest_sha256") != work_unit_manifest.get(
        "work_unit_manifest_sha256"
    ):
        errors.append("sealed work-unit snapshot contains another manifest")
    declared_files, declared_errors = declared_work_unit_files(work_unit_manifest)
    errors.extend(
        "sealed work-unit manifest: " + error for error in declared_errors
    )
    if set(supplied) != declared_files:
        errors.append("sealed work-unit snapshot contains undeclared files")
    return snapshot_dir, work_unit_manifest, errors


def validate_audit(
    package_dir: Path,
    audit_id: str,
    audit_path: Path | None = None,
    *,
    amendment_of: str | None = None,
    sealed_seal: dict[str, Any] | None = None,
) -> list[str]:
    if audit_id not in AUDIT_IDS:
        return [f"unsupported audit identity: {audit_id}"]
    bundle_root = package_dir / BUNDLE_DIRECTORY
    bundle = bundle_root / audit_id
    audit_path = audit_path or bundle / AUDIT_FILE
    errors = [
        *_contained_child_errors(
            bundle_root, package_dir, "audit-bundle directory"
        ),
        *_contained_child_errors(bundle, bundle_root, f"{audit_id} bundle"),
    ]
    if sealed_seal is None:
        errors.extend(
            _contained_child_errors(
                audit_path, bundle, f"{audit_id} audit candidate"
            )
        )
    else:
        canonical_root = package_dir / "audits"
        seal_root = package_dir / SEAL_DIRECTORY
        history_root = seal_root / HISTORY_DIRECTORY
        errors.extend(
            [
                *_contained_child_errors(
                    canonical_root,
                    package_dir,
                    "canonical-audit directory",
                ),
                *_contained_child_errors(
                    seal_root, package_dir, "audit-seal directory"
                ),
                *_contained_child_errors(
                    history_root, seal_root, "audit history directory"
                ),
            ]
        )
        if audit_path.parent == canonical_root:
            sealed_parent = canonical_root
        elif audit_path.parent == history_root:
            sealed_parent = history_root
        else:
            errors.append(f"{audit_id} sealed audit path has an invalid owner")
            sealed_parent = audit_path.parent
        errors.extend(
            _contained_child_errors(
                audit_path, sealed_parent, f"{audit_id} sealed audit artifact"
            )
        )
    if errors:
        return errors
    manifest, bundle_errors = _bundle_manifest_errors(bundle)
    errors.extend(bundle_errors)
    release_path = bundle / RELEASE_MANIFEST_FILE
    checkpoint_seal_path = bundle / CHECKPOINT_SEAL_FILE
    checkpoint_path = bundle / CHECKPOINT_FILE
    ledger_path = bundle / "obligation-ledger.json"
    if not all(
        path.is_file()
        for path in (release_path, checkpoint_seal_path, checkpoint_path)
    ):
        errors.append("source checkpoint must be sealed and coverage released first")
        return errors
    release = json.loads(release_path.read_text(encoding="utf-8"))
    checkpoint_seal = json.loads(
        checkpoint_seal_path.read_text(encoding="utf-8")
    )
    if release.get("release_manifest_sha256") != _hash_without(release, "release_manifest_sha256"):
        errors.append("coverage release manifest hash is invalid")
    if release.get("kind") != "gtm_cleanroom_coverage_release_manifest":
        errors.append("coverage release manifest kind is invalid")
    if release.get("schema_version") != 1 or release.get("audit_id") != audit_id:
        errors.append("coverage release manifest identity is invalid")
    if checkpoint_seal.get("checkpoint_seal_sha256") != _hash_without(
        checkpoint_seal, "checkpoint_seal_sha256"
    ):
        errors.append("source checkpoint seal content hash is invalid")
    if checkpoint_seal.get("checkpoint_sha256") != file_sha256(checkpoint_path):
        errors.append("source checkpoint changed after sealing")
    if release.get("source_checkpoint_seal_sha256") != checkpoint_seal.get(
        "checkpoint_seal_sha256"
    ):
        errors.append("coverage release manifest is bound to another checkpoint")
    for record in as_list(release.get("released_files")):
        path = bundle / str(record.get("path") or "")
        if not path.is_file() or file_sha256(path) != record.get("sha256"):
            errors.append(f"released immutable input changed: {path.name}")
    work_unit_record = release.get("work_units") or {}
    work_unit_directory = bundle / WORK_UNIT_DIRECTORY
    work_unit_manifest: dict[str, Any] = {}
    if sealed_seal is not None:
        (
            work_unit_directory,
            work_unit_manifest,
            snapshot_errors,
        ) = _sealed_work_unit_snapshot(package_dir, audit_id, sealed_seal)
        errors.extend(snapshot_errors)
        work_unit_manifest_path = work_unit_directory / WORK_UNIT_MANIFEST
    else:
        work_unit_manifest_path = bundle / str(
            work_unit_record.get("manifest") or ""
        )
    if not work_unit_manifest_path.is_file():
        errors.append("work-unit manifest is missing")
    else:
        if not work_unit_manifest:
            work_unit_manifest = json.loads(
                work_unit_manifest_path.read_text(encoding="utf-8")
            )
        if work_unit_manifest.get("work_unit_manifest_sha256") != work_unit_record.get(
            "work_unit_manifest_sha256"
        ) or work_unit_manifest.get("work_unit_manifest_sha256") != work_unit_identity_hash(
            work_unit_manifest
        ):
            errors.append("work-unit manifest identity changed")
        errors.extend(
            "work-unit manifest: " + error
            for error in declared_work_unit_files(work_unit_manifest)[1]
        )
    if not audit_path.is_file() or not ledger_path.is_file():
        errors.append("completed audit or obligation ledger is missing")
        return errors
    audit = json.loads(audit_path.read_text(encoding="utf-8"))
    ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
    if work_unit_manifest_path.is_file():
        errors.extend(
            work_unit_completion_errors(
                bundle,
                audit,
                work_unit_manifest,
                work_unit_directory=work_unit_directory,
            )
        )
    checks = (
        ("kind", "gtm_cleanroom_semantic_audit"),
        ("schema_version", 1),
        ("audit_id", audit_id),
        ("source_sha256", ledger.get("source_sha256")),
        ("canonical_scan_sha256", ledger.get("canonical_scan_sha256")),
        ("scan_assurance_sha256", ledger.get("scan_assurance_sha256")),
        ("obligation_ledger_sha256", ledger.get("obligation_ledger_sha256")),
        (
            "source_checkpoint_seal_sha256",
            checkpoint_seal.get("checkpoint_seal_sha256"),
        ),
        ("status", "complete"),
    )
    for field, expected in checks:
        if audit.get(field) != expected:
            errors.append(f"audit {field} differs from its locked contract")

    seal_path = package_dir / SEAL_DIRECTORY / f"{audit_id}.json"
    previous = (
        json.loads(seal_path.read_text(encoding="utf-8"))
        if seal_path.is_file()
        else None
    )
    context_id = str(audit.get("independent_context_id") or "").strip()
    receipt = audit.get("host_isolation_receipt") or {}
    receipt_id = str(receipt.get("receipt_id") or "").strip()
    sequence = 0
    if sealed_seal is not None:
        try:
            sequence = int(sealed_seal.get("amendment_sequence") or 0)
        except (TypeError, ValueError):
            sequence = 0
            errors.append("sealed audit amendment sequence is invalid")
        if sequence < 0:
            errors.append("sealed audit amendment sequence is invalid")
        parent = str(sealed_seal.get("amendment_parent_seal_sha256") or "")
        if sequence == 0:
            if parent:
                errors.append("initial sealed audit unexpectedly declares a parent")
            if audit.get("independent_context_id") != checkpoint_seal.get(
                "independent_context_id"
            ):
                errors.append("initial sealed audit context differs from its checkpoint")
            if receipt != checkpoint_seal.get("host_isolation_receipt"):
                errors.append("initial sealed audit receipt differs from its checkpoint")
            if audit.get("amendment_parent_seal_sha256"):
                errors.append("initial sealed audit artifact declares an amendment parent")
        else:
            if len(context_id) < 12:
                errors.append("sealed audit amendment context identity is missing")
            if audit.get("amendment_parent_seal_sha256") != parent:
                errors.append("sealed audit amendment parent binding is invalid")
            errors.extend(
                _host_isolation_receipt_errors(
                    receipt,
                    str(manifest.get("bundle_manifest_sha256") or ""),
                    "sealed audit amendment",
                    amendment_parent_seal_sha256=parent,
                )
            )
    elif amendment_of:
        if not previous:
            errors.append("audit amendment requires a current prior audit seal")
        else:
            sequence = int(previous.get("amendment_sequence") or 0) + 1
            if previous.get("audit_seal_sha256") != _hash_without(
                previous, "audit_seal_sha256"
            ):
                errors.append("prior audit seal content hash is invalid")
            if amendment_of != previous.get("audit_seal_sha256"):
                errors.append("audit amendment does not cite the current audit seal")
            if context_id == str(previous.get("independent_context_id") or ""):
                errors.append("audit amendment requires a fresh reasoning context")
            previous_receipt_id = str(
                (previous.get("host_isolation_receipt") or {}).get("receipt_id")
                or ""
            )
            if receipt_id == previous_receipt_id:
                errors.append("audit amendment requires a fresh host isolation receipt")
        if len(context_id) < 12:
            errors.append("audit amendment requires a strong independent_context_id")
        if audit.get("amendment_parent_seal_sha256") != amendment_of:
            errors.append("audit amendment artifact is not bound to its prior seal")
        errors.extend(
            _host_isolation_receipt_errors(
                receipt,
                str(manifest.get("bundle_manifest_sha256") or ""),
                "audit amendment",
                amendment_parent_seal_sha256=amendment_of,
            )
        )
    else:
        if audit.get("independent_context_id") != checkpoint_seal.get(
            "independent_context_id"
        ):
            errors.append("audit independent_context_id differs from its checkpoint")
        if receipt != checkpoint_seal.get("host_isolation_receipt"):
            errors.append("audit host_isolation_receipt differs from its checkpoint")
        if audit.get("amendment_parent_seal_sha256"):
            errors.append("initial audit unexpectedly declares an amendment parent")

    errors.extend(
        reasoning_identity_reuse_errors(
            collect_reasoning_identity_registry(package_dir),
            owner=f"source-audit:{audit_id}:{sequence}",
            label=f"{audit_id} audit",
            context_id=context_id,
            receipt_id=receipt_id,
        )
    )

    obligations = {
        str(row.get("obligation_id") or ""): row
        for row in as_list(ledger.get("obligations"))
        if isinstance(row, dict)
    }
    decision_rows = [row for row in as_list(audit.get("decisions")) if isinstance(row, dict)]
    decisions = {str(row.get("obligation_id") or ""): row for row in decision_rows}
    if len(decisions) != len(decision_rows) or "" in decisions:
        errors.append("audit decisions contain blank or duplicate obligation IDs")
    if set(decisions) != set(obligations):
        errors.append("audit decisions must cover every obligation exactly once")
    operation_ids: set[str] = set()
    for obligation_id, obligation in obligations.items():
        decision = decisions.get(obligation_id)
        if not decision:
            continue
        label = f"decision {decision.get('decision_id') or obligation_id}"
        if decision.get("decision_id") != f"{audit_id.upper()}-{obligation_id}":
            errors.append(f"{label}: decision_id is not deterministic")
        for field, expected in _locked_decision_fields(obligation).items():
            if decision.get(field) != expected:
                errors.append(f"{label}: locked field {field} changed")
        if decision.get("status") != "complete":
            errors.append(f"{label}: status must be complete")
        errors.extend(semantic_contract_errors(decision, label))
        if obligation.get("applicability") == "source_counted_zero":
            if decision.get("decision_class") != "not_applicable":
                errors.append(f"{label}: source-counted zero must be Not applicable")
        elif decision.get("decision_class") == "not_applicable":
            errors.append(f"{label}: applicable obligation cannot be Not applicable")
        citations = {str(value) for value in as_list(decision.get("evidence_citations"))}
        allowed = set(as_list(obligation.get("source_coordinates")))
        if allowed and (not citations or citations - allowed):
            errors.append(f"{label}: evidence citations must use locked source coordinates")
        decision_class = str(decision.get("decision_class") or "")
        proposal = decision.get("operation_proposal")
        if decision_class in ACTIONABLE_DECISION_CLASSES:
            if not isinstance(proposal, dict):
                errors.append(f"{label}: actionable operation proposal is missing")
            else:
                errors.extend(operation_proposal_errors(proposal, decision, operation_ids, label))
        elif proposal:
            errors.append(f"{label}: non-actionable decision cannot carry an operation")

    valid_keys = {
        key
        for obligation in obligations.values()
        for key in as_list(obligation.get("subject_keys"))
        if OBJECT_KEY_RE.match(str(key))
    }
    errors.extend(_discovery_errors(as_list(audit.get("open_discoveries")), valid_keys, audit_id))
    closure = audit.get("coverage_closure") or {}
    if set(as_list(closure.get("reviewed_obligation_ids"))) != set(obligations):
        errors.append("coverage closure must attest every obligation ID")
    expected_objects = {
        key for row in obligations.values() for key in as_list(row.get("subject_keys"))
    }
    if set(as_list(closure.get("reviewed_object_keys"))) != expected_objects:
        errors.append("coverage closure must attest every obligation-owned object")
    expected_families = {
        value for row in obligations.values() for value in as_list(row.get("family_ids"))
    }
    if set(as_list(closure.get("reviewed_family_ids"))) != expected_families:
        errors.append("coverage closure must attest every family")
    expected_candidates = {
        str(row.get("candidate_id") or "")
        for row in obligations.values()
        if str(row.get("candidate_id") or "")
    }
    if set(as_list(closure.get("reviewed_relationship_candidate_ids"))) != expected_candidates:
        errors.append("coverage closure must attest every generated candidate")
    for field in (
        "global_shared_infrastructure_review",
        "global_target_architecture_review",
    ):
        if not _specific_text(closure.get(field), 10):
            errors.append(f"coverage closure {field} is incomplete")
    attestation = audit.get("completion_attestation") or {}
    if attestation.get("status") != "complete":
        errors.append("completion attestation must be complete")
    if as_list(attestation.get("foreign_audit_artifacts_used")):
        errors.append("audit used foreign-audit artifacts before reconciliation")
    if as_list(attestation.get("test_or_bulk_semantic_helpers_used")):
        errors.append("audit used test or bulk semantic-completion helpers")
    if attestation.get("decision_authoring_method") not in {
        "independent_agent_review",
        "independent_manual_review",
        "independent_test_fixture_review",
    }:
        errors.append("decision authoring method is invalid")
    if attestation.get("host_scope_preserved_through_completion") is not True:
        errors.append("audit did not attest preservation of its enforced host scope")
    return errors


def _atomic_replace(source: Path, target: Path) -> None:
    source.replace(target)


def _commit_audit_transition(
    *,
    audit_id: str,
    bundle: Path,
    audit_path: Path,
    canonical_path: Path,
    seal_path: Path,
    seal: dict[str, Any],
    previous: dict[str, Any] | None,
    snapshot_relative_path: str,
    snapshot_manifest: dict[str, Any],
) -> None:
    """Stage one audit/seal transition and restore every prior artifact on failure."""

    seal_dir = seal_path.parent
    canonical_dir = canonical_path.parent
    package_dir = seal_dir.parent
    history = seal_dir / HISTORY_DIRECTORY
    snapshot_root = seal_dir / WORK_UNIT_SNAPSHOT_ROOT
    snapshot_target = seal_dir / snapshot_relative_path
    snapshot_audit_root = snapshot_target.parent
    bundle_root = bundle.parent
    containment_errors = [
        *_contained_child_errors(seal_dir, package_dir, "audit-seal directory"),
        *_contained_child_errors(
            canonical_dir, package_dir, "canonical-audit directory"
        ),
        *_contained_child_errors(bundle_root, package_dir, "audit-bundle directory"),
        *_contained_child_errors(bundle, bundle_root, "owner audit bundle"),
        *_contained_child_errors(audit_path, bundle, "completed audit candidate"),
        *_contained_child_errors(seal_path, seal_dir, "current audit seal"),
        *_contained_child_errors(
            canonical_path, canonical_dir, "canonical completed audit"
        ),
        *_contained_child_errors(history, seal_dir, "audit history directory"),
        *_contained_child_errors(
            snapshot_root, seal_dir, "work-unit snapshot root"
        ),
        *_contained_child_errors(
            snapshot_audit_root,
            snapshot_root,
            "owner work-unit snapshot directory",
        ),
        *_contained_child_errors(
            snapshot_target,
            snapshot_audit_root,
            "sequence work-unit snapshot",
        ),
    ]
    if containment_errors:
        raise ValueError("; ".join(containment_errors))
    seal_dir.mkdir(exist_ok=True)
    canonical_dir.mkdir(exist_ok=True)
    staging = Path(
        tempfile.mkdtemp(prefix=f".{audit_id}-transition-", dir=seal_dir)
    )
    history_existed = history.exists()
    history_targets: list[Path] = []
    prior_seal_backup = staging / "prior-seal.json"
    prior_audit_backup = staging / "prior-audit.json"
    staged_audit = staging / "next-audit.json"
    staged_seal = staging / "next-seal.json"
    staged_snapshot = staging / "next-work-unit-snapshot"
    snapshot_root_existed = snapshot_root.exists()
    snapshot_audit_root_existed = snapshot_audit_root.exists()
    seal_existed = seal_path.is_file()
    audit_existed = canonical_path.is_file()
    prior_seal_sha256 = file_sha256(seal_path) if seal_existed else ""
    prior_audit_sha256 = file_sha256(canonical_path) if audit_existed else ""
    audit_replaced = False
    seal_replaced = False
    snapshot_replaced = False
    preserve_staging = False
    try:
        expected_snapshot_target = seal_dir / _work_unit_snapshot_relative_path(
            audit_id, int(seal.get("amendment_sequence") or 0)
        )
        if snapshot_target != expected_snapshot_target:
            raise ValueError("work-unit snapshot target identity is invalid")
        if snapshot_target.exists():
            raise ValueError("work-unit snapshot identity already exists")
        if snapshot_manifest.get("work_unit_snapshot_sha256") != _hash_without(
            snapshot_manifest, "work_unit_snapshot_sha256"
        ):
            raise ValueError("work-unit snapshot manifest identity is invalid")
        if seal.get("work_unit_snapshot_sha256") != snapshot_manifest.get(
            "work_unit_snapshot_sha256"
        ):
            raise ValueError("new audit seal is bound to another work-unit snapshot")

        staged_snapshot.mkdir()
        source_root = (bundle / WORK_UNIT_DIRECTORY).resolve()
        declared_files: dict[str, str] = {}
        for record in as_list(snapshot_manifest.get("files")):
            if not isinstance(record, dict):
                raise ValueError("work-unit snapshot file record is malformed")
            relative_text = str(record.get("path") or "")
            relative_path = Path(relative_text)
            if (
                not relative_text
                or relative_path.is_absolute()
                or ".." in relative_path.parts
                or relative_path.as_posix() != relative_text
                or relative_text in declared_files
            ):
                raise ValueError("work-unit snapshot file identity is invalid")
            expected_sha256 = str(record.get("sha256") or "")
            source = bundle / WORK_UNIT_DIRECTORY / relative_path
            if (
                not source.is_file()
                or _path_is_link_or_reparse(source)
                or not source.resolve().is_relative_to(source_root)
                or file_sha256(source) != expected_sha256
            ):
                raise ValueError(
                    f"work-unit snapshot source changed: {relative_text}"
                )
            target = staged_snapshot / relative_path
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
            if file_sha256(target) != expected_sha256:
                raise OSError(
                    f"staged work-unit snapshot verification failed: {relative_text}"
                )
            declared_files[relative_text] = expected_sha256
        write_json(staged_snapshot / WORK_UNIT_SNAPSHOT_MANIFEST, snapshot_manifest)
        staged_files = {
            path.relative_to(staged_snapshot).as_posix(): file_sha256(path)
            for path in staged_snapshot.rglob("*")
            if path.is_file()
            and path != staged_snapshot / WORK_UNIT_SNAPSHOT_MANIFEST
        }
        if staged_files != declared_files:
            raise OSError("staged work-unit snapshot files differ from their manifest")

        if seal_existed:
            shutil.copy2(seal_path, prior_seal_backup)
            if file_sha256(prior_seal_backup) != prior_seal_sha256:
                raise OSError("prior audit seal backup verification failed")
        if audit_existed:
            shutil.copy2(canonical_path, prior_audit_backup)
            if file_sha256(prior_audit_backup) != prior_audit_sha256:
                raise OSError("prior completed audit backup verification failed")
        shutil.copy2(audit_path, staged_audit)
        write_json(staged_seal, seal)
        if file_sha256(staged_audit) != seal.get("completed_audit_sha256"):
            raise ValueError("staged completed audit hash differs from its new seal")

        snapshot_audit_root.mkdir(parents=True, exist_ok=True)
        for path, expected_parent in (
            (snapshot_root, seal_dir),
            (snapshot_audit_root, snapshot_root),
        ):
            if _path_is_link_or_reparse(path) or (
                path.resolve().parent != expected_parent.resolve()
            ):
                raise ValueError("work-unit snapshot target leaves its sealed root")
        _atomic_replace(staged_snapshot, snapshot_target)
        snapshot_replaced = True

        if previous:
            history.mkdir(exist_ok=True)
            previous_seal_hash = str(previous.get("audit_seal_sha256") or "")
            previous_audit_hash = str(previous.get("completed_audit_sha256") or "")
            history_seal = history / f"{audit_id}.{previous_seal_hash}.seal.json"
            history_audit = history / f"{audit_id}.{previous_audit_hash}.audit.json"
            if history_seal.exists() or history_audit.exists():
                raise ValueError("audit amendment history identity already exists")
            staged_history_seal = staging / "history-seal.json"
            staged_history_audit = staging / "history-audit.json"
            shutil.copy2(prior_seal_backup, staged_history_seal)
            shutil.copy2(prior_audit_backup, staged_history_audit)
            _atomic_replace(staged_history_seal, history_seal)
            history_targets.append(history_seal)
            _atomic_replace(staged_history_audit, history_audit)
            history_targets.append(history_audit)

        _atomic_replace(staged_audit, canonical_path)
        audit_replaced = True
        _atomic_replace(staged_seal, seal_path)
        seal_replaced = True
    except Exception as exc:
        rollback_errors: list[str] = []
        if audit_replaced:
            if audit_existed:
                if (
                    not prior_audit_backup.is_file()
                    or file_sha256(prior_audit_backup) != prior_audit_sha256
                ):
                    rollback_errors.append("prior completed audit backup is invalid")
                else:
                    try:
                        restore_audit = staging / "restore-audit.json"
                        shutil.copy2(prior_audit_backup, restore_audit)
                        _atomic_replace(restore_audit, canonical_path)
                    except OSError as rollback_exc:
                        rollback_errors.append(
                            f"completed audit restoration failed: {rollback_exc}"
                        )
            elif canonical_path.exists():
                try:
                    canonical_path.unlink()
                except OSError as rollback_exc:
                    rollback_errors.append(
                        f"new completed audit removal failed: {rollback_exc}"
                    )
        if seal_replaced:
            if seal_existed:
                if (
                    not prior_seal_backup.is_file()
                    or file_sha256(prior_seal_backup) != prior_seal_sha256
                ):
                    rollback_errors.append("prior audit seal backup is invalid")
                else:
                    try:
                        restore_seal = staging / "restore-seal.json"
                        shutil.copy2(prior_seal_backup, restore_seal)
                        _atomic_replace(restore_seal, seal_path)
                    except OSError as rollback_exc:
                        rollback_errors.append(
                            f"audit seal restoration failed: {rollback_exc}"
                        )
            elif seal_path.exists():
                try:
                    seal_path.unlink()
                except OSError as rollback_exc:
                    rollback_errors.append(
                        f"new audit seal removal failed: {rollback_exc}"
                    )
        for target in history_targets:
            if target.exists():
                try:
                    target.unlink()
                except OSError as rollback_exc:
                    rollback_errors.append(
                        f"partial history removal failed: {rollback_exc}"
                    )
        if snapshot_replaced and snapshot_target.exists():
            try:
                if (
                    _path_is_link_or_reparse(snapshot_root)
                    or _path_is_link_or_reparse(snapshot_audit_root)
                    or _path_is_link_or_reparse(snapshot_target)
                    or snapshot_root.resolve().parent != seal_dir.resolve()
                    or snapshot_audit_root.resolve().parent
                    != snapshot_root.resolve()
                    or snapshot_target.resolve().parent
                    != snapshot_audit_root.resolve()
                ):
                    raise OSError("snapshot target leaves its sealed root")
                shutil.rmtree(snapshot_target)
            except OSError as rollback_exc:
                rollback_errors.append(
                    f"new work-unit snapshot removal failed: {rollback_exc}"
                )
        if not history_existed and history.is_dir() and not any(history.iterdir()):
            try:
                history.rmdir()
            except OSError as rollback_exc:
                rollback_errors.append(
                    f"empty history cleanup failed: {rollback_exc}"
                )
        for directory, existed in (
            (snapshot_audit_root, snapshot_audit_root_existed),
            (snapshot_root, snapshot_root_existed),
        ):
            if not existed and directory.is_dir() and not any(directory.iterdir()):
                try:
                    directory.rmdir()
                except OSError as rollback_exc:
                    rollback_errors.append(
                        f"empty work-unit snapshot cleanup failed: {rollback_exc}"
                    )
        if rollback_errors:
            preserve_staging = True
            raise RuntimeError(
                "audit transition failed and rollback is incomplete; recovery "
                f"artifacts remain at {staging}: " + "; ".join(rollback_errors)
            ) from exc
        raise
    finally:
        if not preserve_staging:
            shutil.rmtree(staging, ignore_errors=True)


def seal_audit(
    package_dir: Path,
    audit_id: str,
    completed_audit: Path | None = None,
    *,
    amendment_of: str | None = None,
) -> dict[str, Any]:
    bundle = package_dir / BUNDLE_DIRECTORY / audit_id
    audit_path = (completed_audit or bundle / AUDIT_FILE).resolve()
    if audit_path.parent != bundle.resolve():
        raise ValueError("completed audit must be inside its own clean-room bundle")
    seal_dir = package_dir / SEAL_DIRECTORY
    seal_path = seal_dir / f"{audit_id}.json"
    canonical_dir = package_dir / "audits"
    canonical_path = canonical_dir / f"{audit_id}.json"
    previous = json.loads(seal_path.read_text(encoding="utf-8")) if seal_path.is_file() else None
    if previous:
        if amendment_of != previous.get("audit_seal_sha256"):
            raise ValueError("audit is already sealed; amendment_of must match its current seal")
    elif amendment_of:
        raise ValueError("amendment_of was supplied but no prior audit seal exists")
    if amendment_of and (package_dir / "canonical-record-seal.json").is_file():
        raise ValueError(
            "source-audit amendment is closed after canonical sealing; start a successor package"
        )
    if amendment_of:
        preflight_errors = _sealed_audit_record_errors(package_dir, audit_id)
        if preflight_errors:
            raise ValueError(
                "existing audit provenance failed before amendment: "
                + "; ".join(preflight_errors)
            )
    errors = validate_audit(
        package_dir,
        audit_id,
        audit_path,
        amendment_of=amendment_of,
    )
    if errors:
        raise ValueError("audit validator failed: " + "; ".join(errors))
    audit = json.loads(audit_path.read_text(encoding="utf-8"))
    sequence = int(previous.get("amendment_sequence", 0)) + 1 if previous else 0
    snapshot_relative_path = _work_unit_snapshot_relative_path(audit_id, sequence)
    snapshot_manifest = _work_unit_snapshot_manifest(bundle, audit_id, sequence)
    checkpoint_seal = json.loads((bundle / CHECKPOINT_SEAL_FILE).read_text(encoding="utf-8"))
    release = json.loads((bundle / RELEASE_MANIFEST_FILE).read_text(encoding="utf-8"))
    seal = {
        "kind": "gtm_cleanroom_audit_seal",
        "schema_version": 1,
        "audit_id": audit_id,
        "source_sha256": audit.get("source_sha256"),
        "canonical_scan_sha256": audit.get("canonical_scan_sha256"),
        "scan_assurance_sha256": audit.get("scan_assurance_sha256"),
        "obligation_ledger_sha256": audit.get("obligation_ledger_sha256"),
        "source_checkpoint_seal_sha256": checkpoint_seal.get("checkpoint_seal_sha256"),
        "release_manifest_sha256": release.get("release_manifest_sha256"),
        "completed_audit_sha256": file_sha256(audit_path),
        "independent_context_id": audit.get("independent_context_id"),
        "host_isolation_receipt": audit.get("host_isolation_receipt"),
        "validator_status": "pass",
        "amendment_sequence": sequence,
        "amendment_parent_seal_sha256": (
            str(previous.get("audit_seal_sha256") or "") if previous else ""
        ),
        "work_unit_snapshot_path": snapshot_relative_path,
        "work_unit_snapshot_sha256": snapshot_manifest[
            "work_unit_snapshot_sha256"
        ],
    }
    seal["audit_seal_sha256"] = _hash_without(seal, "audit_seal_sha256")
    _commit_audit_transition(
        audit_id=audit_id,
        bundle=bundle,
        audit_path=audit_path,
        canonical_path=canonical_path,
        seal_path=seal_path,
        seal=seal,
        previous=previous,
        snapshot_relative_path=snapshot_relative_path,
        snapshot_manifest=snapshot_manifest,
    )
    return seal


def _audit_history_errors(
    package_dir: Path,
    audit_id: str,
    current_seal: dict[str, Any],
    *,
    checkpoint_seal_sha256: str,
    release_manifest_sha256: str,
    bundle_manifest_sha256: str,
) -> list[str]:
    errors: list[str] = []
    try:
        current_sequence = int(current_seal.get("amendment_sequence") or 0)
    except (TypeError, ValueError):
        return [f"{audit_id}: current amendment sequence is invalid"]
    if current_sequence < 0:
        return [f"{audit_id}: current amendment sequence is invalid"]

    seal_root = package_dir / SEAL_DIRECTORY
    history = seal_root / HISTORY_DIRECTORY
    history_containment_errors = [
        *_contained_child_errors(
            seal_root, package_dir, "audit-seal directory"
        ),
        *_contained_child_errors(history, seal_root, "audit history directory"),
    ]
    if history_containment_errors:
        return [
            *errors,
            *(
                f"{audit_id}: {error}"
                for error in history_containment_errors
            ),
        ]
    seal_paths = sorted(history.glob(f"{audit_id}.*.seal.json")) if history.is_dir() else []
    audit_paths = sorted(history.glob(f"{audit_id}.*.audit.json")) if history.is_dir() else []
    if len(seal_paths) != current_sequence:
        errors.append(f"{audit_id}: amendment history seal count is incomplete")
    if len(audit_paths) != current_sequence:
        errors.append(f"{audit_id}: amendment history audit count is incomplete")

    seals_by_sequence: dict[int, dict[str, Any]] = {}
    expected_audit_paths: set[Path] = set()
    for path in seal_paths:
        historical_seal = json.loads(path.read_text(encoding="utf-8"))
        seal_hash = str(historical_seal.get("audit_seal_sha256") or "")
        if seal_hash != _hash_without(historical_seal, "audit_seal_sha256"):
            errors.append(f"{audit_id}: historical audit seal hash is invalid")
        if path.name != f"{audit_id}.{seal_hash}.seal.json":
            errors.append(f"{audit_id}: historical audit seal filename is invalid")
        try:
            sequence = int(historical_seal.get("amendment_sequence") or 0)
        except (TypeError, ValueError):
            errors.append(f"{audit_id}: historical amendment sequence is invalid")
            continue
        if sequence in seals_by_sequence:
            errors.append(f"{audit_id}: historical amendment sequence is duplicated")
        seals_by_sequence[sequence] = historical_seal
        audit_hash = str(historical_seal.get("completed_audit_sha256") or "")
        historical_audit_path = history / f"{audit_id}.{audit_hash}.audit.json"
        expected_audit_paths.add(historical_audit_path)
        if not historical_audit_path.is_file():
            errors.append(f"{audit_id}: historical completed audit is missing")
            continue
        if file_sha256(historical_audit_path) != audit_hash:
            errors.append(f"{audit_id}: historical completed audit changed")
        historical_audit = json.loads(
            historical_audit_path.read_text(encoding="utf-8")
        )
        errors.extend(
            f"{audit_id}: historical audit validation: {error}"
            for error in validate_audit(
                package_dir,
                audit_id,
                historical_audit_path,
                sealed_seal=historical_seal,
            )
        )
        for field in (
            "audit_id",
            "source_sha256",
            "canonical_scan_sha256",
            "scan_assurance_sha256",
            "obligation_ledger_sha256",
            "source_checkpoint_seal_sha256",
            "independent_context_id",
            "host_isolation_receipt",
        ):
            if historical_seal.get(field) != historical_audit.get(field):
                errors.append(
                    f"{audit_id}: historical seal field {field} differs from its audit"
                )
        if historical_seal.get("validator_status") != "pass":
            errors.append(f"{audit_id}: historical audit validator did not pass")
        if historical_seal.get("source_checkpoint_seal_sha256") != (
            checkpoint_seal_sha256
        ) or historical_audit.get("source_checkpoint_seal_sha256") != (
            checkpoint_seal_sha256
        ):
            errors.append(f"{audit_id}: historical audit is bound to another checkpoint")
        if historical_seal.get("release_manifest_sha256") != release_manifest_sha256:
            errors.append(f"{audit_id}: historical audit is bound to another coverage release")
        expected_parent = str(
            historical_seal.get("amendment_parent_seal_sha256") or ""
        )
        if str(historical_audit.get("amendment_parent_seal_sha256") or "") != (
            expected_parent
        ):
            errors.append(f"{audit_id}: historical audit parent binding differs from its seal")
        errors.extend(
            _host_isolation_receipt_errors(
                historical_seal.get("host_isolation_receipt") or {},
                bundle_manifest_sha256,
                f"{audit_id} historical audit",
                amendment_parent_seal_sha256=(expected_parent or None),
            )
        )

    if set(seals_by_sequence) != set(range(current_sequence)):
        errors.append(f"{audit_id}: historical amendment sequences are not contiguous")
    for sequence, historical_seal in sorted(seals_by_sequence.items()):
        expected_parent = (
            ""
            if sequence == 0
            else str(
                seals_by_sequence.get(sequence - 1, {}).get("audit_seal_sha256")
                or ""
            )
        )
        if str(historical_seal.get("amendment_parent_seal_sha256") or "") != (
            expected_parent
        ):
            errors.append(f"{audit_id}: historical amendment parent chain is invalid")
    expected_current_parent = (
        ""
        if current_sequence == 0
        else str(
            seals_by_sequence.get(current_sequence - 1, {}).get(
                "audit_seal_sha256"
            )
            or ""
        )
    )
    if str(current_seal.get("amendment_parent_seal_sha256") or "") != (
        expected_current_parent
    ):
        errors.append(f"{audit_id}: current amendment parent chain is invalid")
    if set(audit_paths) != expected_audit_paths:
        errors.append(f"{audit_id}: amendment history contains orphan audit artifacts")
    snapshot_audit_root = (
        package_dir / SEAL_DIRECTORY / WORK_UNIT_SNAPSHOT_ROOT / audit_id
    )
    expected_snapshot_dirs = {
        snapshot_audit_root / f"sequence-{sequence:03d}"
        for sequence in range(current_sequence + 1)
    }
    snapshot_entries: list[Path] = []
    snapshot_root = snapshot_audit_root.parent
    if snapshot_audit_root.exists():
        if _path_is_link_or_reparse(snapshot_audit_root) or (
            snapshot_audit_root.resolve().parent != snapshot_root.resolve()
        ):
            errors.append(
                f"{audit_id}: sealed work-unit snapshot history leaves its root"
            )
        else:
            snapshot_entries = list(snapshot_audit_root.iterdir())
    reparse_entries = [
        path for path in snapshot_entries if _path_is_link_or_reparse(path)
    ]
    if reparse_entries:
        errors.append(
            f"{audit_id}: sealed work-unit snapshot history contains reparse points"
        )
    actual_snapshot_dirs = {
        path
        for path in snapshot_entries
        if path.is_dir() and path not in reparse_entries
    }
    if actual_snapshot_dirs != expected_snapshot_dirs:
        errors.append(
            f"{audit_id}: sealed work-unit snapshot history identity is incomplete"
        )
    if any(path.is_file() for path in snapshot_entries):
        errors.append(
            f"{audit_id}: sealed work-unit snapshot history contains orphan artifacts"
        )
    return errors


def _sealed_audit_record_errors(package_dir: Path, audit_id: str) -> list[str]:
    errors: list[str] = []
    seal_root = package_dir / SEAL_DIRECTORY
    audit_root = package_dir / "audits"
    bundle_root = package_dir / BUNDLE_DIRECTORY
    seal_path = seal_root / f"{audit_id}.json"
    audit_path = audit_root / f"{audit_id}.json"
    bundle = bundle_root / audit_id
    checkpoint_path = bundle / CHECKPOINT_FILE
    checkpoint_seal_path = bundle / CHECKPOINT_SEAL_FILE
    release_path = bundle / RELEASE_MANIFEST_FILE
    bundle_manifest_path = bundle / BUNDLE_MANIFEST_FILE
    history = seal_root / HISTORY_DIRECTORY
    containment_errors = [
        *_contained_child_errors(seal_root, package_dir, "audit-seal directory"),
        *_contained_child_errors(audit_root, package_dir, "canonical-audit directory"),
        *_contained_child_errors(bundle_root, package_dir, "audit-bundle directory"),
        *_contained_child_errors(bundle, bundle_root, f"{audit_id} bundle"),
        *_contained_child_errors(seal_path, seal_root, f"{audit_id} seal"),
        *_contained_child_errors(history, seal_root, "audit history directory"),
        *_contained_child_errors(audit_path, audit_root, f"{audit_id} audit"),
        *_contained_child_errors(
            checkpoint_path, bundle, f"{audit_id} checkpoint"
        ),
        *_contained_child_errors(
            checkpoint_seal_path, bundle, f"{audit_id} checkpoint seal"
        ),
        *_contained_child_errors(release_path, bundle, f"{audit_id} release"),
        *_contained_child_errors(
            bundle_manifest_path, bundle, f"{audit_id} bundle manifest"
        ),
    ]
    if containment_errors:
        return [f"{audit_id}: {error}" for error in containment_errors]
    if seal_root.is_dir() and any(seal_root.glob(".*-transition-*")):
        errors.append("an incomplete audit transition staging directory remains")
    required_paths = (
        seal_path,
        audit_path,
        checkpoint_path,
        checkpoint_seal_path,
        release_path,
        bundle_manifest_path,
    )
    if not all(path.is_file() for path in required_paths):
        return [*errors, f"{audit_id}: sealed audit artifacts are missing"]
    seal = json.loads(seal_path.read_text(encoding="utf-8"))
    audit = json.loads(audit_path.read_text(encoding="utf-8"))
    checkpoint_seal = json.loads(
        checkpoint_seal_path.read_text(encoding="utf-8")
    )
    release = json.loads(release_path.read_text(encoding="utf-8"))
    bundle_manifest, bundle_errors = _bundle_manifest_errors(bundle)
    errors.extend(f"{audit_id}: {error}" for error in bundle_errors)
    errors.extend(
        f"{audit_id}: sealed audit validation: {error}"
        for error in validate_audit(
            package_dir,
            audit_id,
            audit_path,
            sealed_seal=seal,
        )
    )
    if seal.get("audit_seal_sha256") != _hash_without(seal, "audit_seal_sha256"):
        errors.append(f"{audit_id}: audit seal content hash is invalid")
    if seal.get("completed_audit_sha256") != file_sha256(audit_path):
        errors.append(f"{audit_id}: completed audit changed after sealing")
    for field in (
        "audit_id",
        "source_sha256",
        "canonical_scan_sha256",
        "scan_assurance_sha256",
        "obligation_ledger_sha256",
        "source_checkpoint_seal_sha256",
        "independent_context_id",
        "host_isolation_receipt",
    ):
        if seal.get(field) != audit.get(field):
            errors.append(f"{audit_id}: audit seal field {field} differs from its audit")
    if checkpoint_seal.get("checkpoint_seal_sha256") != _hash_without(
        checkpoint_seal, "checkpoint_seal_sha256"
    ):
        errors.append(f"{audit_id}: source checkpoint seal content hash is invalid")
    if checkpoint_seal.get("checkpoint_sha256") != file_sha256(checkpoint_path):
        errors.append(f"{audit_id}: source checkpoint changed after sealing")
    current_checkpoint_seal = checkpoint_seal.get("checkpoint_seal_sha256")
    if seal.get("source_checkpoint_seal_sha256") != current_checkpoint_seal:
        errors.append(f"{audit_id}: audit seal is bound to another checkpoint")
    if audit.get("source_checkpoint_seal_sha256") != current_checkpoint_seal:
        errors.append(f"{audit_id}: completed audit is bound to another checkpoint")
    if release.get("release_manifest_sha256") != _hash_without(
        release, "release_manifest_sha256"
    ):
        errors.append(f"{audit_id}: coverage release manifest hash is invalid")
    if release.get("kind") != "gtm_cleanroom_coverage_release_manifest" or (
        release.get("schema_version") != 1 or release.get("audit_id") != audit_id
    ):
        errors.append(f"{audit_id}: coverage release manifest identity is invalid")
    if release.get("source_checkpoint_seal_sha256") != current_checkpoint_seal:
        errors.append(f"{audit_id}: coverage release is bound to another checkpoint")
    for record in as_list(release.get("released_files")):
        released_path = bundle / str((record or {}).get("path") or "")
        if not released_path.is_file() or file_sha256(released_path) != (
            record or {}
        ).get("sha256"):
            errors.append(f"{audit_id}: released immutable input changed")
    if seal.get("release_manifest_sha256") != release.get(
        "release_manifest_sha256"
    ):
        errors.append(f"{audit_id}: audit seal is bound to another coverage release")
    try:
        current_sequence = int(seal.get("amendment_sequence") or 0)
    except (TypeError, ValueError):
        current_sequence = 0
        errors.append(f"{audit_id}: current amendment sequence is invalid")
    current_parent = str(seal.get("amendment_parent_seal_sha256") or "")
    if str(audit.get("amendment_parent_seal_sha256") or "") != current_parent:
        errors.append(f"{audit_id}: completed audit parent binding differs from its seal")
    errors.extend(
        _host_isolation_receipt_errors(
            seal.get("host_isolation_receipt") or {},
            str(bundle_manifest.get("bundle_manifest_sha256") or ""),
            f"{audit_id} sealed audit",
            amendment_parent_seal_sha256=(
                current_parent if current_sequence > 0 else None
            ),
        )
    )
    errors.extend(
        _audit_history_errors(
            package_dir,
            audit_id,
            seal,
            checkpoint_seal_sha256=str(current_checkpoint_seal or ""),
            release_manifest_sha256=str(
                release.get("release_manifest_sha256") or ""
            ),
            bundle_manifest_sha256=str(
                bundle_manifest.get("bundle_manifest_sha256") or ""
            ),
        )
    )
    if seal.get("validator_status") != "pass":
        errors.append(f"{audit_id}: audit validator did not pass")
    return errors


def sealed_audit_errors(package_dir: Path) -> list[str]:
    seal_root = package_dir / SEAL_DIRECTORY
    errors = [
        *_contained_child_errors(
            seal_root, package_dir, "audit-seal directory"
        ),
        *_contained_child_errors(
            seal_root / HISTORY_DIRECTORY,
            seal_root,
            "audit history directory",
        ),
    ]
    if errors:
        return errors
    context_ids = []
    receipt_ids = []
    for audit_id in AUDIT_IDS:
        errors.extend(_sealed_audit_record_errors(package_dir, audit_id))
        seal_path = package_dir / SEAL_DIRECTORY / f"{audit_id}.json"
        if not seal_path.is_file():
            continue
        seal = json.loads(seal_path.read_text(encoding="utf-8"))
        receipt = seal.get("host_isolation_receipt") or {}
        receipt_ids.append(str(receipt.get("receipt_id") or ""))
        context_ids.append(str(seal.get("independent_context_id") or ""))
    if len(context_ids) == 2 and len(set(context_ids)) != 2:
        errors.append("the two sealed audits reuse one reasoning context")
    if len(receipt_ids) == 2 and len(set(receipt_ids)) != 2:
        errors.append("the two sealed audits reuse one host isolation receipt")
    snapshot_root = seal_root / WORK_UNIT_SNAPSHOT_ROOT
    if snapshot_root.exists() and (
        _path_is_link_or_reparse(snapshot_root)
        or snapshot_root.resolve().parent != seal_root.resolve()
    ):
        errors.append("sealed work-unit snapshot root leaves the audit-seal directory")
    elif snapshot_root.is_dir():
        snapshot_children = list(snapshot_root.iterdir())
        if (
            any(_path_is_link_or_reparse(path) for path in snapshot_children)
            or any(path.is_file() for path in snapshot_children)
            or {
                path.name for path in snapshot_children if path.is_dir()
            }
            - set(AUDIT_IDS)
        ):
            errors.append("sealed work-unit snapshots contain orphan audit identities")
    errors.extend(workflow_reasoning_identity_errors(package_dir))
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    checkpoint = subparsers.add_parser("checkpoint")
    checkpoint.add_argument("package_dir", type=Path)
    checkpoint.add_argument("audit_id", choices=AUDIT_IDS)
    checkpoint.add_argument("--completed-checkpoint", type=Path)
    validate = subparsers.add_parser("validate")
    validate.add_argument("package_dir", type=Path)
    validate.add_argument("audit_id", choices=AUDIT_IDS)
    validate.add_argument("--audit", type=Path)
    validate.add_argument("--amendment-of")
    seal = subparsers.add_parser("seal")
    seal.add_argument("package_dir", type=Path)
    seal.add_argument("audit_id", choices=AUDIT_IDS)
    seal.add_argument("--completed-audit", type=Path)
    seal.add_argument("--amendment-of")
    args = parser.parse_args()
    try:
        if args.command == "checkpoint":
            result = checkpoint_audit(
                args.package_dir,
                args.audit_id,
                args.completed_checkpoint,
            )
        elif args.command == "validate":
            errors = validate_audit(
                args.package_dir,
                args.audit_id,
                args.audit,
                amendment_of=args.amendment_of,
            )
            result = {"status": "pass" if not errors else "blocked", "errors": errors}
        else:
            result = seal_audit(
                args.package_dir,
                args.audit_id,
                args.completed_audit,
                amendment_of=args.amendment_of,
            )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"status": "blocked", "errors": [str(exc)]}))
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result.get("status", "pass") == "pass" else 2


if __name__ == "__main__":
    raise SystemExit(main())
