#!/usr/bin/env python3
"""Prepare, checkpoint, validate, and seal the two clean-room GTM audits."""

from __future__ import annotations

import argparse
import json
import re
import shutil
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
    work_unit_completion_errors,
    work_unit_identity_hash,
)
from gtm_lib import as_list, file_sha256, stable_hash, write_json

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
            source_ledger = {
                **ledger,
                "obligations": [
                    row
                    for row in as_list(ledger.get("obligations"))
                    if row.get("obligation_id") in source_ids
                ],
                "release_sets": {"source_only": sorted(source_ids)},
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
    if receipt.get("status") != "enforced":
        errors.append("source checkpoint requires an enforced host isolation receipt")
    if len(str(receipt.get("receipt_id") or "").strip()) < 12:
        errors.append("host isolation receipt_id is missing or too weak")
    if receipt.get("mechanism") not in ISOLATION_MECHANISMS:
        errors.append("host isolation mechanism is unsupported or absent")
    if receipt.get("allowed_bundle_manifest_sha256") != bundle_manifest_sha256:
        errors.append("host isolation receipt is not bound to this audit bundle")
    if receipt.get("other_audit_accessible") is not False:
        errors.append("the other audit must be inaccessible in this execution scope")
    if receipt.get("prohibited_artifacts_accessible") is not False:
        errors.append("prohibited artifacts must be inaccessible in this execution scope")
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
    for other_id in AUDIT_IDS:
        if other_id == audit_id:
            continue
        other_seal_path = package_dir / BUNDLE_DIRECTORY / other_id / CHECKPOINT_SEAL_FILE
        if other_seal_path.is_file():
            other_seal = json.loads(other_seal_path.read_text(encoding="utf-8"))
            if other_seal.get("independent_context_id") == context_id:
                errors.append("the two audits cannot reuse one reasoning-context identity")
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


def validate_audit(
    package_dir: Path,
    audit_id: str,
    audit_path: Path | None = None,
) -> list[str]:
    if audit_id not in AUDIT_IDS:
        return [f"unsupported audit identity: {audit_id}"]
    bundle = package_dir / BUNDLE_DIRECTORY / audit_id
    audit_path = audit_path or bundle / AUDIT_FILE
    errors: list[str] = []
    _manifest, bundle_errors = _bundle_manifest_errors(bundle)
    errors.extend(bundle_errors)
    release_path = bundle / RELEASE_MANIFEST_FILE
    checkpoint_seal_path = bundle / CHECKPOINT_SEAL_FILE
    ledger_path = bundle / "obligation-ledger.json"
    if not release_path.is_file() or not checkpoint_seal_path.is_file():
        errors.append("source checkpoint must be sealed and coverage released first")
        return errors
    release = json.loads(release_path.read_text(encoding="utf-8"))
    if release.get("release_manifest_sha256") != _hash_without(release, "release_manifest_sha256"):
        errors.append("coverage release manifest hash is invalid")
    for record in as_list(release.get("released_files")):
        path = bundle / str(record.get("path") or "")
        if not path.is_file() or file_sha256(path) != record.get("sha256"):
            errors.append(f"released immutable input changed: {path.name}")
    work_unit_record = release.get("work_units") or {}
    work_unit_manifest_path = bundle / str(work_unit_record.get("manifest") or "")
    if not work_unit_manifest_path.is_file():
        errors.append("work-unit manifest is missing")
    else:
        work_unit_manifest = json.loads(work_unit_manifest_path.read_text(encoding="utf-8"))
        if work_unit_manifest.get("work_unit_manifest_sha256") != work_unit_record.get(
            "work_unit_manifest_sha256"
        ) or work_unit_manifest.get("work_unit_manifest_sha256") != work_unit_identity_hash(
            work_unit_manifest
        ):
            errors.append("work-unit manifest identity changed")
    if not audit_path.is_file() or not ledger_path.is_file():
        errors.append("completed audit or obligation ledger is missing")
        return errors
    audit = json.loads(audit_path.read_text(encoding="utf-8"))
    ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
    checkpoint_seal = json.loads(checkpoint_seal_path.read_text(encoding="utf-8"))
    if work_unit_manifest_path.is_file():
        errors.extend(work_unit_completion_errors(bundle, audit, work_unit_manifest))
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
        ("independent_context_id", checkpoint_seal.get("independent_context_id")),
        ("host_isolation_receipt", checkpoint_seal.get("host_isolation_receipt")),
        ("status", "complete"),
    )
    for field, expected in checks:
        if audit.get(field) != expected:
            errors.append(f"audit {field} differs from its locked contract")

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
    errors = validate_audit(package_dir, audit_id, audit_path)
    if errors:
        raise ValueError("audit validator failed: " + "; ".join(errors))
    audit = json.loads(audit_path.read_text(encoding="utf-8"))
    seal_dir = package_dir / SEAL_DIRECTORY
    seal_dir.mkdir(exist_ok=True)
    seal_path = seal_dir / f"{audit_id}.json"
    canonical_dir = package_dir / "audits"
    canonical_dir.mkdir(exist_ok=True)
    canonical_path = canonical_dir / f"{audit_id}.json"
    previous = json.loads(seal_path.read_text(encoding="utf-8")) if seal_path.is_file() else None
    if previous:
        if amendment_of != previous.get("audit_seal_sha256"):
            raise ValueError("audit is already sealed; amendment_of must match its current seal")
        if previous.get("independent_context_id") == audit.get("independent_context_id"):
            raise ValueError("an audit amendment requires a fresh reasoning context")
        history = seal_dir / HISTORY_DIRECTORY
        history.mkdir(exist_ok=True)
        previous_seal_hash = str(previous.get("audit_seal_sha256") or "")
        previous_audit_hash = str(previous.get("completed_audit_sha256") or "")
        shutil.copy2(seal_path, history / f"{audit_id}.{previous_seal_hash}.seal.json")
        shutil.copy2(
            canonical_path,
            history / f"{audit_id}.{previous_audit_hash}.audit.json",
        )
    elif amendment_of:
        raise ValueError("amendment_of was supplied but no prior audit seal exists")
    shutil.copy2(audit_path, canonical_path)
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
        "completed_audit_sha256": file_sha256(canonical_path),
        "independent_context_id": audit.get("independent_context_id"),
        "host_isolation_receipt": audit.get("host_isolation_receipt"),
        "validator_status": "pass",
        "amendment_sequence": (int(previous.get("amendment_sequence", 0)) + 1 if previous else 0),
        "amendment_parent_seal_sha256": (
            str(previous.get("audit_seal_sha256") or "") if previous else ""
        ),
    }
    seal["audit_seal_sha256"] = _hash_without(seal, "audit_seal_sha256")
    write_json(seal_path, seal)
    return seal


def sealed_audit_errors(package_dir: Path) -> list[str]:
    errors: list[str] = []
    context_ids = []
    receipt_ids = []
    for audit_id in AUDIT_IDS:
        seal_path = package_dir / SEAL_DIRECTORY / f"{audit_id}.json"
        audit_path = package_dir / "audits" / f"{audit_id}.json"
        if not seal_path.is_file() or not audit_path.is_file():
            errors.append(f"{audit_id}: sealed audit artifacts are missing")
            continue
        seal = json.loads(seal_path.read_text(encoding="utf-8"))
        if seal.get("audit_seal_sha256") != _hash_without(seal, "audit_seal_sha256"):
            errors.append(f"{audit_id}: audit seal content hash is invalid")
        if seal.get("completed_audit_sha256") != file_sha256(audit_path):
            errors.append(f"{audit_id}: completed audit changed after sealing")
        if seal.get("validator_status") != "pass":
            errors.append(f"{audit_id}: audit validator did not pass")
        receipt = seal.get("host_isolation_receipt") or {}
        if receipt.get("status") != "enforced":
            errors.append(f"{audit_id}: host isolation receipt is not enforced")
        receipt_ids.append(str(receipt.get("receipt_id") or ""))
        context_ids.append(str(seal.get("independent_context_id") or ""))
    if len(context_ids) == 2 and len(set(context_ids)) != 2:
        errors.append("the two sealed audits reuse one reasoning context")
    if len(receipt_ids) == 2 and len(set(receipt_ids)) != 2:
        errors.append("the two sealed audits reuse one host isolation receipt")
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
            errors = validate_audit(args.package_dir, args.audit_id, args.audit)
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
