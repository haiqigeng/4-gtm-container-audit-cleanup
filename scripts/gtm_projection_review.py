#!/usr/bin/env python3
"""Run focused dual clean-room review of fixed-point projection obligations."""

from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path
from typing import Any

from gtm_audit_contract import (
    ACTIONABLE_DECISION_CLASSES,
    MATERIAL_NEUTRAL_REVIEW_TRIGGERS,
    semantic_contract_errors,
)
from gtm_cleanroom_audit import ISOLATION_MECHANISMS, operation_proposal_errors
from gtm_lib import as_list, file_sha256, stable_hash, write_json
from gtm_reconciliation import (
    canonical_matches_allowed,
    comparison_classification,
    material_verification_reasons,
    neutral_bundle_manifest_sha256,
    neutral_isolation_errors,
)

REVIEW_IDS = ("review-a", "review-b")
REVIEW_ROOT = "reviews"
REVIEW_FILE = "review.json"
REVIEW_MANIFEST_FILE = "bundle-manifest.json"
REVIEW_SEAL_ROOT = "review-seals"
RECONCILIATION_SCAFFOLD_FILE = "projection-reconciliation-scaffold.json"
RECONCILIATION_FILE = "projection-reconciliation.json"
NEUTRAL_QUEUE_FILE = "projection-neutral-queue.json"
NEUTRAL_FILE = "projection-neutral-verification.json"
CLOSURE_FILE = "projection-closure.json"
CLOSURE_SEAL_FILE = "projection-closure-seal.json"

LOCKED_DECISION_FIELDS = (
    "obligation_id",
    "obligation_sha256",
    "area_id",
    "scope_level",
    "audit_mechanism",
    "fact_kind",
    "subject_keys",
    "family_ids",
    "candidate_id",
    "source_coordinates",
    "applicability",
    "material_verification_triggers",
    "semantic_repair_records",
    "projection_delta_class",
)


def _hash_without(payload: dict[str, Any], *fields: str) -> str:
    return stable_hash(
        {key: value for key, value in payload.items() if key not in set(fields)},
        64,
    )


def _scaffold_decision(
    review_id: str, cycle_number: int, obligation: dict[str, Any]
) -> dict[str, Any]:
    return {
        "decision_id": (
            f"PCR-{review_id[-1].upper()}-C{cycle_number:02d}-{obligation['obligation_id']}"
        ),
        **{field: obligation.get(field) for field in LOCKED_DECISION_FIELDS},
        "status": "pending",
        "decision_class": "",
        "current_behavior": "",
        "criteria_assessment": "",
        "consequence_or_benefit": "",
        "preserved_distinctions": "",
        "target_direction": "",
        "evidence_boundary": "",
        "owner_question": "",
        "next_step": "",
        "priority": "",
        "confidence": "",
        "static_verification": "",
        "rollback": "",
        "evidence_citations": [],
        "operation_proposal": None,
    }


def prepare_projection_reviews(
    cycle_dir: Path,
    cycle_number: int,
    delta_ledger: dict[str, Any],
) -> dict[str, Any]:
    root = cycle_dir / REVIEW_ROOT
    if root.exists():
        raise ValueError("projection review bundles already exist for this cycle")
    obligations = [row for row in as_list(delta_ledger.get("obligations")) if isinstance(row, dict)]
    if not obligations:
        return {"status": "not_required", "reviews": 0, "obligations": 0}
    locked_names = (
        "projected-container.json",
        "canonical-scan.json",
        "scan-assurance.json",
        "projection-obligations.json",
        "cycle-state.json",
    )
    root.mkdir(parents=True)
    results = {}
    for review_id in REVIEW_IDS:
        bundle = root / review_id
        bundle.mkdir()
        locked_files = []
        for name in locked_names:
            source = cycle_dir / name
            if not source.is_file():
                raise ValueError(f"projection review input is missing: {name}")
            target = bundle / name
            shutil.copy2(source, target)
            locked_files.append({"path": name, "sha256": file_sha256(target), "mutable": False})
        review = {
            "kind": "gtm_projection_cleanroom_review",
            "schema_version": 1,
            "review_id": review_id,
            "cycle_number": cycle_number,
            "source_sha256": delta_ledger.get("source_sha256"),
            "canonical_scan_sha256": delta_ledger.get("canonical_scan_sha256"),
            "scan_assurance_sha256": delta_ledger.get("scan_assurance_sha256"),
            "projection_obligation_set_sha256": delta_ledger.get(
                "projection_obligation_set_sha256"
            ),
            "review_method": (
                "projected_evidence_first" if review_id == "review-a" else "projected_target_first"
            ),
            "status": "pending",
            "independent_context_id": "",
            "host_isolation_receipt": {
                "status": "pending",
                "receipt_id": "",
                "mechanism": "",
                "allowed_bundle_manifest_sha256": "",
                "peer_review_accessible": None,
                "prohibited_artifacts_accessible": None,
            },
            "decisions": [_scaffold_decision(review_id, cycle_number, row) for row in obligations],
            "completion_attestation": {
                "status": "pending",
                "foreign_projection_review_used": False,
                "fresh_context": False,
                "host_scope_preserved_through_completion": None,
                "conclusion": "",
            },
        }
        write_json(bundle / REVIEW_FILE, review)
        manifest = {
            "kind": "gtm_projection_review_bundle_manifest",
            "schema_version": 1,
            "review_id": review_id,
            "cycle_number": cycle_number,
            "locked_files": locked_files,
            "mutable_output": REVIEW_FILE,
            "isolation_contract": {
                "required": True,
                "accepted_host_mechanisms": sorted(ISOLATION_MECHANISMS),
                "boundary": (
                    "The host must make the peer review and prohibited downstream "
                    "artifacts inaccessible. The validator proves receipt consistency, "
                    "not access control by itself."
                ),
            },
        }
        manifest["bundle_manifest_sha256"] = _hash_without(manifest, "bundle_manifest_sha256")
        write_json(bundle / REVIEW_MANIFEST_FILE, manifest)
        results[review_id] = {
            "bundle": f"{REVIEW_ROOT}/{review_id}",
            "bundle_manifest_sha256": manifest["bundle_manifest_sha256"],
        }
    return {
        "status": "ready_for_projection_reviews",
        "reviews": 2,
        "obligations": len(obligations),
        "bundles": results,
    }


def _manifest_errors(bundle: Path) -> list[str]:
    path = bundle / REVIEW_MANIFEST_FILE
    if not path.is_file():
        return ["projection review bundle manifest is missing"]
    manifest = json.loads(path.read_text(encoding="utf-8"))
    errors = []
    if manifest.get("bundle_manifest_sha256") != _hash_without(manifest, "bundle_manifest_sha256"):
        errors.append("projection review bundle manifest hash is invalid")
    allowed = {REVIEW_FILE, REVIEW_MANIFEST_FILE}
    for record in as_list(manifest.get("locked_files")):
        name = str(record.get("path") or "")
        allowed.add(name)
        target = bundle / name
        if not target.is_file():
            errors.append(f"locked projection input is missing: {name}")
        elif file_sha256(target) != record.get("sha256"):
            errors.append(f"locked projection input changed: {name}")
    unexpected = sorted(
        path.name for path in bundle.iterdir() if path.is_file() and path.name not in allowed
    )
    if unexpected:
        errors.append("projection review bundle has undeclared files: " + ", ".join(unexpected))
    return errors


def validate_projection_review(cycle_dir: Path, review_id: str) -> list[str]:
    if review_id not in REVIEW_IDS:
        return [f"unsupported projection review: {review_id}"]
    bundle = cycle_dir / REVIEW_ROOT / review_id
    errors = _manifest_errors(bundle)
    review_path = bundle / REVIEW_FILE
    ledger_path = bundle / "projection-obligations.json"
    if not review_path.is_file() or not ledger_path.is_file():
        return [*errors, "projection review or obligation ledger is missing"]
    review = json.loads(review_path.read_text(encoding="utf-8"))
    ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
    manifest = json.loads((bundle / REVIEW_MANIFEST_FILE).read_text(encoding="utf-8"))
    checks = (
        ("kind", "gtm_projection_cleanroom_review"),
        ("schema_version", 1),
        ("review_id", review_id),
        ("cycle_number", ledger.get("cycle_number")),
        ("source_sha256", ledger.get("source_sha256")),
        ("canonical_scan_sha256", ledger.get("canonical_scan_sha256")),
        ("scan_assurance_sha256", ledger.get("scan_assurance_sha256")),
        (
            "projection_obligation_set_sha256",
            ledger.get("projection_obligation_set_sha256"),
        ),
        ("status", "complete"),
    )
    for field, expected in checks:
        if review.get(field) != expected:
            errors.append(f"projection review {field} differs from its lock")
    context_id = str(review.get("independent_context_id") or "")
    if len(context_id) < 12:
        errors.append("projection review independent context identity is missing")
    receipt = review.get("host_isolation_receipt") or {}
    if receipt.get("status") != "enforced":
        errors.append("projection review requires an enforced host isolation receipt")
    if len(str(receipt.get("receipt_id") or "").strip()) < 12:
        errors.append("projection host isolation receipt_id is missing or too weak")
    if receipt.get("mechanism") not in ISOLATION_MECHANISMS:
        errors.append("projection host isolation mechanism is unsupported or absent")
    if receipt.get("allowed_bundle_manifest_sha256") != manifest.get("bundle_manifest_sha256"):
        errors.append("projection host receipt is not bound to this review bundle")
    if receipt.get("peer_review_accessible") is not False:
        errors.append("the peer projection review must be inaccessible")
    if receipt.get("prohibited_artifacts_accessible") is not False:
        errors.append("prohibited projection artifacts must be inaccessible")
    obligations = {
        str(row.get("obligation_id") or ""): row
        for row in as_list(ledger.get("obligations"))
        if isinstance(row, dict)
    }
    rows = [row for row in as_list(review.get("decisions")) if isinstance(row, dict)]
    decisions = {str(row.get("obligation_id") or ""): row for row in rows}
    if len(decisions) != len(rows) or set(decisions) != set(obligations):
        errors.append("projection review must cover every released obligation exactly once")
    operation_ids: set[str] = set()
    for obligation_id, obligation in obligations.items():
        decision = decisions.get(obligation_id)
        if not decision:
            continue
        label = f"projection decision {decision.get('decision_id') or obligation_id}"
        expected_id = (
            f"PCR-{review_id[-1].upper()}-C{int(ledger.get('cycle_number') or 0):02d}-"
            f"{obligation_id}"
        )
        if decision.get("decision_id") != expected_id:
            errors.append(f"{label}: decision identity changed")
        for field in LOCKED_DECISION_FIELDS:
            if decision.get(field) != obligation.get(field):
                errors.append(f"{label}: locked field {field} changed")
        if decision.get("status") != "complete":
            errors.append(f"{label}: status must be complete")
        errors.extend(semantic_contract_errors(decision, label))
        citations = {str(value) for value in as_list(decision.get("evidence_citations"))}
        allowed = set(as_list(obligation.get("source_coordinates")))
        if allowed and (not citations or citations - allowed):
            errors.append(f"{label}: citations must use projected-source coordinates")
        proposal = decision.get("operation_proposal")
        if decision.get("decision_class") in ACTIONABLE_DECISION_CLASSES:
            if not isinstance(proposal, dict):
                errors.append(f"{label}: exact operation proposal is missing")
            else:
                errors.extend(operation_proposal_errors(proposal, decision, operation_ids, label))
        elif proposal:
            errors.append(f"{label}: non-actionable decision cannot carry an operation")
    attestation = review.get("completion_attestation") or {}
    if attestation.get("status") != "complete":
        errors.append("projection review completion attestation is incomplete")
    if attestation.get("foreign_projection_review_used") is not False:
        errors.append("projection review used its peer before reconciliation")
    if attestation.get("fresh_context") is not True:
        errors.append("projection review did not attest a fresh context")
    if attestation.get("host_scope_preserved_through_completion") is not True:
        errors.append("projection review did not preserve its enforced host scope")
    if len(str(attestation.get("conclusion") or "").split()) < 8:
        errors.append("projection review completion conclusion is incomplete")
    return errors


def _all_prior_context_ids(package_dir: Path) -> set[str]:
    contexts: set[str] = set()
    for path in (package_dir / "audit-seals").glob("*.json"):
        data = json.loads(path.read_text(encoding="utf-8"))
        contexts.add(str(data.get("independent_context_id") or ""))
    for path in (package_dir / "fixed-point").glob("cycle-*/review-seals/*.json"):
        data = json.loads(path.read_text(encoding="utf-8"))
        contexts.add(str(data.get("independent_context_id") or ""))
    contexts.discard("")
    return contexts


def seal_projection_review(package_dir: Path, cycle_number: int, review_id: str) -> dict[str, Any]:
    cycle_dir = package_dir / "fixed-point" / f"cycle-{cycle_number:02d}"
    errors = validate_projection_review(cycle_dir, review_id)
    if errors:
        raise ValueError("projection review gate failed: " + "; ".join(errors))
    source = cycle_dir / REVIEW_ROOT / review_id / REVIEW_FILE
    review = json.loads(source.read_text(encoding="utf-8"))
    context_id = str(review.get("independent_context_id") or "")
    if context_id in _all_prior_context_ids(package_dir):
        raise ValueError("projection review context identity was already used")
    seals = cycle_dir / REVIEW_SEAL_ROOT
    seals.mkdir(exist_ok=True)
    seal_path = seals / f"{review_id}.json"
    canonical_path = seals / f"{review_id}.review.json"
    if seal_path.exists():
        raise ValueError("projection review is already sealed")
    shutil.copy2(source, canonical_path)
    seal = {
        "kind": "gtm_projection_review_seal",
        "schema_version": 1,
        "review_id": review_id,
        "cycle_number": cycle_number,
        "independent_context_id": context_id,
        "host_isolation_receipt": review.get("host_isolation_receipt"),
        "completed_review_sha256": file_sha256(canonical_path),
        "validator_status": "pass",
    }
    seal["review_seal_sha256"] = _hash_without(seal, "review_seal_sha256")
    write_json(seal_path, seal)
    return seal


def _sealed_review_errors(cycle_dir: Path) -> list[str]:
    errors = []
    contexts = []
    receipt_ids = []
    for review_id in REVIEW_IDS:
        root = cycle_dir / REVIEW_SEAL_ROOT
        seal_path = root / f"{review_id}.json"
        review_path = root / f"{review_id}.review.json"
        if not seal_path.is_file() or not review_path.is_file():
            errors.append(f"{review_id}: sealed projection review is missing")
            continue
        seal = json.loads(seal_path.read_text(encoding="utf-8"))
        if seal.get("review_seal_sha256") != _hash_without(seal, "review_seal_sha256"):
            errors.append(f"{review_id}: seal hash is invalid")
        if seal.get("completed_review_sha256") != file_sha256(review_path):
            errors.append(f"{review_id}: sealed review changed")
        contexts.append(str(seal.get("independent_context_id") or ""))
        receipt_ids.append(str((seal.get("host_isolation_receipt") or {}).get("receipt_id") or ""))
    if len(contexts) == 2 and len(set(contexts)) != 2:
        errors.append("projection reviews reuse one reasoning context")
    if len(receipt_ids) == 2 and len(set(receipt_ids)) != 2:
        errors.append("projection reviews reuse one host isolation receipt")
    return errors


def scaffold_projection_reconciliation(cycle_dir: Path) -> dict[str, Any]:
    errors = _sealed_review_errors(cycle_dir)
    if errors:
        raise ValueError("projection review seals failed: " + "; ".join(errors))
    ledger = json.loads((cycle_dir / "projection-obligations.json").read_text(encoding="utf-8"))
    reviews = {
        review_id: json.loads(
            (cycle_dir / REVIEW_SEAL_ROOT / f"{review_id}.review.json").read_text(encoding="utf-8")
        )
        for review_id in REVIEW_IDS
    }
    decisions = {
        review_id: {
            str(row.get("obligation_id") or ""): row
            for row in as_list(reviews[review_id].get("decisions"))
        }
        for review_id in REVIEW_IDS
    }
    comparisons = []
    neutral_rows = []
    for obligation in as_list(ledger.get("obligations")):
        obligation_id = str(obligation.get("obligation_id") or "")
        left = decisions["review-a"][obligation_id]
        right = decisions["review-b"][obligation_id]
        classification = comparison_classification(left, right)
        reasons = material_verification_reasons(obligation, left, right, classification)
        reasons = sorted(
            set(reasons) & set(MATERIAL_NEUTRAL_REVIEW_TRIGGERS)
            | (
                {classification}
                if classification not in {"agreement", "compatible_complementary_conclusions"}
                else set()
            )
        )
        verification_id = (
            "PNV-"
            + stable_hash(
                {
                    "cycle": ledger.get("cycle_number"),
                    "obligation_id": obligation_id,
                    "classification": classification,
                    "reasons": reasons,
                },
                16,
            ).upper()
        )
        row = {
            "comparison_id": "PREC-" + stable_hash(obligation_id, 16).upper(),
            **{field: obligation.get(field) for field in LOCKED_DECISION_FIELDS},
            "classification": classification,
            "review_decisions": {"review-a": left, "review-b": right},
            "neutral_verification_required": bool(reasons),
            "neutral_verification_id": verification_id if reasons else "",
            "neutral_verification_reasons": reasons,
            "status": "pending",
            "canonical_decision": {},
            "reconciliation_rationale": "",
        }
        comparisons.append(row)
        if reasons:
            neutral_row = {
                "verification_id": verification_id,
                **{field: obligation.get(field) for field in LOCKED_DECISION_FIELDS},
                "verification_reasons": reasons,
                "neutral_question": (
                    "From this projected-source evidence and contract only, what "
                    "source-supported decision and narrowest safe target follow?"
                ),
                "neutral_evidence": obligation.get("evidence", {}),
                "prohibited_context": (
                    "Do not expose source-audit, prior-cycle, peer-review, peer-neutral, "
                    "reconciliation, fixed-point, or workbook conclusions."
                ),
                "status": "pending",
                "independent_context_id": "",
                "host_isolation_receipt": {
                    "status": "pending",
                    "receipt_id": "",
                    "mechanism": "",
                    "allowed_bundle_manifest_sha256": "",
                    "prior_reasoning_contexts_accessible": None,
                    "peer_neutral_contexts_accessible": None,
                    "prohibited_artifacts_accessible": None,
                },
                "canonical_decision": {},
                "evidence_citations": [],
                "verification_rationale": "",
            }
            neutral_row["neutral_bundle_manifest_sha256"] = (
                neutral_bundle_manifest_sha256(neutral_row)
            )
            neutral_rows.append(neutral_row)
    reconciliation = {
        "kind": "gtm_projection_reconciliation",
        "schema_version": 1,
        "cycle_number": ledger.get("cycle_number"),
        "projection_obligation_set_sha256": ledger.get("projection_obligation_set_sha256"),
        "status": "pending",
        "comparisons": comparisons,
    }
    neutral = {
        "kind": "gtm_projection_neutral_verification",
        "schema_version": 1,
        "cycle_number": ledger.get("cycle_number"),
        "status": "pending" if neutral_rows else "not_required",
        "verifications": neutral_rows,
    }
    reconciliation["reconciliation_scaffold_sha256"] = stable_hash(reconciliation, 64)
    neutral["neutral_queue_sha256"] = stable_hash(neutral, 64)
    write_json(cycle_dir / RECONCILIATION_SCAFFOLD_FILE, reconciliation)
    write_json(cycle_dir / RECONCILIATION_FILE, reconciliation)
    write_json(cycle_dir / NEUTRAL_QUEUE_FILE, neutral)
    write_json(cycle_dir / NEUTRAL_FILE, neutral)
    return {
        "status": "ready_for_projection_reconciliation",
        "comparisons": len(comparisons),
        "neutral_verifications": len(neutral_rows),
    }


def _prior_reasoning_identities(cycle_dir: Path) -> tuple[set[str], set[str]]:
    package_dir = cycle_dir.parents[1]
    contexts: set[str] = set()
    receipts: set[str] = set()

    def add_record(data: dict[str, Any]) -> None:
        context_id = str(data.get("independent_context_id") or "").strip()
        receipt_id = str(
            (data.get("host_isolation_receipt") or {}).get("receipt_id") or ""
        ).strip()
        if context_id:
            contexts.add(context_id)
        if receipt_id:
            receipts.add(receipt_id)

    paths = [
        *(package_dir / "audit-seals").glob("**/*.json"),
        *(package_dir / "audit-bundles").glob("*/source-checkpoint-seal.json"),
        *(cycle_dir / REVIEW_SEAL_ROOT).glob("review-?.json"),
    ]
    for path in paths:
        add_record(json.loads(path.read_text(encoding="utf-8")))

    base_neutral = package_dir / "neutral-verification.json"
    if base_neutral.is_file():
        data = json.loads(base_neutral.read_text(encoding="utf-8"))
        for row in as_list(data.get("verifications")):
            if isinstance(row, dict):
                add_record(row)

    current_cycle = int(cycle_dir.name.removeprefix("cycle-") or 0)
    for path in (package_dir / "fixed-point").glob(
        "cycle-*/projection-neutral-verification.json"
    ):
        prior_cycle = int(path.parent.name.removeprefix("cycle-") or 0)
        if prior_cycle >= current_cycle:
            continue
        data = json.loads(path.read_text(encoding="utf-8"))
        for row in as_list(data.get("verifications")):
            if isinstance(row, dict):
                add_record(row)
    return contexts, receipts


def _neutral_errors(
    cycle_dir: Path, neutral: dict[str, Any], expected: dict[str, Any]
) -> list[str]:
    errors = []
    expected_rows = {
        str(row.get("verification_id") or ""): row for row in as_list(expected.get("verifications"))
    }
    supplied_rows = [row for row in as_list(neutral.get("verifications")) if isinstance(row, dict)]
    supplied = {str(row.get("verification_id") or ""): row for row in supplied_rows}
    if len(supplied) != len(supplied_rows) or set(supplied) != set(expected_rows):
        errors.append("projection neutral verification set differs from its queue")
    expected_status = "complete" if expected_rows else "not_required"
    if neutral.get("status") != expected_status:
        errors.append(f"projection neutral status must be {expected_status}")
    contexts, receipts = _prior_reasoning_identities(cycle_dir)
    for verification_id, expected_row in expected_rows.items():
        row = supplied.get(verification_id)
        if not row:
            continue
        label = f"projection neutral verification {verification_id}"
        for field in (
            "verification_id",
            *LOCKED_DECISION_FIELDS,
            "verification_reasons",
            "neutral_question",
            "neutral_evidence",
            "prohibited_context",
            "neutral_bundle_manifest_sha256",
        ):
            if row.get(field) != expected_row.get(field):
                errors.append(f"{label}: locked field {field} changed")
        if row.get("status") != "complete":
            errors.append(f"{label}: status must be complete")
        errors.extend(
            neutral_isolation_errors(
                row, expected_row, label, contexts, receipts
            )
        )
        decision = row.get("canonical_decision")
        if not isinstance(decision, dict):
            errors.append(f"{label}: canonical decision is missing")
        else:
            errors.extend(semantic_contract_errors(decision, label))
        citations = {str(value) for value in as_list(row.get("evidence_citations"))}
        allowed = set(as_list(expected_row.get("source_coordinates")))
        if allowed and (not citations or citations - allowed):
            errors.append(f"{label}: citations are outside projected evidence")
        if len(str(row.get("verification_rationale") or "").split()) < 8:
            errors.append(f"{label}: verification rationale is incomplete")
    return errors


def finalize_projection_reconciliation(cycle_dir: Path) -> dict[str, Any]:
    scaffold_path = cycle_dir / RECONCILIATION_SCAFFOLD_FILE
    neutral_queue_path = cycle_dir / NEUTRAL_QUEUE_FILE
    if not scaffold_path.is_file() or not neutral_queue_path.is_file():
        raise ValueError("projection reconciliation must be scaffolded first")
    expected = json.loads(scaffold_path.read_text(encoding="utf-8"))
    expected_neutral = json.loads(neutral_queue_path.read_text(encoding="utf-8"))
    reconciliation = json.loads((cycle_dir / RECONCILIATION_FILE).read_text(encoding="utf-8"))
    neutral = json.loads((cycle_dir / NEUTRAL_FILE).read_text(encoding="utf-8"))
    errors = _neutral_errors(cycle_dir, neutral, expected_neutral)
    expected_rows = {
        str(row.get("comparison_id") or ""): row for row in as_list(expected.get("comparisons"))
    }
    supplied_rows = [
        row for row in as_list(reconciliation.get("comparisons")) if isinstance(row, dict)
    ]
    supplied = {str(row.get("comparison_id") or ""): row for row in supplied_rows}
    if len(supplied) != len(supplied_rows) or set(supplied) != set(expected_rows):
        errors.append("projection reconciliation comparison set changed")
    neutral_by_id = {
        str(row.get("verification_id") or ""): row for row in as_list(neutral.get("verifications"))
    }
    canonical_rows = []
    for comparison_id, expected_row in expected_rows.items():
        row = supplied.get(comparison_id)
        if not row:
            continue
        label = f"projection reconciliation {comparison_id}"
        for field in (
            "comparison_id",
            *LOCKED_DECISION_FIELDS,
            "classification",
            "review_decisions",
            "neutral_verification_required",
            "neutral_verification_id",
            "neutral_verification_reasons",
        ):
            if row.get(field) != expected_row.get(field):
                errors.append(f"{label}: locked field {field} changed")
        if row.get("status") != "complete":
            errors.append(f"{label}: status must be complete")
        canonical = row.get("canonical_decision")
        if not isinstance(canonical, dict):
            errors.append(f"{label}: canonical decision is missing")
            continue
        errors.extend(semantic_contract_errors(canonical, label))
        if row.get("applicability") == "source_counted_zero":
            if canonical.get("decision_class") != "not_applicable":
                errors.append(f"{label}: source-counted zero must be Not applicable")
        elif canonical.get("decision_class") == "not_applicable":
            errors.append(f"{label}: applicable obligation cannot be Not applicable")
        source_decisions = [
            value
            for value in (row.get("review_decisions") or {}).values()
            if isinstance(value, dict)
        ]
        if row.get("neutral_verification_required"):
            verification = neutral_by_id.get(str(row.get("neutral_verification_id") or ""))
            if not verification or canonical != verification.get("canonical_decision"):
                errors.append(f"{label}: canonical decision differs from neutral result")
        if not canonical_matches_allowed(
            canonical,
            source_decisions,
            allow_neutral_rejection=bool(row.get("neutral_verification_required")),
        ):
            errors.append(f"{label}: canonical target was not proposed by either review")
        if len(str(row.get("reconciliation_rationale") or "").split()) < 8:
            errors.append(f"{label}: reconciliation rationale is incomplete")
        canonical_rows.append(
            {
                "canonical_decision_id": "PCD-" + comparison_id.removeprefix("PREC-"),
                **{field: row.get(field) for field in LOCKED_DECISION_FIELDS},
                "reconciliation_class": row.get("classification"),
                "neutral_verification_id": row.get("neutral_verification_id"),
                "decision": canonical,
                "owning_reviews": list(REVIEW_IDS),
                "reconciliation_rationale": row.get("reconciliation_rationale"),
            }
        )
    if errors:
        raise ValueError("projection reconciliation gate failed: " + "; ".join(errors))
    closure = {
        "kind": "gtm_projection_semantic_closure",
        "schema_version": 1,
        "cycle_number": expected.get("cycle_number"),
        "projection_obligation_set_sha256": expected.get("projection_obligation_set_sha256"),
        "canonical_decisions": sorted(
            canonical_rows, key=lambda value: str(value["canonical_decision_id"])
        ),
    }
    closure["projection_closure_sha256"] = stable_hash(closure, 64)
    closure_path = cycle_dir / CLOSURE_FILE
    write_json(closure_path, closure)
    seal = {
        "kind": "gtm_projection_closure_seal",
        "schema_version": 1,
        "cycle_number": expected.get("cycle_number"),
        "projection_closure_sha256": closure["projection_closure_sha256"],
        "projection_closure_file_sha256": file_sha256(closure_path),
        "validator_status": "pass",
    }
    seal["projection_closure_seal_sha256"] = _hash_without(seal, "projection_closure_seal_sha256")
    write_json(cycle_dir / CLOSURE_SEAL_FILE, seal)
    return {
        "status": "pass",
        "canonical_decisions": len(canonical_rows),
        "actionable_decisions": sum(
            row["decision"].get("decision_class") in ACTIONABLE_DECISION_CLASSES
            for row in canonical_rows
        ),
        "projection_closure_sha256": closure["projection_closure_sha256"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    seal = subparsers.add_parser("seal-review")
    seal.add_argument("package_dir", type=Path)
    seal.add_argument("cycle", type=int)
    seal.add_argument("review_id", choices=REVIEW_IDS)
    reconcile = subparsers.add_parser("scaffold-reconciliation")
    reconcile.add_argument("package_dir", type=Path)
    reconcile.add_argument("cycle", type=int)
    finalize = subparsers.add_parser("finalize")
    finalize.add_argument("package_dir", type=Path)
    finalize.add_argument("cycle", type=int)
    args = parser.parse_args()
    try:
        cycle_dir = args.package_dir / "fixed-point" / f"cycle-{args.cycle:02d}"
        if args.command == "seal-review":
            result = seal_projection_review(args.package_dir, args.cycle, args.review_id)
        elif args.command == "scaffold-reconciliation":
            result = scaffold_projection_reconciliation(cycle_dir)
        else:
            result = finalize_projection_reconciliation(cycle_dir)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"status": "blocked", "errors": [str(exc)]}))
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
