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
from gtm_cleanroom_audit import operation_proposal_errors
from gtm_lib import (
    as_list,
    contained_relative_path,
    file_sha256,
    locked_evidence_coordinates,
    require_safe_package_root,
    stable_hash,
    write_json,
)
from gtm_reconciliation import (
    canonical_matches_allowed,
    comparison_classification,
    material_verification_reasons,
    neutral_bundle_manifest_sha256,
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
RETAINED_REVIEW_FILE = "retained-review.json"
PRIOR_CYCLE_DIRECTORY = "prior-cycle"

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


def projection_canonical_decision_id(
    cycle_number: int, comparison_id: str
) -> str:
    """Keep one canonical projection decision addressable in every cycle."""

    return f"PCD-C{cycle_number:02d}-" + comparison_id.removeprefix("PREC-")


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


def retained_projection_review(cycle_dir: Path, review_id: str) -> dict[str, Any] | None:
    """Reuse only exact unchanged obligations from this peer's sealed predecessor."""
    require_safe_package_root(cycle_dir.parents[1])
    state = json.loads((cycle_dir / "cycle-state.json").read_text(encoding="utf-8"))
    binding = state.get("scan_repair")
    prior = cycle_dir / PRIOR_CYCLE_DIRECTORY
    if binding is None and not prior.exists():
        return None
    if not isinstance(binding, dict) or not prior.is_dir():
        raise ValueError("scan repair predecessor binding or snapshot is missing")
    prior_state = json.loads((prior / "cycle-state.json").read_text(encoding="utf-8"))
    if prior_state.get("cycle_state_sha256") != _hash_without(prior_state, "cycle_state_sha256") or (
        binding.get("prior_cycle_state_sha256") != prior_state.get("cycle_state_sha256")
    ):
        raise ValueError("scan repair predecessor cycle binding is invalid")
    seal_path = prior / REVIEW_SEAL_ROOT / f"{review_id}.json"
    review_path = prior / REVIEW_SEAL_ROOT / f"{review_id}.review.json"
    seal = json.loads(seal_path.read_text(encoding="utf-8"))
    if (binding.get("prior_review_seal_sha256") or {}).get(review_id) != seal.get("review_seal_sha256"):
        raise ValueError("scan repair predecessor review binding is invalid")
    if seal.get("review_seal_sha256") != _hash_without(seal, "review_seal_sha256"):
        raise ValueError("retained projection review predecessor seal is invalid")
    if seal.get("completed_review_sha256") != file_sha256(review_path):
        raise ValueError("retained projection review predecessor changed")
    errors = validate_projection_review(prior, review_id, _review_path=review_path)
    if errors:
        raise ValueError("retained projection review predecessor failed: " + "; ".join(errors))
    before = json.loads((prior / "projection-obligations.json").read_text(encoding="utf-8"))
    after = json.loads((cycle_dir / "projection-obligations.json").read_text(encoding="utf-8"))
    if before.get("cycle_number") != after.get("cycle_number"):
        raise ValueError("scan repair must keep the owning projection cycle")
    if json.loads((prior / "projected-container.json").read_text(encoding="utf-8")) != json.loads(
        (cycle_dir / "projected-container.json").read_text(encoding="utf-8")
    ):
        raise ValueError("scan repair cannot change the projected container")
    old = {row["obligation_id"]: row for row in before["obligations"]}
    unchanged = {row["obligation_id"] for row in after["obligations"]
                 if row == old.get(row["obligation_id"])}
    review = json.loads(review_path.read_text(encoding="utf-8"))
    return {
        "kind": "gtm_retained_projection_review",
        "review_id": review_id,
        "prior_review_seal_sha256": seal["review_seal_sha256"],
        "prior_agent_id": review["independent_agent_id"],
        "prior_context_id": review["independent_context_id"],
        "decisions": [row for row in review["decisions"] if row["obligation_id"] in unchanged],
    }


def projection_repair_prior_identities(cycle_dir: Path) -> tuple[set[str], set[str]]:
    """A fresh amendment cannot reuse either prior peer or their reconciler."""
    require_safe_package_root(cycle_dir.parents[1])
    prior = cycle_dir / PRIOR_CYCLE_DIRECTORY
    if not prior.exists():
        return set(), set()
    paths = [prior / REVIEW_SEAL_ROOT / f"{review_id}.json" for review_id in REVIEW_IDS]
    reconciliation = prior / RECONCILIATION_FILE
    if reconciliation.is_file():
        paths.append(reconciliation)
    identities = [json.loads(path.read_text(encoding="utf-8")) for path in paths]
    return (
        {str(row["independent_agent_id"]) for row in identities if row.get("independent_agent_id")},
        {str(row["independent_context_id"]) for row in identities if row.get("independent_context_id")},
    )


def prepare_projection_reviews(
    cycle_dir: Path,
    cycle_number: int,
    delta_ledger: dict[str, Any],
) -> dict[str, Any]:
    require_safe_package_root(cycle_dir.parents[1])
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
            "independent_agent_id": "",
            "independent_context_id": "",
            "input_manifest_sha256": "",
            "decisions": [_scaffold_decision(review_id, cycle_number, row) for row in obligations],
            "completion_attestation": {
                "status": "pending",
                "foreign_projection_review_used": False,
                "fresh_context": False,
                "peer_findings_received_before_completion": None,
                "conclusion": "",
            },
        }
        retained = retained_projection_review(cycle_dir, review_id)
        if retained is not None:
            retained_path = bundle / RETAINED_REVIEW_FILE
            write_json(retained_path, retained)
            locked_files.append({
                "path": RETAINED_REVIEW_FILE,
                "sha256": file_sha256(retained_path), "mutable": False,
            })
            by_id = {row["obligation_id"]: row for row in retained["decisions"]}
            review["decisions"] = [by_id.get(row["obligation_id"], row)
                                   for row in review["decisions"]]
        manifest = {
            "kind": "gtm_projection_review_bundle_manifest",
            "schema_version": 1,
            "review_id": review_id,
            "cycle_number": cycle_number,
            "locked_files": locked_files,
            "mutable_output": REVIEW_FILE,
            "independence_contract": {
                "required": True,
                "boundary": (
                    "Use a fresh agent and context and withhold peer findings until both "
                    "projection reviews are complete. No operating-system access proof is required."
                ),
            },
        }
        manifest["bundle_manifest_sha256"] = _hash_without(manifest, "bundle_manifest_sha256")
        write_json(bundle / REVIEW_MANIFEST_FILE, manifest)
        review["input_manifest_sha256"] = manifest["bundle_manifest_sha256"]
        write_json(bundle / REVIEW_FILE, review)
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
        name = record.get("path")
        if not isinstance(name, str):
            errors.append("locked projection input path is invalid")
            continue
        allowed.add(name)
        try:
            target = contained_relative_path(
                bundle,
                name,
                "locked projection input path",
            )
        except ValueError as exc:
            errors.append(str(exc))
            continue
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


def validate_projection_review(
    cycle_dir: Path,
    review_id: str,
    *,
    _review_path: Path | None = None,
) -> list[str]:
    require_safe_package_root(cycle_dir.parents[1])
    if review_id not in REVIEW_IDS:
        return [f"unsupported projection review: {review_id}"]
    bundle = cycle_dir / REVIEW_ROOT / review_id
    errors = _manifest_errors(bundle)
    review_path = _review_path or bundle / REVIEW_FILE
    ledger_path = bundle / "projection-obligations.json"
    if not review_path.is_file() or not ledger_path.is_file():
        return [*errors, "projection review or obligation ledger is missing"]
    review = json.loads(review_path.read_text(encoding="utf-8"))
    ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
    manifest = json.loads((bundle / REVIEW_MANIFEST_FILE).read_text(encoding="utf-8"))
    try:
        retained = retained_projection_review(cycle_dir, review_id)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return [*errors, str(exc)]
    retained_path = bundle / RETAINED_REVIEW_FILE
    if retained is not None:
        if not retained_path.is_file() or json.loads(retained_path.read_text(encoding="utf-8")) != retained:
            errors.append("retained projection decisions differ from their sealed predecessor")
        actual = {row.get("obligation_id"): row for row in as_list(review.get("decisions"))
                  if isinstance(row, dict)}
        if any(actual.get(row["obligation_id"]) != row for row in retained["decisions"]):
            errors.append("unchanged retained projection decision was edited")
        prior_agents, prior_contexts = projection_repair_prior_identities(cycle_dir)
        if review.get("independent_agent_id") in prior_agents:
            errors.append("projection repair requires a fresh agent")
        if review.get("independent_context_id") in prior_contexts:
            errors.append("projection repair requires a fresh context")
    elif retained_path.exists():
        errors.append("retained projection decisions have no sealed predecessor")
    expected_review_fields = {
        "kind",
        "schema_version",
        "review_id",
        "cycle_number",
        "source_sha256",
        "canonical_scan_sha256",
        "scan_assurance_sha256",
        "projection_obligation_set_sha256",
        "review_method",
        "status",
        "independent_agent_id",
        "independent_context_id",
        "input_manifest_sha256",
        "decisions",
        "completion_attestation",
    }
    if set(review) != expected_review_fields:
        errors.append("projection review schema contains missing or undeclared fields")
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
    agent_id = str(review.get("independent_agent_id") or "").strip()
    context_id = str(review.get("independent_context_id") or "").strip()
    if not agent_id:
        errors.append("projection review independent agent identity is missing")
    if not context_id:
        errors.append("projection review independent context identity is missing")
    if review.get("input_manifest_sha256") != manifest.get("bundle_manifest_sha256"):
        errors.append("projection review is not bound to this review bundle")
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
        if set(decision) != set(
            _scaffold_decision(review_id, int(ledger.get("cycle_number") or 0), obligation)
        ):
            errors.append(f"{label}: schema contains missing or undeclared fields")
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
    if set(attestation) != {
        "status",
        "foreign_projection_review_used",
        "fresh_context",
        "peer_findings_received_before_completion",
        "conclusion",
    }:
        errors.append("projection review attestation schema changed")
    if attestation.get("status") != "complete":
        errors.append("projection review completion attestation is incomplete")
    if attestation.get("foreign_projection_review_used") is not False:
        errors.append("projection review used its peer before reconciliation")
    if attestation.get("fresh_context") is not True:
        errors.append("projection review did not attest a fresh context")
    if attestation.get("peer_findings_received_before_completion") is not False:
        errors.append("projection review must attest that peer findings were withheld")
    if len(str(attestation.get("conclusion") or "").split()) < 8:
        errors.append("projection review completion conclusion is incomplete")
    return errors


def seal_projection_review(package_dir: Path, cycle_number: int, review_id: str) -> dict[str, Any]:
    require_safe_package_root(package_dir)
    cycle_dir = package_dir / "fixed-point" / f"cycle-{cycle_number:02d}"
    errors = validate_projection_review(cycle_dir, review_id)
    if errors:
        raise ValueError("projection review gate failed: " + "; ".join(errors))
    source = cycle_dir / REVIEW_ROOT / review_id / REVIEW_FILE
    review = json.loads(source.read_text(encoding="utf-8"))
    agent_id = str(review.get("independent_agent_id") or "")
    context_id = str(review.get("independent_context_id") or "")
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
        "independent_agent_id": agent_id,
        "independent_context_id": context_id,
        "input_manifest_sha256": review.get("input_manifest_sha256"),
        "completed_review_sha256": file_sha256(canonical_path),
        "validator_status": "pass",
    }
    seal["review_seal_sha256"] = _hash_without(seal, "review_seal_sha256")
    write_json(seal_path, seal)
    return seal


def _sealed_review_errors(cycle_dir: Path) -> list[str]:
    require_safe_package_root(cycle_dir.parents[1])
    errors = []
    agents = []
    contexts = []
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
        errors.extend(
            validate_projection_review(
                cycle_dir, review_id, _review_path=review_path
            )
        )
        agents.append(str(seal.get("independent_agent_id") or ""))
        contexts.append(str(seal.get("independent_context_id") or ""))
    if len(agents) == 2 and len(set(agents)) != 2:
        errors.append("projection reviews reuse one agent")
    if len(contexts) == 2 and len(set(contexts)) != 2:
        errors.append("projection reviews reuse one reasoning context")
    return errors


def _projection_reconciliation_payloads(
    cycle_dir: Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Reconstruct the only valid projection scaffold from sealed reviews."""

    require_safe_package_root(cycle_dir.parents[1])
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
                    "From this projected-source evidence and contract, what "
                    "source-supported decision and narrowest safe target follow?"
                ),
                "neutral_evidence": obligation.get("evidence", {}),
                "allowed_evidence_citations": locked_evidence_coordinates(
                    obligation.get("source_coordinates"), obligation.get("evidence", {})
                ),
                "prohibited_context": (
                    "Do not decide by vote count, prior preference, expected fixed-point "
                    "outcome, or workbook wording; resolve evidence and criteria directly."
                ),
                "status": "pending",
                "canonical_decision": {},
                "evidence_citations": [],
                "verification_rationale": "",
            }
            neutral_row["neutral_bundle_manifest_sha256"] = (
                neutral_bundle_manifest_sha256(neutral_row)
            )
            neutral_rows.append(neutral_row)
    review_seal_sha256 = {
        review_id: json.loads(
            (cycle_dir / REVIEW_SEAL_ROOT / f"{review_id}.json").read_text(
                encoding="utf-8"
            )
        ).get("review_seal_sha256")
        for review_id in REVIEW_IDS
    }
    reconciliation_input_sha256 = stable_hash(
        {
            "cycle_number": ledger.get("cycle_number"),
            "projection_obligation_set_sha256": ledger.get(
                "projection_obligation_set_sha256"
            ),
            "review_seal_sha256": review_seal_sha256,
        },
        64,
    )
    reconciliation = {
        "kind": "gtm_projection_reconciliation",
        "schema_version": 1,
        "cycle_number": ledger.get("cycle_number"),
        "projection_obligation_set_sha256": ledger.get("projection_obligation_set_sha256"),
        "review_seal_sha256": review_seal_sha256,
        "independent_agent_id": "",
        "independent_context_id": "",
        "input_manifest_sha256": reconciliation_input_sha256,
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
    return reconciliation, neutral


def scaffold_projection_reconciliation(cycle_dir: Path) -> dict[str, Any]:
    reconciliation, neutral = _projection_reconciliation_payloads(cycle_dir)
    write_json(cycle_dir / RECONCILIATION_SCAFFOLD_FILE, reconciliation)
    write_json(cycle_dir / NEUTRAL_QUEUE_FILE, neutral)
    retained_count = _retain_completed_reconciliation(cycle_dir, reconciliation, neutral)
    write_json(cycle_dir / RECONCILIATION_FILE, reconciliation)
    write_json(cycle_dir / NEUTRAL_FILE, neutral)
    return {
        "status": "ready_for_projection_reconciliation",
        "comparisons": len(as_list(reconciliation.get("comparisons"))),
        "neutral_verifications": len(as_list(neutral.get("verifications"))),
        "retained_comparisons": retained_count,
    }


def _retain_completed_reconciliation(
    cycle_dir: Path, reconciliation: dict[str, Any], neutral: dict[str, Any]
) -> int:
    """Carry validated authored rows only when both reviews and evidence still match."""
    prior = cycle_dir / PRIOR_CYCLE_DIRECTORY
    paths = (prior / RECONCILIATION_FILE, prior / NEUTRAL_FILE)
    if not all(path.is_file() for path in paths):
        return 0
    previous, previous_neutral = [json.loads(path.read_text(encoding="utf-8")) for path in paths]
    old_comparisons = {row.get("comparison_id"): row for row in previous.get("comparisons", [])
                       if isinstance(row, dict)}
    old_neutral = {row.get("verification_id"): row for row in previous_neutral.get("verifications", [])
                   if isinstance(row, dict)}
    neutral_by_id = {row["verification_id"]: row for row in neutral["verifications"]}
    retained_count = 0
    mutable = {"status", "canonical_decision", "reconciliation_rationale"}
    for row in reconciliation["comparisons"]:
        old = old_comparisons.get(row["comparison_id"], {})
        if set(old) != set(row) or any(old[key] != row[key] for key in row.keys() - mutable):
            continue
        decision = old.get("canonical_decision")
        if (old.get("status") != "complete" or not isinstance(decision, dict)
                or semantic_contract_errors(decision, "retained reconciliation")
                or len(str(old.get("reconciliation_rationale") or "").split()) < 8
                or not canonical_matches_allowed(decision, list(row["review_decisions"].values()),
                                                 allow_neutral_rejection=row["neutral_verification_required"])):
            continue
        if (decision.get("decision_class") == "not_applicable") != (row.get("applicability") == "source_counted_zero"):
            continue
        if row["neutral_verification_required"]:
            expected_row = neutral_by_id[row["neutral_verification_id"]]
            authored = old_neutral.get(row["neutral_verification_id"])
            if not authored or authored.get("canonical_decision") != decision:
                continue
            expected = {**neutral, "verifications": [expected_row]}
            candidate = {**neutral, "status": "complete", "verifications": [authored]}
            if _neutral_errors(cycle_dir, candidate, expected):
                continue
            expected_row.update(authored)
        row.update({key: old[key] for key in mutable})
        retained_count += 1
    return retained_count


def _neutral_errors(
    cycle_dir: Path, neutral: dict[str, Any], expected: dict[str, Any]
) -> list[str]:
    errors = []
    if set(neutral) != set(expected):
        errors.append("projection neutral top-level schema differs from its queue")
    for field in set(expected) - {"status", "verifications"}:
        if neutral.get(field) != expected.get(field):
            errors.append(f"projection neutral locked field {field} changed")
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
    for verification_id, expected_row in expected_rows.items():
        row = supplied.get(verification_id)
        if not row:
            continue
        label = f"projection neutral verification {verification_id}"
        if set(row) != set(expected_row):
            errors.append(f"{label}: schema contains missing or undeclared fields")
        for field in (
            "verification_id",
            *LOCKED_DECISION_FIELDS,
            "verification_reasons",
            "neutral_question",
            "neutral_evidence",
            "allowed_evidence_citations",
            "prohibited_context",
            "neutral_bundle_manifest_sha256",
        ):
            if row.get(field) != expected_row.get(field):
                errors.append(f"{label}: locked field {field} changed")
        if row.get("status") != "complete":
            errors.append(f"{label}: status must be complete")
        expected_hash = str(expected_row.get("neutral_bundle_manifest_sha256") or "")
        if not expected_hash or expected_hash != neutral_bundle_manifest_sha256(
            expected_row
        ):
            errors.append(f"{label}: neutral bundle manifest hash is invalid")
        if row.get("neutral_bundle_manifest_sha256") != expected_hash:
            errors.append(f"{label}: neutral result is not bound to its released bundle")
        decision = row.get("canonical_decision")
        if not isinstance(decision, dict):
            errors.append(f"{label}: canonical decision is missing")
        else:
            errors.extend(semantic_contract_errors(decision, label))
        citations = {str(value) for value in as_list(row.get("evidence_citations"))}
        allowed = set(as_list(expected_row.get("allowed_evidence_citations")))
        if citations - allowed or (allowed and not citations):
            errors.append(f"{label}: citations are outside allowed projected evidence")
        if len(str(row.get("verification_rationale") or "").split()) < 8:
            errors.append(f"{label}: verification rationale is incomplete")
    return errors


def finalize_projection_reconciliation(
    cycle_dir: Path, *, _validate_only: bool = False
) -> dict[str, Any]:
    require_safe_package_root(cycle_dir.parents[1])
    scaffold_path = cycle_dir / RECONCILIATION_SCAFFOLD_FILE
    neutral_queue_path = cycle_dir / NEUTRAL_QUEUE_FILE
    if not scaffold_path.is_file() or not neutral_queue_path.is_file():
        raise ValueError("projection reconciliation must be scaffolded first")
    expected, expected_neutral = _projection_reconciliation_payloads(cycle_dir)
    stored_scaffold = json.loads(scaffold_path.read_text(encoding="utf-8"))
    stored_neutral = json.loads(neutral_queue_path.read_text(encoding="utf-8"))
    reconciliation = json.loads((cycle_dir / RECONCILIATION_FILE).read_text(encoding="utf-8"))
    neutral = json.loads((cycle_dir / NEUTRAL_FILE).read_text(encoding="utf-8"))
    errors: list[str] = []
    if stored_scaffold != expected:
        errors.append(
            "projection reconciliation scaffold differs from sealed-review reconstruction"
        )
    if stored_neutral != expected_neutral:
        errors.append(
            "projection neutral queue differs from sealed-review reconstruction"
        )
    if set(reconciliation) != set(expected):
        errors.append("projection reconciliation top-level schema differs from its scaffold")
    for field in set(expected) - {
        "status",
        "comparisons",
        "independent_agent_id",
        "independent_context_id",
    }:
        if reconciliation.get(field) != expected.get(field):
            errors.append(f"projection reconciliation locked field {field} changed")
    agent_id = str(reconciliation.get("independent_agent_id") or "").strip()
    context_id = str(reconciliation.get("independent_context_id") or "").strip()
    if not agent_id:
        errors.append("projection reconciliation requires an independent_agent_id")
    if not context_id:
        errors.append("projection reconciliation requires an independent_context_id")
    review_seals = [
        json.loads(
            (cycle_dir / REVIEW_SEAL_ROOT / f"{review_id}.json").read_text(
                encoding="utf-8"
            )
        )
        for review_id in REVIEW_IDS
    ]
    if agent_id and agent_id in {
        str(seal.get("independent_agent_id") or "") for seal in review_seals
    }:
        errors.append("projection reconciliation must use a distinct agent")
    if context_id and context_id in {
        str(seal.get("independent_context_id") or "") for seal in review_seals
    }:
        errors.append("projection reconciliation must use a distinct context")
    prior_agents, prior_contexts = projection_repair_prior_identities(cycle_dir)
    if agent_id in prior_agents or context_id in prior_contexts:
        errors.append("projection repair reconciliation requires a fresh agent and context")
    errors.extend(_neutral_errors(cycle_dir, neutral, expected_neutral))
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
        if set(row) != set(expected_row):
            errors.append(f"{label}: schema contains missing or undeclared fields")
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
                "canonical_decision_id": projection_canonical_decision_id(
                    int(expected.get("cycle_number") or 0), comparison_id
                ),
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
        "independent_agent_id": agent_id,
        "independent_context_id": context_id,
        "input_manifest_sha256": reconciliation.get("input_manifest_sha256"),
        "canonical_decisions": sorted(
            canonical_rows, key=lambda value: str(value["canonical_decision_id"])
        ),
    }
    closure["projection_closure_sha256"] = stable_hash(closure, 64)
    if _validate_only:
        return closure
    closure_path = cycle_dir / CLOSURE_FILE
    write_json(closure_path, closure)
    seal = {
        "kind": "gtm_projection_closure_seal",
        "schema_version": 1,
        "cycle_number": expected.get("cycle_number"),
        "review_seal_sha256": {
            review_id: json.loads(
                (cycle_dir / REVIEW_SEAL_ROOT / f"{review_id}.json").read_text(
                    encoding="utf-8"
                )
            ).get("review_seal_sha256")
            for review_id in REVIEW_IDS
        },
        "reconciliation_scaffold_sha256": expected.get(
            "reconciliation_scaffold_sha256"
        ),
        "neutral_queue_sha256": expected_neutral.get("neutral_queue_sha256"),
        "reconciliation_file_sha256": file_sha256(
            cycle_dir / RECONCILIATION_FILE
        ),
        "neutral_file_sha256": file_sha256(cycle_dir / NEUTRAL_FILE),
        "independent_agent_id": closure.get("independent_agent_id"),
        "independent_context_id": closure.get("independent_context_id"),
        "input_manifest_sha256": closure.get("input_manifest_sha256"),
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


def projection_closure_seal_errors(
    cycle_dir: Path,
) -> tuple[dict[str, Any], list[str]]:
    """Reconstruct one projection closure and its seal from review authority."""

    require_safe_package_root(cycle_dir.parents[1])
    closure_path = cycle_dir / CLOSURE_FILE
    seal_path = cycle_dir / CLOSURE_SEAL_FILE
    reconciliation_path = cycle_dir / RECONCILIATION_FILE
    neutral_path = cycle_dir / NEUTRAL_FILE
    required = (closure_path, seal_path, reconciliation_path, neutral_path)
    if not all(path.is_file() for path in required):
        return {}, ["sealed projection closure or its authority files are missing"]
    try:
        expected = finalize_projection_reconciliation(
            cycle_dir, _validate_only=True
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return {}, [f"projection closure reconstruction failed: {exc}"]
    closure = json.loads(closure_path.read_text(encoding="utf-8"))
    errors: list[str] = []
    if closure != expected:
        errors.append("projection closure differs from deterministic reconstruction")
    scaffold, neutral_queue = _projection_reconciliation_payloads(cycle_dir)
    expected_seal = {
        "kind": "gtm_projection_closure_seal",
        "schema_version": 1,
        "cycle_number": expected.get("cycle_number"),
        "review_seal_sha256": {
            review_id: json.loads(
                (cycle_dir / REVIEW_SEAL_ROOT / f"{review_id}.json").read_text(
                    encoding="utf-8"
                )
            ).get("review_seal_sha256")
            for review_id in REVIEW_IDS
        },
        "reconciliation_scaffold_sha256": scaffold.get(
            "reconciliation_scaffold_sha256"
        ),
        "neutral_queue_sha256": neutral_queue.get("neutral_queue_sha256"),
        "reconciliation_file_sha256": file_sha256(reconciliation_path),
        "neutral_file_sha256": file_sha256(neutral_path),
        "independent_agent_id": expected.get("independent_agent_id"),
        "independent_context_id": expected.get("independent_context_id"),
        "input_manifest_sha256": expected.get("input_manifest_sha256"),
        "projection_closure_sha256": expected.get("projection_closure_sha256"),
        "projection_closure_file_sha256": file_sha256(closure_path),
        "validator_status": "pass",
    }
    expected_seal["projection_closure_seal_sha256"] = _hash_without(
        expected_seal, "projection_closure_seal_sha256"
    )
    seal = json.loads(seal_path.read_text(encoding="utf-8"))
    if seal != expected_seal:
        errors.append("projection closure seal differs from reconstructed authority")
    return closure, errors


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
