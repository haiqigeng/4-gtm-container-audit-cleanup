#!/usr/bin/env python3
"""Reconcile two sealed clean-room GTM audits with neutral verification."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

from gtm_audit_contract import (
    ACTIONABLE_DECISION_CLASSES,
    CANONICAL_DECISION_FIELDS,
    OPERATION_ACTION_FIELDS,
    semantic_contract_errors,
)
from gtm_cleanroom_audit import AUDIT_IDS, sealed_audit_errors
from gtm_lib import (
    as_list,
    file_sha256,
    locked_evidence_coordinates,
    require_safe_package_root,
    stable_hash,
    write_json,
)

RECONCILIATION_FILE = "reconciliation.json"
NEUTRAL_FILE = "neutral-verification.json"
RECONCILIATION_SCAFFOLD_FILE = "reconciliation-scaffold.json"
NEUTRAL_QUEUE_FILE = "neutral-verification-queue.json"
RECONCILED_RECORD_FILE = "reconciled-decisions.json"
RECONCILIATION_SEAL_FILE = "reconciliation-seal.json"

NEUTRAL_MUTABLE_FIELDS = {
    "status",
    "canonical_decision",
    "evidence_citations",
    "verification_rationale",
    "neutral_bundle_manifest_sha256",
}


def _normalized_text(value: Any) -> str:
    return " ".join(str(value or "").casefold().split())


def neutral_bundle_manifest_sha256(row: dict[str, Any]) -> str:
    """Hash exactly the evidence and question released to one neutral verifier."""

    return stable_hash(
        {
            key: value
            for key, value in row.items()
            if key not in NEUTRAL_MUTABLE_FIELDS
        },
        64,
    )


def operation_action_payload(proposal: Any) -> dict[str, Any]:
    if not isinstance(proposal, dict):
        return {}
    return {
        field: proposal.get(field, [])
        for field in OPERATION_ACTION_FIELDS
        if as_list(proposal.get(field))
    }


def semantic_signature(decision: dict[str, Any]) -> dict[str, Any]:
    decision_class = str(decision.get("decision_class") or "")
    return {
        "decision_class": decision_class,
        "action_payload_sha256": stable_hash(
            operation_action_payload(decision.get("operation_proposal")), 64
        ),
        "has_action": decision_class in ACTIONABLE_DECISION_CLASSES,
        "priority": decision.get("priority"),
        "owner_boundary": bool(str(decision.get("owner_question") or "").strip()),
        "evidence_boundary": bool(
            str(decision.get("evidence_boundary") or "").strip()
        ),
    }


def canonical_semantic_payload(decision: dict[str, Any]) -> dict[str, Any]:
    """Return every field whose meaning reconciliation is forbidden to invent."""

    return {
        **{field: decision.get(field) for field in CANONICAL_DECISION_FIELDS},
        "operation_proposal": decision.get("operation_proposal"),
        "evidence_citations": sorted(
            str(value) for value in as_list(decision.get("evidence_citations"))
        ),
    }


def comparison_classification(left: dict[str, Any], right: dict[str, Any]) -> str:
    left_signature = semantic_signature(left)
    right_signature = semantic_signature(right)
    if left_signature == right_signature:
        semantic_text_fields = (
            "target_direction",
            "owner_question",
            "evidence_boundary",
            "preserved_distinctions",
        )
        if all(
            _normalized_text(left.get(field)) == _normalized_text(right.get(field))
            for field in semantic_text_fields
        ):
            return "agreement"
        return "compatible_complementary_conclusions"
    left_class = str(left.get("decision_class") or "")
    right_class = str(right.get("decision_class") or "")
    if (left_class in ACTIONABLE_DECISION_CLASSES) != (
        right_class in ACTIONABLE_DECISION_CLASSES
    ):
        return "one_sided_finding"
    if left_class != right_class:
        return "conflicting_verdict"
    if left_class in {"owner_decision", "container_evidence_limit"}:
        return "different_evidence_boundary"
    return "conflicting_target"


def material_verification_reasons(
    obligation: dict[str, Any],
    left: dict[str, Any],
    right: dict[str, Any],
    classification: str,
) -> list[str]:
    reasons = {
        str(value)
        for value in as_list(obligation.get("material_verification_triggers"))
        if str(value)
    }
    if classification not in {"agreement", "compatible_complementary_conclusions"}:
        reasons.add(classification)
    priorities = {str(left.get("priority") or ""), str(right.get("priority") or "")}
    if priorities & {"Critical", "High"}:
        reasons.add("high_or_critical_operation")
    for decision in (left, right):
        proposal = decision.get("operation_proposal") or {}
        deletions = as_list(proposal.get("deletions"))
        if deletions:
            reasons.add("active_deletion")
        if as_list(proposal.get("remaps")) and deletions:
            reasons.add("active_consolidation")
    return sorted(reasons)


def _discovery_decisions(audit: dict[str, Any]) -> dict[str, dict[str, Any]]:
    result = {}
    for row in as_list(audit.get("open_discoveries")):
        if not isinstance(row, dict):
            continue
        discovery_id = str(row.get("discovery_id") or "")
        decision = row.get("decision")
        if discovery_id and isinstance(decision, dict):
            result[discovery_id] = {
                **decision,
                "decision_id": decision.get("decision_id") or discovery_id,
                "obligation_id": discovery_id,
                "area_id": row.get("area_id"),
                "scope_level": row.get("scope_level") or "relationship",
                "audit_mechanism": "independent_discovery",
                "fact_kind": "independent_discovery",
                "subject_keys": row.get("subject_keys", []),
                "family_ids": row.get("family_ids", []),
                "candidate_id": discovery_id,
                "source_coordinates": row.get("source_coordinates", []),
                "material_verification_triggers": ["one_sided_finding"],
            }
    return result


def _comparison_row(
    obligation_id: str,
    obligation: dict[str, Any],
    left: dict[str, Any] | None,
    right: dict[str, Any] | None,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    if left is None or right is None:
        classification = "one_sided_finding"
        present = left or right or {}
        reasons = sorted(
            {
                "one_sided_finding",
                *as_list(obligation.get("material_verification_triggers")),
            }
        )
    else:
        classification = comparison_classification(left, right)
        reasons = material_verification_reasons(
            obligation, left, right, classification
        )
        present = left
    verification_id = "NV-" + stable_hash(
        {
            "obligation_id": obligation_id,
            "classification": classification,
            "reasons": reasons,
            "obligation_sha256": obligation.get("obligation_sha256"),
        },
        16,
    ).upper()
    requires_neutral = bool(reasons)
    comparison = {
        "comparison_id": "REC-" + stable_hash(obligation_id, 16).upper(),
        "obligation_id": obligation_id,
        "obligation_sha256": obligation.get("obligation_sha256"),
        "area_id": obligation.get("area_id") or present.get("area_id"),
        "scope_level": obligation.get("scope_level") or present.get("scope_level"),
        "audit_mechanism": obligation.get("audit_mechanism")
        or present.get("audit_mechanism"),
        "fact_kind": obligation.get("fact_kind") or present.get("fact_kind"),
        "subject_keys": obligation.get("subject_keys") or present.get("subject_keys", []),
        "family_ids": obligation.get("family_ids") or present.get("family_ids", []),
        "candidate_id": obligation.get("candidate_id") or present.get("candidate_id", ""),
        "applicability": obligation.get("applicability")
        or present.get("applicability", "applicable"),
        "source_coordinates": obligation.get("source_coordinates")
        or present.get("source_coordinates", []),
        "semantic_repair_records": obligation.get("semantic_repair_records")
        or present.get("semantic_repair_records", []),
        "classification": classification,
        "neutral_verification_required": requires_neutral,
        "neutral_verification_id": verification_id if requires_neutral else "",
        "neutral_verification_reasons": reasons,
        "audit_decisions": {
            "audit-a": left or {},
            "audit-b": right or {},
        },
        "status": "pending",
        "canonical_decision": {},
        "reconciliation_rationale": "",
    }
    if not requires_neutral:
        return comparison, None
    queue = {
        "verification_id": verification_id,
        "obligation_id": obligation_id,
        "obligation_sha256": obligation.get("obligation_sha256"),
        "area_id": comparison["area_id"],
        "audit_mechanism": comparison["audit_mechanism"],
        "fact_kind": comparison["fact_kind"],
        "subject_keys": comparison["subject_keys"],
        "source_coordinates": comparison["source_coordinates"],
        "semantic_repair_records": obligation.get("semantic_repair_records", []),
        "verification_reasons": reasons,
        "neutral_question": (
            "From the supplied evidence and applicable contract, what source-supported "
            "decision and narrowest safe target follow?"
        ),
        "neutral_evidence": obligation.get("evidence", {}),
        "allowed_evidence_citations": locked_evidence_coordinates(
            comparison["source_coordinates"], obligation.get("evidence", {})
        ),
        "prohibited_context": (
            "Do not decide by vote count, expected outcome, reconciliation preference, "
            "or workbook wording; resolve the evidence and criteria directly."
        ),
        "status": "pending",
        "canonical_decision": {},
        "evidence_citations": [],
        "verification_rationale": "",
    }
    queue["neutral_bundle_manifest_sha256"] = neutral_bundle_manifest_sha256(queue)
    return comparison, queue


def _reconciliation_scaffold_payloads(
    package_dir: Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Reconstruct the only valid scaffold and neutral queue from sealed inputs."""

    require_safe_package_root(package_dir)
    errors = sealed_audit_errors(package_dir)
    if errors:
        raise ValueError("sealed-audit gate failed: " + "; ".join(errors))
    ledger_path = package_dir / "obligation-ledger.json"
    if not ledger_path.is_file():
        raise ValueError("obligation ledger is missing")
    ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
    audits = {
        audit_id: json.loads(
            (package_dir / "audits" / f"{audit_id}.json").read_text(encoding="utf-8")
        )
        for audit_id in AUDIT_IDS
    }
    obligations = {
        str(row.get("obligation_id") or ""): row
        for row in as_list(ledger.get("obligations"))
    }
    decisions = {
        audit_id: {
            str(row.get("obligation_id") or ""): row
            for row in as_list(audits[audit_id].get("decisions"))
        }
        for audit_id in AUDIT_IDS
    }
    discoveries = {
        audit_id: _discovery_decisions(audits[audit_id]) for audit_id in AUDIT_IDS
    }
    all_ids = sorted(
        set(obligations)
        | set(discoveries["audit-a"])
        | set(discoveries["audit-b"])
    )
    comparisons = []
    neutral_queue = []
    for obligation_id in all_ids:
        obligation = obligations.get(obligation_id)
        left = decisions["audit-a"].get(obligation_id) or discoveries[
            "audit-a"
        ].get(obligation_id)
        right = decisions["audit-b"].get(obligation_id) or discoveries[
            "audit-b"
        ].get(obligation_id)
        if obligation is None:
            source = left or right or {}
            obligation = {
                "obligation_id": obligation_id,
                "obligation_sha256": stable_hash(
                    {
                        "obligation_id": obligation_id,
                        "area_id": source.get("area_id"),
                        "subject_keys": source.get("subject_keys", []),
                        "source_coordinates": source.get("source_coordinates", []),
                    },
                    64,
                ),
                "area_id": source.get("area_id"),
                "scope_level": source.get("scope_level"),
                "audit_mechanism": "independent_discovery",
                "fact_kind": "independent_discovery",
                "subject_keys": source.get("subject_keys", []),
                "family_ids": source.get("family_ids", []),
                "candidate_id": obligation_id,
                "source_coordinates": source.get("source_coordinates", []),
                "material_verification_triggers": ["one_sided_finding"],
                "evidence": {
                    "discovery_id": obligation_id,
                    "source_coordinates": source.get("source_coordinates", []),
                    "subject_keys": source.get("subject_keys", []),
                },
            }
        comparison, queue = _comparison_row(
            obligation_id, obligation, left, right
        )
        comparisons.append(comparison)
        if queue:
            neutral_queue.append(queue)
    audit_seals = {
        audit_id: json.loads(
            (package_dir / "audit-seals" / f"{audit_id}.json").read_text(
                encoding="utf-8"
            )
        )
        for audit_id in AUDIT_IDS
    }
    audit_seal_sha256 = {
        audit_id: audit_seals[audit_id].get("audit_seal_sha256")
        for audit_id in AUDIT_IDS
    }
    reconciliation_input_sha256 = stable_hash(
        {
            "source_sha256": ledger.get("source_sha256"),
            "obligation_ledger_sha256": ledger.get("obligation_ledger_sha256"),
            "audit_seal_sha256": audit_seal_sha256,
        },
        64,
    )
    reconciliation = {
        "kind": "gtm_contradiction_aware_reconciliation",
        "schema_version": 1,
        "source_sha256": ledger.get("source_sha256"),
        "canonical_scan_sha256": ledger.get("canonical_scan_sha256"),
        "obligation_ledger_sha256": ledger.get("obligation_ledger_sha256"),
        "audit_seal_sha256": audit_seal_sha256,
        "independent_agent_id": "",
        "independent_context_id": "",
        "input_manifest_sha256": reconciliation_input_sha256,
        "status": "pending",
        "comparisons": comparisons,
    }
    neutral = {
        "kind": "gtm_neutral_verification_queue",
        "schema_version": 1,
        "source_sha256": ledger.get("source_sha256"),
        "canonical_scan_sha256": ledger.get("canonical_scan_sha256"),
        "status": "pending" if neutral_queue else "not_required",
        "verifications": neutral_queue,
        "review_contract": (
            "The fresh reconciliation agent resolves queued rows from evidence and "
            "criteria without voting or following an expected outcome."
        ),
    }
    reconciliation["reconciliation_scaffold_sha256"] = stable_hash(
        reconciliation, 64
    )
    neutral["neutral_queue_sha256"] = stable_hash(neutral, 64)
    return reconciliation, neutral


def scaffold_reconciliation(package_dir: Path) -> dict[str, Any]:
    reconciliation, neutral = _reconciliation_scaffold_payloads(package_dir)
    write_json(package_dir / RECONCILIATION_SCAFFOLD_FILE, reconciliation)
    write_json(package_dir / NEUTRAL_QUEUE_FILE, neutral)
    write_json(package_dir / RECONCILIATION_FILE, reconciliation)
    write_json(package_dir / NEUTRAL_FILE, neutral)
    return {
        "status": "pass",
        "comparisons": len(as_list(reconciliation.get("comparisons"))),
        "neutral_verifications": len(as_list(neutral.get("verifications"))),
        "reconciliation_file": RECONCILIATION_FILE,
        "neutral_file": NEUTRAL_FILE,
    }


def _neutral_errors(
    package_dir: Path, neutral: dict[str, Any], expected: dict[str, Any]
) -> list[str]:
    errors: list[str] = []
    if set(neutral) != set(expected):
        errors.append("neutral verification top-level schema differs from its queue")
    for field in set(expected) - {"status", "verifications"}:
        if neutral.get(field) != expected.get(field):
            errors.append(f"neutral verification locked field {field} changed")
    expected_rows = {
        str(row.get("verification_id") or ""): row
        for row in as_list(expected.get("verifications"))
    }
    supplied_rows = [
        row for row in as_list(neutral.get("verifications")) if isinstance(row, dict)
    ]
    supplied = {
        str(row.get("verification_id") or ""): row for row in supplied_rows
    }
    if len(supplied) != len(supplied_rows) or "" in supplied:
        errors.append("neutral verification IDs are blank or duplicated")
    if set(supplied) != set(expected_rows):
        errors.append("neutral verification must cover the exact queued rows")
    expected_status = "complete" if expected_rows else "not_required"
    if neutral.get("status") != expected_status:
        errors.append(f"neutral verification status must be {expected_status}")
    for verification_id, expected_row in expected_rows.items():
        row = supplied.get(verification_id)
        if not row:
            continue
        label = f"neutral verification {verification_id}"
        if set(row) != set(expected_row):
            errors.append(f"{label}: schema contains missing or undeclared fields")
        for field in (
            "verification_id",
            "obligation_id",
            "obligation_sha256",
            "area_id",
            "subject_keys",
            "source_coordinates",
            "semantic_repair_records",
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
        citations = {
            str(value) for value in as_list(row.get("evidence_citations"))
        }
        allowed = set(as_list(expected_row.get("allowed_evidence_citations")))
        if allowed and (not citations or citations - allowed):
            errors.append(f"{label}: citations must use allowed_evidence_citations")
        if not re.search(
            r"\b(?:because|shows|configured|evidence|source|field|route|object)\b",
            str(row.get("verification_rationale") or ""),
            re.I,
        ):
            errors.append(f"{label}: verification rationale is not evidence-bound")
    return errors


def canonical_matches_allowed(
    canonical: dict[str, Any],
    candidates: list[dict[str, Any]],
    *,
    allow_neutral_rejection: bool = False,
) -> bool:
    payload_hash = stable_hash(canonical_semantic_payload(canonical), 64)
    if any(
        payload_hash == stable_hash(canonical_semantic_payload(row), 64)
        for row in candidates
    ):
        return True
    # A neutral verifier may reject or narrow a proposal to a non-actionable
    # state, but it cannot invent a third actionable target.
    return bool(
        allow_neutral_rejection
        and canonical.get("decision_class")
        in {
            "justified_as_is",
            "owner_decision",
            "container_evidence_limit",
            "not_applicable",
        }
        and not operation_action_payload(canonical.get("operation_proposal"))
    )


def finalize_reconciliation(
    package_dir: Path,
    reconciliation_path: Path | None = None,
    neutral_path: Path | None = None,
    *,
    _validate_only: bool = False,
) -> dict[str, Any]:
    require_safe_package_root(package_dir)
    base_reconciliation_path = package_dir / RECONCILIATION_SCAFFOLD_FILE
    base_neutral_path = package_dir / NEUTRAL_QUEUE_FILE
    if not base_reconciliation_path.is_file() or not base_neutral_path.is_file():
        raise ValueError("reconciliation must be scaffolded first")
    expected_reconciliation, expected_neutral = _reconciliation_scaffold_payloads(
        package_dir
    )
    stored_reconciliation = json.loads(
        base_reconciliation_path.read_text(encoding="utf-8")
    )
    stored_neutral = json.loads(base_neutral_path.read_text(encoding="utf-8"))
    reconciliation = json.loads(
        (reconciliation_path or package_dir / RECONCILIATION_FILE).read_text(
            encoding="utf-8"
        )
    )
    neutral = json.loads(
        (neutral_path or package_dir / NEUTRAL_FILE).read_text(encoding="utf-8")
    )
    errors: list[str] = []
    if stored_reconciliation != expected_reconciliation:
        errors.append(
            "reconciliation scaffold differs from deterministic sealed-audit reconstruction"
        )
    if stored_neutral != expected_neutral:
        errors.append(
            "neutral queue differs from deterministic sealed-audit reconstruction"
        )
    if set(reconciliation) != set(expected_reconciliation):
        errors.append("reconciliation top-level schema differs from its scaffold")
    for field in set(expected_reconciliation) - {
        "status",
        "comparisons",
        "independent_agent_id",
        "independent_context_id",
    }:
        if reconciliation.get(field) != expected_reconciliation.get(field):
            errors.append(f"reconciliation locked field {field} changed")
    agent_id = str(reconciliation.get("independent_agent_id") or "").strip()
    context_id = str(reconciliation.get("independent_context_id") or "").strip()
    if not agent_id:
        errors.append("reconciliation requires an independent_agent_id")
    if not context_id:
        errors.append("reconciliation requires an independent_context_id")
    source_seals = [
        json.loads(
            (package_dir / "audit-seals" / f"{audit_id}.json").read_text(
                encoding="utf-8"
            )
        )
        for audit_id in AUDIT_IDS
    ]
    assurance = json.loads(
        (package_dir / "scan-assurance.json").read_text(encoding="utf-8")
    )
    prior_agent_ids = {
        str(assurance.get("independent_agent_id") or ""),
        *(str(seal.get("independent_agent_id") or "") for seal in source_seals),
    }
    prior_context_ids = {
        str(assurance.get("independent_context_id") or ""),
        *(str(seal.get("independent_context_id") or "") for seal in source_seals),
    }
    if agent_id and agent_id in prior_agent_ids:
        errors.append(
            "reconciliation must use an agent distinct from scan assurance and both audits"
        )
    if context_id and context_id in prior_context_ids:
        errors.append(
            "reconciliation must use a context distinct from scan assurance and both audits"
        )
    errors.extend(_neutral_errors(package_dir, neutral, expected_neutral))
    expected_rows = {
        str(row.get("comparison_id") or ""): row
        for row in as_list(expected_reconciliation.get("comparisons"))
    }
    supplied_rows = [
        row
        for row in as_list(reconciliation.get("comparisons"))
        if isinstance(row, dict)
    ]
    supplied = {
        str(row.get("comparison_id") or ""): row for row in supplied_rows
    }
    if set(supplied) != set(expected_rows) or len(supplied) != len(supplied_rows):
        errors.append("reconciliation must cover the exact comparison set")
    neutral_by_id = {
        str(row.get("verification_id") or ""): row
        for row in as_list(neutral.get("verifications"))
    }
    canonical_rows = []
    for comparison_id, expected in expected_rows.items():
        row = supplied.get(comparison_id)
        if not row:
            continue
        label = f"reconciliation {comparison_id}"
        if set(row) != set(expected):
            errors.append(f"{label}: schema contains missing or undeclared fields")
        for field in (
            "comparison_id",
            "obligation_id",
            "obligation_sha256",
            "area_id",
            "scope_level",
            "audit_mechanism",
            "fact_kind",
            "subject_keys",
            "family_ids",
            "candidate_id",
            "applicability",
            "source_coordinates",
            "semantic_repair_records",
            "classification",
            "neutral_verification_required",
            "neutral_verification_id",
            "neutral_verification_reasons",
            "audit_decisions",
        ):
            if row.get(field) != expected.get(field):
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
            decision
            for decision in (row.get("audit_decisions") or {}).values()
            if isinstance(decision, dict) and decision
        ]
        if row.get("neutral_verification_required"):
            verification = neutral_by_id.get(
                str(row.get("neutral_verification_id") or "")
            )
            if not verification:
                errors.append(f"{label}: required neutral verification is missing")
            elif canonical != verification.get("canonical_decision"):
                errors.append(f"{label}: canonical decision differs from neutral result")
        elif not canonical_matches_allowed(canonical, source_decisions):
            errors.append(f"{label}: canonical decision introduces a new semantic choice")
        if not canonical_matches_allowed(
            canonical,
            source_decisions,
            allow_neutral_rejection=bool(row.get("neutral_verification_required")),
        ):
            errors.append(f"{label}: actionable target was not proposed by either audit")
        if not re.search(
            r"\b(?:both|source|evidence|configured|decision|target|audit)\b",
            str(row.get("reconciliation_rationale") or ""),
            re.I,
        ):
            errors.append(f"{label}: reconciliation rationale is incomplete")
        canonical_rows.append(
            {
                "canonical_decision_id": "CD-" + comparison_id.removeprefix("REC-"),
                "obligation_id": row.get("obligation_id"),
                "obligation_sha256": row.get("obligation_sha256"),
                "area_id": row.get("area_id"),
                "scope_level": row.get("scope_level"),
                "audit_mechanism": row.get("audit_mechanism"),
                "fact_kind": row.get("fact_kind"),
                "subject_keys": row.get("subject_keys", []),
                "family_ids": row.get("family_ids", []),
                "candidate_id": row.get("candidate_id"),
                "applicability": row.get("applicability"),
                "source_coordinates": row.get("source_coordinates", []),
                "semantic_repair_records": row.get(
                    "semantic_repair_records", []
                ),
                "reconciliation_class": row.get("classification"),
                "neutral_verification_id": row.get("neutral_verification_id"),
                "decision": canonical,
                "audit_support": [
                    {
                        "decision_id": source.get("decision_id"),
                        "decision_sha256": stable_hash(source, 64),
                    }
                    for source in source_decisions
                ],
                "owning_audits": sorted(
                    audit_id
                    for audit_id, source in (row.get("audit_decisions") or {}).items()
                    if source
                ),
                "reconciliation_rationale": row.get("reconciliation_rationale"),
            }
        )
    if errors:
        raise ValueError("reconciliation gate failed: " + "; ".join(errors))
    record = {
        "kind": "gtm_reconciled_semantic_record",
        "schema_version": 1,
        "source_sha256": expected_reconciliation.get("source_sha256"),
        "canonical_scan_sha256": expected_reconciliation.get(
            "canonical_scan_sha256"
        ),
        "obligation_ledger_sha256": expected_reconciliation.get(
            "obligation_ledger_sha256"
        ),
        "audit_seal_sha256": expected_reconciliation.get("audit_seal_sha256"),
        "neutral_queue_sha256": expected_neutral.get("neutral_queue_sha256"),
        "independent_agent_id": agent_id,
        "independent_context_id": context_id,
        "input_manifest_sha256": reconciliation.get("input_manifest_sha256"),
        "canonical_decisions": sorted(
            canonical_rows, key=lambda item: str(item["canonical_decision_id"])
        ),
    }
    record["reconciled_record_sha256"] = stable_hash(record, 64)
    if _validate_only:
        return record
    record_path = package_dir / RECONCILED_RECORD_FILE
    write_json(record_path, record)
    seal = {
        "kind": "gtm_reconciliation_seal",
        "schema_version": 1,
        "source_sha256": record.get("source_sha256"),
        "audit_seal_sha256": record.get("audit_seal_sha256"),
        "reconciliation_scaffold_sha256": expected_reconciliation.get(
            "reconciliation_scaffold_sha256"
        ),
        "neutral_queue_sha256": expected_neutral.get("neutral_queue_sha256"),
        "reconciliation_file_sha256": file_sha256(
            reconciliation_path or package_dir / RECONCILIATION_FILE
        ),
        "neutral_file_sha256": file_sha256(
            neutral_path or package_dir / NEUTRAL_FILE
        ),
        "independent_agent_id": record.get("independent_agent_id"),
        "independent_context_id": record.get("independent_context_id"),
        "input_manifest_sha256": record.get("input_manifest_sha256"),
        "reconciled_record_sha256": record.get("reconciled_record_sha256"),
        "reconciled_file_sha256": file_sha256(record_path),
        "validator_status": "pass",
    }
    seal["reconciliation_seal_sha256"] = stable_hash(seal, 64)
    write_json(package_dir / RECONCILIATION_SEAL_FILE, seal)
    return {
        "status": "pass",
        "canonical_decisions": len(canonical_rows),
        "reconciled_record_sha256": record["reconciled_record_sha256"],
        "reconciliation_seal_sha256": seal["reconciliation_seal_sha256"],
    }


def reconciliation_seal_errors(package_dir: Path) -> list[str]:
    """Reconstruct the reconciled record and its exact seal from sealed authority."""

    require_safe_package_root(package_dir)
    record_path = package_dir / RECONCILED_RECORD_FILE
    seal_path = package_dir / RECONCILIATION_SEAL_FILE
    reconciliation_path = package_dir / RECONCILIATION_FILE
    neutral_path = package_dir / NEUTRAL_FILE
    required = (record_path, seal_path, reconciliation_path, neutral_path)
    if not all(path.is_file() for path in required):
        return ["sealed reconciled decision record or its authority files are missing"]
    errors: list[str] = []
    try:
        expected_record = finalize_reconciliation(
            package_dir,
            reconciliation_path,
            neutral_path,
            _validate_only=True,
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return [f"reconciliation reconstruction failed: {exc}"]
    record = json.loads(record_path.read_text(encoding="utf-8"))
    if record != expected_record:
        errors.append("reconciled decision record differs from deterministic reconstruction")
    seal = json.loads(seal_path.read_text(encoding="utf-8"))
    expected_scaffold, expected_neutral = _reconciliation_scaffold_payloads(
        package_dir
    )
    expected_seal = {
        "kind": "gtm_reconciliation_seal",
        "schema_version": 1,
        "source_sha256": expected_record.get("source_sha256"),
        "audit_seal_sha256": expected_record.get("audit_seal_sha256"),
        "reconciliation_scaffold_sha256": expected_scaffold.get(
            "reconciliation_scaffold_sha256"
        ),
        "neutral_queue_sha256": expected_neutral.get("neutral_queue_sha256"),
        "reconciliation_file_sha256": file_sha256(reconciliation_path),
        "neutral_file_sha256": file_sha256(neutral_path),
        "independent_agent_id": expected_record.get("independent_agent_id"),
        "independent_context_id": expected_record.get("independent_context_id"),
        "input_manifest_sha256": expected_record.get("input_manifest_sha256"),
        "reconciled_record_sha256": expected_record.get("reconciled_record_sha256"),
        "reconciled_file_sha256": file_sha256(record_path),
        "validator_status": "pass",
    }
    expected_seal["reconciliation_seal_sha256"] = stable_hash(expected_seal, 64)
    if seal != expected_seal:
        errors.append("reconciliation seal differs from exact reconstructed authority")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    scaffold = subparsers.add_parser("scaffold")
    scaffold.add_argument("package_dir", type=Path)
    finalize = subparsers.add_parser("finalize")
    finalize.add_argument("package_dir", type=Path)
    finalize.add_argument("--reconciliation", type=Path)
    finalize.add_argument("--neutral", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "scaffold":
            result = scaffold_reconciliation(args.package_dir)
        else:
            result = finalize_reconciliation(
                args.package_dir,
                args.reconciliation,
                args.neutral,
            )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"status": "blocked", "errors": [str(exc)]}))
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
