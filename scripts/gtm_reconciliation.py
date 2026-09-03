#!/usr/bin/env python3
"""Reconcile two sealed clean-room GTM audits with neutral verification."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from gtm_audit_contract import (
    ACTIONABLE_DECISION_CLASSES,
    CANONICAL_DECISION_FIELDS,
    OPERATION_ACTION_FIELDS,
    semantic_contract_errors,
)
from gtm_cleanroom_audit import (
    AUDIT_IDS,
    decision_obligation_alignment_errors,
    sealed_audit_errors,
)
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
RECONCILIATION_UNIT_DIRECTORY = "reconciliation-units"
RECONCILIATION_UNIT_MANIFEST = "manifest.json"
RECONCILIATION_COMPLETION_FILE = "reconciliation-completion.json"
MAX_RECONCILIATION_UNIT_COMPARISONS = 30

NEUTRAL_MUTABLE_FIELDS = {
    "status",
    "canonical_decision",
    "evidence_citations",
    "verification_rationale",
    "neutral_bundle_manifest_sha256",
}


def _normalized_text(value: Any) -> str:
    return " ".join(str(value or "").casefold().split())


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"JSON root must be an object: {path}")
    return value


def _reconciliation_unit_payloads(
    reconciliation: dict[str, Any], neutral: dict[str, Any]
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    comparisons = as_list(reconciliation.get("comparisons"))
    verification_by_id = {
        str(row.get("verification_id") or ""): row
        for row in as_list(neutral.get("verifications"))
        if isinstance(row, dict)
    }
    units: list[dict[str, Any]] = []
    records: list[dict[str, Any]] = []
    for offset in range(0, len(comparisons), MAX_RECONCILIATION_UNIT_COMPARISONS):
        rows = comparisons[offset : offset + MAX_RECONCILIATION_UNIT_COMPARISONS]
        unit_number = offset // MAX_RECONCILIATION_UNIT_COMPARISONS + 1
        unit_id = f"reconciliation-unit-{unit_number:03d}"
        filename = f"unit-{unit_number:03d}.json"
        comparison_ids = [str(row.get("comparison_id") or "") for row in rows]
        verification_ids = [
            str(row.get("neutral_verification_id") or "")
            for row in rows
            if row.get("neutral_verification_required")
        ]
        unit = {
            "kind": "gtm_reconciliation_work_unit",
            "schema_version": 1,
            "unit_id": unit_id,
            "comparison_ids": comparison_ids,
            "verification_ids": verification_ids,
            "comparisons": rows,
            "verifications": [verification_by_id[value] for value in verification_ids],
        }
        units.append(unit)
        records.append(
            {
                "unit_id": unit_id,
                "filename": filename,
                "comparison_ids": comparison_ids,
                "verification_ids": verification_ids,
            }
        )
    manifest = {
        "kind": "gtm_reconciliation_work_unit_manifest",
        "schema_version": 1,
        "reconciliation_scaffold_sha256": reconciliation.get(
            "reconciliation_scaffold_sha256"
        ),
        "neutral_queue_sha256": neutral.get("neutral_queue_sha256"),
        "max_comparisons_per_unit": MAX_RECONCILIATION_UNIT_COMPARISONS,
        "comparison_count": len(comparisons),
        "verification_count": len(verification_by_id),
        "units": records,
    }
    manifest["manifest_sha256"] = stable_hash(manifest, 64)
    return manifest, units


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
    # Equal verdict labels do not prove agreement between the assessed reasons
    # or their referenced operations. Existing neutral reviews already inspect
    # both complete decisions; only previously automatic rows need this reason.
    if not reasons and canonical_semantic_payload(left) != canonical_semantic_payload(right):
        reasons.add("different_semantic_content")
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
        candidates = [
            decision for decision in (left, right) if isinstance(decision, dict)
        ]
        canonical = min(
            candidates,
            key=lambda decision: stable_hash(
                canonical_semantic_payload(decision), 64
            ),
        )
        comparison.update(
            {
                "status": "complete",
                "canonical_decision": canonical,
                "reconciliation_rationale": (
                    "Deterministic reconciliation retained one "
                    f"{('equivalent' if classification == 'agreement' else 'compatible')} "
                    "sealed audit decision."
                ),
            }
        )
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
        "authoring_contract": {
            "reconciliation_rationale": (
                "Explain the chosen conclusion concisely using the relevant evidence."
            )
        },
        "status": "pending",
        "comparisons": comparisons,
    }
    neutral = {
        "kind": "gtm_neutral_verification_queue",
        "schema_version": 1,
        "authoring_contract": {
            "verification_rationale": (
                "Explain the verification conclusion concisely and cite the relevant "
                "evidence using allowed_evidence_citations."
            )
        },
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
    require_safe_package_root(package_dir)
    outputs = (
        RECONCILIATION_SCAFFOLD_FILE, NEUTRAL_QUEUE_FILE,
        RECONCILIATION_UNIT_DIRECTORY, RECONCILIATION_COMPLETION_FILE,
        RECONCILIATION_FILE, NEUTRAL_FILE, RECONCILED_RECORD_FILE,
        RECONCILIATION_SEAL_FILE,
    )
    existing = [name for name in outputs if (package_dir / name).exists()]
    if existing:
        raise FileExistsError(
            "reconciliation outputs already exist; preserve completed work: "
            + ", ".join(existing)
        )
    reconciliation, neutral = _reconciliation_scaffold_payloads(package_dir)
    write_json(package_dir / RECONCILIATION_SCAFFOLD_FILE, reconciliation)
    write_json(package_dir / NEUTRAL_QUEUE_FILE, neutral)
    unit_root = package_dir / RECONCILIATION_UNIT_DIRECTORY
    unit_root.mkdir()
    manifest, units = _reconciliation_unit_payloads(reconciliation, neutral)
    write_json(unit_root / RECONCILIATION_UNIT_MANIFEST, manifest)
    for record, unit in zip(manifest["units"], units, strict=True):
        write_json(unit_root / record["filename"], unit)
    write_json(
        package_dir / RECONCILIATION_COMPLETION_FILE,
        {
            "kind": "gtm_reconciliation_completion",
            "schema_version": 1,
            "independent_agent_id": "",
            "independent_context_id": "",
            "status": "pending",
        },
    )
    return {
        "status": "pass",
        "comparisons": len(as_list(reconciliation.get("comparisons"))),
        "neutral_verifications": len(as_list(neutral.get("verifications"))),
        "work_units": len(units),
        "unit_manifest": (
            f"{RECONCILIATION_UNIT_DIRECTORY}/{RECONCILIATION_UNIT_MANIFEST}"
        ),
        "completion_file": RECONCILIATION_COMPLETION_FILE,
    }


def _merge_reconciliation_units(
    package_dir: Path,
    expected_reconciliation: dict[str, Any],
    expected_neutral: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    unit_root = package_dir / RECONCILIATION_UNIT_DIRECTORY
    expected_manifest, expected_units = _reconciliation_unit_payloads(
        expected_reconciliation, expected_neutral
    )
    manifest = _read_json(unit_root / RECONCILIATION_UNIT_MANIFEST)
    if manifest != expected_manifest:
        raise ValueError("reconciliation unit manifest differs from reconstruction")
    expected_filenames = {
        RECONCILIATION_UNIT_MANIFEST,
        *(str(row["filename"]) for row in expected_manifest["units"]),
    }
    actual_entries = list(unit_root.iterdir())
    actual_filenames = {path.name for path in actual_entries}
    if actual_filenames != expected_filenames or not all(
        path.is_file() for path in actual_entries
    ):
        raise ValueError("reconciliation unit file inventory differs from its manifest")
    comparisons: list[dict[str, Any]] = []
    verifications: list[dict[str, Any]] = []
    identity_fields = {
        "kind",
        "schema_version",
        "unit_id",
        "comparison_ids",
        "verification_ids",
    }
    for record, expected_unit in zip(
        expected_manifest["units"], expected_units, strict=True
    ):
        unit = _read_json(unit_root / str(record["filename"]))
        if set(unit) != set(expected_unit):
            raise ValueError(f"{record['unit_id']}: work-unit schema changed")
        if any(unit.get(field) != expected_unit.get(field) for field in identity_fields):
            raise ValueError(f"{record['unit_id']}: work-unit identity changed")
        unit_comparisons = as_list(unit.get("comparisons"))
        unit_verifications = as_list(unit.get("verifications"))
        if [
            str(row.get("comparison_id") or "")
            for row in unit_comparisons
            if isinstance(row, dict)
        ] != expected_unit["comparison_ids"]:
            raise ValueError(f"{record['unit_id']}: comparison membership changed")
        if [
            str(row.get("verification_id") or "")
            for row in unit_verifications
            if isinstance(row, dict)
        ] != expected_unit["verification_ids"]:
            raise ValueError(f"{record['unit_id']}: verification membership changed")
        if unit_comparisons != expected_unit["comparisons"]:
            raise ValueError(
                f"{record['unit_id']}: deterministic comparison rows changed"
            )
        comparisons.extend(unit_comparisons)
        verifications.extend(unit_verifications)
    completion = _read_json(package_dir / RECONCILIATION_COMPLETION_FILE)
    if set(completion) != {
        "kind",
        "schema_version",
        "independent_agent_id",
        "independent_context_id",
        "status",
    }:
        raise ValueError("reconciliation completion schema changed")
    if completion.get("kind") != "gtm_reconciliation_completion" or completion.get(
        "schema_version"
    ) != 1:
        raise ValueError("reconciliation completion identity changed")
    verification_by_id = {
        str(row.get("verification_id") or ""): row
        for row in verifications
        if isinstance(row, dict)
    }
    projected_comparisons = []
    for comparison in comparisons:
        projected = dict(comparison)
        if comparison.get("neutral_verification_required"):
            verification = verification_by_id.get(
                str(comparison.get("neutral_verification_id") or "")
            )
            if verification:
                projected.update(
                    {
                        "status": verification.get("status"),
                        "canonical_decision": verification.get(
                            "canonical_decision"
                        ),
                        "reconciliation_rationale": verification.get(
                            "verification_rationale"
                        ),
                    }
                )
        projected_comparisons.append(projected)
    reconciliation = dict(expected_reconciliation)
    reconciliation.update(
        {
            "independent_agent_id": completion.get("independent_agent_id"),
            "independent_context_id": completion.get("independent_context_id"),
            "status": completion.get("status"),
            "comparisons": projected_comparisons,
        }
    )
    neutral = dict(expected_neutral)
    neutral.update(
        {
            "status": "complete" if verifications else "not_required",
            "verifications": verifications,
        }
    )
    return reconciliation, neutral


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
        if citations - allowed or (allowed and not citations):
            errors.append(f"{label}: citations must use allowed_evidence_citations")
        rationale = row.get("verification_rationale")
        if not isinstance(rationale, str) or not rationale.strip():
            errors.append(f"{label}: verification rationale must be a non-blank string")
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
    if (reconciliation_path is None) != (neutral_path is None):
        raise ValueError("reconciliation and neutral paths must be supplied together")
    if reconciliation_path is None:
        reconciliation, neutral = _merge_reconciliation_units(
            package_dir, expected_reconciliation, expected_neutral
        )
    else:
        reconciliation = _read_json(reconciliation_path)
        neutral = _read_json(neutral_path)
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
    ledger = _read_json(package_dir / "obligation-ledger.json")
    obligation_by_id = {
        str(row.get("obligation_id") or ""): row
        for row in as_list(ledger.get("obligations"))
        if isinstance(row, dict)
    }
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
        obligation = obligation_by_id.get(str(row.get("obligation_id") or ""))
        if obligation:
            errors.extend(
                decision_obligation_alignment_errors(canonical, obligation, label)
            )
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
        rationale = row.get("reconciliation_rationale")
        if not isinstance(rationale, str) or not rationale.strip():
            errors.append(f"{label}: reconciliation rationale must be a non-blank string")
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
        # Reuse this invocation's validated reconstruction when checking the
        # seal; rebuilding the same source comparison adds no assurance.
        return {
            "record": record,
            "reconciliation_scaffold_sha256": expected_reconciliation.get(
                "reconciliation_scaffold_sha256"
            ),
        }
    if reconciliation_path is None:
        write_json(package_dir / RECONCILIATION_FILE, reconciliation)
        write_json(package_dir / NEUTRAL_FILE, neutral)
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
        reconstructed = finalize_reconciliation(
            package_dir,
            reconciliation_path,
            neutral_path,
            _validate_only=True,
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return [f"reconciliation reconstruction failed: {exc}"]
    expected_record = reconstructed["record"]
    record = json.loads(record_path.read_text(encoding="utf-8"))
    if record != expected_record:
        errors.append("reconciled decision record differs from deterministic reconstruction")
    seal = json.loads(seal_path.read_text(encoding="utf-8"))
    expected_seal = {
        "kind": "gtm_reconciliation_seal",
        "schema_version": 1,
        "source_sha256": expected_record.get("source_sha256"),
        "audit_seal_sha256": expected_record.get("audit_seal_sha256"),
        "reconciliation_scaffold_sha256": reconstructed.get(
            "reconciliation_scaffold_sha256"
        ),
        "neutral_queue_sha256": expected_record.get("neutral_queue_sha256"),
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
    args = parser.parse_args()
    try:
        if args.command == "scaffold":
            result = scaffold_reconciliation(args.package_dir)
        else:
            result = finalize_reconciliation(args.package_dir)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"status": "blocked", "errors": [str(exc)]}))
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
