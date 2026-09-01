#!/usr/bin/env python3
"""Prove a reconciled GTM target state reaches a deterministic fixed point."""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from gtm_audit_contract import ACTIONABLE_DECISION_CLASSES, semantic_contract_errors
from gtm_canonical_scan import build_canonical_scan
from gtm_lib import as_list, file_sha256, stable_hash, write_json
from gtm_obligation_ledger import build_obligation_ledger
from gtm_operation_model import (
    apply_operations,
    dependency_order,
    merge_exact_operation_ids,
    normalize_operation,
    operation_packet_sha256,
    operation_write_conflicts,
    validate_operations,
)
from gtm_projection_review import (
    CLOSURE_FILE,
    CLOSURE_SEAL_FILE,
    prepare_projection_reviews,
)
from gtm_scan_assurance import assure_scan

FIXED_POINT_ROOT = "fixed-point"
STATE_FILE = "state.json"
PROOF_FILE = "fixed-point-proof.json"
SEAL_FILE = "fixed-point-seal.json"
PROJECTION_DECISIONS_FILE = "projection-decisions.json"
MAX_CYCLES = 3


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


def _candidate_records(scan: dict[str, Any]) -> list[dict[str, Any]]:
    records = []
    sources = (
        (
            "operational",
            as_list((scan.get("operational_evidence") or {}).get("candidates")),
            "finding_id",
        ),
        (
            "optimisation",
            as_list((scan.get("optimization_facts") or {}).get("optimization_candidates")),
            "candidate_id",
        ),
        (
            "relationship",
            as_list((scan.get("architecture_evidence") or {}).get("relationships")),
            "comparison_id",
        ),
        (
            "family",
            as_list((scan.get("architecture_evidence") or {}).get("families")),
            "family_id",
        ),
    )
    for owner, rows, id_field in sources:
        for row in rows:
            if not isinstance(row, dict):
                continue
            records.append(
                {
                    "owner": owner,
                    "candidate_id": str(row.get(id_field) or ""),
                    "candidate_sha256": stable_hash(row, 64),
                }
            )
    return sorted(
        records,
        key=lambda value: (value["owner"], value["candidate_id"], value["candidate_sha256"]),
    )


def _semantic_obligation_sha256(obligation: dict[str, Any]) -> str:
    """Hash audit meaning while excluding source-file serialization provenance."""

    comparable = {
        key: value
        for key, value in obligation.items()
        if key not in {"obligation_sha256", "evidence_sha256"}
    }
    evidence = comparable.get("evidence")
    if isinstance(evidence, dict):
        comparable["evidence"] = {
            key: value for key, value in evidence.items() if key != "source_sha256"
        }
    return stable_hash(comparable, 64)


def _projection_hashes(
    projected: dict[str, Any],
    scan: dict[str, Any],
    assurance: dict[str, Any],
    ledger: dict[str, Any],
    decisions: list[dict[str, Any]],
    packet: dict[str, Any],
) -> dict[str, str]:
    return {
        "projected_graph_sha256": stable_hash(projected, 64),
        "scan_fact_sha256": str(scan.get("canonical_scan_sha256") or ""),
        "scan_assurance_sha256": str(assurance.get("scan_assurance_sha256") or ""),
        "obligation_set_sha256": stable_hash(
            sorted(
                (
                    str(row.get("obligation_id") or ""),
                    _semantic_obligation_sha256(row),
                )
                for row in as_list(ledger.get("obligations"))
            ),
            64,
        ),
        "relationship_candidate_set_sha256": stable_hash(
            _candidate_records(scan), 64
        ),
        "decision_set_sha256": stable_hash(
            sorted(
                (
                    str(row.get("canonical_decision_id") or ""),
                    stable_hash(row.get("decision") or {}, 64),
                )
                for row in decisions
            ),
            64,
        ),
        "operation_packet_sha256": str(
            packet.get("operation_packet_sha256") or ""
        ),
    }


def _provided_context(package_dir: Path) -> dict[str, Any]:
    path = package_dir / "context.json"
    if not path.is_file():
        return {}
    return dict(_load(path).get("provided_context") or {})


def _approved_requirements(package_dir: Path) -> dict[str, Any]:
    path = package_dir / "approved-requirements.json"
    return _load(path) if path.is_file() else {}


def _build_projection_artifacts(
    package_dir: Path,
    output_dir: Path,
    projected: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    projected_path = output_dir / "projected-container.json"
    write_json(projected_path, projected)
    result = build_canonical_scan(
        projected_path,
        provided_context=_provided_context(package_dir),
        approved_requirements=_approved_requirements(package_dir),
    )
    scan = result["canonical_scan"]
    registry = (
        Path(__file__).resolve().parents[1]
        / "references"
        / "03-rules"
        / "vendor-registry.toml"
    )
    assurance = assure_scan(
        projected_path,
        scan,
        vendor_registry_path=registry,
    )
    if assurance.get("status") != "pass":
        failed = [
            str(row.get("check_id") or "unknown")
            for row in as_list(assurance.get("checks"))
            if row.get("status") != "pass"
        ]
        raise ValueError(
            "projected scan assurance failed: " + ", ".join(sorted(failed))
        )
    requirements = _approved_requirements(package_dir)
    ledger = build_obligation_ledger(scan, assurance, requirements)
    write_json(output_dir / "canonical-scan.json", scan)
    write_json(output_dir / "scan-assurance.json", assurance)
    write_json(output_dir / "obligation-ledger.json", ledger)
    return scan, assurance, ledger


def _projection_delta(
    cycle_number: int,
    previous_ledger: dict[str, Any],
    current_ledger: dict[str, Any],
    scan: dict[str, Any],
    assurance: dict[str, Any],
) -> dict[str, Any]:
    previous = {
        str(row.get("obligation_id") or ""): row
        for row in as_list(previous_ledger.get("obligations"))
        if isinstance(row, dict)
    }
    current = {
        str(row.get("obligation_id") or ""): row
        for row in as_list(current_ledger.get("obligations"))
        if isinstance(row, dict)
    }
    rows = []
    for obligation_id in sorted(current):
        row = current[obligation_id]
        prior = previous.get(obligation_id)
        if prior and _semantic_obligation_sha256(prior) == _semantic_obligation_sha256(row):
            continue
        rows.append(
            {
                **row,
                "projection_delta_class": "changed" if prior else "new",
                "prior_obligation_sha256": (
                    str(prior.get("obligation_sha256") or "") if prior else ""
                ),
            }
        )
    retired = [
        {
            "obligation_id": obligation_id,
            "prior_obligation_sha256": previous[obligation_id].get(
                "obligation_sha256"
            ),
            "subject_keys": previous[obligation_id].get("subject_keys", []),
            "retirement_basis": "absent_from_complete_projected_obligation_graph",
        }
        for obligation_id in sorted(set(previous) - set(current))
    ]
    payload = {
        "kind": "gtm_projection_obligation_delta",
        "schema_version": 1,
        "cycle_number": cycle_number,
        "source_sha256": scan.get("source_sha256"),
        "canonical_scan_sha256": scan.get("canonical_scan_sha256"),
        "scan_assurance_sha256": assurance.get("scan_assurance_sha256"),
        "previous_obligation_ledger_sha256": previous_ledger.get(
            "obligation_ledger_sha256"
        ),
        "current_obligation_ledger_sha256": current_ledger.get(
            "obligation_ledger_sha256"
        ),
        "obligations": rows,
        "retired_obligations": retired,
        "counts": {
            "new": sum(row["projection_delta_class"] == "new" for row in rows),
            "changed": sum(
                row["projection_delta_class"] == "changed" for row in rows
            ),
            "retired": len(retired),
        },
    }
    payload["projection_obligation_set_sha256"] = stable_hash(
        {
            "obligations": [
                (
                    row.get("obligation_id"),
                    row.get("obligation_sha256"),
                    row.get("projection_delta_class"),
                )
                for row in rows
            ],
            "retired_obligations": retired,
        },
        64,
    )
    return payload


def _base_decisions(package_dir: Path) -> list[dict[str, Any]]:
    return as_list(_load(package_dir / "reconciled-decisions.json").get("canonical_decisions"))


def _projection_decisions(package_dir: Path) -> list[dict[str, Any]]:
    path = package_dir / FIXED_POINT_ROOT / PROJECTION_DECISIONS_FILE
    if not path.is_file():
        return []
    return as_list(_load(path).get("canonical_decisions"))


def _all_decisions(package_dir: Path) -> list[dict[str, Any]]:
    return [*_base_decisions(package_dir), *_projection_decisions(package_dir)]


def _operation_source_errors(
    packet: dict[str, Any], decisions: list[dict[str, Any]]
) -> list[str]:
    valid_ids = {
        str(row.get("canonical_decision_id") or "")
        for row in decisions
        if str(row.get("canonical_decision_id") or "")
    }
    errors = []
    for operation in as_list(packet.get("operations")):
        operation_id = str(operation.get("operation_id") or "")
        sources = {
            str(value)
            for value in as_list(operation.get("source_reconciled_decision_ids"))
        }
        if not sources or sources - valid_ids:
            errors.append(
                f"{operation_id}: operation no longer resolves every source decision"
            )
    return errors


def _cycle_directory(package_dir: Path, cycle_number: int) -> Path:
    return package_dir / FIXED_POINT_ROOT / f"cycle-{cycle_number:02d}"


def _create_cycle(
    package_dir: Path,
    cycle_number: int,
    packet: dict[str, Any],
    previous_ledger: dict[str, Any],
) -> dict[str, Any]:
    cycle_dir = _cycle_directory(package_dir, cycle_number)
    if cycle_dir.exists():
        raise ValueError(f"fixed-point cycle {cycle_number} already exists")
    cycle_dir.mkdir(parents=True)
    source = _load(package_dir / "locked-source.json")
    operations = as_list(packet.get("operations"))
    errors = validate_operations(
        source,
        operations,
        do_not_touch={
            str(value)
            for value in as_list(
                (_load(package_dir / "context.json").get("context") or {}).get(
                    "do_not_touch"
                )
            )
        },
    )
    errors.extend(operation_write_conflicts(operations))
    errors.extend(_operation_source_errors(packet, _all_decisions(package_dir)))
    if errors:
        raise ValueError("fixed-point operation gate failed: " + "; ".join(errors))
    projected = apply_operations(source, operations)
    scan, assurance, ledger = _build_projection_artifacts(
        package_dir, cycle_dir, projected
    )
    delta = _projection_delta(
        cycle_number, previous_ledger, ledger, scan, assurance
    )
    write_json(cycle_dir / "projection-obligations.json", delta)
    decisions = _all_decisions(package_dir)
    hashes = _projection_hashes(
        projected, scan, assurance, ledger, decisions, packet
    )
    state = {
        "kind": "gtm_fixed_point_cycle",
        "schema_version": 1,
        "cycle_number": cycle_number,
        "status": (
            "awaiting_projection_reviews"
            if as_list(delta.get("obligations"))
            else "stable_candidate"
        ),
        "hashes": hashes,
        "projection_obligation_set_sha256": delta.get(
            "projection_obligation_set_sha256"
        ),
        "counts": delta.get("counts", {}),
        "invariants": {
            "started_from_locked_original": True,
            "complete_packet_applied_in_dependency_order": True,
            "global_canonical_scan_passed": True,
            "independent_scan_assurance_passed": True,
            "prior_operations_resolve_source_decisions": True,
        },
    }
    state["cycle_state_sha256"] = _hash_without(state, "cycle_state_sha256")
    write_json(cycle_dir / "cycle-state.json", state)
    review = prepare_projection_reviews(cycle_dir, cycle_number, delta)
    state["projection_review_status"] = review.get("status")
    state["cycle_state_sha256"] = _hash_without(state, "cycle_state_sha256")
    write_json(cycle_dir / "cycle-state.json", state)
    return state


def _global_state(package_dir: Path) -> dict[str, Any]:
    return _load(package_dir / FIXED_POINT_ROOT / STATE_FILE)


def _write_global_state(package_dir: Path, state: dict[str, Any]) -> None:
    state["state_sha256"] = _hash_without(state, "state_sha256")
    write_json(package_dir / FIXED_POINT_ROOT / STATE_FILE, state)


def _packet_errors(package_dir: Path, packet: dict[str, Any]) -> list[str]:
    errors = []
    source_path = package_dir / "locked-source.json"
    if packet.get("source_sha256") != file_sha256(source_path):
        errors.append("operation packet source identity differs from locked original")
    if packet.get("operation_packet_sha256") != operation_packet_sha256(
        as_list(packet.get("operations"))
    ):
        errors.append("operation packet content hash is invalid")
    if packet.get("status") not in {
        "ready_for_fixed_point_projection",
        "fixed_point_iteration",
    }:
        errors.append("operation packet is not ready for fixed-point projection")
    return errors


def fixed_point_seal_errors(package_dir: Path) -> list[str]:
    """Verify the immutable proof, replay target, and fixed-point seal."""

    root = package_dir / FIXED_POINT_ROOT
    proof_path = root / PROOF_FILE
    seal_path = root / SEAL_FILE
    replay_path = root / "replay" / "projected-container.json"
    packet_path = package_dir / "operation-packet.json"
    if not all(path.is_file() for path in (proof_path, seal_path, replay_path, packet_path)):
        return ["fixed-point proof, seal, replay target, or operation packet is missing"]
    proof = _load(proof_path)
    seal = _load(seal_path)
    errors = []
    if proof.get("status") != "pass":
        errors.append("fixed-point proof did not pass")
    if proof.get("fixed_point_proof_sha256") != stable_hash(
        {key: value for key, value in proof.items() if key != "fixed_point_proof_sha256"},
        64,
    ):
        errors.append("fixed-point proof content hash is invalid")
    if seal.get("fixed_point_seal_sha256") != _hash_without(
        seal, "fixed_point_seal_sha256"
    ):
        errors.append("fixed-point seal content hash is invalid")
    if seal.get("fixed_point_proof_file_sha256") != file_sha256(proof_path):
        errors.append("fixed-point proof changed after sealing")
    if seal.get("stable_projected_container_sha256") != file_sha256(replay_path):
        errors.append("stable projected container changed after sealing")
    if seal.get("operation_packet_file_sha256") != file_sha256(packet_path):
        errors.append("operation packet changed after fixed-point sealing")
    if seal.get("validator_status") != "pass":
        errors.append("fixed-point seal validator did not pass")
    return errors


def start_fixed_point(package_dir: Path) -> dict[str, Any]:
    root = package_dir / FIXED_POINT_ROOT
    if root.exists():
        raise ValueError("fixed-point proof already exists; artifacts are never overwritten")
    required = (
        "locked-source.json",
        "obligation-ledger.json",
        "reconciled-decisions.json",
        "reconciliation-seal.json",
        "operation-packet.json",
    )
    missing = [name for name in required if not (package_dir / name).is_file()]
    if missing:
        raise ValueError("fixed-point prerequisites are missing: " + ", ".join(missing))
    packet = _load(package_dir / "operation-packet.json")
    errors = _packet_errors(package_dir, packet)
    if errors:
        raise ValueError("operation packet gate failed: " + "; ".join(errors))
    root.mkdir()
    projection_decisions = {
        "kind": "gtm_projection_canonical_decisions",
        "schema_version": 1,
        "canonical_decisions": [],
    }
    projection_decisions["projection_decisions_sha256"] = stable_hash(
        projection_decisions, 64
    )
    write_json(root / PROJECTION_DECISIONS_FILE, projection_decisions)
    cycle = _create_cycle(
        package_dir,
        1,
        packet,
        _load(package_dir / "obligation-ledger.json"),
    )
    state = {
        "kind": "gtm_fixed_point_state",
        "schema_version": 1,
        "status": cycle["status"],
        "max_cycles": MAX_CYCLES,
        "current_cycle": 1,
        "cycle_history": [
            {
                "cycle_number": 1,
                "cycle_state_sha256": cycle["cycle_state_sha256"],
                "hashes": cycle["hashes"],
                "status": cycle["status"],
            }
        ],
    }
    _write_global_state(package_dir, state)
    if cycle["status"] == "stable_candidate":
        return _seal_stable_fixed_point(package_dir, state, cycle)
    return {
        "status": cycle["status"],
        "cycle": 1,
        "new_or_changed_obligations": sum(
            int(value) for key, value in cycle["counts"].items() if key != "retired"
        ),
    }


def _closure_errors(cycle_dir: Path) -> tuple[dict[str, Any], list[str]]:
    closure_path = cycle_dir / CLOSURE_FILE
    seal_path = cycle_dir / CLOSURE_SEAL_FILE
    if not closure_path.is_file() or not seal_path.is_file():
        return {}, ["sealed projection closure is missing"]
    closure = _load(closure_path)
    seal = _load(seal_path)
    errors = []
    if seal.get("projection_closure_seal_sha256") != _hash_without(
        seal, "projection_closure_seal_sha256"
    ):
        errors.append("projection closure seal hash is invalid")
    if seal.get("projection_closure_file_sha256") != file_sha256(closure_path):
        errors.append("projection closure changed after sealing")
    if seal.get("projection_closure_sha256") != closure.get(
        "projection_closure_sha256"
    ):
        errors.append("projection closure seal is bound to another record")
    return closure, errors


def _append_projection_decisions(
    package_dir: Path, cycle_number: int, closure: dict[str, Any]
) -> list[dict[str, Any]]:
    path = package_dir / FIXED_POINT_ROOT / PROJECTION_DECISIONS_FILE
    payload = _load(path)
    existing = as_list(payload.get("canonical_decisions"))
    existing_ids = {
        str(row.get("canonical_decision_id") or "") for row in existing
    }
    additions = []
    for row in as_list(closure.get("canonical_decisions")):
        decision_id = str(row.get("canonical_decision_id") or "")
        if not decision_id or decision_id in existing_ids:
            raise ValueError("projection canonical decision identity is blank or repeated")
        decision = row.get("decision") or {}
        errors = semantic_contract_errors(decision, decision_id)
        if errors:
            raise ValueError("projection canonical decision is invalid: " + "; ".join(errors))
        additions.append({**row, "owning_cycle": cycle_number})
    payload["canonical_decisions"] = [*existing, *additions]
    payload["projection_decisions_sha256"] = _hash_without(
        payload, "projection_decisions_sha256"
    )
    write_json(path, payload)
    return additions


def _packet_with_projection_operations(
    package_dir: Path,
    packet: dict[str, Any],
    decisions: list[dict[str, Any]],
) -> dict[str, Any]:
    new_operations = []
    for row in decisions:
        decision = row.get("decision") or {}
        if decision.get("decision_class") not in ACTIONABLE_DECISION_CLASSES:
            continue
        proposal = decision.get("operation_proposal")
        if not isinstance(proposal, dict):
            raise ValueError("actionable projection decision has no operation proposal")
        new_operations.append(
            normalize_operation(
                proposal,
                str(row.get("canonical_decision_id") or ""),
                decision,
            )
        )
    operations = merge_exact_operation_ids(
        [*as_list(packet.get("operations")), *new_operations]
    )
    errors = operation_write_conflicts(operations)
    errors.extend(validate_operations(_load(package_dir / "locked-source.json"), operations))
    if errors:
        raise ValueError(
            "projection operation cannot enter the packet: " + "; ".join(errors)
        )
    ordered = dependency_order(operations)
    reverse: dict[str, list[str]] = defaultdict(list)
    for operation in ordered:
        for dependency in as_list(operation.get("depends_on")):
            reverse[str(dependency)].append(str(operation.get("operation_id") or ""))
    updated = {
        **packet,
        "status": "fixed_point_iteration",
        "operations": ordered,
        "operation_order": [str(row.get("operation_id") or "") for row in ordered],
        "reverse_dependencies": dict(sorted(reverse.items())),
        "operation_packet_sha256": operation_packet_sha256(ordered),
    }
    mapping = dict(updated.get("decision_to_operation") or {})
    for operation in new_operations:
        for decision_id in as_list(operation.get("source_reconciled_decision_ids")):
            mapping[str(decision_id)] = str(operation.get("operation_id") or "")
    updated["decision_to_operation"] = mapping
    updated.pop("operation_record_sha256", None)
    updated["operation_record_sha256"] = stable_hash(updated, 64)
    write_json(package_dir / "operation-packet.json", updated)
    return updated


def _block_non_convergent(
    package_dir: Path, state: dict[str, Any], reason: str
) -> dict[str, Any]:
    state["status"] = "non_convergent_target_state"
    state["blocked_reason"] = reason
    _write_global_state(package_dir, state)
    proof = {
        "kind": "gtm_fixed_point_proof",
        "schema_version": 1,
        "status": "non_convergent_target_state",
        "max_cycles": MAX_CYCLES,
        "cycle_history": state.get("cycle_history", []),
        "blocked_reason": reason,
        "required_next_step": (
            "Correct the target architecture and reseal its owning semantic chain; "
            "do not drop obligations or loosen assurance."
        ),
    }
    proof["fixed_point_proof_sha256"] = stable_hash(proof, 64)
    write_json(package_dir / FIXED_POINT_ROOT / PROOF_FILE, proof)
    return {"status": "non_convergent_target_state", "reason": reason}


def _replay_projection(
    package_dir: Path, packet: dict[str, Any]
) -> tuple[dict[str, str], Path]:
    replay = package_dir / FIXED_POINT_ROOT / "replay"
    if replay.exists():
        raise ValueError("fixed-point replay directory already exists")
    replay.mkdir()
    source = _load(package_dir / "locked-source.json")
    projected = apply_operations(source, as_list(packet.get("operations")))
    scan, assurance, ledger = _build_projection_artifacts(
        package_dir, replay, projected
    )
    hashes = _projection_hashes(
        projected,
        scan,
        assurance,
        ledger,
        _all_decisions(package_dir),
        packet,
    )
    replay_record = {
        "kind": "gtm_fixed_point_deterministic_replay",
        "schema_version": 1,
        "hashes": hashes,
        "started_from_locked_original": True,
        "complete_packet_applied_in_dependency_order": True,
        "scan_assurance_status": assurance.get("status"),
    }
    replay_record["replay_record_sha256"] = stable_hash(replay_record, 64)
    write_json(replay / "replay-proof.json", replay_record)
    return hashes, replay


def _seal_stable_fixed_point(
    package_dir: Path,
    state: dict[str, Any],
    cycle: dict[str, Any],
) -> dict[str, Any]:
    packet = _load(package_dir / "operation-packet.json")
    replay_hashes, replay_dir = _replay_projection(package_dir, packet)
    if replay_hashes != cycle.get("hashes"):
        return _block_non_convergent(
            package_dir,
            state,
            "deterministic replay did not reproduce the stable cycle hash tuple",
        )
    state["status"] = "stable_replayed"
    state["stable_cycle"] = cycle.get("cycle_number")
    state["replay_record_sha256"] = _load(
        replay_dir / "replay-proof.json"
    ).get("replay_record_sha256")
    _write_global_state(package_dir, state)
    proof = {
        "kind": "gtm_fixed_point_proof",
        "schema_version": 1,
        "status": "pass",
        "termination_rule": (
            "No new or changed actionable obligation remained after at most three "
            "cycles, all bounded decisions remained explicit, scan assurance passed, "
            "and replay reproduced the complete stable hash tuple."
        ),
        "max_cycles": MAX_CYCLES,
        "completed_cycles": len(state.get("cycle_history", [])),
        "stable_cycle": cycle.get("cycle_number"),
        "stable_hashes": cycle.get("hashes"),
        "cycle_history": state.get("cycle_history", []),
        "replay_record_sha256": state.get("replay_record_sha256"),
        "operation_packet_sha256": packet.get("operation_packet_sha256"),
        "projection_decisions_sha256": _load(
            package_dir / FIXED_POINT_ROOT / PROJECTION_DECISIONS_FILE
        ).get("projection_decisions_sha256"),
    }
    proof["fixed_point_proof_sha256"] = stable_hash(proof, 64)
    proof_path = package_dir / FIXED_POINT_ROOT / PROOF_FILE
    write_json(proof_path, proof)
    seal = {
        "kind": "gtm_fixed_point_seal",
        "schema_version": 1,
        "status": "pass",
        "fixed_point_proof_sha256": proof["fixed_point_proof_sha256"],
        "fixed_point_proof_file_sha256": file_sha256(proof_path),
        "stable_projected_container_sha256": file_sha256(
            replay_dir / "projected-container.json"
        ),
        "operation_packet_file_sha256": file_sha256(
            package_dir / "operation-packet.json"
        ),
        "validator_status": "pass",
    }
    seal["fixed_point_seal_sha256"] = _hash_without(
        seal, "fixed_point_seal_sha256"
    )
    write_json(package_dir / FIXED_POINT_ROOT / SEAL_FILE, seal)
    return {
        "status": "pass",
        "stable_cycle": cycle.get("cycle_number"),
        "completed_cycles": proof["completed_cycles"],
        "fixed_point_seal_sha256": seal["fixed_point_seal_sha256"],
    }


def advance_fixed_point(package_dir: Path) -> dict[str, Any]:
    state = _global_state(package_dir)
    if state.get("status") in {"pass", "stable_replayed"}:
        raise ValueError("fixed-point proof is already complete")
    if state.get("status") == "non_convergent_target_state":
        raise ValueError("fixed-point proof is blocked as non_convergent_target_state")
    cycle_number = int(state.get("current_cycle") or 0)
    cycle_dir = _cycle_directory(package_dir, cycle_number)
    cycle = _load(cycle_dir / "cycle-state.json")
    if cycle.get("status") == "stable_candidate":
        return _seal_stable_fixed_point(package_dir, state, cycle)
    closure, errors = _closure_errors(cycle_dir)
    if errors:
        raise ValueError("projection closure gate failed: " + "; ".join(errors))
    additions = _append_projection_decisions(package_dir, cycle_number, closure)
    actionable = [
        row
        for row in additions
        if (row.get("decision") or {}).get("decision_class")
        in ACTIONABLE_DECISION_CLASSES
    ]
    packet = _load(package_dir / "operation-packet.json")
    if not actionable:
        final_hashes = _projection_hashes(
            _load(cycle_dir / "projected-container.json"),
            _load(cycle_dir / "canonical-scan.json"),
            _load(cycle_dir / "scan-assurance.json"),
            _load(cycle_dir / "obligation-ledger.json"),
            _all_decisions(package_dir),
            packet,
        )
        cycle["hashes"] = final_hashes
        cycle["status"] = "stable_candidate"
        cycle["projection_closure_sha256"] = closure.get(
            "projection_closure_sha256"
        )
        cycle["cycle_state_sha256"] = _hash_without(cycle, "cycle_state_sha256")
        write_json(cycle_dir / "cycle-state.json", cycle)
        state["cycle_history"][-1] = {
            "cycle_number": cycle_number,
            "cycle_state_sha256": cycle["cycle_state_sha256"],
            "hashes": cycle["hashes"],
            "status": cycle["status"],
        }
        return _seal_stable_fixed_point(package_dir, state, cycle)
    if cycle_number >= MAX_CYCLES:
        return _block_non_convergent(
            package_dir,
            state,
            "the third projection cycle produced a new or changed actionable obligation",
        )
    tuple_hash = stable_hash(cycle.get("hashes", {}), 64)
    previous_tuples = {
        stable_hash(row.get("hashes", {}), 64)
        for row in state.get("cycle_history", [])[:-1]
    }
    if tuple_hash in previous_tuples:
        return _block_non_convergent(
            package_dir,
            state,
            "a prior projection hash tuple recurred with an actionable obligation",
        )
    try:
        packet = _packet_with_projection_operations(package_dir, packet, actionable)
    except ValueError as exc:
        return _block_non_convergent(package_dir, state, str(exc))
    previous_ledger = _load(cycle_dir / "obligation-ledger.json")
    next_cycle = cycle_number + 1
    created = _create_cycle(
        package_dir, next_cycle, packet, previous_ledger
    )
    state["status"] = created["status"]
    state["current_cycle"] = next_cycle
    state["cycle_history"].append(
        {
            "cycle_number": next_cycle,
            "cycle_state_sha256": created["cycle_state_sha256"],
            "hashes": created["hashes"],
            "status": created["status"],
        }
    )
    _write_global_state(package_dir, state)
    if created["status"] == "stable_candidate":
        return _seal_stable_fixed_point(package_dir, state, created)
    return {
        "status": created["status"],
        "cycle": next_cycle,
        "new_or_changed_obligations": sum(
            int(value)
            for key, value in created["counts"].items()
            if key != "retired"
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    start = subparsers.add_parser("start")
    start.add_argument("package_dir", type=Path)
    advance = subparsers.add_parser("advance")
    advance.add_argument("package_dir", type=Path)
    status = subparsers.add_parser("status")
    status.add_argument("package_dir", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "start":
            result = start_fixed_point(args.package_dir)
        elif args.command == "advance":
            result = advance_fixed_point(args.package_dir)
        else:
            result = _global_state(args.package_dir)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"status": "blocked", "errors": [str(exc)]}))
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
