#!/usr/bin/env python3
"""Prove a reconciled GTM target state reaches a deterministic fixed point."""

from __future__ import annotations

import argparse
import json
import re
import shutil
import tempfile
from collections import defaultdict
from pathlib import Path
from typing import Any

from gtm_audit_contract import ACTIONABLE_DECISION_CLASSES, semantic_contract_errors
from gtm_canonical_scan import build_canonical_scan
from gtm_lib import as_list, file_sha256, require_safe_package_root, stable_hash, write_json
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
    PRIOR_CYCLE_DIRECTORY,
    _sealed_review_errors,
    prepare_projection_reviews,
    projection_closure_seal_errors,
)
from gtm_scan_assurance import assure_scan
from gtm_target_synthesis import (
    build_operation_packet_payloads,
    server_consent_gate_regression_errors,
)

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


def _semantic_repair_evidence(package_dir: Path) -> dict[str, Any]:
    path = package_dir / "semantic-repair-evidence.json"
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
    ledger = build_obligation_ledger(
        scan,
        assurance,
        requirements,
        _semantic_repair_evidence(package_dir),
    )
    write_json(output_dir / "canonical-scan.json", scan)
    write_json(output_dir / "scan-assurance.json", assurance)
    write_json(output_dir / "obligation-ledger.json", ledger)
    return scan, assurance, ledger


def _relocated_obligation_hash(
    obligation: dict[str, Any], positions: dict[str, str]
) -> str:
    """Compare evidence by object identity without changing stored provenance."""
    path_fields = {
        "source_json_path", "json_path", "source_reference_path",
        "source_coordinates", "source_json_paths",
    }

    def relocate(value: Any, field: str = "") -> Any:
        if isinstance(value, dict):
            result = {key: relocate(child, key) for key, child in value.items()}
            # The ledger adds review_area_ids after hashing the scan topology.
            # Retain malformed/opaque digests so they cannot hide a difference.
            digest = value.get("control_topology_sha256")
            if digest and digest == _hash_without(
                value, "control_topology_sha256", "review_area_ids"
            )[:32]:
                result["control_topology_sha256"] = _hash_without(
                    result, "control_topology_sha256", "review_area_ids"
                )[:32]
            return result
        if isinstance(value, list):
            result = [relocate(child, field) for child in value]
            if field in {"source_coordinates", "source_json_paths"}:
                return sorted(result)
            return result
        if isinstance(value, str) and (
            field in path_fields or field.endswith("_evidence_anchors")
        ):
            match = re.match(r"^(\$(?:\.containerVersion)?\.[A-Za-z]+\[\d+\])(?=\.|\[|$)", value)
            if match and match[1] in positions:
                return positions[match[1]] + value[len(match[1]):]
        return value

    comparable = relocate(obligation)
    comparable.pop("obligation_id", None)
    return _semantic_obligation_sha256(comparable)


def _object_positions(scan: dict[str, Any]) -> dict[str, str]:
    """Use only unambiguous scan-owned object coordinates."""
    rows = as_list(scan.get("objects"))
    keys = [row.get("object_key") for row in rows]
    paths = [row.get("source_json_path") for row in rows]
    if len(set(keys)) != len(keys) or len(set(paths)) != len(paths):
        raise ValueError("projection comparison requires unique object identities and paths")
    return {
        row["source_json_path"]: "@" + row["object_key"]
        for row in rows
        if row.get("source_json_path") and row.get("object_key")
    }


def _projection_delta(
    cycle_number: int,
    previous_ledger: dict[str, Any],
    current_ledger: dict[str, Any],
    scan: dict[str, Any],
    assurance: dict[str, Any],
    previous_scan: dict[str, Any],
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
    prior_positions = _object_positions(previous_scan)
    current_positions = _object_positions(scan)
    previous_meanings: dict[str, list[str]] = defaultdict(list)
    current_meanings: dict[str, list[str]] = defaultdict(list)
    for identity, row in previous.items():
        previous_meanings[_relocated_obligation_hash(row, prior_positions)].append(identity)
    for identity, row in current.items():
        current_meanings[_relocated_obligation_hash(row, current_positions)].append(identity)
    unchanged = {
        current_ids[0]: previous_meanings[meaning][0]
        for meaning, current_ids in current_meanings.items()
        if len(current_ids) == 1 and len(previous_meanings.get(meaning, [])) == 1
    }
    rows = []
    for obligation_id in sorted(current):
        row = current[obligation_id]
        prior = previous.get(obligation_id)
        if prior and _semantic_obligation_sha256(prior) == _semantic_obligation_sha256(row):
            continue
        if obligation_id in unchanged:
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
        for obligation_id in sorted(set(previous) - set(current) - set(unchanged.values()))
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


def _projection_decisions(
    package_dir: Path, payload: dict[str, Any] | None = None
) -> list[dict[str, Any]]:
    if payload is not None:
        return as_list(payload.get("canonical_decisions"))
    path = package_dir / FIXED_POINT_ROOT / PROJECTION_DECISIONS_FILE
    if not path.is_file():
        return []
    return as_list(_load(path).get("canonical_decisions"))


def _all_decisions(
    package_dir: Path, projection_payload: dict[str, Any] | None = None
) -> list[dict[str, Any]]:
    return [
        *_base_decisions(package_dir),
        *_projection_decisions(package_dir, projection_payload),
    ]


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
    *,
    cycle_dir: Path | None = None,
    decisions: list[dict[str, Any]] | None = None,
    prior_cycle_dir: Path | None = None,
) -> dict[str, Any]:
    cycle_dir = cycle_dir or _cycle_directory(package_dir, cycle_number)
    if cycle_dir.exists() and any(cycle_dir.iterdir()):
        raise ValueError(f"fixed-point cycle {cycle_number} already exists")
    source = _load(package_dir / "locked-source.json")
    operations = as_list(packet.get("operations"))
    decision_rows = decisions if decisions is not None else _all_decisions(package_dir)
    context_record = _load(package_dir / "context.json")
    errors = validate_operations(
        source,
        operations,
        do_not_touch={
            str(value)
            for value in as_list(
                (context_record.get("context") or {}).get(
                    "do_not_touch"
                )
            )
        },
    )
    errors.extend(operation_write_conflicts(operations))
    errors.extend(_operation_source_errors(packet, decision_rows))
    if errors:
        raise ValueError("fixed-point operation gate failed: " + "; ".join(errors))
    projected = apply_operations(source, operations)
    consent_errors = server_consent_gate_regression_errors(
        source, projected, context_record
    )
    if consent_errors:
        raise ValueError(
            "fixed-point consent ownership gate failed: "
            + "; ".join(consent_errors)
        )
    cycle_dir.mkdir(parents=True, exist_ok=True)
    scan, assurance, ledger = _build_projection_artifacts(
        package_dir, cycle_dir, projected
    )
    delta = _projection_delta(
        cycle_number, previous_ledger, ledger, scan, assurance,
        _load(
            (package_dir if cycle_number == 1 else _cycle_directory(package_dir, cycle_number - 1))
            / "canonical-scan.json"
        ),
    )
    write_json(cycle_dir / "projection-obligations.json", delta)
    hashes = _projection_hashes(
        projected, scan, assurance, ledger, decision_rows, packet
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
    if prior_cycle_dir is not None:
        state["scan_repair"] = {
            "prior_cycle_state_sha256": _load(prior_cycle_dir / "cycle-state.json")["cycle_state_sha256"],
            "prior_review_seal_sha256": {
                review_id: _load(prior_cycle_dir / "review-seals" / f"{review_id}.json")["review_seal_sha256"]
                for review_id in ("review-a", "review-b")
            },
        }
    state["cycle_state_sha256"] = _hash_without(state, "cycle_state_sha256")
    write_json(cycle_dir / "cycle-state.json", state)
    if prior_cycle_dir is not None:
        shutil.copytree(prior_cycle_dir, cycle_dir / PRIOR_CYCLE_DIRECTORY)
    review = prepare_projection_reviews(cycle_dir, cycle_number, delta)
    state["projection_review_status"] = review.get("status")
    state["cycle_state_sha256"] = _hash_without(state, "cycle_state_sha256")
    write_json(cycle_dir / "cycle-state.json", state)
    return state


def _global_state(package_dir: Path) -> dict[str, Any]:
    require_safe_package_root(package_dir)
    return _load(package_dir / FIXED_POINT_ROOT / STATE_FILE)


def _write_global_state(package_dir: Path, state: dict[str, Any]) -> None:
    state["state_sha256"] = _hash_without(state, "state_sha256")
    write_json(package_dir / FIXED_POINT_ROOT / STATE_FILE, state)


def _packet_errors(package_dir: Path, packet: dict[str, Any]) -> list[str]:
    errors: list[str] = []
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
    try:
        expected_packet, expected_initial_projection = build_operation_packet_payloads(
            package_dir
        )
        projection_rows = [
            row
            for row in _projection_decisions(package_dir)
            if isinstance(row, dict)
            and (row.get("decision") or {}).get("decision_class")
            in ACTIONABLE_DECISION_CLASSES
        ]
        if projection_rows:
            expected_packet = _packet_with_projection_operations(
                package_dir, expected_packet, projection_rows
            )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        errors.append(f"operation packet reconstruction failed: {exc}")
        return errors
    if packet != expected_packet:
        errors.append("operation packet differs from sealed semantic reconstruction")
    initial_projection_path = package_dir / "projected-container.json"
    if not initial_projection_path.is_file():
        errors.append("initial projected container is missing")
    elif _load(initial_projection_path) != expected_initial_projection:
        errors.append("initial projected container differs from base packet reconstruction")
    return errors


def fixed_point_seal_errors(package_dir: Path) -> list[str]:
    """Verify the immutable proof, replay target, and fixed-point seal."""

    require_safe_package_root(package_dir)
    root = package_dir / FIXED_POINT_ROOT
    proof_path = root / PROOF_FILE
    seal_path = root / SEAL_FILE
    replay_root = root / "replay"
    replay_path = replay_root / "projected-container.json"
    replay_proof_path = replay_root / "replay-proof.json"
    packet_path = package_dir / "operation-packet.json"
    state_path = root / STATE_FILE
    decisions_path = root / PROJECTION_DECISIONS_FILE
    required = (
        proof_path,
        seal_path,
        replay_path,
        replay_proof_path,
        replay_root / "canonical-scan.json",
        replay_root / "scan-assurance.json",
        replay_root / "obligation-ledger.json",
        packet_path,
        state_path,
        decisions_path,
    )
    if not all(path.is_file() for path in required):
        return ["fixed-point proof, seal, replay target, or operation packet is missing"]
    proof = _load(proof_path)
    seal = _load(seal_path)
    packet = _load(packet_path)
    state = _load(state_path)
    projection_decisions = _load(decisions_path)
    errors = _packet_errors(package_dir, packet)
    if state.get("state_sha256") != _hash_without(state, "state_sha256"):
        errors.append("fixed-point global state content hash is invalid")
    stable_cycle = int(state.get("stable_cycle") or 0)
    cycle_path = _cycle_directory(package_dir, stable_cycle) / "cycle-state.json"
    if not stable_cycle or not cycle_path.is_file():
        errors.append("fixed-point stable cycle state is missing")
        cycle = {}
    else:
        cycle = _load(cycle_path)
        if cycle.get("cycle_state_sha256") != _hash_without(
            cycle, "cycle_state_sha256"
        ):
            errors.append("fixed-point stable cycle content hash is invalid")
    expected_history = []
    reconstructed_projection_rows: list[dict[str, Any]] = []
    for row in as_list(state.get("cycle_history")):
        cycle_number = int((row or {}).get("cycle_number") or 0)
        history_path = _cycle_directory(package_dir, cycle_number) / "cycle-state.json"
        if not cycle_number or not history_path.is_file():
            errors.append("fixed-point cycle history references a missing cycle")
            continue
        history_cycle = _load(history_path)
        if history_cycle.get("cycle_state_sha256") != _hash_without(
            history_cycle, "cycle_state_sha256"
        ):
            errors.append(f"fixed-point cycle {cycle_number} content hash is invalid")
        expected_history.append(
            {
                "cycle_number": cycle_number,
                "cycle_state_sha256": history_cycle.get("cycle_state_sha256"),
                "hashes": history_cycle.get("hashes"),
                "status": history_cycle.get("status"),
            }
        )
        closure_path = _cycle_directory(package_dir, cycle_number) / "projection-closure.json"
        if closure_path.is_file():
            closure, closure_errors = projection_closure_seal_errors(
                _cycle_directory(package_dir, cycle_number)
            )
            errors.extend(
                f"fixed-point cycle {cycle_number}: {error}"
                for error in closure_errors
            )
            reconstructed_projection_rows.extend(
                {**decision, "owning_cycle": cycle_number}
                for decision in as_list(closure.get("canonical_decisions"))
                if isinstance(decision, dict)
            )
    if as_list(state.get("cycle_history")) != expected_history:
        errors.append("fixed-point cycle history differs from exact cycle records")
    expected_projection_decisions = {
        "kind": "gtm_projection_canonical_decisions",
        "schema_version": 1,
        "canonical_decisions": reconstructed_projection_rows,
    }
    expected_projection_decisions["projection_decisions_sha256"] = _hash_without(
        expected_projection_decisions, "projection_decisions_sha256"
    )
    if projection_decisions != expected_projection_decisions:
        errors.append(
            "projection decisions differ from deterministic sealed-closure reconstruction"
        )
    try:
        source = _load(package_dir / "locked-source.json")
        projected = apply_operations(source, as_list(packet.get("operations")))
        with tempfile.TemporaryDirectory() as temporary:
            replay_candidate = Path(temporary)
            scan, assurance, ledger = _build_projection_artifacts(
                package_dir, replay_candidate, projected
            )
        expected_hashes = _projection_hashes(
            projected,
            scan,
            assurance,
            ledger,
            _all_decisions(package_dir),
            packet,
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        errors.append(f"fixed-point deterministic replay reconstruction failed: {exc}")
        expected_hashes = {}
        projected = {}
        scan = {}
        assurance = {}
        ledger = {}
    expected_replay = {
        "kind": "gtm_fixed_point_deterministic_replay",
        "schema_version": 1,
        "hashes": expected_hashes,
        "started_from_locked_original": True,
        "complete_packet_applied_in_dependency_order": True,
        "scan_assurance_status": assurance.get("status"),
    }
    expected_replay["replay_record_sha256"] = stable_hash(expected_replay, 64)
    replay_pairs = (
        ("projected container", projected, replay_path),
        ("canonical scan", scan, replay_root / "canonical-scan.json"),
        ("scan assurance", assurance, replay_root / "scan-assurance.json"),
        ("obligation ledger", ledger, replay_root / "obligation-ledger.json"),
        ("replay proof", expected_replay, replay_proof_path),
    )
    for label, expected_payload, actual_path in replay_pairs:
        if _load(actual_path) != expected_payload:
            errors.append(f"fixed-point replay {label} differs from reconstruction")
    expected_proof = {
        "kind": "gtm_fixed_point_proof",
        "schema_version": 1,
        "status": "pass",
        "termination_rule": (
            "No new or changed actionable obligation remained after at most three "
            "cycles, all bounded decisions remained explicit, scan assurance passed, "
            "and replay reproduced the complete stable hash tuple."
        ),
        "max_cycles": MAX_CYCLES,
        "completed_cycles": len(expected_history),
        "stable_cycle": stable_cycle,
        "stable_hashes": cycle.get("hashes"),
        "cycle_history": expected_history,
        "replay_record_sha256": expected_replay.get("replay_record_sha256"),
        "operation_packet_sha256": packet.get("operation_packet_sha256"),
        "projection_decisions_sha256": projection_decisions.get(
            "projection_decisions_sha256"
        ),
    }
    expected_proof["fixed_point_proof_sha256"] = stable_hash(expected_proof, 64)
    if proof != expected_proof:
        errors.append("fixed-point proof differs from deterministic reconstruction")
    expected_seal = {
        "kind": "gtm_fixed_point_seal",
        "schema_version": 1,
        "status": "pass",
        "fixed_point_proof_sha256": expected_proof.get("fixed_point_proof_sha256"),
        "fixed_point_proof_file_sha256": file_sha256(proof_path),
        "stable_projected_container_sha256": file_sha256(replay_path),
        "replay_proof_file_sha256": file_sha256(replay_proof_path),
        "replay_scan_file_sha256": file_sha256(replay_root / "canonical-scan.json"),
        "replay_assurance_file_sha256": file_sha256(
            replay_root / "scan-assurance.json"
        ),
        "replay_ledger_file_sha256": file_sha256(
            replay_root / "obligation-ledger.json"
        ),
        "operation_packet_file_sha256": file_sha256(packet_path),
        "projection_decisions_file_sha256": file_sha256(decisions_path),
        "state_file_sha256": file_sha256(state_path),
        "stable_cycle_state_file_sha256": (
            file_sha256(cycle_path) if cycle_path.is_file() else ""
        ),
        "validator_status": "pass",
    }
    expected_seal["fixed_point_seal_sha256"] = _hash_without(
        expected_seal, "fixed_point_seal_sha256"
    )
    if seal != expected_seal:
        errors.append("fixed-point seal differs from deterministic reconstruction")
    return errors


def start_fixed_point(package_dir: Path) -> dict[str, Any]:
    require_safe_package_root(package_dir)
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
    return projection_closure_seal_errors(cycle_dir)


def _projection_decision_candidate(
    package_dir: Path, cycle_number: int, closure: dict[str, Any]
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
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
    return payload, additions


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
    source = _load(package_dir / "locked-source.json")
    context_record = _load(package_dir / "context.json")
    errors.extend(
        validate_operations(
            source,
            operations,
            do_not_touch={
                str(value)
                for value in as_list(
                    (context_record.get("context") or {}).get("do_not_touch")
                )
            },
        )
    )
    errors.extend(
        server_consent_gate_regression_errors(
            source, apply_operations(source, operations), context_record
        )
    )
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
    return updated


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    """Replace one JSON artifact without exposing a partially written file."""

    temporary = path.with_name(f".{path.name}.next")
    try:
        write_json(temporary, payload)
        temporary.replace(path)
    finally:
        if temporary.exists():
            temporary.unlink()


def _commit_next_cycle(
    package_dir: Path,
    final_cycle_dir: Path,
    staged_cycle_dir: Path,
    projection_payload: dict[str, Any],
    packet: dict[str, Any],
    state: dict[str, Any],
) -> None:
    """Commit the candidate semantic state and cycle, restoring prior files on failure."""

    decisions_path = package_dir / FIXED_POINT_ROOT / PROJECTION_DECISIONS_FILE
    packet_path = package_dir / "operation-packet.json"
    state_path = package_dir / FIXED_POINT_ROOT / STATE_FILE
    prior_decisions = decisions_path.read_bytes()
    prior_packet = packet_path.read_bytes()
    prior_state = state_path.read_bytes()
    try:
        _atomic_write_json(decisions_path, projection_payload)
        _atomic_write_json(packet_path, packet)
        _atomic_write_json(state_path, state)
        staged_cycle_dir.replace(final_cycle_dir)
    except OSError:
        decisions_path.write_bytes(prior_decisions)
        packet_path.write_bytes(prior_packet)
        state_path.write_bytes(prior_state)
        raise


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
        "replay_proof_file_sha256": file_sha256(
            replay_dir / "replay-proof.json"
        ),
        "replay_scan_file_sha256": file_sha256(
            replay_dir / "canonical-scan.json"
        ),
        "replay_assurance_file_sha256": file_sha256(
            replay_dir / "scan-assurance.json"
        ),
        "replay_ledger_file_sha256": file_sha256(
            replay_dir / "obligation-ledger.json"
        ),
        "operation_packet_file_sha256": file_sha256(
            package_dir / "operation-packet.json"
        ),
        "projection_decisions_file_sha256": file_sha256(
            package_dir / FIXED_POINT_ROOT / PROJECTION_DECISIONS_FILE
        ),
        "state_file_sha256": file_sha256(
            package_dir / FIXED_POINT_ROOT / STATE_FILE
        ),
        "stable_cycle_state_file_sha256": file_sha256(
            _cycle_directory(package_dir, int(cycle.get("cycle_number") or 0))
            / "cycle-state.json"
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
    require_safe_package_root(package_dir)
    state = _global_state(package_dir)
    current_packet = _load(package_dir / "operation-packet.json")
    packet_errors = _packet_errors(package_dir, current_packet)
    if packet_errors:
        raise ValueError("operation packet gate failed: " + "; ".join(packet_errors))
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
    projection_payload, additions = _projection_decision_candidate(
        package_dir, cycle_number, closure
    )
    actionable = [
        row
        for row in additions
        if (row.get("decision") or {}).get("decision_class")
        in ACTIONABLE_DECISION_CLASSES
    ]
    packet = current_packet
    if not actionable:
        final_hashes = _projection_hashes(
            _load(cycle_dir / "projected-container.json"),
            _load(cycle_dir / "canonical-scan.json"),
            _load(cycle_dir / "scan-assurance.json"),
            _load(cycle_dir / "obligation-ledger.json"),
            _all_decisions(package_dir, projection_payload),
            packet,
        )
        _atomic_write_json(
            package_dir / FIXED_POINT_ROOT / PROJECTION_DECISIONS_FILE,
            projection_payload,
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
    previous_ledger = _load(cycle_dir / "obligation-ledger.json")
    next_cycle = cycle_number + 1
    final_cycle_dir = _cycle_directory(package_dir, next_cycle)
    if final_cycle_dir.exists():
        return _block_non_convergent(
            package_dir,
            state,
            f"fixed-point cycle {next_cycle} already exists",
        )
    staged_cycle_dir = Path(
        tempfile.mkdtemp(
            prefix=f".cycle-{next_cycle:02d}-",
            dir=package_dir / FIXED_POINT_ROOT,
        )
    )
    try:
        packet = _packet_with_projection_operations(
            package_dir, packet, actionable
        )
        created = _create_cycle(
            package_dir,
            next_cycle,
            packet,
            previous_ledger,
            cycle_dir=staged_cycle_dir,
            decisions=_all_decisions(package_dir, projection_payload),
        )
        next_state = {
            **state,
            "status": created["status"],
            "current_cycle": next_cycle,
            "cycle_history": [
                *as_list(state.get("cycle_history")),
                {
                    "cycle_number": next_cycle,
                    "cycle_state_sha256": created["cycle_state_sha256"],
                    "hashes": created["hashes"],
                    "status": created["status"],
                },
            ],
        }
        next_state["state_sha256"] = _hash_without(next_state, "state_sha256")
        _commit_next_cycle(
            package_dir,
            final_cycle_dir,
            staged_cycle_dir,
            projection_payload,
            packet,
            next_state,
        )
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
        if staged_cycle_dir.exists():
            shutil.rmtree(staged_cycle_dir)
        return _block_non_convergent(package_dir, state, str(exc))
    state = next_state
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


def repair_projection_scan(package_dir: Path, reason: str) -> dict[str, Any]:
    """Reopen only the current unfinished projection after a derived-scan fix."""
    require_safe_package_root(package_dir)
    if not reason.strip():
        raise ValueError("scan repair requires the concrete scanner correction reason")
    state = _global_state(package_dir)
    number = int(state.get("current_cycle") or 0)
    if state.get("status") != "awaiting_projection_reviews" or not 1 <= number <= MAX_CYCLES:
        raise ValueError("scan repair requires an unfinished current projection cycle")
    cycle = _cycle_directory(package_dir, number)
    if (cycle / "projection-closure-seal.json").exists() or (package_dir / "canonical-record-seal.json").exists():
        raise ValueError("scan repair cannot replace a sealed closure or canonical record")
    current_cycle = _load(cycle / "cycle-state.json")
    history = as_list(state.get("cycle_history"))
    if (state.get("state_sha256") != _hash_without(state, "state_sha256")
            or len(history) != number or history[-1].get("cycle_number") != number
            or history[-1].get("cycle_state_sha256") != current_cycle.get("cycle_state_sha256")
            or current_cycle.get("cycle_state_sha256") != _hash_without(current_cycle, "cycle_state_sha256")):
        raise ValueError("scan repair requires the exact current cycle and state history")
    packet = _load(package_dir / "operation-packet.json")
    errors = _packet_errors(package_dir, packet) + _sealed_review_errors(cycle)
    if errors:
        raise ValueError("scan repair predecessor gate failed: " + "; ".join(errors))
    projected = apply_operations(_load(package_dir / "locked-source.json"), packet["operations"])
    if projected != _load(cycle / "projected-container.json"):
        raise ValueError("scan repair cannot change the source or operation packet")
    previous = package_dir if number == 1 else _cycle_directory(package_dir, number - 1)
    root = package_dir / FIXED_POINT_ROOT
    staged = Path(tempfile.mkdtemp(prefix=f".cycle-{number:02d}-scan-repair-", dir=root))
    backup = staged.with_name(staged.name + "-previous")
    scratch = package_dir / "projection-scratch" / f"cycle-{number:02d}"
    state_path = root / STATE_FILE
    prior_state = state_path.read_bytes()
    rollback_failed = False
    try:
        created = _create_cycle(
            package_dir, number, packet, _load(previous / "obligation-ledger.json"),
            cycle_dir=staged, prior_cycle_dir=cycle,
        )
        if _load(staged / "canonical-scan.json") == _load(cycle / "canonical-scan.json"):
            raise ValueError("scan repair produced no corrected scan evidence")
        if created["status"] != "awaiting_projection_reviews":
            raise ValueError("corrected scan requires review before it can claim closure")
        snapshot = staged / PRIOR_CYCLE_DIRECTORY
        def hashes(directory: Path) -> dict[str, str]:
            return {str(path.relative_to(directory)): file_sha256(path)
                    for path in directory.rglob("*") if path.is_file()}
        if hashes(cycle) != hashes(snapshot):
            raise ValueError("projection predecessor changed while copying its snapshot")
        if scratch.exists():
            shutil.copytree(scratch, snapshot / "projection-scratch")
            if hashes(scratch) != hashes(snapshot / "projection-scratch"):
                raise ValueError("projection plans changed while copying their snapshot")
        created["scan_repair_reason"] = reason.strip()
        created["cycle_state_sha256"] = _hash_without(created, "cycle_state_sha256")
        write_json(staged / "cycle-state.json", created)
        next_state = {**state, "status": created["status"], "cycle_history": [
            *state["cycle_history"][:-1],
            {"cycle_number": number, "cycle_state_sha256": created["cycle_state_sha256"],
             "hashes": created["hashes"], "status": created["status"]},
        ]}
        next_state["state_sha256"] = _hash_without(next_state, "state_sha256")
        moved_cycle = moved_scratch = installed = False
        try:
            cycle.replace(backup)
            moved_cycle = True
            if scratch.exists():
                scratch.replace(backup / "projection-scratch")
                moved_scratch = True
            staged.replace(cycle)
            installed = True
            _atomic_write_json(state_path, next_state)
        except OSError:
            try:
                if installed:
                    cycle.replace(staged)
                if moved_scratch:
                    (backup / "projection-scratch").replace(scratch)
                if moved_cycle:
                    backup.replace(cycle)
                state_path.write_bytes(prior_state)
            except OSError as recovery_error:
                rollback_failed = True
                raise RuntimeError(f"scan repair rollback needs recovery; preserve {staged} and {backup}") from recovery_error
            raise
        # The exact predecessor and plans remain in cycle/prior-cycle.
        if hashes(backup) != hashes(cycle / PRIOR_CYCLE_DIRECTORY):
            raise RuntimeError(f"scan repair snapshot verification failed; preserve {backup}")
        require_safe_package_root(package_dir)
        shutil.rmtree(backup)
        retained_counts = {}
        for review_id in ("review-a", "review-b"):
            review = _load(cycle / "reviews" / review_id / "review.json")
            retained_counts[review_id] = sum(row["status"] == "complete" for row in review["decisions"])
        return {"status": "awaiting_projection_reviews", "cycle": number,
                "retained_decisions": retained_counts,
                "pending_decisions_per_review": len(review["decisions"]) - retained_counts["review-b"],
                "prior_cycle": str(cycle / PRIOR_CYCLE_DIRECTORY)}
    finally:
        if staged.exists() and not rollback_failed:
            require_safe_package_root(package_dir)
            shutil.rmtree(staged)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    start = subparsers.add_parser("start")
    start.add_argument("package_dir", type=Path)
    advance = subparsers.add_parser("advance")
    advance.add_argument("package_dir", type=Path)
    status = subparsers.add_parser("status")
    status.add_argument("package_dir", type=Path)
    repair = subparsers.add_parser("repair-scan")
    repair.add_argument("package_dir", type=Path)
    repair.add_argument("--reason", required=True)
    args = parser.parse_args()
    try:
        if args.command == "start":
            result = start_fixed_point(args.package_dir)
        elif args.command == "advance":
            result = advance_fixed_point(args.package_dir)
        elif args.command == "repair-scan":
            result = repair_projection_scan(args.package_dir, args.reason)
        else:
            result = _global_state(args.package_dir)
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"status": "blocked", "errors": [str(exc)]}))
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
