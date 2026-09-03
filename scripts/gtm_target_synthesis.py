#!/usr/bin/env python3
"""Compile exact operations from the sealed reconciled semantic record."""

from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

from gtm_audit_contract import ACTIONABLE_DECISION_CLASSES
from gtm_consent_model import normalized_context_hosts
from gtm_lib import (
    ID_KEYS,
    as_list,
    container_version,
    require_safe_package_root,
    stable_hash,
    write_json,
)
from gtm_operation_model import (
    _action_targets,
    apply_operations,
    dependency_order,
    merge_exact_operation_ids,
    normalize_operation,
    operation_packet_sha256,
    operation_write_conflicts,
    validate_operations,
)
from gtm_optimization_facts import (
    client_consent_gate_facts,
    trigger_control_fact,
)
from gtm_reconciliation import reconciliation_seal_errors
from gtm_shared_facts import effective_server_route_hosts_by_tag

OPERATION_PACKET_FILE = "operation-packet.json"


def operation_error_context(
    operations: list[dict[str, Any]], errors: list[str]
) -> list[str]:
    """Distinguish explicit owners, related action targets, and unresolved errors."""
    def mentions(error: str, identity: str) -> bool:
        return bool(identity and re.search(
            rf"(?<![\w-]){re.escape(identity)}(?![\w-])", error
        ))

    result = []
    for error in errors:
        owners = [
            row for row in operations
            if mentions(error, str(row.get("operation_id") or ""))
        ]
        explicit = bool(owners)
        if not explicit:
            for row in operations:
                targets = _action_targets(row)
                for creation in as_list(row.get("creations")):
                    if not isinstance(creation, dict):
                        continue
                    layer = str(creation.get("layer") or "")
                    obj = creation.get("object")
                    id_key = ID_KEYS.get(layer)
                    if id_key and isinstance(obj, dict) and obj.get(id_key):
                        targets.add(f"{layer}:{obj[id_key]}")
                if any(mentions(error, target) for target in targets):
                    owners.append(row)
        if not owners:
            result.append(
                f"{error} [packet-wide validation; operation ownership unresolved]"
            )
            continue
        operation_ids = sorted({str(row["operation_id"]) for row in owners})
        decision_ids = sorted({
            str(value) for row in owners
            for value in as_list(row.get("source_reconciled_decision_ids"))
        })
        operation_label = "packet operations" if explicit else "candidate operations (object match)"
        decision_label = "owning source decisions" if explicit else "candidate source decisions"
        uncertainty = "" if explicit else "; operation ownership unresolved"
        result.append(
            f"{error} [{operation_label}: {', '.join(operation_ids) or 'none'}; "
            f"{decision_label}: {', '.join(decision_ids) or 'none'}{uncertainty}]"
        )
    return result


def _trigger_facts_by_id(cv: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(trigger.get("triggerId") or ""): trigger_control_fact(trigger)
        for trigger in as_list(cv.get("trigger"))
        if isinstance(trigger, dict) and str(trigger.get("triggerId") or "")
    }


def _tags_by_id(cv: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(tag.get("tagId") or ""): tag
        for tag in as_list(cv.get("tag"))
        if isinstance(tag, dict) and str(tag.get("tagId") or "")
    }


def server_consent_gate_regression_errors(
    source: dict[str, Any],
    projected: dict[str, Any],
    context_record: dict[str, Any],
) -> list[str]:
    """Block removal of a visible client gate without approved downstream ownership."""

    source_cv = container_version(source)
    projected_cv = container_version(projected)
    source_triggers = _trigger_facts_by_id(source_cv)
    projected_triggers = _trigger_facts_by_id(projected_cv)
    source_routes = effective_server_route_hosts_by_tag(source_cv)
    projected_routes = effective_server_route_hosts_by_tag(projected_cv)
    projected_tags = _tags_by_id(projected_cv)
    context = context_record.get("context") or {}
    approved_hosts = set(
        normalized_context_hosts(as_list(context.get("server_consent_gating_hosts")))
    )
    errors: list[str] = []

    for tag_id, source_tag in _tags_by_id(source_cv).items():
        object_key = f"tag:{tag_id}"
        source_hosts = set(as_list(source_routes.get(object_key)))
        source_gate = client_consent_gate_facts(source_tag, source_triggers)
        if not source_gate["client_consent_gate_visible"]:
            continue

        projected_tag = projected_tags.get(tag_id)
        if projected_tag is None:
            continue
        projected_gate = client_consent_gate_facts(
            projected_tag,
            projected_triggers,
        )
        if projected_gate["client_consent_gate_visible"]:
            continue

        projected_hosts = set(as_list(projected_routes.get(object_key)))
        # A route can be introduced by the same operation packet that removes
        # the client gate.  Scope the fence to any source or projected server
        # route, then judge ownership against the complete projected topology.
        if not source_hosts and not projected_hosts:
            continue
        unapproved_hosts = projected_hosts - approved_hosts
        if projected_hosts and not unapproved_hosts:
            continue

        if projected_hosts:
            ownership_gap = (
                "unapproved projected route host(s): "
                + ", ".join(sorted(unapproved_hosts))
            )
        else:
            ownership_gap = "the projected tag has no downstream server route owner"
        errors.append(
            f"{object_key}: visible client consent gating would be removed while "
            f"{ownership_gap}; retain a client gate or lock approved ownership for "
            "every projected server route host"
        )
    return errors


def build_operation_packet_payloads(
    package_dir: Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Derive the only valid base operation packet from sealed reconciliation."""

    require_safe_package_root(package_dir)
    errors = reconciliation_seal_errors(package_dir)
    if errors:
        raise ValueError("; ".join(errors))
    source_path = package_dir / "locked-source.json"
    record_path = package_dir / "reconciled-decisions.json"
    context_path = package_dir / "context.json"
    source = json.loads(source_path.read_text(encoding="utf-8"))
    record = json.loads(record_path.read_text(encoding="utf-8"))
    context = json.loads(context_path.read_text(encoding="utf-8"))
    operations = []
    decision_to_operation: dict[str, str] = {}
    blocked_decisions = []
    for canonical in as_list(record.get("canonical_decisions")):
        if not isinstance(canonical, dict):
            continue
        canonical_id = str(canonical.get("canonical_decision_id") or "")
        decision = canonical.get("decision") or {}
        decision_class = str(decision.get("decision_class") or "")
        if decision_class in ACTIONABLE_DECISION_CLASSES:
            proposal = decision.get("operation_proposal")
            if not isinstance(proposal, dict):
                raise ValueError(f"{canonical_id} has no exact operation proposal")
            operation = normalize_operation(proposal, canonical_id, decision)
            operations.append(operation)
            decision_to_operation[canonical_id] = str(
                operation.get("operation_id") or ""
            )
        elif decision_class in {"owner_decision", "container_evidence_limit"}:
            blocked_decisions.append(
                {
                    "canonical_decision_id": canonical_id,
                    "decision_class": decision_class,
                    "subject_keys": canonical.get("subject_keys", []),
                    "next_step": decision.get("next_step"),
                }
            )
    try:
        operations = merge_exact_operation_ids(operations)
    except ValueError as exc:
        raise ValueError("; ".join(operation_error_context(operations, [str(exc)]))) from exc
    errors = operation_write_conflicts(operations)
    do_not_touch = {
        str(value)
        for value in as_list((context.get("context") or {}).get("do_not_touch"))
        if str(value)
    }
    errors.extend(validate_operations(source, operations, do_not_touch=do_not_touch))
    if errors:
        raise ValueError("operation safety gate failed: " + "; ".join(
            operation_error_context(operations, errors)
        ))
    ordered = dependency_order(operations)
    try:
        projected = apply_operations(source, ordered)
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("operation simulation failed: " + "; ".join(
            operation_error_context(ordered, [str(exc)])
        )) from exc
    gate_errors = server_consent_gate_regression_errors(source, projected, context)
    if gate_errors:
        raise ValueError("operation safety gate failed: " + "; ".join(
            operation_error_context(ordered, gate_errors)
        ))
    operation_ids = {str(row.get("operation_id") or "") for row in ordered}
    reverse_dependencies: dict[str, list[str]] = defaultdict(list)
    for operation in ordered:
        for dependency in as_list(operation.get("depends_on")):
            reverse_dependencies[str(dependency)].append(
                str(operation.get("operation_id") or "")
            )
    for operation in ordered:
        unknown = set(as_list(operation.get("depends_on"))) - operation_ids
        if unknown:
            raise ValueError(
                f"{operation.get('operation_id')}: unknown dependencies {sorted(unknown)}"
            )
    packet = {
        "kind": "gtm_reconciled_operation_packet",
        "schema_version": 1,
        "status": "ready_for_target_validation",
        "source_sha256": record.get("source_sha256"),
        "reconciled_record_sha256": record.get("reconciled_record_sha256"),
        "operations": ordered,
        "operation_order": [str(row.get("operation_id") or "") for row in ordered],
        "decision_to_operation": decision_to_operation,
        "blocked_decisions": blocked_decisions,
        "reverse_dependencies": dict(sorted(reverse_dependencies.items())),
        "operation_packet_sha256": operation_packet_sha256(ordered),
        "boundary": (
            "This is a static target-state packet for workbook delivery. It is not "
            "approval, an import, a GTM mutation request, or proof of execution."
        ),
    }
    packet["operation_record_sha256"] = stable_hash(packet, 64)
    return packet, projected


def compile_operation_packet(package_dir: Path) -> dict[str, Any]:
    require_safe_package_root(package_dir)
    packet_path = package_dir / OPERATION_PACKET_FILE
    if packet_path.exists():
        raise ValueError("operation packet outputs already exist and are never overwritten")
    packet, projected = build_operation_packet_payloads(package_dir)
    write_json(packet_path, packet)
    return {
        "status": "pass",
        "operations": len(as_list(packet.get("operations"))),
        "blocked_decisions": len(as_list(packet.get("blocked_decisions"))),
        "operation_packet_sha256": packet["operation_packet_sha256"],
        "projected_container_sha256": stable_hash(projected, 64),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("package_dir", type=Path)
    args = parser.parse_args()
    try:
        result = compile_operation_packet(args.package_dir)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"status": "blocked", "errors": [str(exc)]}))
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
