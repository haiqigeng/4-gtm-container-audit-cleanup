#!/usr/bin/env python3
"""Create and validate a row-level approval response for a GTM cleanup packet."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from gtm_lib import as_list, load_json, stable_hash, write_json

RESPONSE_KIND = "gtm_cleanup_approval_response"
RESPONSE_SCHEMA_VERSION = 1
ALLOWED_DECISIONS = {"Approve", "Reject", "Amend"}


def approval_packet_payload(packet: dict[str, Any]) -> dict[str, Any]:
    """Return the immutable approval surface, excluding its self-declared hash."""

    return {
        "kind": packet.get("kind"),
        "schema_version": packet.get("schema_version"),
        "source_sha256": packet.get("source_sha256"),
        "shared_facts_sha256": packet.get("shared_facts_sha256"),
        "context_sha256": packet.get("context_sha256"),
        "route": packet.get("route"),
        "plan_status": packet.get("plan_status"),
        "projected_object_counts": packet.get("projected_object_counts"),
        "measurement_preservation": packet.get("measurement_preservation"),
        "target_organization": packet.get("target_organization"),
        "decision_ledger": packet.get("decision_ledger"),
        "operations": packet.get("operations"),
    }


def approval_packet_sha256(packet: dict[str, Any]) -> str:
    return stable_hash(approval_packet_payload(packet), 64)


def approval_contract(packet: dict[str, Any]) -> dict[str, Any]:
    operations = as_list(packet.get("operations"))
    return {
        "schema_version": RESPONSE_SCHEMA_VERSION,
        "packet_sha256": approval_packet_sha256(packet),
        "response_kind": RESPONSE_KIND,
        "allowed_decisions": sorted(ALLOWED_DECISIONS),
        "required_columns": [
            "operation_id",
            "decision",
            "comment",
        ],
        "operation_ids": [
            str(operation.get("operation_id") or "") for operation in operations
        ],
        "instruction": (
            "Return one row per operation. Approve, Reject, or Amend each row; an "
            "Amend or Reject response needs a concrete comment. Risk confirmations "
            "remain separate explicit booleans and do not replace operation approval."
        ),
    }


def required_confirmation_fields(operation: dict[str, Any]) -> list[str]:
    safety = operation.get("execution_safety") or {}
    fields = []
    if safety.get("server_coupled"):
        fields.append("confirm_server_coupled")
    if (safety.get("configured_activation_risk") or {}).get("flag"):
        fields.append("confirm_activation_risk")
    if as_list(operation.get("deletions")) and (
        safety.get("decommission") or {}
    ).get("required"):
        fields.append("confirm_observation_complete")
    return fields


def response_template(packet: dict[str, Any]) -> dict[str, Any]:
    contract = packet.get("approval_contract") or approval_contract(packet)
    return {
        "kind": RESPONSE_KIND,
        "schema_version": RESPONSE_SCHEMA_VERSION,
        "source_sha256": str(packet.get("source_sha256") or ""),
        "packet_sha256": str(contract.get("packet_sha256") or ""),
        "responses": [
            {
                "operation_id": str(operation.get("operation_id") or ""),
                "operation_title": str(operation.get("title") or ""),
                "operation_sha256": stable_hash(operation, 64),
                "decision": "Pending",
                "comment": "",
                "confirm_server_coupled": False,
                "confirm_activation_risk": False,
                "confirm_observation_complete": False,
                "required_confirmations": required_confirmation_fields(operation),
            }
            for operation in as_list(packet.get("operations"))
        ],
    }


def validate_response(
    packet: dict[str, Any], response: dict[str, Any]
) -> tuple[dict[str, Any], list[str]]:
    errors: list[str] = []
    contract = packet.get("approval_contract") or {}
    calculated_hash = approval_packet_sha256(packet)
    if packet.get("kind") != "gtm_reconciled_operations":
        errors.append("cleanup packet kind is invalid")
    if packet.get("schema_version") != 4:
        errors.append("cleanup packet schema version is invalid")
    if packet.get("plan_status") != "complete":
        errors.append("cleanup packet is not approval-ready")
    if contract != approval_contract(packet):
        errors.append("cleanup packet approval contract is missing, changed, or unsupported")
    if response.get("kind") != RESPONSE_KIND:
        errors.append("approval response kind is invalid")
    if response.get("schema_version") != RESPONSE_SCHEMA_VERSION:
        errors.append("approval response schema version is invalid")
    if response.get("source_sha256") != packet.get("source_sha256"):
        errors.append("approval response source hash differs from the cleanup packet")
    if response.get("packet_sha256") != calculated_hash:
        errors.append("approval response targets another cleanup packet")

    raw_operations = as_list(packet.get("operations"))
    operation_ids = [
        str(operation.get("operation_id") or "")
        for operation in raw_operations
        if isinstance(operation, dict)
    ]
    if len(operation_ids) != len(raw_operations):
        errors.append("cleanup packet contains a malformed operation")
    if any(not value for value in operation_ids) or len(operation_ids) != len(
        set(operation_ids)
    ):
        errors.append("cleanup packet operation IDs must be unique and nonblank")
    operations = {
        str(operation.get("operation_id") or ""): operation
        for operation in raw_operations
        if isinstance(operation, dict)
        if str(operation.get("operation_id") or "")
    }
    raw_rows = as_list(response.get("responses"))
    rows = [row for row in raw_rows if isinstance(row, dict)]
    by_id = {str(row.get("operation_id") or ""): row for row in rows}
    if len(rows) != len(raw_rows):
        errors.append("approval response contains a malformed row")
    if len(by_id) != len(rows) or "" in by_id:
        errors.append("approval response operation IDs must be unique and nonblank")
    if set(by_id) != set(operations):
        errors.append("approval response must cover every packet operation exactly once")

    approved: list[str] = []
    rejected: list[str] = []
    amended: list[str] = []
    confirmations = {
        "server_coupled": [],
        "activation_risk": [],
        "observation_complete": [],
    }
    for operation_id, operation in operations.items():
        row = by_id.get(operation_id)
        if not row:
            continue
        if row.get("operation_sha256") != stable_hash(operation, 64):
            errors.append(f"{operation_id}: operation content hash differs from the packet")
        if as_list(row.get("required_confirmations")) != required_confirmation_fields(
            operation
        ):
            errors.append(f"{operation_id}: required confirmation list changed")
        decision = str(row.get("decision") or "")
        comment = " ".join(str(row.get("comment") or "").split())
        if decision not in ALLOWED_DECISIONS:
            errors.append(f"{operation_id}: decision must be Approve, Reject, or Amend")
            continue
        if decision in {"Reject", "Amend"} and len(comment.split()) < 3:
            errors.append(f"{operation_id}: {decision} needs a concrete comment")
        if decision == "Approve":
            approved.append(operation_id)
        elif decision == "Reject":
            rejected.append(operation_id)
        else:
            amended.append(operation_id)
        confirmation_map = {
            "confirm_server_coupled": "server_coupled",
            "confirm_activation_risk": "activation_risk",
            "confirm_observation_complete": "observation_complete",
        }
        required_confirmations = set(required_confirmation_fields(operation))
        for field, selection_field in confirmation_map.items():
            value = row.get(field)
            if not isinstance(value, bool):
                errors.append(f"{operation_id}: {field} must be true or false")
                continue
            if value and field not in required_confirmations:
                errors.append(
                    f"{operation_id}: {field} is not applicable to this operation"
                )
                continue
            if value:
                confirmations[selection_field].append(operation_id)

    selection = {
        "kind": "gtm_cleanup_approval_selection",
        "schema_version": 1,
        "status": "pass" if not errors else "fail",
        "source_sha256": str(packet.get("source_sha256") or ""),
        "packet_sha256": calculated_hash,
        "approved_operation_ids": sorted(approved),
        "rejected_operation_ids": sorted(rejected),
        "amended_operation_ids": sorted(amended),
        "server_confirmed_operation_ids": sorted(confirmations["server_coupled"]),
        "activation_confirmed_operation_ids": sorted(confirmations["activation_risk"]),
        "observation_confirmed_operation_ids": sorted(
            confirmations["observation_complete"]
        ),
        "errors": errors,
    }
    return selection, errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    template = subparsers.add_parser("template")
    template.add_argument("operations", type=Path)
    template.add_argument("output", type=Path)
    template.add_argument("--pretty", action="store_true")
    validate = subparsers.add_parser("validate")
    validate.add_argument("operations", type=Path)
    validate.add_argument("response", type=Path)
    validate.add_argument("--output", type=Path)
    validate.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    try:
        packet = load_json(args.operations)
        if args.command == "template":
            payload = response_template(packet)
            write_json(args.output, payload, args.pretty)
            print(json.dumps({"status": "pass", "output": str(args.output)}))
            return 0
        selection, errors = validate_response(packet, load_json(args.response))
        if args.output:
            write_json(args.output, selection, args.pretty)
        print(json.dumps(selection, ensure_ascii=False, indent=2 if args.pretty else None))
        if errors:
            for error in errors:
                print(f"ERROR: {error}", file=sys.stderr)
            return 1
        return 0
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
