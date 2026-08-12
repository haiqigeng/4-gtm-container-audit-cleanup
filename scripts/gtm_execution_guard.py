#!/usr/bin/env python3
"""Fail-closed preflight for an explicitly approved GTM cleanup execution."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

from gtm_approval_response import validate_response
from gtm_lib import (
    ID_KEYS,
    as_list,
    container_configuration_differences,
    container_configuration_sha256,
    container_identity,
    load_json,
    source_descriptor,
    source_integrity_findings,
)

EXACT_OBJECT_KEY_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*:[^:\s]+$")


def live_readback_binding(
    source_export: dict[str, Any] | None,
    live_readback: dict[str, Any] | None,
    source_export_sha256: str,
    expected_source_sha256: str,
) -> tuple[dict[str, Any], list[str]]:
    """Bind execution to a fresh complete workspace readback of the audited state."""

    errors: list[str] = []
    if source_export is None:
        errors.append("the locked source export is required for execution preflight")
    if live_readback is None:
        errors.append("a fresh complete GTM workspace readback is required before mutation")
    if errors:
        return {
            "status": "fail",
            "matches_audited_configuration": False,
            "errors": list(errors),
        }, errors

    source_integrity = [
        row for row in source_integrity_findings(source_export) if row.get("blocking")
    ]
    live_integrity = [
        row for row in source_integrity_findings(live_readback) if row.get("blocking")
    ]
    if source_integrity:
        errors.append("locked source export fails the complete-source integrity gate")
    if live_integrity:
        errors.append("live GTM readback fails the complete-source integrity gate")
    if not source_export_sha256:
        errors.append("locked source export SHA-256 is unavailable")
    elif source_export_sha256 != expected_source_sha256:
        errors.append("locked source export hash differs from the approved operation packet")

    source_identity = container_identity(source_export)
    live_identity = container_identity(live_readback)
    if source_identity and live_identity != source_identity:
        errors.append(
            "live readback container identity differs from the audited source: "
            f"expected={source_identity}, actual={live_identity}"
        )

    source_configuration_sha256 = container_configuration_sha256(source_export)
    live_configuration_sha256 = container_configuration_sha256(live_readback)
    differences = container_configuration_differences(source_export, live_readback)
    difference_count = sum(len(values) for values in differences.values())
    if difference_count:
        errors.append(
            "live workspace configuration drifted after the audit; regenerate the "
            "audit/plan from this readback before mutation"
        )
    report = {
        "status": "pass" if not errors else "fail",
        "matches_audited_configuration": not difference_count and not errors,
        "source_identity": source_identity,
        "live_identity": live_identity,
        "source_configuration_sha256": source_configuration_sha256,
        "live_configuration_sha256": live_configuration_sha256,
        "configuration_differences": differences,
        "source_integrity_findings": source_integrity,
        "live_integrity_findings": live_integrity,
        "errors": list(errors),
    }
    return report, errors


def operation_scope_keys(operation: dict[str, Any]) -> set[str]:
    keys = {
        str(value)
        for field in ("affected_object_keys", "source_object_keys")
        for value in as_list(operation.get(field))
        if str(value)
    }
    for field in ("changes", "additions", "deletions", "renames"):
        keys.update(
            str(item.get("object_key") or "")
            for item in as_list(operation.get(field))
            if isinstance(item, dict) and str(item.get("object_key") or "")
        )
    for remap in as_list(operation.get("remaps")):
        if not isinstance(remap, dict):
            continue
        keys.update(
            str(value)
            for value in (
                remap.get("from_object_key"),
                remap.get("to_object_key"),
            )
            if str(value or "")
        )
        keys.update(
            str(value)
            for value in as_list(remap.get("consumer_object_keys"))
            if str(value)
        )
    return keys


def execution_preflight(
    operations: dict[str, Any],
    context: dict[str, Any],
    future_state: dict[str, Any],
    approved_ids: set[str],
    server_confirmed_ids: set[str],
    activation_confirmed_ids: set[str],
    observation_confirmed_ids: set[str],
    approval_validation_errors: list[str] | None = None,
    source_export: dict[str, Any] | None = None,
    live_readback: dict[str, Any] | None = None,
    source_export_sha256: str = "",
) -> dict[str, Any]:
    errors: list[str] = list(approval_validation_errors or [])
    warnings: list[str] = []
    readback_binding, binding_errors = live_readback_binding(
        source_export,
        live_readback,
        source_export_sha256,
        str(operations.get("source_sha256") or ""),
    )
    errors.extend(binding_errors)
    by_id = {
        str(operation.get("operation_id") or ""): operation
        for operation in as_list(operations.get("operations"))
        if str(operation.get("operation_id") or "")
    }
    missing_ids = sorted(approved_ids - set(by_id))
    if missing_ids:
        errors.append("unknown approved operation IDs: " + ", ".join(missing_ids))
    if not approved_ids:
        errors.append("no exact operation IDs were approved")

    do_not_touch = {
        str(value)
        for value in as_list((context.get("context") or {}).get("do_not_touch"))
        if str(value)
    }
    do_not_touch_status = str(
        (
            (context.get("context_evidence") or {}).get("do_not_touch")
            or {}
        ).get("status")
        or ""
    )
    if do_not_touch_status == "unresolved":
        errors.append(
            "do_not_touch intake must be explicitly confirmed, including an "
            "explicit empty list, before execution"
        )
    invalid_fences = sorted(
        value
        for value in do_not_touch
        if not EXACT_OBJECT_KEY_RE.fullmatch(value)
        or value.split(":", 1)[0] not in ID_KEYS
    )
    if invalid_fences:
        errors.append(
            "do_not_touch entries must be exact layer:ID keys: "
            + ", ".join(invalid_fences)
        )

    selected = [by_id[value] for value in sorted(approved_ids & set(by_id))]
    for operation in selected:
        operation_id = str(operation.get("operation_id") or "")
        required_ids = {
            str(value)
            for value in as_list(operation.get("depends_on_operation_ids"))
            if str(value)
        }
        missing_dependencies = sorted(required_ids - approved_ids)
        if missing_dependencies:
            errors.append(
                f"{operation_id} requires approved prerequisite operations: "
                + ", ".join(missing_dependencies)
            )
        operation_order = int(operation.get("execution_order") or 0)
        misordered_dependencies = sorted(
            dependency_id
            for dependency_id in required_ids
            if dependency_id in by_id
            and int(by_id[dependency_id].get("execution_order") or 0)
            >= operation_order
        )
        if misordered_dependencies:
            errors.append(
                f"{operation_id} is not ordered after prerequisite operations: "
                + ", ".join(misordered_dependencies)
            )
        protected = sorted(operation_scope_keys(operation) & do_not_touch)
        if protected:
            errors.append(
                f"{operation_id} intersects do_not_touch objects: "
                + ", ".join(protected)
            )
        safety = operation.get("execution_safety") or {}
        if safety.get("server_coupled") and operation_id not in server_confirmed_ids:
            errors.append(
                f"{operation_id} is server_coupled and lacks explicit server-route confirmation"
            )
        activation = safety.get("configured_activation_risk") or {}
        if activation.get("flag") and operation_id not in activation_confirmed_ids:
            errors.append(
                f"{operation_id} may change configured activation scope and lacks "
                "explicit activation-risk confirmation"
            )
        decommission = safety.get("decommission") or {}
        if (
            as_list(operation.get("deletions"))
            and decommission.get("required")
            and operation_id not in observation_confirmed_ids
        ):
            errors.append(
                f"{operation_id} requires quarantine evidence and a separate "
                "post-observation deletion confirmation"
            )

    if future_state.get("status") != "pass":
        errors.append("future-state validation must pass before execution")
    if future_state.get("source_sha256") != operations.get("source_sha256"):
        errors.append("future-state and operations source hashes differ")
    future_operation_count = future_state.get("operation_count")
    if (
        isinstance(future_operation_count, int)
        and future_operation_count != len(approved_ids)
    ):
        errors.append(
            "future state was not regenerated for the exact approved operation set"
        )
    projected_activation = future_state.get("configured_activation_risk") or {}
    if projected_activation.get("flag"):
        candidate_ids = {
            str(value)
            for value in as_list(projected_activation.get("candidate_operation_ids"))
            if str(value)
        }
        unconfirmed = sorted(
            (approved_ids & candidate_ids) - activation_confirmed_ids
        )
        if unconfirmed:
            errors.append(
                "future state has newly reachable configured tags and these approved "
                "operations lack activation confirmation: "
                + ", ".join(unconfirmed)
            )
        warnings.append(
            "future state contains newly reachable configured tags; runtime acceptance "
            "is still required before publication"
        )

    return {
        "kind": "gtm_execution_preflight",
        "schema_version": 1,
        "status": "pass" if not errors else "fail",
        "source_sha256": str(operations.get("source_sha256") or ""),
        "approved_operation_ids": sorted(approved_ids),
        "do_not_touch_object_keys": sorted(do_not_touch),
        "errors": errors,
        "warnings": warnings,
        "live_readback_binding": readback_binding,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operations", type=Path)
    parser.add_argument("context", type=Path)
    parser.add_argument("future_state", type=Path)
    parser.add_argument(
        "--source-export",
        type=Path,
        required=True,
        help="Exact source export used to build the approved operation packet",
    )
    parser.add_argument(
        "--live-readback",
        type=Path,
        required=True,
        help="Fresh complete pre-mutation GTM workspace readback",
    )
    parser.add_argument("--approve", action="append", default=[])
    parser.add_argument(
        "--approval-response",
        type=Path,
        help="Validated row-level approval response; replaces direct --approve flags",
    )
    parser.add_argument("--confirm-server-coupled", action="append", default=[])
    parser.add_argument("--confirm-activation-risk", action="append", default=[])
    parser.add_argument("--confirm-observation", action="append", default=[])
    parser.add_argument("--output", type=Path)
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()
    operations = load_json(args.operations)
    approval_errors: list[str] = []
    approved_ids = set(args.approve)
    server_ids = set(args.confirm_server_coupled)
    activation_ids = set(args.confirm_activation_risk)
    observation_ids = set(args.confirm_observation)
    if args.approval_response:
        if approved_ids or server_ids or activation_ids or observation_ids:
            approval_errors.append(
                "--approval-response cannot be combined with direct approval or confirmation flags"
            )
        selection, response_errors = validate_response(
            operations, load_json(args.approval_response)
        )
        approval_errors.extend(response_errors)
        approved_ids = set(as_list(selection.get("approved_operation_ids")))
        server_ids = set(as_list(selection.get("server_confirmed_operation_ids")))
        activation_ids = set(
            as_list(selection.get("activation_confirmed_operation_ids"))
        )
        observation_ids = set(
            as_list(selection.get("observation_confirmed_operation_ids"))
        )
    report = execution_preflight(
        operations,
        load_json(args.context),
        load_json(args.future_state),
        approved_ids,
        server_ids,
        activation_ids,
        observation_ids,
        approval_errors,
        load_json(args.source_export),
        load_json(args.live_readback),
        source_descriptor(args.source_export)["source_sha256"],
    )
    rendered = json.dumps(
        report,
        ensure_ascii=False,
        indent=2 if args.pretty else None,
    )
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    if report["status"] != "pass":
        for error in report["errors"]:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
