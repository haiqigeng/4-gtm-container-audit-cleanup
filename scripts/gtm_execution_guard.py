#!/usr/bin/env python3
"""Fail-closed preflight for an explicitly approved GTM cleanup execution."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

from gtm_lib import ID_KEYS, as_list, load_json

EXACT_OBJECT_KEY_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*:[^:\s]+$")


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
) -> dict[str, Any]:
    errors: list[str] = []
    warnings: list[str] = []
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
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operations", type=Path)
    parser.add_argument("context", type=Path)
    parser.add_argument("future_state", type=Path)
    parser.add_argument("--approve", action="append", default=[])
    parser.add_argument("--confirm-server-coupled", action="append", default=[])
    parser.add_argument("--confirm-activation-risk", action="append", default=[])
    parser.add_argument("--confirm-observation", action="append", default=[])
    parser.add_argument("--output", type=Path)
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()
    report = execution_preflight(
        load_json(args.operations),
        load_json(args.context),
        load_json(args.future_state),
        set(args.approve),
        set(args.confirm_server_coupled),
        set(args.confirm_activation_risk),
        set(args.confirm_observation),
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
