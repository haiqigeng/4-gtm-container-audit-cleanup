#!/usr/bin/env python3
"""Translate reconciled GTM operations into compact human cleanup-plan rows."""

from __future__ import annotations

import argparse
import json
import re
import sys
import unicodedata
from pathlib import Path
from typing import Any

from gtm_lib import as_list
from gtm_privacy import redact_text
from gtm_taxonomy import (
    AREAS,
    CLEANUP_PLAN_COLUMNS,
    GENERAL_CATEGORY_BY_PROBLEM_TYPE,
    PROBLEM_TYPES,
    general_problem_category,
)

PRIORITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
STATUS_ORDER = {
    "Incomplete draft": 0,
    "Proposed action": 1,
    "Conditional action": 2,
    "Owner confirmation": 3,
    "Evidence boundary": 4,
}
BATCHABLE_PROBLEM_TYPES = {
    "Unused object",
    "Exact duplicate",
    "Naming inconsistency",
    "Folder organization",
    "Generic hygiene batch",
}
MAX_VISIBLE_BATCH_CELL_TEXT = 720
SOURCE_PATH_RE = re.compile(
    r"\$\.containerVersion(?:\[[^\]]+\]|\.[A-Za-z0-9_]+)*"
)
OBJECT_KEY_RE = re.compile(
    r"\b(?:tag|trigger|variable|folder|customTemplate|builtInVariable):[^\s,;]+\s*"
)
INTERNAL_HASH_RE = re.compile(r"\b[a-f0-9]{32,}\b", re.I)
GTM_REFERENCE_RE = re.compile(r"\{\{([^{}]+)\}\}")
NONSTANDARD_SPACE_RE = re.compile(r"[\u00a0\u1680\u2000-\u200b\u202f\u205f\u3000]")


def compact_visible_text(value: Any, limit: int = 360) -> str:
    text = " ".join(redact_text(value).split())
    if len(text) <= limit:
        return text
    suffix = ". See the reconciled operations packet for full evidence."
    available = max(80, limit - len(suffix))
    boundary = max(text.rfind(". ", 0, available), text.rfind("; ", 0, available))
    if boundary < available // 2:
        boundary = available
    return text[:boundary].rstrip(" .;") + suffix


def visible_decision_text(value: Any) -> str:
    """Remove machine-only source paths from the visible analyst worksheet."""
    text = " ".join(redact_text(value).split())
    text = SOURCE_PATH_RE.sub("the recorded GTM setting", text)
    return INTERNAL_HASH_RE.sub("implementation detail", text)


def compact_owner_question(value: Any) -> str:
    question = OBJECT_KEY_RE.sub("", visible_decision_text(value))
    if len(question) <= 360:
        return question
    lowered = question.lower()
    if any(term in lowered for term in ("retire", "rollback", "migration")):
        return (
            "Which listed paused, rollback, or migration objects must remain, and which "
            "can be retired from the maintained container?"
        )
    if any(term in lowered for term in ("route", "trigger", "consent", "canonical")):
        return (
            "Which listed source route should remain canonical, and should the overlapping "
            "route be retained or consolidated?"
        )
    return (
        "Which listed source objects require the proposed owner decision, and which "
        "target state should be approved?"
    )


def compact_owner_recommendation(value: Any) -> str:
    raw = " ".join(redact_text(value).split())
    lowered = raw.lower()
    if "exact source anchor" in lowered or "$.containerversion" in lowered:
        return (
            "After the owner selects the business-safe target, repair, remove, or "
            "reconfigure only the recorded GTM setting; retain the object if it "
            "remains required."
        )
    return compact_visible_text(OBJECT_KEY_RE.sub("", visible_decision_text(raw)))


def compact_decision_summary(value: Any) -> str:
    text = visible_decision_text(value)
    lowered = text.lower()
    configuration_match = re.match(
        r"The configuration assessment for (.+?) is bound to source anchors and exact "
        r"behavior terms:",
        text,
        re.I,
    )
    if configuration_match:
        return (
            f"{configuration_match.group(1)} has configured code or template behavior "
            "whose business-safe purpose cannot be proven from the export alone; owner "
            "confirmation is required before changing it."
        )
    if lowered.startswith("the family evaluation uses chain-specific exported facts"):
        return (
            "The route family has overlapping configured evidence, but the export does "
            "not prove whether separate routes are intentional; owner confirmation is "
            "required before consolidation or deletion."
        )
    if len(text) <= 420:
        return text
    # Operational summaries commonly enumerate every object before stating the
    # actual decision. Surface that substantive sentence rather than an
    # unreadable partial object list; the full list is already linked in the
    # affected-object cell and hidden review tab.
    match = re.search(
        r"\b\d+\s+(?:configurable\s+objects|tags|triggers|variables|folders|"
        r"objects|candidates)\b[^.]{0,420}\.",
        text,
        re.I,
    )
    if match:
        return match.group(0) + " See the hidden review for the complete source list."
    return compact_visible_text(text, 360)


def compact_affected_scope(value: Any, limit: int = 440) -> str:
    """Keep the visible plan scannable without losing the exact hidden scope."""
    text = " ".join(redact_text(value).split())
    parts = [part.strip() for part in text.split(";") if part.strip()]
    if len(parts) > 6:
        preview = "; ".join(parts[:6])
        return (
            f"{len(parts)} exact objects: {preview}; +{len(parts) - 6} more in the "
            "Reconciled Operations proof sheet."
        )
    return compact_visible_text(text, limit)


def plain_text(value: Any, limit: int = 320) -> str:
    text = visible_decision_text(value)
    text = NONSTANDARD_SPACE_RE.sub(" ", text)
    text = unicodedata.normalize("NFC", text)
    sentences = re.split(r"(?<=[.!?])\s+", text)
    selected = " ".join(sentences[:2]).strip()
    return compact_visible_text(selected or text, limit)


def catalog_label(
    object_key: str, catalog: dict[str, dict[str, Any]]
) -> str:
    name = str((catalog.get(object_key) or {}).get("object_name") or "")
    return f"{name} ({object_key})" if name else object_key


def short_labels(
    object_keys: list[str],
    catalog: dict[str, dict[str, Any]],
    limit: int = 4,
) -> str:
    labels = list(
        dict.fromkeys(
            catalog_label(key, catalog) for key in object_keys if str(key)
        )
    )
    if not labels:
        return "none"
    if len(labels) <= limit:
        return ", ".join(labels)
    return ", ".join(labels[:limit]) + f", +{len(labels) - limit} more"


def family_scope(
    operation: dict[str, Any], family_by_id: dict[str, str]
) -> str:
    labels = list(
        dict.fromkeys(
            family_by_id.get(str(family_id), str(family_id))
            for family_id in as_list(
                operation.get("affected_measurement_family_ids")
            )
            if str(family_id)
        )
    )
    if not labels:
        return "no active measurement family"
    if len(labels) == 1:
        return f"the {labels[0]} measurement family"
    preview = ", ".join(labels[:3])
    if len(labels) > 3:
        preview += f", +{len(labels) - 3} more"
    return f"{len(labels)} measurement families ({preview})"


def changed_reference_details(
    operation: dict[str, Any],
) -> tuple[list[str], list[str], list[str]]:
    broken: list[str] = []
    replacements: list[str] = []
    changed_objects: list[str] = []
    for change in as_list(operation.get("changes")):
        before = str(change.get("before") or "")
        after = str(change.get("after") or "")
        before_refs = GTM_REFERENCE_RE.findall(before)
        after_refs = GTM_REFERENCE_RE.findall(after)
        for reference in before_refs:
            if NONSTANDARD_SPACE_RE.search(reference) and reference not in after_refs:
                normalized = NONSTANDARD_SPACE_RE.sub(" ", reference)
                candidate = next(
                    (
                        value
                        for value in after_refs
                        if unicodedata.normalize("NFKC", value)
                        == unicodedata.normalize("NFKC", normalized)
                    ),
                    "",
                )
                if candidate:
                    broken.append(reference)
                    replacements.append(candidate)
                    changed_objects.append(str(change.get("object_key") or ""))
    return (
        list(dict.fromkeys(broken)),
        list(dict.fromkeys(replacements)),
        list(dict.fromkeys(changed_objects)),
    )


def operation_problem_text(
    operation: dict[str, Any],
    catalog: dict[str, dict[str, Any]],
    family_by_id: dict[str, str],
) -> str:
    problem_type = str(operation.get("problem_type") or "")
    preserved = family_scope(operation, family_by_id)
    deleted = [
        str(item.get("object_key") or "")
        for item in as_list(operation.get("deletions"))
        if str(item.get("object_key") or "")
    ]
    broken, replacements, _changed_objects = changed_reference_details(operation)
    if problem_type == "Broken reference" and broken:
        return (
            f"An invisible non-breaking space corrupts {len(broken)} GTM variable "
            f"reference occurrence(s). The text looks like "
            f"{', '.join('{{' + value + '}}' for value in replacements)}, but GTM "
            "matches variable names exactly, so the configured input can resolve as "
            f"missing. The repair preserves {preserved}."
        )
    if problem_type == "Exact duplicate":
        canonical = str(operation.get("canonical_object_key") or "")
        if not canonical and not deleted:
            return (
                f"{plain_text(operation.get('problem'), 250)} Separate copies add "
                "maintenance and drift risk; the exact mutation remains attached to "
                "its operation ID."
            )
        return (
            f"{short_labels(deleted, catalog)} has the same exported configuration "
            f"as {catalog_label(canonical, catalog)} and adds no distinct configured "
            f"measurement behavior. Separate copies can drift later. Consolidation "
            f"preserves {preserved}."
        )
    if problem_type == "Unused object":
        reachability = str(
            (operation.get("priority_basis") or {}).get(
                "active_reachability"
            )
            or ""
        )
        evidence = (
            "Only paused configuration reaches the listed object"
            if reachability == "paused_only"
            else "No active configured consumer or execution path reaches the listed object"
        )
        return (
            f"{evidence}. Keeping it adds search, ownership, and accidental-reuse "
            f"risk without adding measurement; {preserved} remains available."
        )
    if (
        problem_type == "Custom code risk"
        and "support document.write" in str(
            operation.get("exact_proposed_action") or ""
        ).lower()
    ):
        return (
            f"The exported Custom HTML and its Support document.write setting do "
            "not match: the legacy capability is enabled when the code does not use "
            "it, or disabled when the code requires it. Aligning that one setting "
            f"preserves the HTML, route, consent controls, and {preserved}."
        )
    if problem_type == "Naming inconsistency":
        return (
            f"{plain_text(operation.get('problem'), 260)} The configured behavior "
            "does not change; the cleanup makes the retained object easier to find "
            "and own."
        )
    problem = plain_text(operation.get("problem"), 300)
    impact = plain_text(operation.get("why_it_matters"), 220)
    return (
        f"{problem} Impact: {impact} The approved target state preserves {preserved}."
    ).strip()


def static_verification_text(operation: dict[str, Any]) -> str:
    phases = set(as_list(operation.get("execution_phases")))
    if "remap" in phases:
        return (
            "re-export; confirm every former consumer points to the canonical "
            "object, deleted IDs are absent, and no reference is missing"
        )
    if "rename" in phases:
        return (
            "re-export; confirm the new name is unique and every name-based "
            "reference resolves"
        )
    if "change" in phases:
        return (
            "re-export; compare the exact changed fields and confirm every other "
            "setting on the affected objects is unchanged"
        )
    if "delete" in phases:
        return (
            "re-export; confirm the approved IDs are absent, projected counts match, "
            "and no missing reference was introduced"
        )
    return "re-export and compare the object graph with the approved target state"


def operation_action_text(
    operation: dict[str, Any],
    catalog: dict[str, dict[str, Any]],
) -> str:
    problem_type = str(operation.get("problem_type") or "")
    deleted = [
        str(item.get("object_key") or "")
        for item in as_list(operation.get("deletions"))
        if str(item.get("object_key") or "")
    ]
    broken, replacements, changed_objects = changed_reference_details(operation)
    if problem_type == "Broken reference" and broken:
        action = (
            f"Retype {', '.join('{{' + value + '}}' for value in replacements)} "
            f"with ordinary spaces in {short_labels(changed_objects, catalog)}. Keep "
            "formulas, trigger predicates, event names, routing, consent, and all "
            "unlisted fields unchanged."
        )
    elif problem_type == "Exact duplicate":
        canonical = str(operation.get("canonical_object_key") or "")
        consumers = [
            str(key)
            for remap in as_list(operation.get("remaps"))
            for key in as_list(remap.get("consumer_object_keys"))
            if str(key)
        ]
        if not canonical and not deleted:
            action = plain_text(operation.get("exact_proposed_action"), 280)
        elif canonical:
            action = f"Keep {catalog_label(canonical, catalog)}"
            if consumers:
                action += f"; repoint {short_labels(consumers, catalog)} to it"
            action += f"; delete {short_labels(deleted, catalog)}."
        else:
            action = (
                f"Delete {short_labels(deleted, catalog)} because the complete "
                "approved target state retires every member of this duplicate set."
            )
    elif problem_type == "Unused object" and deleted:
        action = (
            f"Delete {short_labels(deleted, catalog)}; no consumer remap is needed."
        )
    elif problem_type == "Naming inconsistency" and as_list(
        operation.get("renames")
    ):
        pairs = [
            f"{plain_text(item.get('before'), 90)} -> {plain_text(item.get('after'), 90)}"
            for item in as_list(operation.get("renames"))
        ]
        action = "Rename " + "; ".join(pairs) + " and update name-based references."
    else:
        action = plain_text(operation.get("exact_proposed_action"), 360)
    return action


def owner_decision_problem(decision: dict[str, Any]) -> str:
    missing = [
        str(item.get("reference") or "")
        for item in as_list(decision.get("missing_reference_terminals"))
        if str(item.get("reference") or "")
    ]
    if missing:
        readable = [
            NONSTANDARD_SPACE_RE.sub(" ", unicodedata.normalize("NFC", value))
            for value in missing
        ]
        return (
            f"The export contains {len(missing)} unresolved GTM variable "
            f"reference(s): {', '.join(readable[:4])}. No unique safe replacement "
            "is proven for every reference, so the owner must select the intended "
            "source before any field is changed."
        )
    technical = [
        item
        for item in as_list(decision.get("technical_findings"))
        if item.get("verdict") == "Owner decision needed"
        and item.get("decision_class") != "review_signal"
    ]
    if technical:
        signals = "; ".join(
            plain_text(item.get("statement"), 180) for item in technical[:3]
        )
        return (
            f"The exported code has a concrete unresolved boundary: {signals} "
            "The static review cannot choose the required business owner, retained "
            "integration, or replacement route."
        )
    problem_type = str(decision.get("problem_type") or "")
    if problem_type in {"Functional overlap", "Duplicate firing"}:
        return (
            "The listed objects serve the same or overlapping configured business "
            "route, but the export does not prove whether the separation is "
            "intentional. One canonical route decision is required before "
            "consolidation or deletion."
        )
    if problem_type == "Consent mismatch":
        return (
            "The listed routes use different exported consent controls for the same "
            "or overlapping integration. The container proves the difference but "
            "cannot choose the approved business consent policy."
        )
    return compact_decision_summary(decision.get("summary"))


def build_rows(payload: dict[str, Any]) -> tuple[list[dict[str, str]], list[str]]:
    staged_rows: list[tuple[tuple[int, int, str], dict[str, str]]] = []
    operation_entries: list[dict[str, Any]] = []
    errors: list[str] = []
    catalog = {
        str(key): value
        for key, value in (payload.get("object_catalog") or {}).items()
        if isinstance(value, dict)
    }
    family_by_id = {
        str(family.get("family_id") or ""): str(
            family.get("family_label") or family.get("family_id") or ""
        )
        for family in as_list(
            (payload.get("measurement_preservation") or {}).get("families")
        )
        if str(family.get("family_id") or "")
    }

    action_completeness = payload.get("action_completeness")
    if isinstance(action_completeness, dict) and action_completeness.get("status") != "pass":
        action_errors = [
            redact_text(value)
            for value in as_list(action_completeness.get("errors"))
            if redact_text(value)
        ]
        error_preview = " ".join(
            f"{index}. {value}" for index, value in enumerate(action_errors[:4], start=1)
        )
        if len(action_errors) > 4:
            error_preview += f" +{len(action_errors) - 4} more in the operations packet."
        return [
            {
                "ID": "BLOCKED-001",
                "Status": "Incomplete draft",
                "General problem category": general_problem_category(
                    "Incomplete action plan"
                ),
                "Area / problem type": "Governance / ownership / Incomplete action plan",
                "Affected object(s)": "Container cleanup plan",
                "Problem / evidence": (
                    f"The audit has {len(action_errors)} unresolved action-completeness "
                    f"error(s). {error_preview}"
                ).strip(),
                "Action / priority / QA": (
                    "Complete every source-visible defect with one exact operation, or "
                    "record a genuine source-locked owner decision/exception; then "
                    "reconcile and rebuild before presenting the plan for approval."
                ),
            }
        ], []

    def stage_row(row: dict[str, str], status: str, priority: str, identifier: str) -> None:
        # The exact operation packet and hidden proof sheets retain all source
        # fields. Keep the visible analyst worksheet within a readable row
        # height rather than silently clipping a long batch or owner narrative.
        row = dict(row)
        area_and_type = str(row.get("Area / problem type") or "")
        matched_problem_type = next(
            (
                problem_type
                for problem_type in sorted(
                    GENERAL_CATEGORY_BY_PROBLEM_TYPE,
                    key=len,
                    reverse=True,
                )
                if area_and_type.endswith(f" / {problem_type}")
            ),
            "",
        )
        if not matched_problem_type:
            errors.append(
                f"{identifier}: cannot derive general category from "
                f"{area_and_type!r}"
            )
            row["General problem category"] = ""
        else:
            row["General problem category"] = general_problem_category(
                matched_problem_type
            )
        row["Affected object(s)"] = compact_visible_text(
            row.get("Affected object(s)", ""), 530
        )
        row["Problem / evidence"] = compact_visible_text(
            row.get("Problem / evidence", ""), 700
        )
        row["Action / priority / QA"] = compact_visible_text(
            row.get("Action / priority / QA", ""), 700
        )
        row = {column: row.get(column, "") for column in CLEANUP_PLAN_COLUMNS}
        staged_rows.append(
            (
                (
                    STATUS_ORDER.get(status, 99),
                    PRIORITY_ORDER.get(priority, 4),
                    identifier,
                ),
                row,
            )
        )

    def append_operation(operation: dict[str, Any], index: int) -> None:
        area = str(operation.get("area") or "")
        problem_type = str(operation.get("problem_type") or "")
        if area not in AREAS:
            errors.append(f"operation {operation.get('operation_id')}: unsupported area {area!r}")
        if problem_type not in PROBLEM_TYPES:
            errors.append(
                f"operation {operation.get('operation_id')}: unsupported problem type {problem_type!r}"
            )
        problem = operation_problem_text(operation, catalog, family_by_id)
        impact = ""
        action = operation_action_text(operation, catalog)
        deletion_keys = [
            str(item.get("object_key") or "")
            for item in as_list(operation.get("deletions"))
            if str(item.get("object_key") or "")
        ]
        if deletion_keys and all(
            key.startswith("builtInVariable:") for key in deletion_keys
        ):
            action = (
                "Disable/deselect the listed built-in variable(s) in GTM; in the "
                "export target state this removes them from the enabled "
                "builtInVariable list."
            )
        qa = static_verification_text(operation)
        blocker = redact_text(operation.get("blocker"))
        operation_id = str(operation.get("operation_id") or f"OP-{index:04d}")
        execution_order = operation.get("execution_order")
        status = (
            "Conditional action"
            if operation.get("approval_status") == "pending_owner_decision"
            else "Proposed action"
        )
        family_values = [
            str(value)
            for value in as_list(operation.get("affected_measurement_family_ids"))
            if str(value)
        ]
        family_ids = ", ".join(family_values)
        if len(family_ids) > 120:
            family_ids = ", ".join(family_values[:8])
            family_ids += f", +{len(family_values) - 8} more"
        priority_basis = operation.get("priority_basis") or {}
        execution_safety = operation.get("execution_safety") or {}
        approval = execution_safety.get("approval") or {}
        approval_scope = str(
            approval.get("scope")
            or (
                "bulk_eligible_exact_low_risk_bundle"
                if str(operation.get("priority") or "") == "Low"
                and str(priority_basis.get("active_reachability") or "")
                not in {"active", "unknown"}
                else "individual_operation"
            )
        )
        approval_reasons = ", ".join(
            str(value) for value in as_list(approval.get("reasons")) if str(value)
        )
        decommission = execution_safety.get("decommission") or {}
        decommission_text = ""
        if decommission.get("required"):
            decommission_text = (
                " Quarantine before deletion; separately approve deletion after a "
                "risk-based observation window."
            )
        priority_reason = redact_text(priority_basis.get("rationale"))
        if len(priority_reason) > 120:
            priority_reason = (
                f"{priority_basis.get('active_reachability') or 'source reach'}; "
                f"impact={','.join(str(value) for value in as_list(priority_basis.get('impact_classes')))}; "
                f"confidence={priority_basis.get('evidence_confidence') or operation.get('confidence') or 'unspecified'}"
            )
        affected_scope = compact_affected_scope(operation.get("affected_objects"))
        if not affected_scope:
            errors.append(f"operation {operation_id}: affected object scope is empty")
        row = {
                "ID": operation_id,
                "Status": status,
                "Area / problem type": f"{area} / {problem_type}",
                "Affected object(s)": affected_scope,
                "Problem / evidence": problem,
                "Action / priority / QA": (
                    f"Change: {action} Priority: {operation.get('priority')}. "
                    + (
                        f"Execution order: {execution_order}. "
                        if execution_order is not None
                        else ""
                    )
                    + f"Static verification: {qa}. "
                    "Rollback: restore the exact before-state from the locked export."
                    + (
                        f" Priority basis: {priority_reason}."
                        if priority_reason
                        else ""
                    )
                    + (
                        " Approval: individual operation"
                        if approval_scope == "individual_operation"
                        else " Approval: exact low-risk bundle eligible"
                    )
                    + (
                        f" ({compact_visible_text(approval_reasons, 90)})."
                        if approval_reasons
                        else "."
                    )
                    + decommission_text
                    + (f" Measurement families: {family_ids}." if family_ids else "")
                    + (f" Blocker: {blocker}" if blocker else "")
                ).strip(),
            }
        operation_entries.append(
            {
                "row": row,
                "status": status,
                "priority": str(operation.get("priority") or ""),
                "identifier": operation_id,
                "area": area,
                "problem_type": problem_type,
                "affected": affected_scope,
                "problem": problem,
                "impact": impact,
                "action": action,
                "qa": qa,
                "readiness": str(operation.get("execution_readiness") or ""),
                "approval_scope": approval_scope,
            }
        )

    active = as_list(payload.get("operations"))
    for index, operation in enumerate(active, start=1):
        append_operation(operation, index)

    grouped: dict[tuple[str, str, str, str, str], list[dict[str, Any]]] = {}
    for entry in operation_entries:
        if entry["problem_type"] not in BATCHABLE_PROBLEM_TYPES:
            stage_row(
                entry["row"],
                entry["status"],
                entry["priority"],
                entry["identifier"],
            )
            continue
        key = (
            entry["status"],
            entry["priority"],
            entry["area"],
            entry["problem_type"],
            entry["approval_scope"],
        )
        grouped.setdefault(key, []).append(entry)

    def display_chunks(entries: list[dict[str, Any]]) -> list[list[dict[str, Any]]]:
        chunks: list[list[dict[str, Any]]] = []
        current: list[dict[str, Any]] = []
        lengths = [0, 0, 0]
        for entry in entries:
            additions = [
                len(entry["identifier"]) + len(entry["affected"]) + 5,
                len(entry["identifier"]) + len(entry["problem"]) + len(entry["impact"]) + 16,
                len(entry["identifier"]) + len(entry["action"]) + len(entry["qa"]) + 16,
            ]
            if current and any(
                total + addition > MAX_VISIBLE_BATCH_CELL_TEXT
                for total, addition in zip(lengths, additions, strict=True)
            ):
                chunks.append(current)
                current = []
                lengths = [0, 0, 0]
            current.append(entry)
            lengths = [
                total + addition
                for total, addition in zip(lengths, additions, strict=True)
            ]
        if current:
            chunks.append(current)
        return chunks

    batch_number = 0
    for (status, priority, area, problem_type, approval_scope), entries in sorted(
        grouped.items(), key=lambda item: item[0]
    ):
        entries.sort(key=lambda entry: entry["identifier"])
        for chunk in display_chunks(entries):
            if len(chunk) == 1:
                entry = chunk[0]
                stage_row(
                    entry["row"],
                    entry["status"],
                    entry["priority"],
                    entry["identifier"],
                )
                continue
            batch_number += 1
            operation_ids = [entry["identifier"] for entry in chunk]
            batch_id = (
                f"BATCH-{batch_number:03d} [" + ", ".join(operation_ids) + "]"
            )
            stage_row(
                {
                    "ID": batch_id,
                    "Status": status,
                    "Area / problem type": f"{area} / {problem_type}",
                    "Affected object(s)": " ".join(
                        f"[{entry['identifier']}] {entry['affected']}"
                        for entry in chunk
                    ),
                    "Problem / evidence": (
                        f"Homogeneous batch of {len(chunk)} {problem_type.lower()} "
                        "operations; each mutation remains separately approvable. "
                        + " ".join(
                            f"[{entry['identifier']}] {entry['problem']}"
                            for entry in chunk
                        )
                    ),
                    "Action / priority / QA": (
                        f"Shared priority: {priority}. "
                        + (
                            "This exact low-risk bundle may be approved together; amend "
                            "or reject any operation ID explicitly. "
                            if approval_scope
                            == "bulk_eligible_exact_low_risk_bundle"
                            else "Approve, reject, or amend each atomic operation ID independently. "
                        )
                        + "Execution and readback remain atomic by operation ID. "
                        "Change set: "
                        + " ".join(
                            f"[{entry['identifier']}] {entry['action']} "
                            f"Static verification: {entry['qa']}"
                            for entry in chunk
                        )
                    ),
                },
                status,
                priority,
                chunk[0]["identifier"],
            )

    unresolved = [
        decision
        for decision in as_list(payload.get("decision_ledger"))
        if decision.get("disposition")
        in {"owner_decision_needed", "container_evidence_limit"}
    ]
    owner_decisions = [
        decision
        for decision in unresolved
        if decision.get("disposition") == "owner_decision_needed"
    ]
    evidence_limits = [
        decision
        for decision in unresolved
        if decision.get("disposition") == "container_evidence_limit"
    ]
    owner_groups: dict[tuple[str, str, str, str], list[dict[str, Any]]] = {}
    for decision in owner_decisions:
        area = str(decision.get("area") or "Governance / ownership")
        problem_type = str(decision.get("problem_type") or "Unclear business purpose")
        key = (
            area,
            problem_type,
            " ".join(str(decision.get("owner_question") or "").split()),
            " ".join(str(decision.get("recommended_action") or "").split()),
        )
        owner_groups.setdefault(key, []).append(decision)

    owner_batch = 0
    for (area, problem_type, _question_key, _recommendation_key), decisions in sorted(
        owner_groups.items(), key=lambda item: item[0]
    ):
        decision = decisions[0]
        if area not in AREAS:
            errors.append(
                f"decision {decision.get('decision_id')}: unsupported area {area!r}"
            )
        if problem_type not in PROBLEM_TYPES:
            errors.append(
                f"decision {decision.get('decision_id')}: unsupported problem type "
                f"{problem_type!r}"
            )
        recommendation = compact_owner_recommendation(decision.get("recommended_action"))
        question = compact_owner_question(decision.get("owner_question"))
        decision_ids = [
            str(item.get("decision_id") or "DECISION") for item in decisions
        ]
        if len(decision_ids) == 1:
            decision_id = decision_ids[0]
        else:
            owner_batch += 1
            decision_id = f"OWNER-{owner_batch:03d}"
        if len(decision_ids) > 6:
            decision_refs = (
                ", ".join(decision_ids[:6])
                + f", +{len(decision_ids) - 6} more in reconciled_operations.json"
            )
        else:
            decision_refs = ", ".join(decision_ids)
        affected_scopes = [
            (
                redact_text(item.get("affected_objects"))
                or ", ".join(
                    str(value)
                    for value in as_list(item.get("source_object_keys"))
                    if str(value)
                )
                or "Container decision scope"
            )
            for item in decisions
        ]
        compact_scopes: list[str] = []
        for scope in affected_scopes:
            parts = [part.strip() for part in scope.split(";") if part.strip()]
            if len(parts) > 6:
                scope = "; ".join(parts[:6]) + f"; +{len(parts) - 6} more objects"
            elif len(scope) > 520:
                scope = scope[:500].rstrip() + "…"
            compact_scopes.append(scope)
        affected_scopes = compact_scopes
        if any(not scope for scope in affected_scopes):
            errors.append(f"decision {decision_id}: affected object scope is empty")
        scope_preview = "; ".join(affected_scopes[:4])
        if len(affected_scopes) > 4:
            scope_preview += (
                f"; +{len(affected_scopes) - 4} exact decision/object links in the "
                "hidden review sheets"
            )
        summaries = list(
            dict.fromkeys(
                owner_decision_problem(item)
                for item in decisions
                if owner_decision_problem(item)
            )
        )
        summary_preview = " ".join(summaries[:2])
        if len(summaries) > 2:
            summary_preview += (
                f" +{len(summaries) - 2} source-specific summaries in the hidden reviews."
            )
        status = "Owner confirmation"
        affected_text = (
            scope_preview
            if len(decisions) == 1
            else f"{len(decisions)} related decisions: {scope_preview}"
        )
        problem_text = (
            summary_preview
            if len(decisions) == 1
            else (
                f"{len(decisions)} related decisions require the same owner answer. "
                f"{summary_preview}"
            )
        )
        stage_row(
            {
                "ID": decision_id,
                "Status": status,
                "Area / problem type": f"{area} / {problem_type}",
                "Affected object(s)": affected_text,
                "Problem / evidence": problem_text,
                "Action / priority / QA": (
                    f"Question: {question} Recommendation: {recommendation} "
                    f"Decision refs: {decision_refs}."
                ),
            },
            status,
            "",
            decision_id,
        )
    if evidence_limits:
        evidence_count = len(evidence_limits)
        status = "Evidence boundary"
        stage_row(
            {
                "ID": "SCOPE-001",
                "Status": status,
                "Area / problem type": (
                    "Governance / ownership / Container-only evidence boundary"
                ),
                "Affected object(s)": (
                    f"{evidence_count} retained review decision(s); complete object "
                    "links remain in the machine-readable operations packet"
                ),
                "Problem / evidence": (
                    f"Scope boundary: {evidence_count} reviewed decisions depend on live "
                    "dataLayer values, page/CMP state, vendor responses, or downstream runtime "
                    "behavior that a GTM container export cannot prove. These are not "
                    "source-visible cleanup defects and do not block unrelated cleanup. "
                    "Every per-object boundary remains lossless in the hidden reviews and "
                    "machine-readable audit package."
                ),
                "Action / priority / QA": (
                    "Scope treatment: do not create a cleanup mutation from unseen "
                    "behavior. Keep each exact evidence boundary visible and continue "
                    "with unrelated source-proven operations."
                ),
            },
            status,
            "",
            "SCOPE-001",
        )
    return [
        row for _sort_key, row in sorted(staged_rows, key=lambda item: item[0])
    ], errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operations", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()
    payload = json.loads(args.operations.read_text(encoding="utf-8"))
    rows, errors = build_rows(payload)
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    output = {
        "kind": "gtm_human_cleanup_rows",
        "source_file": payload.get("source_file"),
        "source_sha256": payload.get("source_sha256"),
        "rows": rows,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(output, ensure_ascii=False, indent=2 if args.pretty else None) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({"output": str(args.output), "rows": len(rows)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
