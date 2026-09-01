#!/usr/bin/env python3
"""Map a sealed GTM canonical record to one human-workbook decision surface."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

from gtm_audit_contract import HUMAN_DECISION_LABELS, HUMAN_DECISION_MEANINGS
from gtm_canonical_record import canonical_record_seal_errors
from gtm_lib import (
    as_list,
    contained_relative_path,
    file_sha256,
    require_safe_package_root,
    stable_hash,
    write_json,
)
from gtm_privacy import privacy_findings, redact_delivery_value

DELIVERY_ROOT = "delivery"
DELIVERY_MAP_FILE = "delivery-map.json"
DELIVERY_MAP_SEAL_FILE = "delivery-map-seal.json"
AUDIENCE_BRIEF_FILE = "audience-brief.json"
EDITORIAL_FILE = "editorial.json"
EDITORIAL_SEAL_FILE = "editorial-seal.json"

VISIBLE_SHEETS = (
    "01 Overview",
    "02 Recommendations",
    "03 Decisions Needed",
    "04 Full Audit",
)
CUSTOM_CODE_SHEET = "05 Custom Code"

PRIORITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "None": 4}
PROHIBITED_VISIBLE_JARGON = re.compile(
    r"\b(?:semantic obligation|clean-room|reconciliation class|challenge context|"
    r"parser trace|validator|source hash|seal(?:ed|ing)?)\b",
    re.I,
)
UNSUPPORTED_CLAIM_RE = re.compile(
    r"\b(?:guarantees?|legally compliant|confirmed (?:to )?fire|vendor (?:has )?received|"
    r"runtime (?:is|was) correct)\b",
    re.I,
)


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


def _unique_text(values: list[Any], separator: str = "\n") -> str:
    seen = set()
    result = []
    for value in values:
        text = " ".join(str(value or "").split())
        if text and text.casefold() not in seen:
            seen.add(text.casefold())
            result.append(text)
    return separator.join(result)


def _name_index(record: dict[str, Any]) -> dict[str, str]:
    rows = as_list((record.get("source") or {}).get("object_directory"))
    rows.extend(as_list((record.get("target") or {}).get("object_directory")))
    result = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        key = str(row.get("object_key") or "")
        name = str(row.get("object_name") or "")
        if key:
            result.setdefault(key, name)
    return result


def _display_scope(keys: list[Any], names: dict[str, str]) -> str:
    values = []
    for value in keys:
        key = str(value or "")
        if not key:
            continue
        name = names.get(key)
        values.append(
            str(redact_delivery_value(f"{name} ({key})" if name else key))
        )
    return "; ".join(values) or "Container-wide"


def _human_audit_focus(row: dict[str, Any]) -> str:
    if row.get("scope_level") == "coverage":
        return "Coverage applicability"
    fact_kind = str(row.get("fact_kind") or "").strip()
    if fact_kind:
        return fact_kind.replace("_", " ").capitalize()
    mechanism = str(row.get("audit_mechanism") or "").strip()
    return mechanism.replace("_", " ").capitalize() or "Configured behavior"


def _max_priority(decisions: list[dict[str, Any]]) -> str:
    values = [
        str((row.get("decision") or {}).get("priority") or "None")
        for row in decisions
    ]
    return min(values or ["None"], key=lambda value: PRIORITY_ORDER.get(value, 99))


def _row(
    *,
    row_id: str,
    sheet: str,
    locked: dict[str, Any],
    prose: dict[str, str],
) -> dict[str, Any]:
    safe_locked = redact_delivery_value(locked)
    safe_prose = {
        key: str(redact_delivery_value(value)) for key, value in prose.items()
    }
    payload = {
        "row_id": row_id,
        "primary_sheet": sheet,
        "locked": safe_locked,
        "allowed_prose_fields": list(safe_prose),
        "canonical_prose": safe_prose,
    }
    payload["binding_sha256"] = stable_hash(
        {"row_id": row_id, "sheet": sheet, "locked": safe_locked}, 64
    )
    return payload


def _recommendation_rows(
    record: dict[str, Any], names: dict[str, str]
) -> list[dict[str, Any]]:
    decisions = {
        str(row.get("canonical_decision_id") or ""): row
        for row in as_list(record.get("audit_decisions"))
    }
    result = []
    for operation in as_list(record.get("operations")):
        operation_id = str(operation.get("operation_id") or "")
        source_ids = [
            str(value)
            for value in as_list(operation.get("source_reconciled_decision_ids"))
        ]
        sources = [decisions[value] for value in source_ids if value in decisions]
        decision_classes = sorted(
            {
                str((row.get("decision") or {}).get("decision_class") or "")
                for row in sources
            }
        )
        human_types = sorted(
            {str(row.get("human_decision_label") or "") for row in sources}
        )
        subject_keys = sorted(
            {
                str(value)
                for row in sources
                for value in as_list(row.get("subject_keys"))
                if str(value)
            }
        )
        priority = _max_priority(sources)
        dependencies = [str(value) for value in as_list(operation.get("depends_on"))]
        operation_family = str(operation.get("operation_family") or "GTM change")
        result.append(
            _row(
                row_id=f"REC-{operation_id}",
                sheet="02 Recommendations",
                locked={
                    "operation_id": operation_id,
                    "source_decision_ids": source_ids,
                    "decision_classes": decision_classes,
                    "human_finding_types": human_types,
                    "priority": priority,
                    "subject_keys": subject_keys,
                    "depends_on": dependencies,
                    "action_payload_sha256": operation.get("action_payload_sha256"),
                    "exact_target_state": operation.get("exact_target_state"),
                    "static_verification": operation.get("static_verification"),
                    "rollback": operation.get("rollback"),
                    "technical_note": {
                        field: operation.get(field, [])
                        for field in (
                            "creations",
                            "additions",
                            "changes",
                            "removals",
                            "remaps",
                            "renames",
                            "pauses",
                            "deletions",
                        )
                    },
                },
                prose={
                    "action_operation_id": f"{operation_family} — {operation_id}",
                    "finding_type_priority": f"{' / '.join(human_types)} — {priority}",
                    "affected_scope": _display_scope(subject_keys, names),
                    "current_setup": _unique_text(
                        [
                            (row.get("decision") or {}).get("current_behavior")
                            for row in sources
                        ]
                    ),
                    "why_it_matters": _unique_text(
                        [
                            (row.get("decision") or {}).get(
                                "consequence_or_benefit"
                            )
                            for row in sources
                        ]
                    ),
                    "recommended_target": _unique_text(
                        [operation.get("exact_target_state")]
                        + [
                            (row.get("decision") or {}).get("target_direction")
                            for row in sources
                        ]
                    ),
                    "analyst_handoff": _unique_text(
                        [
                            (row.get("decision") or {}).get("next_step")
                            for row in sources
                        ]
                        + ([f"Complete after: {', '.join(dependencies)}"] if dependencies else [])
                    ),
                    "verification_rollback": _unique_text(
                        [
                            f"Verify: {operation.get('static_verification')}",
                            f"Rollback: {operation.get('rollback')}",
                        ]
                    ),
                },
            )
        )
    return sorted(
        result,
        key=lambda row: (
            PRIORITY_ORDER.get(str(row["locked"].get("priority") or "None"), 99),
            row["row_id"],
        ),
    )


def _owner_rows(
    record: dict[str, Any], names: dict[str, str]
) -> list[dict[str, Any]]:
    rows = {
        str(row.get("canonical_decision_id") or ""): row
        for row in as_list(record.get("audit_decisions"))
    }
    result = []
    for decision_id in as_list(record.get("owner_decision_ids")):
        row = rows[str(decision_id)]
        decision = row.get("decision") or {}
        scope = _display_scope(as_list(row.get("subject_keys")), names)
        result.append(
            _row(
                row_id=f"OWN-{decision_id}",
                sheet="03 Decisions Needed",
                locked={
                    "decision_id": decision_id,
                    "subject_keys": row.get("subject_keys", []),
                    "priority": decision.get("priority"),
                    "confidence": decision.get("confidence"),
                    "owner_question": decision.get("owner_question"),
                },
                prose={
                    "question": str(decision.get("owner_question") or ""),
                    "why_needed": str(decision.get("consequence_or_benefit") or ""),
                    "recommendation": str(decision.get("target_direction") or ""),
                    "affected_scope": scope,
                    "answer_unlocks": str(decision.get("next_step") or ""),
                },
            )
        )
    return result


def _full_audit_rows(
    record: dict[str, Any], names: dict[str, str], excluded_decision_ids: set[str]
) -> list[dict[str, Any]]:
    mapping = dict(record.get("decision_to_operation") or {})
    result = []
    for row in as_list(record.get("audit_decisions")):
        decision_id = str(row.get("canonical_decision_id") or "")
        if decision_id in excluded_decision_ids:
            continue
        decision = row.get("decision") or {}
        operation_id = str(mapping.get(decision_id) or "")
        result.append(
            _row(
                row_id=f"AUD-{decision_id}",
                sheet="04 Full Audit",
                locked={
                    "decision_id": decision_id,
                    "area_id": row.get("area_id"),
                    "area_title": row.get("area_title"),
                    "scope_level": row.get("scope_level"),
                    "audit_mechanism": row.get("audit_mechanism"),
                    "fact_kind": row.get("fact_kind"),
                    "audit_focus": _human_audit_focus(row),
                    "subject_keys": row.get("subject_keys", []),
                    "decision_class": decision.get("decision_class"),
                    "human_decision_label": row.get("human_decision_label"),
                    "operation_id": operation_id,
                    "priority": decision.get("priority"),
                    "confidence": decision.get("confidence"),
                    "record_owner": row.get("record_owner"),
                },
                prose={
                    "affected_scope": _display_scope(
                        as_list(row.get("subject_keys")), names
                    ),
                    "plain_finding": _unique_text(
                        [
                            decision.get("current_behavior"),
                            decision.get("criteria_assessment"),
                            decision.get("consequence_or_benefit"),
                        ]
                    ),
                    "outcome_linked_action": (
                        f"See operation {operation_id}. {decision.get('next_step')}"
                        if operation_id
                        else str(decision.get("next_step") or "")
                    ),
                },
            )
        )
    return result


def _custom_code_rows(
    record: dict[str, Any], names: dict[str, str], selected: set[str]
) -> list[dict[str, Any]]:
    decisions = {
        str(row.get("canonical_decision_id") or ""): row
        for row in as_list(record.get("audit_decisions"))
    }
    mapping = dict(record.get("decision_to_operation") or {})
    result = []
    for decision_id in sorted(selected):
        source = decisions[decision_id]
        decision = source.get("decision") or {}
        operation_id = str(mapping.get(decision_id) or "")
        result.append(
            _row(
                row_id=f"CODE-{decision_id}",
                sheet=CUSTOM_CODE_SHEET,
                locked={
                    "decision_id": decision_id,
                    "subject_keys": source.get("subject_keys", []),
                    "decision_class": decision.get("decision_class"),
                    "operation_id": operation_id,
                    "priority": decision.get("priority"),
                    "confidence": decision.get("confidence"),
                },
                prose={
                    "affected_scope": _display_scope(
                        as_list(source.get("subject_keys")), names
                    ),
                    "current_behavior": str(decision.get("current_behavior") or ""),
                    "finding": str(decision.get("criteria_assessment") or ""),
                    "safest_target": str(decision.get("target_direction") or ""),
                    "linked_action": (
                        f"See operation {operation_id}. {decision.get('next_step')}"
                        if operation_id
                        else str(decision.get("next_step") or "")
                    ),
                },
            )
        )
    return result


def _overview(record: dict[str, Any], recommendations: list[dict[str, Any]]) -> dict[str, Any]:
    source = record.get("source") or {}
    target = record.get("target") or {}
    identity = source.get("container_identity") or {}
    top = recommendations[:5]
    area_26 = [
        row
        for row in as_list(record.get("audit_decisions"))
        if row.get("area_id") == "AREA-26"
    ]
    retained = [
        row
        for row in as_list(record.get("audit_decisions"))
        if (row.get("decision") or {}).get("decision_class") == "justified_as_is"
    ]
    return {
        "container_label": _unique_text(
            [
                identity.get("container_name"),
                identity.get("public_id"),
                identity.get("container_id"),
            ],
            " — ",
        )
        or "GTM container",
        "audit_status": "Static container audit complete; analyst decision required before implementation.",
        "scope_boundary": source.get("scope_boundary"),
        "decision_counts": (record.get("summary") or {}).get("decision_counts", {}),
        "decision_labels": HUMAN_DECISION_LABELS,
        "decision_meanings": HUMAN_DECISION_MEANINGS,
        "priority_counts": (record.get("summary") or {}).get("priority_counts", {}),
        "highest_value_actions": [
            str(
                (row.get("canonical_prose") or {}).get(
                    "action_operation_id"
                )
                or ""
            )
            for row in top
        ],
        "target_architecture_summary": _unique_text(
            [
                (row.get("decision") or {}).get("target_direction")
                for row in area_26
            ]
        )
        or "The target preserves the proven container architecture with only reviewed changes.",
        "important_retained_summary": _unique_text(
            [
                (row.get("decision") or {}).get("preserved_distinctions")
                for row in retained[:5]
            ]
        )
        or "No material retained-family summary was required.",
        "blocking_summary": (
            f"{(record.get('summary') or {}).get('owner_decision_count', 0)} owner "
            f"decision(s) and {(record.get('summary') or {}).get('evidence_limit_count', 0)} "
            "container-evidence limit(s) remain explicit."
        ),
        "material_count_deltas": target.get("material_count_deltas", []),
        "next_step": (
            "Review the recommendations and decisions needed. Approve, reject, or revise "
            "them in a separate implementation task; this workbook is not execution approval."
        ),
    }


def _delivery_coverage_errors(
    record: dict[str, Any], delivery_map: dict[str, Any]
) -> list[str]:
    coverage = delivery_map.get("coverage") or {}
    all_decisions = {
        str(row.get("canonical_decision_id") or "")
        for row in as_list(record.get("audit_decisions"))
    }
    owner = set(as_list(coverage.get("owner_decision_ids")))
    code = set(as_list(coverage.get("custom_code_decision_ids")))
    full = set(as_list(coverage.get("full_audit_decision_ids")))
    errors = []
    primary_sets = (owner, code, full)
    if any(
        primary_sets[left] & primary_sets[right]
        for left in range(3)
        for right in range(left + 1, 3)
    ):
        errors.append("a canonical audit decision has more than one primary sheet")
    if owner | code | full != all_decisions:
        errors.append("primary sheets do not cover every canonical audit decision")
    expected_owner = set(as_list(record.get("owner_decision_ids")))
    expected_code = set(as_list(record.get("custom_code_decision_ids"))) - expected_owner
    if owner != expected_owner:
        errors.append("Decisions Needed ownership differs from the canonical record")
    if code != expected_code:
        errors.append("Custom Code ownership differs from the canonical precedence")
    if full != all_decisions - expected_owner - expected_code:
        errors.append("Full Audit ownership differs from the canonical precedence")
    expected_operations = {
        str(row.get("operation_id") or "")
        for row in as_list(record.get("operations"))
    }
    if set(as_list(coverage.get("recommendation_operation_ids"))) != expected_operations:
        errors.append("Recommendations do not cover every canonical operation")
    expected_map = {
        **{decision_id: "03 Decisions Needed" for decision_id in expected_owner},
        **{decision_id: CUSTOM_CODE_SHEET for decision_id in expected_code},
        **{
            decision_id: "04 Full Audit"
            for decision_id in all_decisions - expected_owner - expected_code
        },
    }
    if coverage.get("primary_decision_owner") != expected_map:
        errors.append("primary decision-owner map is incomplete or incorrect")
    row_ids = [str(row.get("row_id") or "") for row in as_list(delivery_map.get("rows"))]
    if "" in row_ids or len(row_ids) != len(set(row_ids)):
        errors.append("delivery row IDs are blank or duplicated")
    return errors


def delivery_map_from_record(
    record: dict[str, Any], language: str = "English"
) -> dict[str, Any]:
    """Project the exact human delivery map from canonical semantic authority."""

    names = _name_index(record)
    recommendations = _recommendation_rows(record, names)
    owner_rows = _owner_rows(record, names)
    owner_ids = set(as_list(record.get("owner_decision_ids")))
    code_ids = set(as_list(record.get("custom_code_decision_ids"))) - owner_ids
    full_rows = _full_audit_rows(record, names, owner_ids | code_ids)
    code_rows = _custom_code_rows(record, names, code_ids)
    rows = [*recommendations, *owner_rows, *full_rows, *code_rows]
    map_payload = {
        "kind": "gtm_human_delivery_map",
        "schema_version": 1,
        "canonical_record_sha256": record.get("canonical_record_sha256"),
        "language": language,
        "visible_sheets": [
            *VISIBLE_SHEETS,
            *([CUSTOM_CODE_SHEET] if code_rows else []),
        ],
        "overview": _overview(record, recommendations),
        "rows": rows,
        "coverage": {
            "recommendation_operation_ids": [
                row["locked"]["operation_id"] for row in recommendations
            ],
            "owner_decision_ids": [
                row["locked"]["decision_id"] for row in owner_rows
            ],
            "full_audit_decision_ids": [
                row["locked"]["decision_id"] for row in full_rows
            ],
            "custom_code_decision_ids": [
                row["locked"]["decision_id"] for row in code_rows
            ],
            "primary_decision_owner": {
                **{
                    row["locked"]["decision_id"]: "03 Decisions Needed"
                    for row in owner_rows
                },
                **{
                    row["locked"]["decision_id"]: CUSTOM_CODE_SHEET
                    for row in code_rows
                },
                **{
                    row["locked"]["decision_id"]: "04 Full Audit"
                    for row in full_rows
                },
            },
        },
    }
    privacy_errors = privacy_findings(json.dumps(map_payload, ensure_ascii=False))
    if privacy_errors:
        raise ValueError(
            "delivery map privacy projection failed: " + ", ".join(privacy_errors)
        )
    coverage_errors = _delivery_coverage_errors(record, map_payload)
    if coverage_errors:
        raise ValueError("delivery ownership failed: " + "; ".join(coverage_errors))
    map_payload["delivery_map_sha256"] = stable_hash(map_payload, 64)
    return map_payload


def audience_brief_payload(language: str) -> dict[str, Any]:
    brief = {
        "kind": "gtm_workbook_audience_brief",
        "schema_version": 1,
        "language": language,
        "primary_audience": (
            "A web analyst reviewing, challenging, deciding on, and potentially handing "
            "off the proposed GTM optimization."
        ),
        "overview_audience": (
            "A marketing or business owner who needs orientation and priorities."
        ),
        "wording_rules": [
            "Lead with the current configured situation, then consequence or benefit, target, and next step.",
            "Preserve exact GTM object names, IDs, event names, parameter names, consent tokens, and operation IDs.",
            "Distinguish source-visible facts from expected consequences and runtime limits.",
            "Do not expose internal workflow jargon or imply execution approval.",
        ],
    }
    brief["audience_brief_sha256"] = stable_hash(brief, 64)
    return brief


def create_delivery_map(
    package_dir: Path,
    language: str = "English",
    *,
    _validate_only: bool = False,
) -> dict[str, Any]:
    require_safe_package_root(package_dir)
    errors = canonical_record_seal_errors(package_dir)
    if errors:
        raise ValueError("canonical record gate failed: " + "; ".join(errors))
    root = package_dir / DELIVERY_ROOT
    if root.exists() and not _validate_only:
        raise ValueError("delivery artifacts already exist and are never overwritten")
    record = _load(package_dir / "canonical-record.json")
    map_payload = delivery_map_from_record(record, language)
    if _validate_only:
        return map_payload
    root.mkdir()
    rows = as_list(map_payload.get("rows"))
    map_path = root / DELIVERY_MAP_FILE
    write_json(map_path, map_payload)
    seal = {
        "kind": "gtm_human_delivery_map_seal",
        "schema_version": 1,
        "canonical_record_sha256": record.get("canonical_record_sha256"),
        "canonical_record_file_sha256": file_sha256(
            package_dir / "canonical-record.json"
        ),
        "delivery_map_sha256": map_payload["delivery_map_sha256"],
        "delivery_map_file_sha256": file_sha256(map_path),
        "validator_status": "pass",
    }
    seal["delivery_map_seal_sha256"] = _hash_without(
        seal, "delivery_map_seal_sha256"
    )
    write_json(root / DELIVERY_MAP_SEAL_FILE, seal)
    brief = audience_brief_payload(language)
    write_json(root / AUDIENCE_BRIEF_FILE, brief)
    editorial = {
        "kind": "gtm_human_editorial_artifact",
        "schema_version": 1,
        "status": "pending",
        "delivery_map_sha256": map_payload["delivery_map_sha256"],
        "audience_brief_sha256": brief["audience_brief_sha256"],
        "language": language,
        "rows": [
            {
                "row_id": row["row_id"],
                "primary_sheet": row["primary_sheet"],
                "binding_sha256": row["binding_sha256"],
                "prose": row["canonical_prose"],
            }
            for row in rows
        ],
        "overview_prose": {
            key: value
            for key, value in map_payload["overview"].items()
            if key
            in {
                "audit_status",
                "scope_boundary",
                "target_architecture_summary",
                "important_retained_summary",
                "blocking_summary",
                "next_step",
            }
        },
        "completion_attestation": {
            "semantic_fields_changed": False,
            "technical_identifiers_preserved": False,
            "conclusion": "",
        },
    }
    write_json(root / EDITORIAL_FILE, editorial)
    return {
        "status": "ready_for_editorial_review",
        "delivery_map_sha256": map_payload["delivery_map_sha256"],
        "rows": len(rows),
        "visible_sheets": map_payload["visible_sheets"],
    }


def _delivery_map_errors(package_dir: Path) -> tuple[dict[str, Any], list[str]]:
    require_safe_package_root(package_dir)
    root = package_dir / DELIVERY_ROOT
    map_path = root / DELIVERY_MAP_FILE
    seal_path = root / DELIVERY_MAP_SEAL_FILE
    if not map_path.is_file() or not seal_path.is_file():
        return {}, ["delivery map or seal is missing"]
    delivery_map = _load(map_path)
    seal = _load(seal_path)
    errors = []
    if delivery_map.get("delivery_map_sha256") != _hash_without(
        delivery_map, "delivery_map_sha256"
    ):
        errors.append("delivery map content hash is invalid")
    if seal.get("delivery_map_seal_sha256") != _hash_without(
        seal, "delivery_map_seal_sha256"
    ):
        errors.append("delivery map seal hash is invalid")
    if seal.get("delivery_map_file_sha256") != file_sha256(map_path):
        errors.append("delivery map changed after sealing")
    canonical_path = package_dir / "canonical-record.json"
    if canonical_path.is_file():
        canonical = _load(canonical_path)
        errors.extend(_delivery_coverage_errors(canonical, delivery_map))
        try:
            expected_map = delivery_map_from_record(
                canonical, str(delivery_map.get("language") or "English")
            )
        except ValueError as exc:
            errors.append(f"delivery map reconstruction failed: {exc}")
        else:
            if delivery_map != expected_map:
                errors.append("delivery map differs from canonical reconstruction")
    errors.extend(canonical_record_seal_errors(package_dir))
    if canonical_path.is_file():
        expected_seal = {
            "kind": "gtm_human_delivery_map_seal",
            "schema_version": 1,
            "canonical_record_sha256": _load(canonical_path).get(
                "canonical_record_sha256"
            ),
            "canonical_record_file_sha256": file_sha256(canonical_path),
            "delivery_map_sha256": delivery_map.get("delivery_map_sha256"),
            "delivery_map_file_sha256": file_sha256(map_path),
            "validator_status": "pass",
        }
        expected_seal["delivery_map_seal_sha256"] = _hash_without(
            expected_seal, "delivery_map_seal_sha256"
        )
        if seal != expected_seal:
            errors.append("delivery map seal differs from canonical reconstruction")
    return delivery_map, errors


def validate_editorial(package_dir: Path) -> list[str]:
    require_safe_package_root(package_dir)
    delivery_map, errors = _delivery_map_errors(package_dir)
    root = package_dir / DELIVERY_ROOT
    path = root / EDITORIAL_FILE
    if not path.is_file():
        return [*errors, "editorial artifact is missing"]
    editorial = _load(path)
    if editorial.get("status") != "complete":
        errors.append("editorial artifact status must be complete")
    if editorial.get("delivery_map_sha256") != delivery_map.get(
        "delivery_map_sha256"
    ):
        errors.append("editorial artifact is bound to another delivery map")
    expected_rows = {
        str(row.get("row_id") or ""): row for row in as_list(delivery_map.get("rows"))
    }
    supplied_rows = [
        row for row in as_list(editorial.get("rows")) if isinstance(row, dict)
    ]
    supplied = {str(row.get("row_id") or ""): row for row in supplied_rows}
    if len(supplied) != len(supplied_rows) or set(supplied) != set(expected_rows):
        errors.append("editorial rows must match the exact mapped row set")
    for row_id, expected in expected_rows.items():
        row = supplied.get(row_id)
        if not row:
            continue
        label = f"editorial row {row_id}"
        for field in ("row_id", "primary_sheet", "binding_sha256"):
            if row.get(field) != expected.get(field):
                errors.append(f"{label}: locked binding field {field} changed")
        prose = row.get("prose")
        if not isinstance(prose, dict) or set(prose) != set(
            expected.get("allowed_prose_fields", [])
        ):
            errors.append(f"{label}: editable prose field set changed")
            continue
        for field, value in prose.items():
            text = str(value or "").strip()
            if not text:
                errors.append(f"{label}: prose field {field} is blank")
            if PROHIBITED_VISIBLE_JARGON.search(text):
                errors.append(f"{label}: prose field {field} exposes internal workflow jargon")
            if UNSUPPORTED_CLAIM_RE.search(text):
                errors.append(f"{label}: prose field {field} overstates static evidence")
            for finding in privacy_findings(text):
                errors.append(f"{label}: prose field {field} contains {finding}")
        if expected["primary_sheet"] == "02 Recommendations":
            operation_id = str(expected["locked"].get("operation_id") or "")
            if operation_id not in str(prose.get("action_operation_id") or ""):
                errors.append(f"{label}: operation ID was removed from visible action")
    allowed_overview = {
        "audit_status",
        "scope_boundary",
        "target_architecture_summary",
        "important_retained_summary",
        "blocking_summary",
        "next_step",
    }
    overview = editorial.get("overview_prose")
    if not isinstance(overview, dict) or set(overview) != allowed_overview:
        errors.append("editorial overview prose fields changed")
    else:
        for field, value in overview.items():
            text = str(value or "").strip()
            if not text:
                errors.append(f"editorial overview {field} is blank")
            if PROHIBITED_VISIBLE_JARGON.search(text):
                errors.append(f"editorial overview {field} exposes internal jargon")
            if UNSUPPORTED_CLAIM_RE.search(text):
                errors.append(f"editorial overview {field} overstates static evidence")
            for finding in privacy_findings(text):
                errors.append(f"editorial overview {field} contains {finding}")
    attestation = editorial.get("completion_attestation") or {}
    if attestation.get("semantic_fields_changed") is not False:
        errors.append("editorial review changed or did not protect semantic fields")
    if attestation.get("technical_identifiers_preserved") is not True:
        errors.append("editorial review did not attest identifier preservation")
    if len(str(attestation.get("conclusion") or "").split()) < 8:
        errors.append("editorial completion conclusion is incomplete")
    return errors


def seal_editorial(
    package_dir: Path, *, amendment_of: str | None = None
) -> dict[str, Any]:
    require_safe_package_root(package_dir)
    errors = validate_editorial(package_dir)
    if errors:
        raise ValueError("editorial gate failed: " + "; ".join(errors))
    root = package_dir / DELIVERY_ROOT
    path = root / EDITORIAL_FILE
    seal_path = root / EDITORIAL_SEAL_FILE
    previous = _load(seal_path) if seal_path.exists() else None
    if previous:
        if amendment_of != previous.get("editorial_seal_sha256"):
            raise ValueError(
                "editorial amendment must cite the current editorial seal"
            )
    elif amendment_of:
        raise ValueError("amendment_of was supplied but no editorial seal exists")
    editorial = _load(path)
    sequence = int(previous.get("amendment_sequence", 0)) + 1 if previous else 0
    versions = root / "editorial-versions"
    versions.mkdir(exist_ok=True)
    version_path = versions / f"editorial-{sequence:03d}.json"
    if version_path.exists():
        raise ValueError("editorial version identity already exists")
    # Normalize representation before sealing so the current artifact and its
    # immutable version are byte-identical without changing semantic content.
    write_json(path, editorial)
    write_json(version_path, editorial)
    seal = {
        "kind": "gtm_human_editorial_seal",
        "schema_version": 1,
        "delivery_map_sha256": editorial.get("delivery_map_sha256"),
        "editorial_version_path": version_path.relative_to(root).as_posix(),
        "editorial_file_sha256": file_sha256(version_path),
        "editorial_content_sha256": stable_hash(editorial, 64),
        "amendment_sequence": sequence,
        "amendment_parent_seal_sha256": (
            str(previous.get("editorial_seal_sha256") or "") if previous else ""
        ),
        "validator_status": "pass",
    }
    seal["editorial_seal_sha256"] = _hash_without(
        seal, "editorial_seal_sha256"
    )
    write_json(seal_path, seal)
    return {
        "status": "pass",
        "editorial_seal_sha256": seal["editorial_seal_sha256"],
    }


def editorial_seal_errors(package_dir: Path) -> list[str]:
    require_safe_package_root(package_dir)
    root = package_dir / DELIVERY_ROOT
    editorial_path = root / EDITORIAL_FILE
    seal_path = root / EDITORIAL_SEAL_FILE
    if not editorial_path.is_file() or not seal_path.is_file():
        return ["editorial artifact or seal is missing"]
    seal = _load(seal_path)
    errors = validate_editorial(package_dir)
    try:
        version_path = contained_relative_path(
            root,
            seal.get("editorial_version_path"),
            "editorial version path",
        )
    except ValueError as exc:
        errors.append(str(exc))
        version_path = root / "__invalid-editorial-version__"
    if seal.get("editorial_seal_sha256") != _hash_without(
        seal, "editorial_seal_sha256"
    ):
        errors.append("editorial seal content hash is invalid")
    if not version_path.is_file():
        errors.append("sealed editorial version is missing")
    elif seal.get("editorial_file_sha256") != file_sha256(version_path):
        errors.append("sealed editorial version changed")
    elif file_sha256(editorial_path) != file_sha256(version_path):
        errors.append("current editorial artifact differs from its sealed version")
    if seal.get("validator_status") != "pass":
        errors.append("editorial validator did not pass")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    create = subparsers.add_parser("create")
    create.add_argument("package_dir", type=Path)
    create.add_argument("--language", default="English")
    validate = subparsers.add_parser("validate-editorial")
    validate.add_argument("package_dir", type=Path)
    seal = subparsers.add_parser("seal-editorial")
    seal.add_argument("package_dir", type=Path)
    seal.add_argument("--amendment-of")
    args = parser.parse_args()
    try:
        if args.command == "create":
            result = create_delivery_map(args.package_dir, args.language)
        elif args.command == "validate-editorial":
            errors = validate_editorial(args.package_dir)
            result = {"status": "pass" if not errors else "blocked", "errors": errors}
            if errors:
                print(json.dumps(result, ensure_ascii=False, indent=2))
                return 2
        else:
            result = seal_editorial(
                args.package_dir, amendment_of=args.amendment_of
            )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"status": "blocked", "errors": [str(exc)]}))
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
