#!/usr/bin/env python3
"""Authoritative machine contract for the GTM audit workflow.

This module contains stable vocabulary and coverage metadata only.  It does not
inspect a container or author an audit verdict.
"""

from __future__ import annotations

from typing import Any

from gtm_lib import stable_hash

SCHEMA_VERSION = 1

DECISION_CLASSES = (
    "defect",
    "correct_but_materially_non_optimal",
    "justified_as_is",
    "owner_decision",
    "container_evidence_limit",
    "not_applicable",
)

ACTIONABLE_DECISION_CLASSES = frozenset(
    {"defect", "correct_but_materially_non_optimal"}
)

PRIORITIES = ("Critical", "High", "Medium", "Low", "None")
CONFIDENCE_LEVELS = ("High", "Medium", "Low", "Evidence limited")

HUMAN_DECISION_LABELS = {
    "defect": "Needs correction",
    "correct_but_materially_non_optimal": "Optimisation",
    "justified_as_is": "Appropriate as configured",
    "owner_decision": "Decision needed",
    "container_evidence_limit": "Cannot determine from container evidence",
    "not_applicable": "Not applicable",
}

HUMAN_DECISION_MEANINGS = {
    "defect": "Incorrect configuration that should be corrected.",
    "correct_but_materially_non_optimal": (
        "Valid setup with a material improvement opportunity."
    ),
    "justified_as_is": "No material change is recommended.",
    "owner_decision": "An owner answer is required.",
    "container_evidence_limit": "The container alone cannot determine this.",
    "not_applicable": "The criterion does not apply.",
}

SCOPE_LEVELS = ("object", "chain", "family", "relationship", "container", "coverage")

# Audit area 1 is a deterministic evidence gate. Areas 2-26 are independently
# judged by both clean-room audits. Area 27 is produced after reconciliation.
AUDIT_AREAS: tuple[dict[str, Any], ...] = (
    {
        "area_id": "AREA-01",
        "title": "Source identity and evidence completeness",
        "phase": "evidence_gate",
        "method": "pre_audit_evidence_gate",
    },
    {
        "area_id": "AREA-02",
        "title": "Object inventory and identity",
        "phase": "semantic",
        "method": "object_chain_first",
    },
    {
        "area_id": "AREA-03",
        "title": "Dependency and reference graph",
        "phase": "semantic",
        "method": "object_chain_first",
    },
    {
        "area_id": "AREA-04",
        "title": "Lifecycle, reachability, and usage",
        "phase": "semantic",
        "method": "cross_level",
    },
    {
        "area_id": "AREA-05",
        "title": "Exact duplicates and functional overlap",
        "phase": "semantic",
        "method": "cross_level",
    },
    {
        "area_id": "AREA-06",
        "title": "Tag and template configuration",
        "phase": "semantic",
        "method": "object_chain_first",
    },
    {
        "area_id": "AREA-07",
        "title": "Trigger event and condition topology",
        "phase": "semantic",
        "method": "cross_level",
    },
    {
        "area_id": "AREA-08",
        "title": "Firing options, priority, scheduling, and sequencing",
        "phase": "semantic",
        "method": "object_chain_first",
    },
    {
        "area_id": "AREA-09",
        "title": "CMP and consent infrastructure",
        "phase": "semantic",
        "method": "cross_level",
    },
    {
        "area_id": "AREA-10",
        "title": "Direct client-side consent architecture",
        "phase": "semantic",
        "method": "cross_level",
    },
    {
        "area_id": "AREA-11",
        "title": "Advanced Consent Mode",
        "phase": "semantic",
        "method": "cross_level",
    },
    {
        "area_id": "AREA-12",
        "title": "Client-to-server transporter architecture",
        "phase": "semantic",
        "method": "cross_level",
    },
    {
        "area_id": "AREA-13",
        "title": "Client-side server handoff and evidence boundary",
        "phase": "semantic",
        "method": "cross_level",
    },
    {
        "area_id": "AREA-14",
        "title": "Variable graph and source contracts",
        "phase": "semantic",
        "method": "object_chain_first",
    },
    {
        "area_id": "AREA-15",
        "title": "Effective Google configuration and field ownership",
        "phase": "semantic",
        "method": "cross_level",
    },
    {
        "area_id": "AREA-16",
        "title": "Destination, loader, and page-view ownership",
        "phase": "semantic",
        "method": "cross_level",
    },
    {
        "area_id": "AREA-17",
        "title": "GA4 event and parameter correctness",
        "phase": "semantic",
        "method": "object_chain_first",
    },
    {
        "area_id": "AREA-18",
        "title": "Ecommerce",
        "phase": "semantic",
        "method": "cross_level",
    },
    {
        "area_id": "AREA-19",
        "title": "Ads, Floodlight, and other vendor tags",
        "phase": "semantic",
        "method": "object_chain_first",
    },
    {
        "area_id": "AREA-20",
        "title": "Transformations and source-to-destination semantics",
        "phase": "semantic",
        "method": "cross_level",
    },
    {
        "area_id": "AREA-21",
        "title": "First-party data, identity, and privacy-sensitive fields",
        "phase": "semantic",
        "method": "cross_level",
    },
    {
        "area_id": "AREA-22",
        "title": "Custom templates and custom code",
        "phase": "semantic",
        "method": "object_chain_first",
    },
    {
        "area_id": "AREA-23",
        "title": "Zones, environments, and portability",
        "phase": "semantic",
        "method": "cross_level",
    },
    {
        "area_id": "AREA-24",
        "title": "Naming, folders, notes, and documentation",
        "phase": "semantic",
        "method": "container_family_first",
    },
    {
        "area_id": "AREA-25",
        "title": "Static efficiency and complexity",
        "phase": "semantic",
        "method": "cross_level",
    },
    {
        "area_id": "AREA-26",
        "title": "Business architecture and greenfield target state",
        "phase": "semantic",
        "method": "container_family_first",
    },
    {
        "area_id": "AREA-27",
        "title": "Exact operations and fixed-point cleanup",
        "phase": "post_reconciliation",
        "method": "post_reconciliation_proof",
    },
)

AREA_BY_ID = {row["area_id"]: row for row in AUDIT_AREAS}
SEMANTIC_AREA_IDS = tuple(
    row["area_id"] for row in AUDIT_AREAS if row["phase"] == "semantic"
)

AUDIT_METHODS = {
    "audit_a": {
        "label": "Evidence-first traversal",
        "order": (
            "object",
            "chain",
            "relationship",
            "family",
            "container",
            "coverage",
        ),
    },
    "audit_b": {
        "label": "Target-first traversal",
        "order": (
            "container",
            "family",
            "relationship",
            "chain",
            "object",
            "coverage",
        ),
    },
}

CONSENT_ROUTE_CLASSES = (
    "consent_infrastructure",
    "confirmed_advanced_consent_mode",
    "pure_client_to_server_transporter",
    "direct_browser_or_vendor",
)

MATERIAL_NEUTRAL_REVIEW_TRIGGERS = frozenset(
    {
        "one_sided_finding",
        "conflicting_verdict",
        "conflicting_target",
        "different_evidence_boundary",
        "consent_architecture",
        "client_server_transport",
        "client_server_consent_handoff",
        "active_deletion",
        "active_consolidation",
        "loader_change",
        "destination_change",
        "page_view_change",
        "ecommerce_change",
        "paid_media_change",
        "identity_change",
        "custom_code_replacement",
        "template_replacement",
        "high_fan_out_shared_setting",
        "cross_market_change",
        "unknown_integration",
        "high_or_critical_operation",
    }
)

OPERATION_ACTION_FIELDS = (
    "creations",
    "additions",
    "changes",
    "removals",
    "remaps",
    "renames",
    "pauses",
    "deletions",
)

CANONICAL_DECISION_FIELDS = (
    "decision_class",
    "current_behavior",
    "criteria_assessment",
    "consequence_or_benefit",
    "preserved_distinctions",
    "target_direction",
    "evidence_boundary",
    "owner_question",
    "next_step",
    "priority",
    "confidence",
    "static_verification",
    "rollback",
)


def audit_contract_payload() -> dict[str, Any]:
    payload = {
        "kind": "gtm_audit_contract",
        "schema_version": SCHEMA_VERSION,
        "audit_areas": list(AUDIT_AREAS),
        "decision_classes": list(DECISION_CLASSES),
        "human_decision_labels": HUMAN_DECISION_LABELS,
        "human_decision_meanings": HUMAN_DECISION_MEANINGS,
        "priorities": list(PRIORITIES),
        "confidence_levels": list(CONFIDENCE_LEVELS),
        "audit_methods": AUDIT_METHODS,
        "consent_route_classes": list(CONSENT_ROUTE_CLASSES),
        "operation_action_fields": list(OPERATION_ACTION_FIELDS),
        "canonical_decision_fields": list(CANONICAL_DECISION_FIELDS),
    }
    payload["audit_contract_sha256"] = stable_hash(payload, 64)
    return payload


def semantic_contract_errors(decision: dict[str, Any], label: str) -> list[str]:
    errors: list[str] = []
    decision_class = str(decision.get("decision_class") or "")
    if decision_class not in DECISION_CLASSES:
        errors.append(f"{label}: decision_class is invalid")
    if decision.get("priority") not in PRIORITIES:
        errors.append(f"{label}: priority is invalid")
    if decision.get("confidence") not in CONFIDENCE_LEVELS:
        errors.append(f"{label}: confidence is invalid")
    for field in CANONICAL_DECISION_FIELDS:
        if field in {"owner_question", "evidence_boundary"}:
            continue
        if not str(decision.get(field) or "").strip():
            errors.append(f"{label}: {field} is missing")
    if decision_class == "owner_decision" and not str(
        decision.get("owner_question") or ""
    ).strip():
        errors.append(f"{label}: owner_decision requires one precise owner_question")
    if decision_class == "container_evidence_limit" and not str(
        decision.get("evidence_boundary") or ""
    ).strip():
        errors.append(
            f"{label}: container_evidence_limit requires an explicit evidence_boundary"
        )
    if decision_class in ACTIONABLE_DECISION_CLASSES:
        proposal = decision.get("operation_proposal")
        if not isinstance(proposal, dict) or not str(
            proposal.get("operation_id") or ""
        ).strip():
            errors.append(f"{label}: actionable decision requires an exact operation_proposal")
    return errors
