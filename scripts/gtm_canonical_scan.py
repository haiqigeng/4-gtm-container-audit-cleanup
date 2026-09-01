#!/usr/bin/env python3
"""Build the single deterministic GTM scan used by both semantic audits."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

from gtm_architecture_review import scaffold_review as architecture_evidence_scaffold
from gtm_audit_contract import AUDIT_AREAS, audit_contract_payload
from gtm_configuration_review import scaffold_review as configuration_evidence_scaffold
from gtm_context_model import build_context_model
from gtm_custom_code_extract import extract_export
from gtm_lib import (
    ID_KEYS,
    as_list,
    container_root_path,
    container_version,
    file_sha256,
    source_descriptor,
    stable_hash,
    write_json,
)
from gtm_operational_review import scaffold_review as operational_evidence_scaffold
from gtm_optimization_facts import build_optimization_facts
from gtm_requirement_evidence import build_requirement_evidence
from gtm_shared_facts import build_shared_facts
from gtm_source_model import build_model

OPERATIONAL_DECISION_FIELDS = frozenset(
    {
        "review_status",
        "disposition",
        "rationale",
        "operation_key",
        "title",
        "area",
        "problem_type",
        "problem",
        "why_it_matters",
        "expected_clean_state",
        "exact_proposed_action",
        "canonical_object_key",
        "canonical_selection_rationale",
        "rationale_evidence_terms",
        "creations",
        "additions",
        "changes",
        "removals",
        "remaps",
        "deletions",
        "renames",
        "pauses",
        "preconditions",
        "qa_steps",
        "rollback",
        "priority",
        "confidence",
        "execution_readiness",
        "owner_question",
        "recommended_action",
        "recommended_canonical_object_key",
        "recommended_canonical_basis",
        "challenge_review",
    }
)

CONFIGURATION_DECISION_FIELDS = frozenset(
    {
        "minimum_semantic_review_depth",
        "semantic_review_basis",
        "behavior_review_groups",
        "configuration_coverage_metrics",
        "semantic_review_depth",
        "review_status",
        "purpose",
        "execution_logic",
        "inputs_and_terminal_sources",
        "configured_output_or_side_effect",
        "consumer_contract",
        "consent_and_sequence",
        "correctness_verdict",
        "correctness_basis",
        "defects",
        "contract_checks",
        "code_behavior_blocks",
        "technical_facts_assessment",
        "technical_code_recommendation",
        "technical_exact_proposed_action",
        "technical_disposition",
        "technical_disposition_vocabulary",
        "technical_finding_reviews",
        "logic_cross_checks",
        "configuration_branch_reviews",
        "evidence_anchors",
        "consumer_evidence_keys",
        "reference_traces",
        "disposition",
        "owner_question",
        "recommended_action",
        "external_evidence_status",
        "external_evidence_summary",
        "external_evidence_next_action",
        "consumer_specific_code_basis",
        "operation",
        "confidence",
        "evidence_citations",
    }
)

ARCHITECTURE_DECISION_FIELDS = frozenset(
    {
        "review_status",
        "business_action",
        "family_purpose",
        "member_assessments",
        "chain_assessments",
        "execution_path_summary",
        "payload_coherence",
        "consent_and_sequence_coherence",
        "necessity_and_ownership",
        "relationship_verdict",
        "analyst_rationale",
        "target_architecture",
        "architecture_effect",
        "disposition",
        "owner_question",
        "recommended_action",
        "recommended_canonical_object_key",
        "recommended_canonical_basis",
        "canonical_selection_rationale",
        "operations",
        "confidence",
    }
)

NEUTRAL_FACT_SEMANTIC_KEY_ALLOWLIST = frozenset(
    {
        "candidate_status",
        "scan_status",
        "parser_status",
        "explicit_firing_priority",
        "firing_priority",
        "firing_priority_raw",
    }
)
SEMANTIC_KEY_RE = re.compile(
    r"(?:^|_)(?:verdict|recommend(?:ed|ation)?|rationale|disposition|"
    r"correctness|priority|confidence|owner_question|target_architecture|"
    r"exact_proposed_action|why_it_matters|problem)(?:$|_)",
    re.I,
)


def _without_fields(row: Any, fields: frozenset[str]) -> Any:
    """Recursively remove every known semantic field from legacy scaffolds."""

    if isinstance(row, dict):
        return {
            key: _without_fields(value, fields)
            for key, value in row.items()
            if key not in fields
        }
    if isinstance(row, list):
        return [_without_fields(value, fields) for value in row]
    return row


def neutral_fact_judgment_leaks(value: Any, path: str = "$") -> list[str]:
    """Fail closed when a projected evidence object contains judgment-shaped keys."""

    leaks: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}"
            if (
                str(key) not in NEUTRAL_FACT_SEMANTIC_KEY_ALLOWLIST
                and SEMANTIC_KEY_RE.search(str(key))
            ):
                leaks.append(child_path)
            leaks.extend(neutral_fact_judgment_leaks(child, child_path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            leaks.extend(neutral_fact_judgment_leaks(child, f"{path}[{index}]"))
    return leaks


def _require_neutral_fact_projection(payload: dict[str, Any], label: str) -> dict[str, Any]:
    leaks = neutral_fact_judgment_leaks(payload)
    if leaks:
        raise ValueError(
            f"{label} leaked judgment-shaped fields into canonical evidence: "
            + ", ".join(leaks[:12])
        )
    return payload


def _neutral_operational_evidence(review: dict[str, Any]) -> dict[str, Any]:
    return _require_neutral_fact_projection({
        "kind": "gtm_operational_candidate_evidence",
        "schema_version": 1,
        "source_sha256": review.get("source_sha256"),
        "inventory_counts": review.get("inventory_counts", {}),
        "lifecycle_matrix": review.get("lifecycle_matrix", []),
        "folder_topology": review.get("folder_topology", {}),
        "destination_matrix": review.get("destination_matrix", []),
        "trigger_lint_summary": review.get("trigger_lint_summary", {}),
        "module_results": review.get("module_results", []),
        "candidates": [
            _without_fields(row, OPERATIONAL_DECISION_FIELDS)
            for row in as_list(review.get("findings"))
            if isinstance(row, dict)
        ],
    }, "operational evidence")


def _neutral_configuration_evidence(review: dict[str, Any]) -> dict[str, Any]:
    return _require_neutral_fact_projection({
        "kind": "gtm_configuration_candidate_evidence",
        "schema_version": 1,
        "source_sha256": review.get("source_sha256"),
        "objects": [
            _without_fields(row, CONFIGURATION_DECISION_FIELDS)
            for row in as_list(review.get("rows"))
            if isinstance(row, dict)
        ],
    }, "configuration evidence")


def _neutral_architecture_evidence(review: dict[str, Any]) -> dict[str, Any]:
    discovery = review.get("open_discovery_attestation") or {}
    return _require_neutral_fact_projection({
        "kind": "gtm_architecture_candidate_evidence",
        "schema_version": 1,
        "source_sha256": review.get("source_sha256"),
        "families": [
            _without_fields(row, ARCHITECTURE_DECISION_FIELDS)
            for row in as_list(review.get("families"))
            if isinstance(row, dict)
        ],
        "relationships": [
            _without_fields(row, ARCHITECTURE_DECISION_FIELDS)
            for row in as_list(review.get("comparisons"))
            if isinstance(row, dict)
        ],
        "open_discovery_methods": [
            {
                key: value
                for key, value in row.items()
                if key
                not in {
                    "review_status",
                    "reviewed_comparison_ids",
                    "reviewed_object_keys",
                    "additional_discovery_ids",
                    "conclusion",
                }
            }
            for row in as_list(discovery.get("method_reviews"))
            if isinstance(row, dict)
        ],
    }, "architecture evidence")


def _source_layer_counts(cv: dict[str, Any]) -> dict[str, int]:
    return {layer: len(as_list(cv.get(layer))) for layer in ID_KEYS}


def _area_source_counts(
    cv: dict[str, Any],
    technical: dict[str, Any],
    operational: dict[str, Any],
    configuration: dict[str, Any],
    architecture: dict[str, Any],
    optimization: dict[str, Any],
) -> dict[str, int]:
    tags = len(as_list(cv.get("tag")))
    triggers = len(as_list(cv.get("trigger")))
    variables = len(as_list(cv.get("variable")))
    templates = len(as_list(cv.get("customTemplate")))
    zones = len(as_list(cv.get("zone")))
    clients = len(as_list(cv.get("client")))
    transformations = len(as_list(cv.get("transformation")))
    gtag_configs = len(as_list(cv.get("gtagConfig")))
    total = sum(_source_layer_counts(cv).values())
    operational_candidates = len(as_list(operational.get("candidates")))
    relationships = len(as_list(architecture.get("relationships")))
    families = len(as_list(architecture.get("families")))
    code_rows = len(as_list(technical.get("rows")))
    consent_tags = sum(
        1
        for row in as_list(optimization.get("tag_control_topology"))
        if row.get("positive_route_contains_consent")
        or row.get("blocker_contains_consent")
        or (row.get("consent_metadata") or {}).get("contains_consent_value")
    )
    google_surfaces = len(as_list(optimization.get("effective_google_settings")))
    destinations = sum(
        len(as_list(row.get("destination_peer_contexts")))
        for row in as_list(configuration.get("objects"))
    )
    ecommerce = sum(
        1
        for row in as_list(configuration.get("objects"))
        if any(
            term in json.dumps(row, ensure_ascii=False).casefold()
            for term in ("purchase", "refund", "ecommerce", "items")
        )
    )
    sensitive = sum(
        1
        for row in as_list(configuration.get("objects"))
        if any(
            term in json.dumps(row, ensure_ascii=False).casefold()
            for term in ("email", "phone", "user_id", "user_data", "address")
        )
    )
    return {
        "AREA-01": 1,
        "AREA-02": total,
        "AREA-03": total,
        "AREA-04": total,
        "AREA-05": relationships + operational_candidates,
        "AREA-06": tags + templates,
        "AREA-07": tags + triggers,
        "AREA-08": tags,
        "AREA-09": consent_tags,
        "AREA-10": consent_tags,
        "AREA-11": consent_tags,
        "AREA-12": sum(
            1
            for row in as_list(optimization.get("tag_control_topology"))
            if as_list(row.get("server_route_hosts"))
        ),
        "AREA-13": clients + transformations,
        "AREA-14": variables,
        "AREA-15": google_surfaces + gtag_configs,
        "AREA-16": tags + gtag_configs + destinations,
        "AREA-17": sum(
            1
            for row in as_list(configuration.get("objects"))
            if str(row.get("object_type") or "") in {"gaawe", "googtag", "gaawc"}
        ),
        "AREA-18": ecommerce,
        "AREA-19": tags,
        "AREA-20": transformations + variables,
        "AREA-21": sensitive,
        "AREA-22": code_rows + templates,
        "AREA-23": zones + gtag_configs,
        "AREA-24": total,
        "AREA-25": total + len(as_list(optimization.get("optimization_candidates"))),
        "AREA-26": families + relationships,
        "AREA-27": 0,
    }


def _coverage_ledger(counts: dict[str, int]) -> list[dict[str, Any]]:
    rows = []
    for area in AUDIT_AREAS:
        area_id = str(area["area_id"])
        count = int(counts.get(area_id, 0))
        rows.append(
            {
                **area,
                "source_count": count,
                "applicability": "applicable" if count else "source_counted_zero",
                "scan_status": "complete",
            }
        )
    return rows


def _content_hash(payload: dict[str, Any]) -> str:
    return stable_hash(
        {key: value for key, value in payload.items() if key != "canonical_scan_sha256"},
        64,
    )


def build_canonical_scan(
    export_path: Path,
    *,
    context_path: Path | None = None,
    requirements_path: Path | None = None,
    provided_context: dict[str, Any] | None = None,
    approved_requirements: dict[str, Any] | None = None,
) -> dict[str, Any]:
    source_model = build_model(export_path)
    if source_model.get("coverage_gate") == "blocked_source_integrity":
        blocking = [
            row
            for row in as_list(source_model.get("source_integrity_findings"))
            if isinstance(row, dict) and row.get("blocking")
        ]
        explanation = "; ".join(
            f"{row.get('finding_type')}: {row.get('details')}" for row in blocking
        )
        raise ValueError(
            "source identity or entity-layer integrity is blocking"
            + (f": {explanation}" if explanation else "")
        )
    context = build_context_model(
        export_path,
        context_path,
        provided_context=provided_context,
    )
    technical = extract_export(export_path)
    shared_facts = build_shared_facts(
        export_path,
        context=context,
        technical=technical,
        navigation=source_model,
    )
    operational = _neutral_operational_evidence(
        operational_evidence_scaffold(export_path, shared_facts)
    )
    configuration = _neutral_configuration_evidence(
        configuration_evidence_scaffold(export_path, technical, shared_facts)
    )
    architecture = _neutral_architecture_evidence(
        architecture_evidence_scaffold(export_path, shared_facts)
    )
    optimization = build_optimization_facts(export_path, shared_facts)
    requirements = dict(approved_requirements or {})
    if requirements_path and not requirements:
        requirements = build_requirement_evidence(requirements_path)

    data = json.loads(export_path.read_text(encoding="utf-8"))
    cv = container_version(data)
    layer_counts = _source_layer_counts(cv)
    area_counts = _area_source_counts(
        cv,
        technical,
        operational,
        configuration,
        architecture,
        optimization,
    )
    contract = audit_contract_payload()
    scan = {
        **source_descriptor(export_path),
        "kind": "gtm_canonical_container_scan",
        "schema_version": 1,
        "container_root_path": container_root_path(data),
        "container_identity": source_model.get("container_identity", {}),
        "context_sha256": context.get("context_sha256"),
        "shared_facts_sha256": shared_facts.get("shared_facts_sha256"),
        "audit_contract_sha256": contract["audit_contract_sha256"],
        "approved_requirements_sha256": (
            stable_hash(requirements, 64) if requirements else ""
        ),
        "source_layer_counts": layer_counts,
        "coverage_ledger": _coverage_ledger(area_counts),
        "objects": as_list(shared_facts.get("objects")),
        "integrity_findings": shared_facts.get("integrity_findings", {}),
        "operational_evidence": operational,
        "configuration_evidence": configuration,
        "architecture_evidence": architecture,
        "optimization_facts": optimization,
        "code_evidence": technical,
        "approved_requirements_present": bool(requirements),
        "source_only_checkpoint_boundary": (
            "Approved requirements are separately identified and must remain withheld "
            "until each audit's source-only checkpoint is sealed."
        ),
        "counts": {
            "objects": sum(layer_counts.values()),
            "source_leaves": shared_facts.get("counts", {}).get("source_leaves", 0),
            "operational_candidates": len(as_list(operational.get("candidates"))),
            "configuration_objects": len(as_list(configuration.get("objects"))),
            "families": len(as_list(architecture.get("families"))),
            "relationships": len(as_list(architecture.get("relationships"))),
            "optimization_candidates": len(
                as_list(optimization.get("optimization_candidates"))
            ),
            "custom_code_objects": source_model.get("counts", {}).get(
                "custom_code_objects", 0
            ),
            "approved_requirements": len(as_list(requirements.get("requirements"))),
        },
    }
    scan["canonical_scan_sha256"] = _content_hash(scan)
    return {
        "canonical_scan": scan,
        "audit_contract": contract,
        "source_model": source_model,
        "context": context,
        "shared_facts": shared_facts,
        "approved_requirements": requirements,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("export", type=Path)
    parser.add_argument("--context", type=Path)
    parser.add_argument("--requirements", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    result = build_canonical_scan(
        args.export,
        context_path=args.context,
        requirements_path=args.requirements,
    )
    write_json(args.out, result["canonical_scan"])
    print(
        json.dumps(
            {
                "status": "pass",
                "source_sha256": file_sha256(args.export),
                "canonical_scan_sha256": result["canonical_scan"][
                    "canonical_scan_sha256"
                ],
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
