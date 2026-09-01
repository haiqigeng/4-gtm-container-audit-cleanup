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
    custom_template_executable_code,
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

APPLICABILITY_SIGNAL_LAYERS = (
    "tag",
    "trigger",
    "variable",
    "customTemplate",
    "gtagConfig",
    "transformation",
)
ECOMMERCE_SIGNAL_RE = re.compile(
    r"\becommerce\b|\bpurchase\b|\brefund\b|\bitems\b|\btransaction[_ .-]?id\b",
    re.I,
)
SENSITIVE_DATA_SIGNAL_RE = re.compile(
    r"\bemail\b|\bphone\b|\buser[_ .-]?id\b|\buser[_ .-]?data\b|\baddress\b",
    re.I,
)

OPERATIONAL_CANDIDATE_FACT_FIELDS = frozenset(
    {
        "module_name",
        "module_status",
        "objects_scanned",
        "finding_id",
        "finding_type",
        "object_type",
        "object_ids",
        "object_names",
        "signature_key",
        "deterministic_evidence",
        "source_lens",
        "object_identities",
        "shared_fact_object_keys",
        "shared_behavior_signatures",
    }
)

CONFIGURATION_OBJECT_FACT_FIELDS = frozenset(
    {
        "review_id",
        "object_key",
        "layer",
        "object_id",
        "object_name",
        "object_type",
        "paused",
        "config_hash",
        "source_json_path",
        "source_facts",
        "available_evidence_anchors",
        "required_logic_anchors",
        "required_branch_reviews",
        "code_line_facts",
        "required_code_line_hashes",
        "referenced_variables",
        "reference_trace_requirements",
        "export_consumers",
        "specificity_tokens",
        "detected_vendor",
        "vendor_category",
        "vendor_contexts",
        "required_contract_topics",
        "official_doc_candidates",
        "technical_code_facts",
        "shared_behavior_signatures",
        "effective_consent_route_facts",
        "execution_dependency_traces",
        "execution_dependency_facts",
        "consumer_dependency_facts",
        "consumer_dependency_contexts",
        "destination_peer_contexts",
        "destination_peer_facts",
        "source_absence_facts",
        "approved_requirement_links",
        "required_logic_cross_checks",
        "required_configuration_obligations",
    }
)

ARCHITECTURE_FAMILY_FACT_FIELDS = frozenset(
    {
        "family_id",
        "family_key",
        "family_label",
        "member_object_keys",
        "member_object_names",
        "member_source_paths",
        "member_behavior_signatures",
        "member_config_hashes",
        "member_evidence_terms",
        "member_distinguishing_terms",
        "member_paused_status",
        "chain_object_keys",
        "chain_object_names",
        "chain_source_paths",
        "chain_edges",
        "chain_behavior_signatures",
        "chain_config_hashes",
        "chain_evidence_terms",
        "chain_specificity_tokens",
        "chain_paused_status",
        "available_member_evidence_anchors",
        "available_chain_evidence_anchors",
        "approved_requirement_links",
    }
)

ARCHITECTURE_RELATIONSHIP_FACT_FIELDS = frozenset(
    {
        "comparison_id",
        "comparison_origin",
        "comparison_type",
        "comparison_types",
        "layer",
        "candidate_object_ids",
        "candidate_object_keys",
        "candidate_object_names",
        "candidate_object_types",
        "candidate_source_paths",
        "candidate_config_hashes",
        "candidate_behavior_signatures",
        "candidate_evidence_terms",
        "candidate_distinguishing_terms",
        "candidate_specificity_tokens",
        "candidate_paused_status",
        "candidate_basis",
        "discovery_methods",
        "similarity_score",
        "required_comparison_dimensions",
        "required_caution_states",
        "available_member_evidence_anchors",
        "approved_requirement_links",
    }
)

ARCHITECTURE_DISCOVERY_FACT_FIELDS = frozenset(
    {
        "method",
        "scan_status",
        "source_scope_sha256",
        "review_scope_object_keys",
        "candidate_object_keys",
        "comparison_ids",
    }
)

CODE_ROW_FACT_FIELDS = frozenset(
    {
        "technical_finding_id",
        "object_identity",
        "layer",
        "object_id",
        "object_name",
        "type",
        "config_hash",
        "code_hash",
        "code_length",
        "logical_line_count",
        "source_lens",
        "source_independent_of_baseline",
        "javascript_parser",
        "javascript_parser_version",
        "parser_input_normalized",
        "parser_gtm_substitutions",
        "ast_parse_errors",
        "ast_node_counts",
        "ast_calls",
        "ast_branch_count",
        "ast_return_count",
        "return_expressions",
        "returned_value_type",
        "referenced_gtm_variables",
        "consumers",
        "side_effects",
        "technical_current_behavior",
        "external_scripts_loaded",
        "network_calls",
        "manual_gtag_calls",
        "dataLayer_reads",
        "dataLayer_pushes_or_writes",
        "dataLayer_resets",
        "cookies_read_written",
        "cookie_writes",
        "dynamic_cookie_missing_attributes",
        "cookie_duration_multiplier_facts",
        "localStorage_use",
        "sessionStorage_use",
        "dom_reads_writes",
        "dom_selector_reads",
        "dom_mutations",
        "document_write_calls",
        "event_listeners",
        "listener_lifecycle",
        "timer_lifecycle",
        "observer_lifecycle",
        "mutation_observer_signals",
        "async_cmp_callback_candidate",
        "postmessage_security",
        "secret_like_credential_signals",
        "base64_signals",
        "debugger_statements",
        "javascript_without_script_wrapper",
        "google_tag_manager_internal_access",
        "optimize_or_antiflicker_signals",
        "cache_buster_signals",
        "fixed_slot_aggregation",
        "fixed_slot_groups",
        "string_coercion_undefined_facts",
        "semantic_name_output_findings",
        "formula_review_required",
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
JUDGMENT_SHAPED_KEYS = frozenset(
    {
        "default_action",
        "deterministic_action_candidate",
        "finding_class",
        "operation_packet_required",
        "required_resolution",
        "policy_confirmation_required",
        "selected_naming_policy",
        "target_naming_pattern",
        "technical_action_candidate",
        "technical_cleanup_implication",
        "technical_expected_clean_state",
        "technical_code_health_status",
        "technical_code_health_findings",
        "technical_code_security_findings",
        "technical_code_optimization_findings",
        "technical_plain_language_summary",
        "technical_preconditions",
        "technical_qa_steps",
        "technical_rollback_note",
        "technical_handoff_packet",
        "behavior_can_be_understood_from_export",
        "container_evidence_limits",
        "required_technical_findings",
    }
)
SEMANTIC_KEY_RE = re.compile(
    r"(?:^|_)(?:verdict|recommend(?:ed|ation)?|rationale|disposition|"
    r"correctness|priority|confidence|owner_question|target_architecture|"
    r"exact_proposed_action|why_it_matters|problem)(?:$|_)",
    re.I,
)


def _select_fields(row: dict[str, Any], fields: frozenset[str]) -> dict[str, Any]:
    """Project only declared neutral fact fields; unknown source fields are dropped."""

    return {key: value for key, value in row.items() if key in fields}


def _neutral_code_row(row: dict[str, Any]) -> dict[str, Any]:
    return _select_fields(row, CODE_ROW_FACT_FIELDS)


def _neutral_code_evidence(report: dict[str, Any]) -> dict[str, Any]:
    return _require_neutral_fact_projection(
        {
            "kind": "gtm_custom_code_fact_evidence",
            "source_file": report.get("source_file"),
            "source_sha256": report.get("source_sha256"),
            "custom_code_count": report.get("custom_code_count", 0),
            "rows": [
                _neutral_code_row(row)
                for row in as_list(report.get("rows"))
                if isinstance(row, dict)
            ],
        },
        "code evidence",
    )


def neutral_fact_judgment_leaks(value: Any, path: str = "$") -> list[str]:
    """Fail closed when a projected evidence object contains judgment-shaped keys."""

    leaks: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}"
            if (
                str(key) not in NEUTRAL_FACT_SEMANTIC_KEY_ALLOWLIST
                and (
                    str(key) in JUDGMENT_SHAPED_KEYS
                    or SEMANTIC_KEY_RE.search(str(key))
                )
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
        "candidates": [
            _select_fields(row, OPERATIONAL_CANDIDATE_FACT_FIELDS)
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
            {
                **_select_fields(row, CONFIGURATION_OBJECT_FACT_FIELDS),
                **(
                    {
                        "technical_code_facts": _neutral_code_row(
                            row["technical_code_facts"]
                        )
                    }
                    if isinstance(row.get("technical_code_facts"), dict)
                    else {}
                ),
            }
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
            _select_fields(row, ARCHITECTURE_FAMILY_FACT_FIELDS)
            for row in as_list(review.get("families"))
            if isinstance(row, dict)
        ],
        "relationships": [
            _select_fields(row, ARCHITECTURE_RELATIONSHIP_FACT_FIELDS)
            for row in as_list(review.get("comparisons"))
            if isinstance(row, dict)
        ],
        "open_discovery_methods": [
            _select_fields(row, ARCHITECTURE_DISCOVERY_FACT_FIELDS)
            for row in as_list(discovery.get("method_reviews"))
            if isinstance(row, dict)
        ],
    }, "architecture evidence")


def _source_layer_counts(cv: dict[str, Any]) -> dict[str, int]:
    return {layer: len(as_list(cv.get(layer))) for layer in ID_KEYS}


def _raw_source_signal_count(cv: dict[str, Any], pattern: re.Pattern[str]) -> int:
    return sum(
        1
        for layer in APPLICABILITY_SIGNAL_LAYERS
        for obj in as_list(cv.get(layer))
        if isinstance(obj, dict)
        and pattern.search(
            custom_template_executable_code(obj.get("templateData"))
            if layer == "customTemplate"
            else json.dumps(obj, ensure_ascii=False)
        )
    )


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
    gtag_configs = len(as_list(cv.get("gtagConfig")))
    transformations = len(as_list(cv.get("transformation")))
    total = sum(_source_layer_counts(cv).values())
    operational_candidates = len(as_list(operational.get("candidates")))
    relationships = len(as_list(architecture.get("relationships")))
    families = len(as_list(architecture.get("families")))
    code_rows = len(as_list(technical.get("rows")))
    topology = [
        row
        for row in as_list(optimization.get("tag_control_topology"))
        if isinstance(row, dict)
    ]
    consent_infrastructure = optimization.get("consent_infrastructure_summary") or {}
    consent_infrastructure_tags = sum(
        1
        for row in topology
        if (row.get("consent_applicability") or {}).get(
            "consent_infrastructure"
        )
    )
    direct_non_advanced_tags = sum(
        1
        for row in topology
        if (row.get("consent_applicability") or {}).get(
            "direct_non_advanced_browser_vendor"
        )
    )
    advanced_google_tags = sum(
        1
        for row in topology
        if (row.get("consent_applicability") or {}).get(
            "advanced_google_destination_review"
        )
    )
    server_route_tags = sum(
        1
        for row in topology
        if (row.get("consent_applicability") or {}).get(
            "client_to_server_transport"
        )
    )
    google_surfaces = len(as_list(optimization.get("effective_google_settings")))
    destinations = sum(
        len(as_list(row.get("destination_peer_contexts")))
        for row in as_list(configuration.get("objects"))
    )
    ecommerce = _raw_source_signal_count(cv, ECOMMERCE_SIGNAL_RE)
    sensitive = _raw_source_signal_count(cv, SENSITIVE_DATA_SIGNAL_RE)
    return {
        "AREA-01": 1,
        "AREA-02": total,
        "AREA-03": total,
        "AREA-04": total,
        "AREA-05": relationships + operational_candidates,
        "AREA-06": tags + templates,
        "AREA-07": tags + triggers,
        "AREA-08": tags,
        "AREA-09": consent_infrastructure_tags
        + int(bool(as_list(consent_infrastructure.get("context_cmp")))),
        "AREA-10": direct_non_advanced_tags,
        "AREA-11": advanced_google_tags,
        "AREA-12": server_route_tags,
        "AREA-13": server_route_tags,
        "AREA-14": variables,
        "AREA-15": google_surfaces,
        "AREA-16": tags + gtag_configs + destinations,
        "AREA-17": sum(
            1
            for row in as_list(configuration.get("objects"))
            if str(row.get("object_type") or "") in {"gaawe", "googtag", "gaawc"}
        ),
        "AREA-18": ecommerce,
        "AREA-19": tags,
        "AREA-20": (
            tags
            + variables
            + transformations
            + gtag_configs
            + templates
            + code_rows
        ),
        "AREA-21": sensitive,
        "AREA-22": code_rows + templates,
        "AREA-23": total,
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
    neutral_code = _neutral_code_evidence(technical)
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
        "code_evidence": neutral_code,
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
    _require_neutral_fact_projection(scan, "canonical scan")
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
