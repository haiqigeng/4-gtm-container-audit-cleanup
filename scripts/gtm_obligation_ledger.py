#!/usr/bin/env python3
"""Generate the complete typed semantic obligation ledger from an assured scan."""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

from gtm_audit_contract import AREA_BY_ID, SEMANTIC_AREA_IDS
from gtm_lib import as_list, locked_evidence_coordinates, stable_hash, write_json

SENSITIVE_RE = re.compile(
    r"email|phone|address|user[_ -]?id|user_data|enhanced conversion|first.party|"
    r"hashed|sha256|identity|customer",
    re.I,
)
ECOMMERCE_RE = re.compile(
    r"purchase|refund|add_to_cart|begin_checkout|ecommerce|transaction_id|items",
    re.I,
)
CONSENT_RE = re.compile(
    r"consent|didomi|onetrust|optanon|cookiebot|analytics_storage|ad_storage|"
    r"ad_user_data|ad_personalization",
    re.I,
)
GOOGLE_TYPES = {"googtag", "gaawe", "gaawc", "gclidw", "flc", "fls"}


def _source_paths(value: Any) -> list[str]:
    paths: set[str] = set()

    def visit(item: Any) -> None:
        if isinstance(item, dict):
            for key, child in item.items():
                if key in {
                    "source_json_path",
                    "json_path",
                    "source_reference_path",
                } and str(child or "").startswith("$"):
                    paths.add(str(child))
                elif key in {"candidate_source_paths", "available_member_evidence_anchors"}:
                    paths.update(locked_evidence_coordinates([], child))
                else:
                    visit(child)
        elif isinstance(item, list):
            for child in item:
                visit(child)

    visit(value)
    return sorted(paths)


def _subject_keys(value: Any) -> list[str]:
    keys: set[str] = set()

    def add(raw: Any) -> None:
        text = str(raw or "")
        if ":" in text and not text.startswith(("http:", "https:")):
            keys.add(text)

    if isinstance(value, dict):
        for field in (
            "object_key",
            "candidate_object_keys",
            "consumer_object_keys",
            "member_object_keys",
            "chain_object_keys",
            "shared_fact_object_keys",
        ):
            raw = value.get(field)
            if isinstance(raw, list):
                for item in raw:
                    add(item)
            else:
                add(raw)
    return sorted(keys)


def _owner_family_ids(value: dict[str, Any]) -> list[str]:
    return sorted(
        {
            str(value.get(field) or "")
            for field in ("family_id", "owner_family_id")
            if str(value.get(field) or "")
        }
    )


def _obligation(
    area_id: str,
    scope_level: str,
    mechanism: str,
    fact_kind: str,
    evidence: dict[str, Any],
    *,
    subject_keys: list[str] | None = None,
    family_ids: list[str] | None = None,
    release_phase: str = "source_only",
    applicability: str = "applicable",
    candidate_id: str = "",
    candidate_owner: str = "",
    material_verification_triggers: list[str] | None = None,
) -> dict[str, Any]:
    subjects = sorted(set(subject_keys or _subject_keys(evidence)))
    families = sorted(set(family_ids or _owner_family_ids(evidence)))
    coordinates = _source_paths(evidence)
    identity = {
        "area_id": area_id,
        "scope_level": scope_level,
        "fact_kind": fact_kind,
        "subject_keys": subjects,
        "family_ids": families,
        "candidate_id": candidate_id,
        "source_coordinates": coordinates,
        "release_phase": release_phase,
    }
    row = {
        "obligation_id": "OBL-" + area_id[-2:] + "-" + stable_hash(identity, 16).upper(),
        "area_id": area_id,
        "area_title": AREA_BY_ID[area_id]["title"],
        "scope_level": scope_level,
        "audit_mechanism": mechanism,
        "fact_kind": fact_kind,
        "applicability": applicability,
        "release_phase": release_phase,
        "subject_keys": subjects,
        "family_ids": families,
        "candidate_id": candidate_id,
        "candidate_owner": candidate_owner,
        "source_coordinates": coordinates,
        "material_verification_triggers": sorted(
            set(material_verification_triggers or [])
        ),
        "evidence": evidence,
        "evidence_sha256": stable_hash(evidence, 64),
        "required_audit_question": (
            "Using only the locked evidence and applicable current contract, decide what "
            "is wrong, what can be materially better, what should stay and why, or what "
            "requires one owner answer or evidence boundary."
        ),
    }
    row["obligation_sha256"] = stable_hash(row, 64)
    return row


def _operational_area(candidate: dict[str, Any]) -> str:
    if candidate.get("finding_type") in {
        "naming_architecture_mismatch", "folder_naming_review"
    }:
        return "AREA-24"
    text = " ".join(
        str(candidate.get(field) or "")
        for field in ("finding_type", "object_type", "details", "problem_type")
    ).casefold()
    if any(term in text for term in ("reference", "cycle", "consumer", "dependency")):
        return "AREA-03"
    if any(term in text for term in ("unused", "paused", "orphan", "reach", "lifecycle")):
        return "AREA-04"
    if any(term in text for term in ("duplicate", "overlap", "equivalent")):
        return "AREA-05"
    if any(term in text for term in ("trigger", "regex", "condition", "blocking")):
        return "AREA-07"
    if any(term in text for term in ("priority", "schedule", "sequenc", "firingoption")):
        return "AREA-08"
    if any(term in text for term in ("name", "folder", "note", "unicode", "whitespace")):
        return "AREA-24"
    return "AREA-02"


def _configuration_area(obj: dict[str, Any], obligation: dict[str, Any]) -> str:
    evidence_anchors = {
        str(value)
        for value in as_list(obligation.get("evidence_anchors"))
        if str(value)
    }
    anchored_source_facts = [
        fact
        for fact in as_list(obj.get("source_facts"))
        if isinstance(fact, dict)
        and str(fact.get("json_path") or "") in evidence_anchors
    ]
    raw_text = json.dumps(
        {
            "layer": obj.get("layer"),
            "type": obj.get("object_type"),
            "source_facts": anchored_source_facts,
        },
        ensure_ascii=False,
    )
    lowered = raw_text.casefold()
    if CONSENT_RE.search(raw_text):
        return "AREA-09"
    if "firingtrigger" in lowered or "blockingtrigger" in lowered or "condition" in lowered:
        return "AREA-07"
    if any(term in lowered for term in ("priority", "schedule", "setuptag", "teardowntag")):
        return "AREA-08"
    if ECOMMERCE_RE.search(raw_text):
        return "AREA-18"
    if SENSITIVE_RE.search(raw_text):
        return "AREA-21"
    if obj.get("layer") == "variable":
        return "AREA-14"
    if obj.get("layer") == "customTemplate" or as_list(obj.get("code_line_facts")):
        return "AREA-22"
    if str(obj.get("object_type") or "") in GOOGLE_TYPES:
        return "AREA-17"
    return "AREA-06"


def _requirement_obligations(
    requirement_evidence: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    rows = []
    for requirement in as_list(
        (requirement_evidence or {}).get("requirements")
    ):
        if not isinstance(requirement, dict):
            continue
        evidence = {
            "requirement_id": requirement.get("requirement_id"),
            "source_reference": requirement.get("source_reference"),
            "source_row": requirement,
        }
        rows.append(
            _obligation(
                "AREA-26",
                "container",
                "approved_requirement_comparison",
                "approved_external_requirement",
                evidence,
                release_phase="post_source_checkpoint",
            )
        )
    return rows


def build_obligation_ledger(
    scan: dict[str, Any],
    assurance: dict[str, Any],
    requirement_evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if assurance.get("status") != "pass":
        raise ValueError("canonical scan assurance must pass before obligations are built")
    if assurance.get("canonical_scan_sha256") != scan.get("canonical_scan_sha256"):
        raise ValueError("scan assurance is bound to another canonical scan")

    rows: list[dict[str, Any]] = []
    objects = [
        row
        for row in as_list((scan.get("configuration_evidence") or {}).get("objects"))
        if isinstance(row, dict)
    ]
    object_keys = {str(row.get("object_key") or "") for row in objects}

    # Every semantic area has an explicit source-counted coverage unit. This
    # makes zero and non-applicability visible instead of a silent skip.
    coverage_by_area = {
        str(row.get("area_id") or ""): row
        for row in as_list(scan.get("coverage_ledger"))
    }
    for area_id in SEMANTIC_AREA_IDS:
        coverage = coverage_by_area[area_id]
        rows.append(
            _obligation(
                area_id,
                "coverage",
                "source_counted_coverage",
                "coverage_attestation",
                coverage,
                applicability=str(coverage.get("applicability") or "applicable"),
            )
        )

    # The assured scan and compact source checkpoint already cover every literal
    # object and source branch. Semantic audits therefore review only transversal,
    # decision-relevant units instead of repeating one prose decision per object-area
    # combination.
    for obj in objects:
        object_key = str(obj.get("object_key") or "")
        code_lines = [
            row
            for row in as_list(obj.get("code_line_facts"))
            if isinstance(row, dict) and str(row.get("line_hash") or "")
        ]
        if code_lines:
            segment_identity = {
                "object_key": object_key,
                "line_hashes": [str(row["line_hash"]) for row in code_lines],
            }
            segment_id = "CODEOBJ-" + stable_hash(segment_identity, 16).upper()
            rows.append(
                _obligation(
                    "AREA-22",
                    "object",
                    "custom_code_object_review",
                    "executable_code_object",
                    {
                        **segment_identity,
                        "segment_id": segment_id,
                        "object_name": obj.get("object_name"),
                        "source_json_path": obj.get("source_json_path"),
                        "start_line": code_lines[0].get("line_number"),
                        "end_line": code_lines[-1].get("line_number"),
                        "line_segments": code_lines,
                        "parser_status": (
                            obj.get("technical_code_facts") or {}
                        ).get("javascript_parser"),
                    },
                    subject_keys=[object_key],
                    candidate_id=segment_id,
                    candidate_owner=segment_id,
                    material_verification_triggers=["custom_code_replacement"],
                )
            )
        for nested in as_list(obj.get("required_configuration_obligations")):
            if not isinstance(nested, dict):
                continue
            area_id = _configuration_area(obj, nested)
            evidence = {
                "object_key": object_key,
                "object_name": obj.get("object_name"),
                "source_json_path": obj.get("source_json_path"),
                "configuration_obligation": nested,
            }
            rows.append(
                _obligation(
                    area_id,
                    "object",
                    "configured_leaf_branch_trace_review",
                    "configuration_obligation",
                    evidence,
                    subject_keys=[object_key],
                    material_verification_triggers=(
                        ["consent_architecture"] if area_id in {"AREA-09", "AREA-10", "AREA-11", "AREA-12"} else []
                    ),
                )
            )

    # Deterministic sanitation candidates remain candidates until both audits
    # make a semantic disposition.
    for candidate in as_list(
        (scan.get("operational_evidence") or {}).get("candidates")
    ):
        if not isinstance(candidate, dict):
            continue
        area_id = _operational_area(candidate)
        candidate_id = str(candidate.get("finding_id") or "")
        subjects = _subject_keys(candidate)
        if not subjects:
            layer = str(candidate.get("object_type") or "")
            subjects = sorted(
                f"{layer}:{value}"
                for value in as_list(candidate.get("object_ids"))
                if f"{layer}:{value}" in object_keys
            )
        rows.append(
            _obligation(
                area_id,
                "relationship" if len(subjects) > 1 else "object",
                "sanitation_candidate_review",
                str(candidate.get("finding_type") or "operational_candidate"),
                candidate,
                subject_keys=subjects,
                candidate_id=candidate_id,
                candidate_owner=candidate_id,
                material_verification_triggers=(
                    ["active_deletion"]
                    if "unused" in str(candidate.get("finding_type") or "").casefold()
                    else []
                ),
            )
        )

    # Neutral optimisation candidates.
    for candidate in as_list(
        (scan.get("optimization_facts") or {}).get("optimization_candidates")
    ):
        if not isinstance(candidate, dict):
            continue
        candidate_type = str(candidate.get("candidate_type") or "")
        area_id = "AREA-08" if candidate_type == "explicit_firing_priority" else "AREA-15"
        subjects = _subject_keys(candidate)
        candidate_id = str(candidate.get("candidate_id") or "")
        rows.append(
            _obligation(
                area_id,
                "relationship" if len(subjects) > 1 else "object",
                "optimization_candidate_review",
                candidate_type,
                candidate,
                subject_keys=subjects,
                candidate_id=candidate_id,
                candidate_owner=candidate_id,
                material_verification_triggers=(
                    ["high_fan_out_shared_setting"]
                    if len(subjects) >= 5
                    else []
                ),
            )
        )

    # Complete consent/control topology is independently judged even when no
    # deterministic defect candidate exists.
    for topology in as_list(
        (scan.get("optimization_facts") or {}).get("tag_control_topology")
    ):
        if not isinstance(topology, dict):
            continue
        key = str(topology.get("object_key") or "")
        applicability = topology.get("consent_applicability") or {}
        review_area_ids = ["AREA-07", "AREA-08"]
        if applicability.get("consent_infrastructure"):
            review_area_ids.append("AREA-09")
        if applicability.get("direct_non_advanced_browser_vendor"):
            review_area_ids.append("AREA-10")
        if applicability.get("advanced_google_destination_review"):
            review_area_ids.append("AREA-11")
        if applicability.get("client_to_server_transport"):
            review_area_ids.extend(["AREA-12", "AREA-13"])
        rows.append(
            _obligation(
                "AREA-07",
                "chain",
                "effective_control_topology_review",
                "tag_event_and_blocker_topology",
                {**topology, "review_area_ids": sorted(set(review_area_ids))},
                subject_keys=[key],
                material_verification_triggers=(
                    ["consent_architecture"]
                    if any(area in review_area_ids for area in ("AREA-09", "AREA-10", "AREA-11"))
                    else []
                )
                + (["client_server_transport"] if "AREA-12" in review_area_ids else []),
            )
        )

    consent_infrastructure = (
        scan.get("optimization_facts") or {}
    ).get("consent_infrastructure_summary") or {}
    if as_list(consent_infrastructure.get("context_cmp")) or as_list(
        consent_infrastructure.get("writer_facts")
    ):
        rows.append(
            _obligation(
                "AREA-09",
                "container",
                "consent_infrastructure_review",
                "source_visible_default_update_architecture",
                consent_infrastructure,
                material_verification_triggers=["consent_architecture"],
            )
        )

    # Source-derived families and deterministic relationship candidates.
    architecture = scan.get("architecture_evidence") or {}
    for family in as_list(architecture.get("families")):
        if not isinstance(family, dict):
            continue
        family_id = str(family.get("family_id") or "")
        rows.append(
            _obligation(
                "AREA-26",
                "family",
                "business_family_review",
                "implementation_family",
                family,
                family_ids=[family_id],
                candidate_id=family_id,
                candidate_owner=family_id,
            )
        )
    for relationship in as_list(architecture.get("relationships")):
        if not isinstance(relationship, dict):
            continue
        comparison_id = str(relationship.get("comparison_id") or "")
        subjects = _subject_keys(relationship)
        triggers = []
        types = " ".join(
            str(value) for value in as_list(relationship.get("comparison_types"))
        ).casefold()
        if "consent" in types:
            triggers.append("consent_architecture")
        if "server" in types or "route" in types:
            triggers.append("client_server_transport")
        rows.append(
            _obligation(
                "AREA-05",
                "relationship",
                "relationship_candidate_review",
                "functional_relationship_candidate",
                relationship,
                subject_keys=subjects,
                candidate_id=comparison_id,
                candidate_owner=comparison_id,
                material_verification_triggers=triggers,
            )
        )

    # Container-level architecture and efficiency are never inferred solely
    # from per-object decisions.
    container_evidence = {
        "source_sha256": scan.get("source_sha256"),
        "source_layer_counts": scan.get("source_layer_counts", {}),
        "counts": scan.get("counts", {}),
        "family_ids": sorted(
            str(row.get("family_id") or "")
            for row in as_list(architecture.get("families"))
        ),
        "relationship_ids": sorted(
            str(row.get("comparison_id") or "")
            for row in as_list(architecture.get("relationships"))
        ),
        "open_discovery_methods": architecture.get("open_discovery_methods", []),
    }
    for area_id, fact_kind in (
        ("AREA-24", "container_organisation"),
        ("AREA-25", "container_complexity_and_change_surface"),
        ("AREA-26", "greenfield_target_architecture"),
    ):
        rows.append(
            _obligation(
                area_id,
                "container",
                "global_container_closure",
                fact_kind,
                container_evidence,
            )
        )

    rows.extend(_requirement_obligations(requirement_evidence))

    rows = sorted(rows, key=lambda row: row["obligation_id"])
    ids = [row["obligation_id"] for row in rows]
    if len(ids) != len(set(ids)):
        duplicates = sorted(key for key, count in Counter(ids).items() if count > 1)
        raise ValueError("obligation identities collide: " + ", ".join(duplicates))
    covered_areas = {row["area_id"] for row in rows}
    missing_areas = sorted(set(SEMANTIC_AREA_IDS) - covered_areas)
    if missing_areas:
        raise ValueError("semantic area coverage is incomplete: " + ", ".join(missing_areas))

    source_only_ids = [
        row["obligation_id"] for row in rows if row["release_phase"] == "source_only"
    ]
    post_checkpoint_ids = [
        row["obligation_id"]
        for row in rows
        if row["release_phase"] == "post_source_checkpoint"
    ]
    payload = {
        "kind": "gtm_semantic_obligation_ledger",
        "schema_version": 1,
        "source_sha256": scan.get("source_sha256"),
        "canonical_scan_sha256": scan.get("canonical_scan_sha256"),
        "scan_assurance_sha256": assurance.get("scan_assurance_sha256"),
        "obligations": rows,
        "release_sets": {
            "source_only": source_only_ids,
            "post_source_checkpoint": post_checkpoint_ids,
        },
        "counts": {
            "obligations": len(rows),
            "source_only": len(source_only_ids),
            "post_source_checkpoint": len(post_checkpoint_ids),
            "by_area": dict(sorted(Counter(row["area_id"] for row in rows).items())),
            "by_scope": dict(sorted(Counter(row["scope_level"] for row in rows).items())),
            "by_mechanism": dict(
                sorted(Counter(row["audit_mechanism"] for row in rows).items())
            ),
        },
    }
    payload["obligation_ledger_sha256"] = stable_hash(payload, 64)
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scan", type=Path)
    parser.add_argument("assurance", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    scan = json.loads(args.scan.read_text(encoding="utf-8"))
    assurance = json.loads(args.assurance.read_text(encoding="utf-8"))
    result = build_obligation_ledger(scan, assurance)
    write_json(args.out, result)
    print(json.dumps({"status": "pass", "counts": result["counts"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
