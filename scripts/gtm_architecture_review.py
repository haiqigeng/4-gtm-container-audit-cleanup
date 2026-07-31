#!/usr/bin/env python3
"""Scaffold and validate GTM business-family and target-architecture review."""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

from gtm_lib import (
    ID_KEYS,
    as_list,
    container_root_path,
    container_version,
    custom_template_ids,
    custom_template_type_index,
    is_system_trigger_reference,
    is_system_variable_reference,
    refs,
    source_descriptor,
    source_integrity_findings,
    stable_hash,
    trigger_group_members,
    write_json,
)
from gtm_relationships import (
    DISCOVERY_METHOD_BY_COMPARISON_TYPE,
    object_records,
    relationship_candidates,
    tag_business_event_key,
    tag_contract,
)
from gtm_review_common import (
    VALID_CONFIDENCE,
    VALID_PRIORITIES,
    VALID_READINESS,
    canonical_review_facts,
    object_consumer_map,
    object_keys,
    object_name_map,
    object_source_path_map,
    pending_completion_attestation,
    precise_question,
    repeated_semantic_template_errors,
    review_input_contract,
    source_specific_owner_question_errors,
    specific_text,
    validate_challenge,
    validate_operation_set,
    validate_review_provenance,
    validate_structured_actions,
)
from gtm_shared_facts import build_shared_facts
from gtm_taxonomy import taxonomy_errors

VALID_RELATIONSHIP_VERDICTS = {
    "Exact duplicate",
    "Functional overlap",
    "Consolidation candidate",
    "Intentional variant",
    "Complementary",
    "Conflict",
    "Unrelated",
    "Owner decision needed",
    "Container evidence limit",
}
ACTIONABLE_VERDICTS = {
    "Exact duplicate",
    "Functional overlap",
    "Consolidation candidate",
    "Conflict",
}
VALID_DISPOSITIONS = {
    "keep",
    "cleanup_operation",
    "owner_decision_needed",
    "container_evidence_limit",
    "not_applicable",
}
OPEN_DISCOVERY_METHODS = [
    "semantic_name_and_business_term_variants",
    "normalized_condition_and_route_variants",
    "terminal_source_formula_and_output_overlap",
    "consumer_destination_and_event_overlap",
    "consent_sequence_and_server_route_conflicts",
    "funnel_question_market_and_product_families",
]
KEEP_VERDICTS = {"Intentional variant", "Complementary", "Unrelated"}
NON_RETENTION_COMPARISON_TYPES = {
    "same_tag_payload_different_route",
    "shared_zone_child_container",
    "cyclic_trigger_group_dependency",
    "browser_server_consent_deduplication_review",
}
EXACT_CONFIGURATION_SEMANTIC_POLICY_TYPES = {
    "different_consent_purposes_same_logic",
}
DISCOVERY_INHERITED_POLICY_TYPES = NON_RETENTION_COMPARISON_TYPES | {
    "exact_configuration",
    "different_consent_purposes_same_logic",
}
UNSAFE_DISCOVERY_METHOD_REQUIREMENTS = {
    "same_tag_payload_different_route": {
        "normalized_condition_and_route_variants",
    },
    "shared_zone_child_container": {
        "normalized_condition_and_route_variants",
    },
    "cyclic_trigger_group_dependency": {
        "normalized_condition_and_route_variants",
    },
    "browser_server_consent_deduplication_review": {
        "consumer_destination_and_event_overlap",
        "consent_sequence_and_server_route_conflicts",
    },
}


def compact_terms(values: list[Any], limit: int = 40) -> list[str]:
    terms: list[str] = []
    for value in values:
        text = " ".join(str(value or "").split()).strip().lower()
        if len(text) < 2 or text in terms:
            continue
        terms.append(text[:160])
    return terms[:limit]


def usable_behavior_preview(value: Any) -> str:
    text = " ".join(str(value or "").split()).strip()
    lowered = text.lower()
    if not text or "<missing from exported object>" in lowered:
        return ""
    if any(
        marker in lowered
        for marker in (
            "<script",
            "function(",
            "function (",
            "document.",
            ".src=",
            ".src =",
            "appendchild",
        )
    ):
        return ""
    if re.search(r"https?\.{2,}|https?[^\s]{0,80}\.{3}$", lowered):
        return ""
    return text


BEHAVIOR_TERM_NOISE = {
    "[]",
    "{}",
    "ambiguous",
    "bad-entry",
    "custom_event",
    "event",
    "false",
    "html",
    "malformed",
    "map",
    "missing",
    "not_applicable",
    "not_set",
    "notset",
    "paused",
    "script",
    "template",
    "track",
    "true",
    "unique",
    "unknown_option",
}


def usable_distinguishing_term(value: Any) -> str:
    text = usable_behavior_preview(value)
    lowered = text.lower()
    if (
        not text
        or lowered in BEHAVIOR_TERM_NOISE
        or lowered.startswith("missing ")
        or re.search(
            r"\b(?:ambiguous|empty|error|invalid|malformed|unknown|unproven)\b",
            lowered,
        )
        or re.search(r"\bsignature\s+[0-9a-f]{8,}\b", lowered)
        or re.fullmatch(r"[-+]?\d+(?:\.\d+)?", lowered)
        or any(
            marker in lowered
            for marker in (
                "document.",
                "window.",
                "createelement",
                "appendchild",
                ".src",
                "ttq.",
                "fbq(",
                "snaptr(",
                "pintrk(",
            )
        )
    ):
        return ""
    return text


def configured_condition_term(value: Any) -> str:
    parts = str(value or "").split("|")
    if len(parts) < 3:
        return usable_distinguishing_term(value)
    operator, left, right = parts[:3]
    left = left.replace("{{", "").replace("}}", "").strip()
    return " ".join(part for part in (left, operator.lower(), right) if part)


def dependency_trace_terms(traces: list[dict[str, Any]]) -> list[str]:
    values: list[Any] = []

    def visit(trace: dict[str, Any]) -> None:
        values.extend(
            [
                trace.get("relation"),
                trace.get("reference"),
                trace.get("resolution_state"),
            ]
        )
        for target in as_list(trace.get("targets")):
            values.extend(
                [
                    target.get("object_key"),
                    target.get("object_name"),
                    target.get("object_type"),
                    "paused" if target.get("paused") else "",
                    *as_list(target.get("conditions")),
                ]
            )
            for child_field in ("member_traces", "sequence_traces"):
                for child in as_list(target.get(child_field)):
                    if isinstance(child, dict):
                        visit(child)

    for trace in traces:
        if isinstance(trace, dict):
            visit(trace)
    return compact_terms(values, 80)


def configured_parameter_terms(shared: dict[str, Any]) -> list[str]:
    """Return compact, source-visible key/value parameter distinctions.

    Tag-template configurations often use the same template, trigger, consent
    controls, and variable inputs while differing only in a destination,
    conversion, pixel, or event parameter.  Keep the key with its value so an
    opaque number is never mistaken for a semantic distinction on its own.
    Nested list/map entries are deliberately excluded: their local ``key`` /
    ``value`` labels describe the list structure rather than a GTM parameter.
    """
    parameter_keys: dict[str, str] = {}
    parameter_values: dict[str, str] = {}
    for fact in as_list(shared.get("source_leaf_facts")):
        path = str(fact.get("json_path") or "")
        match = re.match(r"^(.*\.parameter\[\d+\])\.(key|value)$", path)
        if not match:
            continue
        parent, field = match.groups()
        value = " ".join(str(fact.get("value_preview") or "").split())
        if not value:
            continue
        if field == "key":
            parameter_keys[parent] = value
        else:
            parameter_values[parent] = value
    return compact_terms(
        f"parameter {parameter_keys[parent]} {parameter_values[parent]}"
        for parent in sorted(set(parameter_keys) & set(parameter_values))
    )


def custom_code_return_terms(shared: dict[str, Any]) -> list[str]:
    """Expose compact return semantics without copying executable source code."""
    ignored = {
        "const", "document", "false", "function", "let", "null", "return",
        "true", "undefined", "var", "window",
    }
    terms: list[str] = []
    for item in as_list((shared.get("custom_code_facts") or {}).get("return_expressions")):
        expression = str(item.get("expression") or "") if isinstance(item, dict) else ""
        for token in re.findall(r"[A-Za-z_][A-Za-z0-9_]{2,}", expression):
            lowered = token.lower()
            if lowered not in ignored:
                terms.append(f"custom return {lowered}")
    return compact_terms(terms, 24)


def object_behavior_terms(shared: dict[str, Any]) -> list[str]:
    contract = shared.get("vendor_event_contract") or {}
    consent = shared.get("effective_consent_route") or {}
    sequence_values = [
        f"{relation.replace('_tags', '')} tag {item.get('tagName')}"
        for relation in ("setup_tags", "teardown_tags")
        for item in as_list(shared.get(relation))
        if isinstance(item, dict)
        if item.get("tagName")
    ]
    direct_dependency_values = [
        f"{str(trace.get('relation') or 'dependency').replace('_', ' ')} "
        f"{trace.get('reference')}"
        for trace in as_list(shared.get("execution_dependency_traces"))
        if isinstance(trace, dict)
        and trace.get("reference")
        and trace.get("resolution_state") != "malformed"
    ]
    candidate_terms = compact_terms(
        [
            # A GTM object type is a source-visible implementation distinction.
            # It prevents a shared trigger or common event family from being
            # mistaken for a duplicate solely because its contract fields are
            # sparse (a common case for vendor template tags).
            f"object type {shared.get('object_type')}"
            if shared.get("object_type")
            else "",
            f"vendor {contract.get('vendor')}"
            if contract.get("vendor")
            else "",
            *configured_parameter_terms(shared),
            *custom_code_return_terms(shared),
            *as_list(shared.get("referenced_variables")),
            *[
                f"firing trigger {value}"
                for value in as_list(shared.get("firing_trigger_ids"))
            ],
            *[
                f"blocking trigger {value}"
                for value in as_list(shared.get("blocking_trigger_ids"))
            ],
            *[
                f"trigger-group member {value}"
                for value in as_list(shared.get("trigger_group_member_ids"))
            ],
            *[
                configured_condition_term(value)
                for value in as_list(shared.get("trigger_conditions"))
            ],
            *as_list(shared.get("business_scope_tokens")),
            *[
                usable_distinguishing_term(value)
                for value in as_list(shared.get("specificity_tokens"))
            ],
            *[f"event {value}" for value in as_list(contract.get("events"))],
            *[
                f"destination {value}"
                for value in as_list(contract.get("destinations"))
            ],
            *sequence_values,
            *direct_dependency_values,
            *as_list(consent.get("consent_variable_references")),
            *as_list(consent.get("server_consent_forwarding_variables")),
            *as_list(consent.get("detected_consent_payload_purposes")),
            *as_list(consent.get("forwarded_consent_purposes")),
            *as_list(consent.get("server_routing_hosts")),
            (
                f"consent status {consent.get('consent_status')}"
                if consent.get("consent_status") not in {None, "", "MISSING"}
                else ""
            ),
            (
                str(consent.get("effective_control_status") or "").replace("_", " ")
                if consent.get("effective_control_status")
                not in {None, "", "unproven_export_control"}
                else ""
            ),
            *as_list(consent.get("detected_vendors")),
        ],
        160,
    )
    return [term for term in candidate_terms if usable_distinguishing_term(term)]


def distinguishing_terms_for_keys(
    keys: list[str], shared_by_key: dict[str, dict[str, Any]]
) -> dict[str, list[str]]:
    terms = {key: set(object_behavior_terms(shared_by_key.get(key, {}))) for key in keys}
    result: dict[str, list[str]] = {}
    for key in keys:
        other_terms = set().union(*(values for other, values in terms.items() if other != key))
        own_unique = sorted(terms[key] - other_terms)
        # A broad trigger can be deliberately paired with a stricter trigger.
        # The broad one has no *additional* term, but its base condition set is
        # still a visible, meaningful distinction from the child scope.  Keep
        # that relationship reviewable as a scope variant instead of forcing an
        # artificial owner decision merely because set subtraction is empty.
        if not own_unique:
            has_strict_superset = any(
                terms[key] < values
                for other, values in terms.items()
                if other != key
            )
            baseline_conditions = sorted(
                value
                for value in terms[key]
                if re.search(r"\b(?:equals|contains|match|starts|ends|regex)\b", value)
            )
            if has_strict_superset and baseline_conditions:
                own_unique = [f"baseline condition set {baseline_conditions[0]}"]
        result[key] = own_unique[:80]
    return result


def object_evidence_terms(shared: dict[str, Any]) -> list[str]:
    contract = shared.get("vendor_event_contract") or {}
    consent = shared.get("effective_consent_route") or {}
    return compact_terms(
        [
            shared.get("object_name"),
            shared.get("object_key"),
            shared.get("object_type"),
            *as_list(shared.get("referenced_variables")),
            *as_list(shared.get("firing_trigger_ids")),
            *as_list(shared.get("blocking_trigger_ids")),
            *as_list(shared.get("trigger_group_member_ids")),
            *as_list(shared.get("specificity_tokens")),
            *[
                item.get("tagName")
                for relation in ("setup_tags", "teardown_tags")
                for item in as_list(shared.get(relation))
                if isinstance(item, dict)
            ],
            *as_list(shared.get("business_scope_tokens")),
            *as_list(contract.get("events")),
            *as_list(contract.get("destinations")),
            *as_list(consent.get("consent_variable_references")),
            *as_list(consent.get("server_consent_forwarding_variables")),
            *as_list(consent.get("detected_consent_payload_purposes")),
            *as_list(consent.get("forwarded_consent_purposes")),
            *as_list(consent.get("server_routing_hosts")),
            *as_list(consent.get("detected_vendors")),
            consent.get("consent_status"),
            consent.get("effective_control_status"),
            *dependency_trace_terms(
                as_list(shared.get("execution_dependency_traces"))
            ),
            *[
                "missing " + str(fact.get("json_path") or "").rsplit(".", 1)[-1]
                for fact in as_list(shared.get("source_absence_facts"))
            ],
        ]
    )


def terms_for_keys(
    keys: list[str], shared_by_key: dict[str, dict[str, Any]]
) -> list[str]:
    return compact_terms(
        [
            term
            for key in keys
            for term in object_evidence_terms(shared_by_key.get(key, {}))
        ],
        120,
    )


def field_evidence_requirements(
    keys: list[str], shared_by_key: dict[str, dict[str, Any]]
) -> dict[str, list[str]]:
    identities = compact_terms(
        [
            shared_by_key.get(key, {}).get("object_name") or key
            for key in keys
        ]
    )
    execution = compact_terms(
        [
            value
            for key in keys
            for value in (
                *as_list(shared_by_key.get(key, {}).get("firing_trigger_ids")),
                *as_list(shared_by_key.get(key, {}).get("blocking_trigger_ids")),
                *as_list(shared_by_key.get(key, {}).get("trigger_group_member_ids")),
                *[
                    part
                    for condition in as_list(
                        shared_by_key.get(key, {}).get("trigger_conditions")
                    )
                    for part in str(condition).split("|")
                    if part
                ],
            )
        ]
    )
    payload = compact_terms(
        [
            value
            for key in keys
            for value in (
                *as_list(shared_by_key.get(key, {}).get("referenced_variables")),
                *as_list(
                    (shared_by_key.get(key, {}).get("vendor_event_contract") or {}).get(
                        "events"
                    )
                ),
                *as_list(
                    (shared_by_key.get(key, {}).get("vendor_event_contract") or {}).get(
                        "destinations"
                    )
                ),
            )
        ]
    )
    consent = compact_terms(
        [
            value
            for key in keys
            for value in (
                *as_list(shared_by_key.get(key, {}).get("blocking_trigger_ids")),
                *as_list(
                    (
                        shared_by_key.get(key, {}).get("effective_consent_route") or {}
                    ).get("consent_variable_references")
                ),
                *as_list(
                    (
                        shared_by_key.get(key, {}).get("effective_consent_route") or {}
                    ).get("server_consent_forwarding_variables")
                ),
                *as_list(
                    (
                        shared_by_key.get(key, {}).get("effective_consent_route") or {}
                    ).get("detected_consent_payload_purposes")
                ),
                *as_list(
                    (
                        shared_by_key.get(key, {}).get("effective_consent_route") or {}
                    ).get("forwarded_consent_purposes")
                ),
                *as_list(
                    (
                        shared_by_key.get(key, {}).get("effective_consent_route") or {}
                    ).get("server_routing_hosts")
                ),
                (
                    shared_by_key.get(key, {}).get("effective_consent_route") or {}
                ).get("consent_status"),
                (
                    shared_by_key.get(key, {}).get("effective_consent_route") or {}
                ).get("effective_control_status"),
            )
        ]
    )
    all_terms = terms_for_keys(keys, shared_by_key)

    def complete(values: list[str]) -> list[str]:
        return compact_terms([*values, *identities, *all_terms])

    return {
        "business_action": complete([*payload, *identities]),
        "family_purpose": complete([*payload, *identities]),
        "execution_path_summary": complete([*execution, *identities]),
        "payload_coherence": complete([*payload, *identities]),
        "consent_and_sequence_coherence": complete([*consent, *execution, *identities]),
        "necessity_and_ownership": complete(identities),
        "analyst_rationale": complete([*payload, *execution, *identities]),
        "target_architecture": complete(identities),
        "architecture_effect": complete([*payload, *execution, *identities]),
    }


def family_key(record: dict[str, Any]) -> str:
    business_key = tag_business_event_key(record)
    if business_key:
        return "event:" + business_key
    triggers = sorted(
        str(value)
        for value in as_list(record["object"].get("firingTriggerId"))
        if not is_system_trigger_reference(str(value))
    )
    if triggers:
        return "route:" + ",".join(triggers)
    contract = tag_contract(record)
    vendor = str(contract.get("vendor") or "unclassified")
    if record["layer"] == "client":
        return "server-client:" + vendor + ":" + record["object_type"]
    if record["layer"] == "transformation":
        return "server-transformation:" + vendor + ":" + record["object_type"]
    if record["layer"] == "zone":
        return "zone:" + record["object_id"]
    if record["layer"] == "gtagConfig":
        return "google-tag-config:" + record["object_type"] + ":" + record["object_id"]
    return "vendor-type:" + vendor + ":" + record["object_type"]


def family_label(key: str) -> str:
    if key.startswith("event:"):
        try:
            events = json.loads(key.split(":", 1)[1])
            return " / ".join(str(value) for value in events)
        except json.JSONDecodeError:
            pass
    return key.replace(":", " - ")


def dependency_graph(
    cv: dict[str, Any], records: dict[str, list[dict[str, Any]]]
) -> tuple[dict[str, list[dict[str, str]]], dict[str, dict[str, Any]]]:
    by_key = {
        record["object_key"]: record
        for layer_records in records.values()
        for record in layer_records
    }
    variables: dict[str, list[str]] = defaultdict(list)
    for record in records.get("variable", []):
        variables[str(record["object"].get("name") or "")].append(
            record["object_key"]
        )
    built_in_names = {
        str(obj.get("name") or "") for obj in as_list(cv.get("builtInVariable"))
    }
    triggers: dict[str, list[str]] = defaultdict(list)
    for record in records.get("trigger", []):
        triggers[str(record["object_id"])].append(record["object_key"])
    tags: dict[str, list[str]] = defaultdict(list)
    for record in records.get("tag", []):
        tags[str(record["object"].get("name") or "")].append(record["object_key"])
    templates: dict[str, list[str]] = defaultdict(list)
    for record in records.get("customTemplate", []):
        templates[str(record["object_id"])].append(record["object_key"])
    template_type_index = custom_template_type_index(
        [record["object"] for record in records.get("customTemplate", [])]
    )
    graph: dict[str, list[dict[str, str]]] = defaultdict(list)
    for key, record in by_key.items():
        obj = record["object"]
        for reference in sorted(refs(obj)):
            targets = variables.get(reference, [])
            for target in targets:
                graph[key].append(
                    {"from_object_key": key, "to_object_key": target, "relation": "variable"}
                )
            if (
                not targets
                and reference not in built_in_names
                and not is_system_variable_reference(reference)
            ):
                graph[key].append(
                    {
                        "from_object_key": key,
                        "to_object_key": f"unresolved:variable:{reference}",
                        "relation": "variable",
                        "target_reference": reference,
                        "resolution_state": "missing",
                    }
                )
        if record["layer"] == "tag":
            for relation in ("firingTriggerId", "blockingTriggerId"):
                for trigger_id in as_list(obj.get(relation)):
                    targets = triggers.get(str(trigger_id), [])
                    for target in targets:
                        graph[key].append(
                            {
                                "from_object_key": key,
                                "to_object_key": target,
                                "relation": relation,
                            }
                        )
                    if not targets and not is_system_trigger_reference(str(trigger_id)):
                        graph[key].append(
                            {
                                "from_object_key": key,
                                "to_object_key": f"unresolved:trigger:{trigger_id}",
                                "relation": relation,
                                "target_reference": str(trigger_id),
                                "resolution_state": "missing",
                            }
                        )
            for relation in ("setupTag", "teardownTag"):
                for reference in as_list(obj.get(relation)):
                    if not isinstance(reference, dict):
                        continue
                    target_name = str(reference.get("tagName") or "")
                    targets = tags.get(target_name, [])
                    for target in targets:
                        graph[key].append(
                            {
                                "from_object_key": key,
                                "to_object_key": target,
                                "relation": relation,
                            }
                        )
                    if target_name and not targets:
                        graph[key].append(
                            {
                                "from_object_key": key,
                                "to_object_key": f"unresolved:tag:{target_name}",
                                "relation": relation,
                                "target_reference": target_name,
                                "resolution_state": "missing",
                            }
                        )
        if record["layer"] == "trigger":
            for trigger_id in trigger_group_members(obj):
                targets = triggers.get(str(trigger_id), [])
                for target in targets:
                    graph[key].append(
                        {
                            "from_object_key": key,
                            "to_object_key": target,
                            "relation": "trigger_group_member",
                        }
                    )
                if not targets:
                    graph[key].append(
                        {
                            "from_object_key": key,
                            "to_object_key": f"unresolved:trigger:{trigger_id}",
                            "relation": "trigger_group_member",
                            "target_reference": str(trigger_id),
                            "resolution_state": "missing",
                        }
                    )
        if record["layer"] == "zone":
            boundary = obj.get("boundary") if isinstance(obj.get("boundary"), dict) else {}
            for trigger_id in as_list(boundary.get("customEvaluationTriggerId")):
                targets = triggers.get(str(trigger_id), [])
                for target in targets:
                    graph[key].append(
                        {
                            "from_object_key": key,
                            "to_object_key": target,
                            "relation": "zone_boundary_trigger",
                        }
                    )
                if not targets:
                    graph[key].append(
                        {
                            "from_object_key": key,
                            "to_object_key": f"unresolved:trigger:{trigger_id}",
                            "relation": "zone_boundary_trigger",
                            "target_reference": str(trigger_id),
                            "resolution_state": "missing",
                        }
                    )
        for template_id in custom_template_ids(obj, template_type_index):
            targets = templates.get(template_id, [])
            for target in targets:
                graph[key].append(
                    {
                        "from_object_key": key,
                        "to_object_key": target,
                        "relation": "custom_template",
                    }
                )
            if not targets:
                graph[key].append(
                    {
                        "from_object_key": key,
                        "to_object_key": f"unresolved:customTemplate:{template_id}",
                        "relation": "custom_template",
                        "target_reference": template_id,
                        "resolution_state": "missing",
                    }
                )
    return dict(graph), by_key


def family_chain(
    member_keys: list[str],
    graph: dict[str, list[dict[str, str]]],
    known_object_keys: set[str],
) -> tuple[list[str], list[dict[str, str]]]:
    visited = set(member_keys)
    edges: list[dict[str, str]] = []
    queue = list(member_keys)
    while queue:
        current = queue.pop(0)
        for edge in graph.get(current, []):
            if edge not in edges:
                edges.append(edge)
            target = edge["to_object_key"]
            if target not in known_object_keys:
                continue
            if target not in visited:
                visited.add(target)
                queue.append(target)
    return sorted(visited), sorted(
        edges,
        key=lambda row: (row["from_object_key"], row["relation"], row["to_object_key"]),
    )


def scaffold_families(
    cv: dict[str, Any], root_path: str = "$.containerVersion"
) -> list[dict[str, Any]]:
    records = object_records(cv, root_path)
    roots = (
        records.get("tag", [])
        + records.get("client", [])
        + records.get("transformation", [])
        + records.get("zone", [])
        + records.get("gtagConfig", [])
    )
    graph, records_by_key = dependency_graph(cv, records)
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in roots:
        groups[family_key(record)].append(record)
    rows: list[dict[str, Any]] = []
    for number, (key, members) in enumerate(sorted(groups.items()), start=1):
        members = sorted(members, key=lambda item: item["object_key"])
        member_keys = [item["object_key"] for item in members]
        chain_keys, chain_edges = family_chain(member_keys, graph, set(records_by_key))
        chain_records = [records_by_key[key] for key in chain_keys if key in records_by_key]
        rows.append(
            {
                "family_id": f"FAM-{number:04d}",
                "family_key": key,
                "family_label": family_label(key),
                "member_object_keys": member_keys,
                "member_object_names": [item["object_name"] for item in members],
                "member_config_hashes": {
                    item["object_key"]: item["config_hash"] for item in members
                },
                "member_source_paths": {
                    item["object_key"]: item["source_json_path"] for item in members
                },
                "available_member_evidence_anchors": {
                    item["object_key"]: item["evidence_anchors"] for item in members
                },
                "member_paused_status": {
                    item["object_key"]: bool(item["object"].get("paused")) for item in members
                },
                "chain_object_keys": chain_keys,
                "chain_object_names": {
                    item["object_key"]: item["object_name"] for item in chain_records
                },
                "chain_config_hashes": {
                    item["object_key"]: item["config_hash"] for item in chain_records
                },
                "chain_source_paths": {
                    item["object_key"]: item["source_json_path"] for item in chain_records
                },
                "available_chain_evidence_anchors": {
                    item["object_key"]: item["evidence_anchors"] for item in chain_records
                },
                "chain_paused_status": {
                    item["object_key"]: bool(item["object"].get("paused"))
                    if item["layer"] == "tag"
                    else False
                    for item in chain_records
                },
                "chain_edges": chain_edges,
                "chain_specificity_tokens": sorted(
                    {token for item in chain_records for token in item["specificity_tokens"]}
                )[:120],
                "review_status": "pending",
                "business_action": "",
                "family_purpose": "",
                "member_assessments": [],
                "chain_assessments": [],
                "execution_path_summary": "",
                "payload_coherence": "",
                "consent_and_sequence_coherence": "",
                "necessity_and_ownership": "",
                "relationship_verdict": "",
                "analyst_rationale": "",
                "target_architecture": "",
                "disposition": "",
                "owner_question": "",
                "recommended_action": "",
                "operations": [],
                "confidence": "",
            }
        )
    return rows


def scaffold_comparisons(
    cv: dict[str, Any], root_path: str = "$.containerVersion"
) -> list[dict[str, Any]]:
    rows = []
    for candidate in relationship_candidates(cv, root_path):
        rows.append(
            {
                **candidate,
                "review_status": "pending",
                "member_assessments": [],
                "relationship_verdict": "",
                "analyst_rationale": "",
                "architecture_effect": "",
                "disposition": "",
                "owner_question": "",
                "recommended_action": "",
                "canonical_selection_rationale": "",
                "operations": [],
                "confidence": "",
            }
        )
    return rows


def add_canonical_recommendations(
    comparisons: list[dict[str, Any]],
    consumer_map: dict[str, set[str]],
) -> None:
    """Add one evidence-derived default for exact duplicates.

    This recommendation does not mutate the container or replace the analyst's
    relationship verdict.  It prevents an exact-duplicate owner decision from
    stopping at "choose one" when the export already supports a sensible
    default.
    """

    weak_name = re.compile(
        r"\b(?:copy|duplicate|duplicat|old|legacy|backup|test|temp|tmp)\b", re.I
    )
    for comparison in comparisons:
        keys = [
            str(value)
            for value in as_list(comparison.get("candidate_object_keys"))
            if str(value)
        ]
        names = {
            key: str(name)
            for key, name in zip(
                keys,
                as_list(comparison.get("candidate_object_names")),
                strict=False,
            )
        }
        paused = comparison.get("candidate_paused_status") or {}
        consumer_keys = {
            key: sorted(consumer_map.get(key, set()))
            for key in keys
        }
        comparison["candidate_consumer_keys"] = consumer_keys
        comparison["candidate_consumer_counts"] = {
            key: len(values) for key, values in consumer_keys.items()
        }
        comparison["recommended_canonical_object_key"] = ""
        comparison["recommended_canonical_basis"] = ""
        if "exact_configuration" not in as_list(
            comparison.get("comparison_types")
        ) or not keys:
            continue

        ranked = sorted(
            keys,
            key=lambda key: (
                -int(not bool(paused.get(key))),
                -len(consumer_keys.get(key, [])),
                int(bool(weak_name.search(names.get(key, "")))),
                key,
            ),
        )
        selected = ranked[0]
        selected_name = names.get(selected, "")
        comparison["recommended_canonical_object_key"] = selected
        comparison["recommended_canonical_basis"] = (
            f"Recommend {selected} ({selected_name!r}) because it is "
            f"{'paused' if paused.get(selected) else 'active'}, has "
            f"{len(consumer_keys.get(selected, []))} container-visible consumer(s) "
            f"{consumer_keys.get(selected, [])!r}, and its name "
            f"{'contains' if weak_name.search(selected_name) else 'does not contain'} "
            "a copy/legacy/test marker. Ranking is active over paused, then more "
            "visible consumers, then a non-copy name; the object key is only the "
            "final deterministic tie-breaker."
        )


def scaffold_review(
    export_path: Path,
    shared_facts: dict[str, Any] | None = None,
    *,
    include_validator_answer_key: bool = False,
) -> dict[str, Any]:
    descriptor = source_descriptor(export_path)
    data = json.loads(export_path.read_text(encoding="utf-8"))
    blocking_integrity = [
        row for row in source_integrity_findings(data) if row.get("blocking")
    ]
    if blocking_integrity:
        finding_types = sorted(
            str(row.get("finding_type") or "source_integrity_error")
            for row in blocking_integrity
        )
        raise ValueError(
            "source integrity gate blocked architecture review: "
            + ", ".join(finding_types)
        )
    cv = container_version(data)
    root_path = container_root_path(data)
    shared_facts = shared_facts or build_shared_facts(export_path)
    shared_by_key = {
        str(row.get("object_key") or ""): row
        for row in as_list(shared_facts.get("objects"))
    }
    families = scaffold_families(cv, root_path)
    for family in families:
        family["member_evidence_terms"] = {
            key: object_evidence_terms(shared_by_key.get(key, {}))
            for key in family["member_object_keys"]
        }
        family["chain_evidence_terms"] = {
            key: object_evidence_terms(shared_by_key.get(key, {}))
            for key in family["chain_object_keys"]
        }
        requirements = field_evidence_requirements(
            family["chain_object_keys"], shared_by_key
        )
        if include_validator_answer_key:
            family["field_evidence_requirements"] = requirements
        family["member_behavior_signatures"] = {
            key: shared_by_key.get(key, {}).get("behavior_signatures", {})
            for key in family["member_object_keys"]
        }
        family["chain_behavior_signatures"] = {
            key: shared_by_key.get(key, {}).get("behavior_signatures", {})
            for key in family["chain_object_keys"]
        }
        family["member_distinguishing_terms"] = distinguishing_terms_for_keys(
            family["member_object_keys"], shared_by_key
        )
    comparisons = scaffold_comparisons(cv, root_path)
    add_canonical_recommendations(comparisons, object_consumer_map(export_path))
    for comparison in comparisons:
        comparison["candidate_evidence_terms"] = {
            key: object_evidence_terms(shared_by_key.get(key, {}))
            for key in comparison["candidate_object_keys"]
        }
        requirements = field_evidence_requirements(
            comparison["candidate_object_keys"], shared_by_key
        )
        if include_validator_answer_key:
            comparison["field_evidence_requirements"] = requirements
        comparison["candidate_behavior_signatures"] = {
            key: shared_by_key.get(key, {}).get("behavior_signatures", {})
            for key in comparison["candidate_object_keys"]
        }
        comparison["candidate_distinguishing_terms"] = distinguishing_terms_for_keys(
            comparison["candidate_object_keys"], shared_by_key
        )
        comparison["required_caution_states"] = comparison_caution_states(
            comparison, shared_by_key
        )
    all_record_keys = sorted(shared_by_key)
    method_coverage = []
    for method in OPEN_DISCOVERY_METHODS:
        method_comparisons = [
            comparison
            for comparison in comparisons
            if method in as_list(comparison.get("discovery_methods"))
        ]
        candidate_keys = sorted(
            {
                str(key)
                for comparison in method_comparisons
                for key in as_list(comparison.get("candidate_object_keys"))
            }
        )
        method_coverage.append(
            {
                "method": method,
                "scan_status": "deterministic_complete",
                "comparison_ids": sorted(
                    str(comparison.get("comparison_id") or "")
                    for comparison in method_comparisons
                ),
                "candidate_object_keys": candidate_keys,
                "review_scope_object_keys": all_record_keys,
                "source_scope_sha256": stable_hash(
                    {
                        "method": method,
                        "objects": {
                            key: shared_by_key.get(key, {}).get("behavior_signatures", {})
                            for key in all_record_keys
                        },
                    },
                    32,
                ),
            }
        )
    input_contract = review_input_contract(
        "business_architecture",
        descriptor["source_sha256"],
        shared_facts["context_sha256"],
        shared_facts["shared_facts_sha256"],
    )
    return {
        **descriptor,
        "kind": "gtm_business_architecture_review",
        "schema_version": 3,
        "shared_facts_sha256": shared_facts["shared_facts_sha256"],
        "context_sha256": shared_facts["context_sha256"],
        "input_contract": input_contract,
        "completion_attestation": pending_completion_attestation(input_contract),
        "audit_context": shared_facts.get("audit_context", {}),
        "inferred_context": shared_facts.get("inferred_context", {}),
        "provided_context": shared_facts.get("provided_context", {}),
        "provided_context_fields": shared_facts.get("provided_context_fields", []),
        "unresolved_context_questions": shared_facts.get(
            "unresolved_context_questions", []
        ),
        "run_status": "pending",
        "families": families,
        "comparisons": comparisons,
        "discovery_method_coverage": method_coverage,
        "discovery_contract": (
            "All deterministic comparisons are mandatory. Add source-grounded DISC-* rows "
            "when complete-chain review reveals a relationship outside that candidate set."
        ),
        "open_discovery_attestation": {
            "review_status": "pending",
            "reviewed_object_keys": [],
            "discovered_comparison_ids": [],
            "zero_discovery_rationale": "",
            "method_reviews": [
                {
                    **coverage,
                    "review_status": "pending",
                    "reviewed_comparison_ids": [],
                    "reviewed_object_keys": [],
                    "additional_discovery_ids": [],
                    "conclusion": "",
                }
                for coverage in method_coverage
            ],
        },
    }


def validate_member_assessments(
    assessments: list[dict[str, Any]],
    member_keys: list[str],
    available_by_key: dict[str, list[str]],
    paused_by_key: dict[str, bool],
    evidence_terms_by_key: dict[str, list[str]],
    label: str,
) -> list[str]:
    errors: list[str] = []
    by_key = {
        str(item.get("object_key") or ""): item for item in assessments if isinstance(item, dict)
    }
    if len(by_key) != len(assessments) or "" in by_key:
        errors.append(
            f"{label}: member assessments contain malformed, duplicate, or blank object keys"
        )
    if set(by_key) != set(member_keys):
        errors.append(f"{label}: member assessments must cover every member exactly once")
    for key in member_keys:
        assessment = by_key.get(key)
        if not assessment:
            continue
        for field in ("configured_role", "necessity", "distinguishing_configuration"):
            if not specific_text(assessment.get(field), 5):
                errors.append(f"{label}: {key} has incomplete {field}")
                continue
            terms = [
                str(value).lower()
                for value in as_list(evidence_terms_by_key.get(key))
                if str(value).strip()
            ]
            required_hits = min(
                2 if field in {"configured_role", "distinguishing_configuration"} else 1,
                len(terms),
            )
            text = str(assessment.get(field) or "").lower()
            if required_hits and sum(term in text for term in terms) < required_hits:
                errors.append(f"{label}: {key} {field} is not tied to source facts")
        expected_status = "paused" if paused_by_key.get(key, False) else "active"
        if assessment.get("status") != expected_status:
            errors.append(f"{label}: {key} status must be {expected_status}")
        anchors = {str(value) for value in as_list(assessment.get("evidence_anchors"))}
        available = {str(value) for value in available_by_key.get(key, [])}
        if not anchors:
            errors.append(f"{label}: {key} has no evidence anchors")
        for anchor in sorted(anchors - available):
            errors.append(f"{label}: {key} references unknown evidence anchor {anchor!r}")
    return errors


def validate_field_evidence_text(
    row: dict[str, Any],
    fields: tuple[str, ...],
    label: str,
    requirements: dict[str, Any] | None = None,
) -> list[str]:
    errors: list[str] = []
    requirements = requirements or row.get("field_evidence_requirements") or {}
    for field in fields:
        if not specific_text(row.get(field), 6):
            errors.append(f"{label}: {field} lacks a concrete assessment")
            continue
        terms = [
            str(value).lower()
            for value in as_list(requirements.get(field))
            if str(value).strip()
        ]
        required_hits = min(2, len(terms))
        text = str(row.get(field) or "").lower()
        if required_hits and sum(term in text for term in terms) < required_hits:
            errors.append(f"{label}: {field} is not tied to source facts")
    return errors


ARCHITECTURE_METADATA_PATH_SUFFIXES = {
    ".name",
    ".notes",
    ".parentFolderId",
    ".fingerprint",
    ".path",
    ".tagManagerUrl",
}


def source_path_matches_object(path: str, source_path: str) -> bool:
    return bool(
        path
        and source_path
        and (path == source_path or path.startswith((source_path + ".", source_path + "[")))
    )


def operation_behavior_keys(
    operation: dict[str, Any], source_paths_by_key: dict[str, str] | None = None
) -> set[str]:
    keys: set[str] = set()
    source_paths_by_key = source_paths_by_key or {}
    for creation in as_list(operation.get("creations")):
        layer = str(creation.get("layer") or "")
        obj = creation.get("object")
        id_key = ID_KEYS.get(layer)
        if layer != "folder" and id_key and isinstance(obj, dict):
            object_id = str(obj.get(id_key) or obj.get("name") or "")
            if object_id:
                keys.add(f"{layer}:{object_id}")
    for field in ("additions", "changes"):
        for item in as_list(operation.get(field)):
            path = str(item.get("json_path") or "")
            if not any(path.endswith(suffix) for suffix in ARCHITECTURE_METADATA_PATH_SUFFIXES):
                key = str(item.get("object_key") or "")
                before_after_is_noop = (
                    field == "changes"
                    and "before" in item
                    and "after" in item
                    and item.get("before") == item.get("after")
                )
                expected_path = source_paths_by_key.get(key)
                path_is_bound = not expected_path or source_path_matches_object(
                    path, expected_path
                )
                if key and not before_after_is_noop and path_is_bound:
                    keys.add(key)
    for remap in as_list(operation.get("remaps")):
        # The relationship decision concerns the remap endpoints. Consumer
        # keys are still exact mutation/precondition evidence, but including
        # them here would force unrelated consumer families to pretend that a
        # behavior-preserving canonical remap is an architecture conflict.
        keys.update(
            str(value)
            for value in (
                remap.get("from_object_key"),
                remap.get("to_object_key"),
            )
            if value and not str(value).startswith("folder:")
        )
    keys.update(
        str(item.get("object_key") or "")
        for item in as_list(operation.get("deletions"))
        if item.get("object_key")
        and not str(item.get("object_key")).startswith("folder:")
    )
    return keys


def comparison_caution_states(
    comparison: dict[str, Any], shared_by_key: dict[str, dict[str, Any]]
) -> list[dict[str, Any]]:
    comparison_types = set(as_list(comparison.get("comparison_types")))
    if "browser_server_consent_deduplication_review" not in comparison_types:
        return []
    keys = [str(value) for value in as_list(comparison.get("candidate_object_keys"))]
    deduplication_evidence: dict[str, list[str]] = {}
    consent_states: dict[str, str] = {}
    for key in keys:
        shared = shared_by_key.get(key, {})
        deduplication_evidence[key] = sorted(
            {
                str(fact.get("value_preview") or "")
                for fact in as_list(shared.get("source_leaf_facts"))
                if re.search(
                    r"(?:dedup|event[_-]?id|transaction[_-]?id)",
                    f"{fact.get('json_path') or ''} {fact.get('value_preview') or ''}",
                    re.I,
                )
            }
        )
        route = shared.get("effective_consent_route") or {}
        consent_states[key] = str(route.get("effective_control_status") or "not_visible")
    nonempty_dedup = [set(values) for values in deduplication_evidence.values() if values]
    aligned_dedup = len(nonempty_dedup) >= 2 and bool(
        set.intersection(*nonempty_dedup)
    )
    cautions: list[dict[str, Any]] = []
    if not aligned_dedup:
        cautions.append(
            {
                "caution_key": "deduplication_alignment_unproven",
                "subject_terms": ["deduplication", "event id", "transaction id"],
                "polarity_terms": ["unproven", "missing", "not visible", "unresolved"],
                "source_states": deduplication_evidence,
            }
        )
    # A client-container export can describe its visible consent controls, but it
    # cannot prove that an unseen server container applies the same purposes and
    # timing. Keep that end-to-end limitation visible even when client-side state
    # labels happen to match.
    cautions.append(
        {
            "caution_key": "consent_alignment_unproven_or_conflicting",
            "subject_terms": ["consent"],
            "polarity_terms": [
                "unproven",
                "conflict",
                "different",
                "unresolved",
                "not aligned",
            ],
            "source_states": consent_states,
        }
    )
    return cautions


def validate_caution_states(
    row: dict[str, Any], cautions: list[dict[str, Any]], label: str
) -> list[str]:
    text = " ".join(
        str(row.get(field) or "")
        for field in ("analyst_rationale", "architecture_effect", "owner_question")
    ).lower()
    errors: list[str] = []
    for caution in cautions:
        subjects = [str(value).lower() for value in as_list(caution.get("subject_terms"))]
        polarities = [str(value).lower() for value in as_list(caution.get("polarity_terms"))]
        if not any(subject in text for subject in subjects) or not any(
            polarity in text for polarity in polarities
        ):
            errors.append(
                f"{label}: source state {caution.get('caution_key')} must be stated with "
                "its unresolved or negative polarity"
            )
        subjects_pattern = r"(?:dedup|event[_ ]?id|transaction[_ ]?id|consent)"
        positive_state_pattern = (
            r"\b(?:complete|proven|aligned|guarantee(?:d|s)?|identical|"
            r"synchroni[sz]ed|verified|confirmed|ensured|equivalent|consistent)\b"
        )
        for match in re.finditer(positive_state_pattern, text):
            sentence_start = max(
                text.rfind(marker, 0, match.start()) for marker in (".", "!", "?", ";")
            )
            sentence_ends = [
                position
                for marker in (".", "!", "?", ";")
                if (position := text.find(marker, match.end())) >= 0
            ]
            sentence_end = min(sentence_ends) if sentence_ends else len(text)
            context = text[sentence_start + 1 : sentence_end]
            prefix = text[max(0, match.start() - 60) : match.start()]
            prefix = re.split(
                r"[.;]|\b(?:and|but|however|yet|although)\b", prefix
            )[-1]
            if re.search(
                r"(?:\bnot\b|\bno\b|\bcannot\b|\bnever\b)\s+(?:\w+\s+){0,5}$",
                prefix,
            ):
                continue
            if re.search(subjects_pattern, context):
                errors.append(
                    f"{label}: architecture text overclaims a complete, guaranteed, "
                    "synchronized, or proven state that "
                    f"contradicts {caution.get('caution_key')}"
                )
                break
    return errors


def validate_operation(
    operation: dict[str, Any],
    valid_keys: set[str],
    label: str,
    expected_consumers: dict[str, set[str]],
    source_paths_by_key: dict[str, str],
) -> list[str]:
    errors: list[str] = []
    if not str(operation.get("operation_key") or "").strip():
        errors.append(f"{label}: operation_key is incomplete")
    for field in (
        "title",
        "area",
        "problem_type",
        "problem",
        "why_it_matters",
        "expected_clean_state",
        "exact_proposed_action",
        "qa_steps",
        "rollback",
    ):
        # Taxonomy labels such as "Over-firing" are intentionally concise.
        minimum = 1 if field in {"area", "problem_type"} else 3
        if not specific_text(operation.get(field), minimum):
            errors.append(f"{label}: operation field {field} is incomplete")
    if operation.get("priority") not in VALID_PRIORITIES:
        errors.append(f"{label}: operation priority is invalid")
    if operation.get("confidence") not in VALID_CONFIDENCE:
        errors.append(f"{label}: operation confidence is invalid")
    if operation.get("execution_readiness") not in VALID_READINESS:
        errors.append(f"{label}: operation execution_readiness is invalid")
    errors.extend(taxonomy_errors(operation.get("area"), operation.get("problem_type"), label))
    flattened = {**operation, "deterministic_action_candidate": ""}
    errors.extend(
        validate_structured_actions(
            flattened,
            valid_keys,
            label,
            expected_consumers,
            source_paths_by_key,
        )
    )
    errors.extend(validate_challenge(flattened, label))
    return errors


def validate_decision(
    row: dict[str, Any],
    valid_keys: set[str],
    label: str,
    expected_consumers: dict[str, set[str]],
    relationship_keys: list[str] | None = None,
    policy_types: list[str] | None = None,
    caution_states: list[dict[str, Any]] | None = None,
    relationship_source_paths: dict[str, str] | None = None,
    relationship_identity_terms: dict[str, list[str]] | None = None,
    source_paths_by_key: dict[str, str] | None = None,
) -> list[str]:
    errors: list[str] = []
    verdict = row.get("relationship_verdict")
    disposition = row.get("disposition")
    if verdict not in VALID_RELATIONSHIP_VERDICTS:
        errors.append(f"{label}: relationship_verdict is invalid")
    if disposition not in VALID_DISPOSITIONS:
        errors.append(f"{label}: disposition is invalid")
    if row.get("confidence") not in VALID_CONFIDENCE:
        errors.append(f"{label}: confidence is invalid")
    raw_operations = as_list(row.get("operations"))
    operations = [operation for operation in raw_operations if isinstance(operation, dict)]
    if len(operations) != len(raw_operations):
        errors.append(f"{label}: operations contain malformed rows")
    relationship_key_set = set(relationship_keys or [])
    relationship_source_paths = relationship_source_paths or {}
    relationship_identity_terms = relationship_identity_terms or {}
    policy_type_set = set(policy_types or [])
    if verdict in ACTIONABLE_VERDICTS and disposition != "cleanup_operation":
        errors.append(f"{label}: actionable verdict requires cleanup_operation disposition")
    if verdict in KEEP_VERDICTS and disposition != "keep":
        errors.append(f"{label}: {verdict} verdict requires keep disposition")
    if verdict == "Owner decision needed" and disposition != "owner_decision_needed":
        errors.append(f"{label}: Owner decision needed verdict requires owner_decision_needed")
    if verdict == "Container evidence limit" and disposition != "container_evidence_limit":
        errors.append(f"{label}: Container evidence limit verdict requires container_evidence_limit")
    expected_verdict_by_disposition = {
        "owner_decision_needed": "Owner decision needed",
        "container_evidence_limit": "Container evidence limit",
    }
    expected_verdict = expected_verdict_by_disposition.get(str(disposition))
    if expected_verdict and verdict != expected_verdict:
        errors.append(
            f"{label}: {disposition} disposition requires {expected_verdict} verdict"
        )
    if disposition == "keep" and verdict not in KEEP_VERDICTS:
        errors.append(f"{label}: keep disposition requires a supported retention verdict")
    if disposition == "not_applicable":
        errors.append(f"{label}: a cross-object relationship decision cannot be not_applicable")
    if disposition == "cleanup_operation" and not operations:
        errors.append(f"{label}: cleanup disposition requires at least one operation")
    if disposition != "cleanup_operation" and operations:
        errors.append(f"{label}: non-operation disposition cannot contain operations")
    if (
        verdict == "Owner decision needed" or disposition == "owner_decision_needed"
    ) and not precise_question(row.get("owner_question"), 5):
        errors.append(f"{label}: owner decision requires one precise question")
    if verdict == "Owner decision needed" or disposition == "owner_decision_needed":
        identities = [
            value
            for key in sorted(relationship_key_set)
            for value in [key, *as_list(relationship_identity_terms.get(key))]
        ]
        evidence_terms = [
            token
            for policy_type in sorted(policy_type_set)
            for token in [policy_type.replace("_", " "), *policy_type.split("_")]
        ]
        evidence_terms.extend(
            caution.get("caution_key")
            for caution in as_list(caution_states)
            if isinstance(caution, dict)
        )
        errors.extend(
            source_specific_owner_question_errors(
                row.get("owner_question"), identities, evidence_terms, label
            )
        )
    if disposition in {
        "owner_decision_needed",
        "container_evidence_limit",
    } and not specific_text(row.get("recommended_action"), 6):
        errors.append(
            f"{label}: unresolved relationship requires one concrete recommended_action"
        )
    if verdict == "Container evidence limit" or disposition == "container_evidence_limit":
        if not precise_question(row.get("owner_question"), 5):
            errors.append(
                f"{label}: container evidence limit requires one precise external-evidence question"
            )
        boundary_text = " ".join(
            str(row.get(field) or "")
            for field in ("analyst_rationale", "architecture_effect")
        ).lower()
        if "visible" not in boundary_text or not any(
            phrase in boundary_text
            for phrase in ("not visible", "unseen", "outside the container", "external evidence")
        ):
            errors.append(
                f"{label}: container evidence limit must separate the visible configuration "
                "conclusion from the specific unseen evidence"
            )
    if verdict == "Owner decision needed" and policy_type_set & NON_RETENTION_COMPARISON_TYPES:
        question = str(row.get("owner_question") or "").lower()
        question_end = question.rfind("?")
        prior_boundaries = [
            question.rfind(marker, 0, question_end)
            for marker in (".", "!", "?")
        ]
        decision_clause = (
            question[max(prior_boundaries) + 1 : question_end + 1].strip()
            if question_end >= 0
            else ""
        )
        policy_terms = {
            "same_tag_payload_different_route": {"canonical", "route", "trigger", "consent"},
            "shared_zone_child_container": {"zone", "child", "boundary", "scope"},
            "cyclic_trigger_group_dependency": {"cycle", "trigger", "group", "dependency"},
            "browser_server_consent_deduplication_review": {
                "browser",
                "server",
                "deduplication",
                "consent",
                "route",
            },
        }
        required_terms = set().union(
            *(policy_terms.get(value, set()) for value in policy_type_set)
        )
        if sum(term in decision_clause for term in required_terms) < min(
            2, len(required_terms)
        ):
            errors.append(
                f"{label}: owner question must name the route, scope, cycle, consent, or "
                "deduplication decision specific to this unsafe relationship"
            )
        identified_members = sum(
            any(
                str(term).lower() in decision_clause
                for term in [key, *as_list(relationship_identity_terms.get(key))]
                if str(term).strip()
            )
            for key in relationship_key_set
        )
        if identified_members < min(2, len(relationship_key_set)):
            errors.append(
                f"{label}: unsafe owner question must identify at least two candidate "
                "objects by source key or exact name"
            )
        if not decision_clause or not re.search(
            r"\b(?:retain|remove|canonical|justify|resolve|break|own|govern|"
            r"forward|deduplicat\w*|consolidat\w*|correct|separate)\b",
            decision_clause,
        ):
            errors.append(
                f"{label}: unsafe owner question must put the candidate identities and "
                "a concrete ownership, retention, routing, consent, or cleanup decision "
                "inside the interrogative clause"
            )
    behavior_keys = set().union(
        *(
            operation_behavior_keys(operation, relationship_source_paths)
            for operation in operations
        )
    )
    for operation_index, operation in enumerate(operations, start=1):
        for field in ("additions", "changes"):
            for item_index, item in enumerate(as_list(operation.get(field)), start=1):
                key = str(item.get("object_key") or "")
                expected_path = relationship_source_paths.get(key)
                path = str(item.get("json_path") or "")
                if expected_path and not source_path_matches_object(path, expected_path):
                    errors.append(
                        f"{label} operation {operation_index} {field[:-1]} {item_index}: "
                        f"candidate {key!r} is paired with an unrelated source path"
                    )
    if operations and relationship_key_set and not (behavior_keys & relationship_key_set):
        errors.append(
            f"{label}: cleanup operations do not change any candidate member's behavior"
        )
    errors.extend(validate_caution_states(row, caution_states or [], label))
    for index, operation in enumerate(operations, start=1):
        errors.extend(
            validate_operation(
                operation,
                valid_keys,
                f"{label} operation {index}",
                expected_consumers,
                source_paths_by_key or {},
            )
        )
        if verdict in {"Exact duplicate", "Consolidation candidate"}:
            canonical = str(operation.get("canonical_object_key") or "")
            deletion_keys = {
                str(item.get("object_key") or "")
                for item in as_list(operation.get("deletions"))
            }
            all_relationship_members_deleted = bool(relationship_key_set) and (
                relationship_key_set <= deletion_keys
            )
            if not canonical and not all_relationship_members_deleted:
                errors.append(f"{label} operation {index}: consolidation lacks canonical object")
            elif canonical and relationship_key_set and canonical not in relationship_key_set:
                errors.append(
                    f"{label} operation {index}: canonical object is outside the relationship"
                )
            if not as_list(operation.get("deletions")):
                errors.append(f"{label} operation {index}: consolidation lacks deletion action")
            elif relationship_key_set and not (deletion_keys & relationship_key_set):
                errors.append(
                    f"{label} operation {index}: consolidation deletes no relationship member"
                )
    return errors


def validate_retention_distinctions(
    row: dict[str, Any],
    member_keys: list[str],
    distinguishing_terms: dict[str, list[str]],
    behavior_signatures: dict[str, dict[str, str]],
    label: str,
) -> list[str]:
    if row.get("relationship_verdict") not in KEEP_VERDICTS or len(member_keys) < 2:
        return []
    errors: list[str] = []
    signature_values = [behavior_signatures.get(key, {}) for key in member_keys]
    if all(value == signature_values[0] for value in signature_values[1:]):
        errors.append(
            f"{label}: retention verdict lacks a source-visible behavior distinction"
        )
    assessments = {
        str(item.get("object_key") or ""): item
        for item in as_list(row.get("member_assessments"))
        if isinstance(item, dict)
    }
    for key in member_keys:
        terms = [
            str(value).lower()
            for value in as_list(distinguishing_terms.get(key))
            if str(value).strip()
        ]
        text = str(
            (assessments.get(key) or {}).get("distinguishing_configuration") or ""
        ).lower()
        if re.search(r"\bsignature\s+[0-9a-f]{8,}\b", text):
            errors.append(
                f"{label}: {key} retention rationale uses an opaque signature instead "
                "of a source-visible semantic distinction"
            )
        if not terms or not any(term in text for term in terms):
            errors.append(
                f"{label}: {key} retention rationale lacks a configuration term unique to that member"
            )
    return errors


def validate_discovered_comparison(
    row: dict[str, Any],
    records_by_key: dict[str, dict[str, Any]],
    valid_keys: set[str],
    expected_consumers: dict[str, set[str]],
    deterministic_rows: list[dict[str, Any]],
    shared_by_key: dict[str, dict[str, Any]],
    source_paths_by_key: dict[str, str],
) -> list[str]:
    comparison_id = str(row.get("comparison_id") or "")
    label = f"comparison {comparison_id or '<missing>'}"
    errors: list[str] = []
    if not comparison_id.startswith("DISC-"):
        errors.append(f"{label}: analyst-discovered comparison ID must start with DISC-")
    if row.get("comparison_origin") != "analyst_discovered":
        errors.append(f"{label}: unknown comparison must declare analyst_discovered origin")
    discovery_methods = {
        str(value) for value in as_list(row.get("discovery_methods")) if str(value)
    }
    if not discovery_methods:
        errors.append(f"{label}: discovery must declare at least one discovery method")
    unknown_methods = sorted(discovery_methods - set(OPEN_DISCOVERY_METHODS))
    if unknown_methods:
        errors.append(f"{label}: discovery declares unknown methods {unknown_methods!r}")
    declared_comparison_types = {
        str(value) for value in as_list(row.get("comparison_types")) if str(value)
    }
    if not declared_comparison_types:
        errors.append(
            f"{label}: discovery must declare at least one mapped comparison type"
        )
    unknown_comparison_types = sorted(
        declared_comparison_types - set(DISCOVERY_METHOD_BY_COMPARISON_TYPE)
    )
    if unknown_comparison_types:
        errors.append(
            f"{label}: discovery declares unknown comparison types "
            f"{unknown_comparison_types!r}"
        )
    declared_required_methods = {
        DISCOVERY_METHOD_BY_COMPARISON_TYPE[comparison_type]
        for comparison_type in declared_comparison_types
        if comparison_type in DISCOVERY_METHOD_BY_COMPARISON_TYPE
    }
    if not declared_required_methods <= discovery_methods:
        errors.append(
            f"{label}: declared comparison types require discovery methods "
            f"{sorted(declared_required_methods)!r}"
        )
    candidate_keys = [str(value) for value in as_list(row.get("candidate_object_keys"))]
    if len(candidate_keys) < 2 or len(set(candidate_keys)) != len(candidate_keys):
        errors.append(f"{label}: discovery requires at least two unique source objects")
    unknown = sorted(set(candidate_keys) - set(records_by_key))
    if unknown:
        errors.append(f"{label}: discovery references unknown objects {unknown!r}")
    basis = " ".join(str(value) for value in as_list(row.get("candidate_basis")))
    if not specific_text(basis, 6):
        errors.append(f"{label}: discovery basis must explain the source-grounded relationship")
    if row.get("review_status") != "complete":
        errors.append(f"{label}: review_status must be complete")
    available = {
        key: records_by_key[key]["evidence_anchors"]
        for key in candidate_keys
        if key in records_by_key
    }
    paused = {
        key: bool(records_by_key[key]["paused"])
        for key in candidate_keys
        if key in records_by_key
    }
    evidence_terms = {
        key: compact_terms(
            [
                records_by_key[key].get("object_name"),
                records_by_key[key].get("object_key"),
                records_by_key[key].get("object_type"),
                *as_list(records_by_key[key].get("specificity_tokens")),
            ]
        )
        for key in candidate_keys
        if key in records_by_key
    }
    comparison_terms = compact_terms(
        [term for key in candidate_keys for term in evidence_terms.get(key, [])]
    )
    validation_row = {
        **row,
        "field_evidence_requirements": {
            "analyst_rationale": comparison_terms,
            "architecture_effect": comparison_terms,
        },
    }
    errors.extend(
        validate_field_evidence_text(
            validation_row,
            ("analyst_rationale", "architecture_effect"),
            label,
        )
    )
    errors.extend(
        validate_member_assessments(
            as_list(row.get("member_assessments")),
            candidate_keys,
            available,
            paused,
            evidence_terms,
            label,
        )
    )
    candidate_set = set(candidate_keys)
    declared_policy_types = {
        str(value)
        for value in as_list(row.get("comparison_types"))
        if str(value) in DISCOVERY_INHERITED_POLICY_TYPES
    }
    inherited_rows = [
        expected_row
        for expected_row in deterministic_rows
        if (
            candidate_set
            <= set(as_list(expected_row.get("candidate_object_keys")))
            or set(as_list(expected_row.get("candidate_object_keys"))) <= candidate_set
        )
        and set(as_list(expected_row.get("comparison_types")))
        & DISCOVERY_INHERITED_POLICY_TYPES
    ]
    inherited_policy_types = sorted(
        declared_policy_types
        | {
            str(comparison_type)
            for expected_row in inherited_rows
            for comparison_type in as_list(expected_row.get("comparison_types"))
            if comparison_type in DISCOVERY_INHERITED_POLICY_TYPES
        }
    )
    for policy_type in inherited_policy_types:
        required_methods = UNSAFE_DISCOVERY_METHOD_REQUIREMENTS.get(policy_type, set())
        if required_methods and not required_methods <= discovery_methods:
            errors.append(
                f"{label}: unsafe relationship {policy_type} must be attributed to "
                f"discovery methods {sorted(required_methods)!r}"
            )
    inherited_cautions_by_key = {
        str(caution.get("caution_key") or ""): caution
        for expected_row in inherited_rows
        for caution in as_list(expected_row.get("required_caution_states"))
        if isinstance(caution, dict) and caution.get("caution_key")
    }
    inherited_cautions = [
        inherited_cautions_by_key[key] for key in sorted(inherited_cautions_by_key)
    ]
    declared_cautions = comparison_caution_states(row, shared_by_key)
    all_cautions_by_key = {
        str(caution.get("caution_key") or ""): caution
        for caution in [*inherited_cautions, *declared_cautions]
        if caution.get("caution_key")
    }
    relationship_sources = {
        key: str(records_by_key[key].get("source_json_path") or "")
        for key in candidate_keys
        if key in records_by_key
    }
    relationship_identities = {
        key: [
            str(records_by_key[key].get("object_name") or ""),
            str(records_by_key[key].get("object_id") or ""),
        ]
        for key in candidate_keys
        if key in records_by_key
    }
    errors.extend(
        validate_decision(
            row,
            valid_keys,
            label,
            expected_consumers,
            candidate_keys,
            inherited_policy_types,
            [all_cautions_by_key[key] for key in sorted(all_cautions_by_key)],
            relationship_sources,
            relationship_identities,
            source_paths_by_key,
        )
    )
    if inherited_policy_types:
        errors.extend(
            deterministic_comparison_policy_errors(
                row,
                {"comparison_types": inherited_policy_types},
                label,
            )
        )
    behavior_terms = {
        key: set(object_behavior_terms(shared_by_key.get(key, {})))
        for key in candidate_keys
        if key in records_by_key
    }
    distinguishing_terms: dict[str, list[str]] = {}
    for key, own_terms in behavior_terms.items():
        other_terms = set().union(
            *(terms for other, terms in behavior_terms.items() if other != key)
        )
        distinguishing_terms[key] = sorted(own_terms - other_terms)
    errors.extend(
        validate_retention_distinctions(
            row,
            candidate_keys,
            distinguishing_terms,
            {
                key: {"configuration": str(records_by_key[key].get("config_hash") or "")}
                for key in candidate_keys
                if key in records_by_key
            },
            label,
        )
    )
    return errors


def validate_review_identity(
    supplied: dict[str, Any],
    expected: dict[str, Any],
    expected_context: dict[str, Any],
    source_sha256: str,
) -> list[str]:
    checks = (
        ("source_sha256", source_sha256, "source_sha256 does not match the export"),
        ("kind", "gtm_business_architecture_review", "kind is invalid"),
        ("schema_version", 3, "schema_version must be 3"),
        (
            "shared_facts_sha256",
            expected.get("shared_facts_sha256"),
            "does not use the canonical shared facts",
        ),
        (
            "context_sha256",
            expected.get("context_sha256"),
            "does not use the canonical audit context",
        ),
        (
            "audit_context",
            expected.get("audit_context"),
            "audit_context differs from the canonical context",
        ),
        (
            "inferred_context",
            expected_context.get("inferred_context"),
            "inferred_context differs from source inference",
        ),
        (
            "provided_context",
            expected_context.get("provided_context"),
            "provided_context differs from its locked provenance",
        ),
        (
            "provided_context_fields",
            expected_context.get("provided_fields"),
            "provided context fields changed",
        ),
        (
            "unresolved_context_questions",
            expected.get("unresolved_context_questions"),
            "unresolved context questions changed",
        ),
        ("run_status", "complete", "run_status must be complete"),
    )
    return [
        f"architecture review {message}"
        for field, expected_value, message in checks
        if supplied.get(field) != expected_value
    ]


def family_source_specificity_errors(
    row: dict[str, Any], expected_row: dict[str, Any], label: str
) -> list[str]:
    family_fields = (
        "business_action",
        "family_purpose",
        "execution_path_summary",
        "payload_coherence",
        "consent_and_sequence_coherence",
        "necessity_and_ownership",
        "analyst_rationale",
        "target_architecture",
    )
    errors = validate_field_evidence_text(
        row,
        family_fields,
        label,
        expected_row.get("field_evidence_requirements") or {},
    )
    family_text = " ".join(str(row.get(field) or "") for field in family_fields).lower()
    source_tokens = [
        str(token).lower() for token in as_list(expected_row["chain_specificity_tokens"])
    ]
    required_hits = min(3, len(source_tokens))
    if required_hits and sum(token in family_text for token in source_tokens) < required_hits:
        errors.append(f"{label}: assessment does not name enough chain-specific source facts")
    return errors


def validate_families(
    supplied: dict[str, Any],
    expected: dict[str, Any],
    valid_keys: set[str],
    expected_consumers: dict[str, set[str]],
    expected_comparisons: list[dict[str, Any]],
    source_paths_by_key: dict[str, str],
) -> list[str]:
    errors: list[str] = []
    expected_rows = {row["family_id"]: row for row in expected["families"]}
    raw_supplied_rows = as_list(supplied.get("families"))
    supplied_list = [row for row in raw_supplied_rows if isinstance(row, dict)]
    supplied_rows = {str(row.get("family_id") or ""): row for row in supplied_list}
    if len(supplied_list) != len(raw_supplied_rows):
        errors.append("architecture families contain malformed rows")
    if len(supplied_rows) != len(supplied_list) or "" in supplied_rows:
        errors.append("architecture family IDs must be unique and nonblank")
    if set(expected_rows) != set(supplied_rows):
        errors.append("architecture family set does not match the source export")
    generated_fields = (
        "family_key",
        "family_label",
        "member_object_keys",
        "member_object_names",
        "member_config_hashes",
        "member_source_paths",
        "available_member_evidence_anchors",
        "member_paused_status",
        "member_behavior_signatures",
        "member_distinguishing_terms",
        "member_evidence_terms",
        "chain_object_keys",
        "chain_object_names",
        "chain_config_hashes",
        "chain_source_paths",
        "available_chain_evidence_anchors",
        "chain_paused_status",
        "chain_behavior_signatures",
        "chain_evidence_terms",
        "chain_edges",
        "chain_specificity_tokens",
    )
    for family_id, expected_row in expected_rows.items():
        row = supplied_rows.get(family_id)
        if not row:
            continue
        label = f"family {family_id}"
        if "field_evidence_requirements" in row:
            errors.append(
                f"{label}: validator-only field_evidence_requirements must not be present "
                "in a reviewer artifact"
            )
        errors.extend(
            f"{label}: generated field {field} differs from source"
            for field in generated_fields
            if row.get(field) != expected_row.get(field)
        )
        if row.get("review_status") != "complete":
            errors.append(f"{label}: review_status must be complete")
        errors.extend(family_source_specificity_errors(row, expected_row, label))
        errors.extend(
            validate_member_assessments(
                as_list(row.get("member_assessments")),
                expected_row["member_object_keys"],
                expected_row["available_member_evidence_anchors"],
                expected_row["member_paused_status"],
                expected_row["member_evidence_terms"],
                label,
            )
        )
        errors.extend(
            validate_member_assessments(
                as_list(row.get("chain_assessments")),
                expected_row["chain_object_keys"],
                expected_row["available_chain_evidence_anchors"],
                expected_row["chain_paused_status"],
                expected_row["chain_evidence_terms"],
                f"{label} chain",
            )
        )
        member_keys = set(expected_row["member_object_keys"])
        related_unsafe_comparisons = [
            comparison
            for comparison in expected_comparisons
            if set(as_list(comparison.get("candidate_object_keys"))) <= member_keys
            and set(as_list(comparison.get("comparison_types")))
            & NON_RETENTION_COMPARISON_TYPES
        ]
        family_policy_types = sorted(
            {
                str(comparison_type)
                for comparison in related_unsafe_comparisons
                for comparison_type in as_list(comparison.get("comparison_types"))
                if comparison_type in NON_RETENTION_COMPARISON_TYPES
            }
        )
        family_cautions_by_key = {
            str(caution.get("caution_key") or ""): caution
            for comparison in related_unsafe_comparisons
            for caution in as_list(comparison.get("required_caution_states"))
            if isinstance(caution, dict) and caution.get("caution_key")
        }
        errors.extend(
            validate_decision(
                row,
                valid_keys,
                label,
                expected_consumers,
                # A family decision covers the complete dependency chain, not
                # only its root members. This lets a source-bound repair or
                # canonical remap of a trigger/variable resolve the family
                # without pretending the root tag itself was mutated.
                expected_row["chain_object_keys"],
                family_policy_types,
                [
                    family_cautions_by_key[key]
                    for key in sorted(family_cautions_by_key)
                ],
                dict(expected_row["chain_source_paths"]),
                {
                    key: [name]
                    for key, name in expected_row["chain_object_names"].items()
                },
                source_paths_by_key,
            )
        )
        errors.extend(
            validate_retention_distinctions(
                row,
                expected_row["member_object_keys"],
                expected_row["member_distinguishing_terms"],
                expected_row["member_behavior_signatures"],
                label,
            )
        )
        if row.get("disposition") == "keep":
            blocking = [
                comparison
                for comparison in expected_comparisons
                if set(as_list(comparison.get("candidate_object_keys"))) <= member_keys
                and set(as_list(comparison.get("comparison_types")))
                & NON_RETENTION_COMPARISON_TYPES
            ]
            if blocking:
                errors.append(
                    f"{label}: family retention is unsupported while member relationships "
                    f"{[row['comparison_id'] for row in blocking]!r} require cleanup or an "
                    "explicit owner decision"
                )
    return errors


GENERATED_COMPARISON_FIELDS = {
    "comparison_id",
    "comparison_origin",
    "layer",
    "candidate_object_keys",
    "candidate_object_ids",
    "candidate_object_names",
    "candidate_object_types",
    "candidate_config_hashes",
    "candidate_source_paths",
    "candidate_paused_status",
    "candidate_consumer_keys",
    "candidate_consumer_counts",
    "recommended_canonical_object_key",
    "recommended_canonical_basis",
    "available_member_evidence_anchors",
    "candidate_specificity_tokens",
    "candidate_behavior_signatures",
    "candidate_distinguishing_terms",
    "candidate_evidence_terms",
    "comparison_types",
    "comparison_type",
    "candidate_basis",
    "similarity_score",
    "required_comparison_dimensions",
    "discovery_methods",
    "required_caution_states",
}


def deterministic_comparison_policy_errors(
    row: dict[str, Any], expected_row: dict[str, Any], label: str
) -> list[str]:
    errors: list[str] = []
    comparison_types = as_list(expected_row.get("comparison_types"))
    comparison_type_set = set(comparison_types)
    verdict = row.get("relationship_verdict")
    disposition = row.get("disposition")
    if (
        "exact_configuration" in comparison_type_set
        and not comparison_type_set & EXACT_CONFIGURATION_SEMANTIC_POLICY_TYPES
    ):
        recommended = str(expected_row.get("recommended_canonical_object_key") or "")
        if recommended not in as_list(expected_row.get("candidate_object_keys")):
            errors.append(f"{label}: exact duplicate lacks a valid canonical recommendation")
        if verdict != "Exact duplicate" or disposition != "cleanup_operation":
            errors.append(
                f"{label}: identical source configuration has no distinct behavior "
                "choice; it must become an Exact duplicate cleanup operation"
            )
        if not as_list(row.get("operations")):
            errors.append(f"{label}: exact duplicate lacks a consolidation operation")
        rationale = str(row.get("canonical_selection_rationale") or "")
        selected = {
            str(operation.get("canonical_object_key") or "")
            for operation in as_list(row.get("operations"))
            if str(operation.get("canonical_object_key") or "")
        }
        if recommended and selected and recommended not in selected and (
            not specific_text(rationale, 7)
            or not re.search(
                r"\b(?:active|paused|consumer|reference|route|configuration|"
                r"consent|sequence|name|destination|payload)\b",
                rationale.lower(),
            )
        ):
            errors.append(
                f"{label}: choosing a canonical object other than the source-ranked "
                "default requires a source-based canonical-selection rationale"
            )
    if "different_consent_purposes_same_logic" in comparison_types:
        if verdict not in {"Conflict", "Owner decision needed"}:
            errors.append(
                f"{label}: different consent purposes with the same exported logic must "
                "be treated as a conflict or a visible owner decision"
            )
        if verdict == "Owner decision needed" and disposition != "owner_decision_needed":
            errors.append(
                f"{label}: unresolved consent-purpose collision requires owner decision"
            )
    if "same_tag_payload_different_route" in comparison_types and verdict not in {
        "Functional overlap",
        "Consolidation candidate",
        "Owner decision needed",
    }:
        errors.append(
            f"{label}: identical tag payload with different execution controls proves an "
            "overlap candidate, not a source-proven intentional variant"
        )
    if "shared_zone_child_container" in comparison_types and verdict not in {
        "Conflict",
        "Consolidation candidate",
        "Owner decision needed",
    }:
        errors.append(
            f"{label}: multiple Zones governing one child container require cleanup or "
            "explicit owner confirmation of non-overlapping scope"
        )
    if "cyclic_trigger_group_dependency" in comparison_types and verdict not in {
        "Conflict",
        "Owner decision needed",
    }:
        errors.append(
            f"{label}: a cyclic trigger-group dependency cannot be retained as an "
            "intentional architecture variant"
        )
    if "browser_server_consent_deduplication_review" in comparison_types and verdict not in {
        "Conflict",
        "Functional overlap",
        "Owner decision needed",
    }:
        errors.append(
            f"{label}: browser/server delivery requires a visible deduplication, consent, "
            "and ownership decision before it can be retained"
        )
    if verdict == "Container evidence limit":
        errors.append(
            f"{label}: a deterministic source-visible relationship cannot be wholly deferred "
            "as a container evidence limit; conclude the visible configuration and use an "
            "owner decision for unseen behavior"
        )
    return errors


def validate_deterministic_comparisons(
    supplied_rows: dict[str, dict[str, Any]],
    expected_rows: dict[str, dict[str, Any]],
    valid_keys: set[str],
    expected_consumers: dict[str, set[str]],
    source_paths_by_key: dict[str, str],
) -> list[str]:
    errors: list[str] = []
    for comparison_id, expected_row in expected_rows.items():
        row = supplied_rows.get(comparison_id)
        if not row:
            continue
        label = f"comparison {comparison_id}"
        if "field_evidence_requirements" in row:
            errors.append(
                f"{label}: validator-only field_evidence_requirements must not be present "
                "in a reviewer artifact"
            )
        errors.extend(
            f"{label}: generated field {field} differs from source"
            for field in GENERATED_COMPARISON_FIELDS
            if row.get(field) != expected_row.get(field)
        )
        if row.get("review_status") != "complete":
            errors.append(f"{label}: review_status must be complete")
        errors.extend(
            validate_field_evidence_text(
                row,
                ("analyst_rationale", "architecture_effect"),
                label,
                expected_row.get("field_evidence_requirements") or {},
            )
        )
        errors.extend(
            validate_member_assessments(
                as_list(row.get("member_assessments")),
                expected_row["candidate_object_keys"],
                expected_row["available_member_evidence_anchors"],
                expected_row["candidate_paused_status"],
                expected_row["candidate_evidence_terms"],
                label,
            )
        )
        errors.extend(
            validate_decision(
                row,
                valid_keys,
                label,
                expected_consumers,
                expected_row["candidate_object_keys"],
                as_list(expected_row.get("comparison_types")),
                as_list(expected_row.get("required_caution_states")),
                dict(expected_row["candidate_source_paths"]),
                {
                    key: [name, object_id]
                    for key, name, object_id in zip(
                        expected_row["candidate_object_keys"],
                        expected_row["candidate_object_names"],
                        expected_row["candidate_object_ids"],
                        strict=True,
                    )
                },
                source_paths_by_key,
            )
        )
        errors.extend(
            validate_retention_distinctions(
                row,
                expected_row["candidate_object_keys"],
                expected_row["candidate_distinguishing_terms"],
                expected_row["candidate_behavior_signatures"],
                label,
            )
        )
        errors.extend(deterministic_comparison_policy_errors(row, expected_row, label))
    return errors


def comparison_sets(
    supplied: dict[str, Any], expected: dict[str, Any]
) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]], list[str], list[str]]:
    expected_rows = {row["comparison_id"]: row for row in expected["comparisons"]}
    raw_supplied_list = as_list(supplied.get("comparisons"))
    supplied_list = [row for row in raw_supplied_list if isinstance(row, dict)]
    supplied_rows = {
        str(row.get("comparison_id") or ""): row for row in supplied_list
    }
    errors = []
    if len(supplied_list) != len(raw_supplied_list):
        errors.append("architecture comparisons contain malformed rows")
    if len(supplied_rows) != len(supplied_list):
        errors.append("architecture comparison IDs must be unique and nonblank")
    missing = sorted(set(expected_rows) - set(supplied_rows))
    if missing:
        errors.append(
            "architecture review is missing deterministic comparisons: " + ", ".join(missing)
        )
    discovered_ids = sorted(set(supplied_rows) - set(expected_rows))
    return expected_rows, supplied_rows, discovered_ids, errors


def validate_method_reviews(
    attestation: dict[str, Any],
    expected: dict[str, Any],
    records_by_key: dict[str, dict[str, Any]],
    discovered_methods_by_id: dict[str, set[str]],
) -> list[str]:
    errors: list[str] = []
    expected_rows = {
        str(row.get("method") or ""): row
        for row in as_list(expected.get("open_discovery_attestation", {}).get("method_reviews"))
    }
    raw_supplied_list = as_list(attestation.get("method_reviews"))
    supplied_list = [
        row
        for row in raw_supplied_list
        if isinstance(row, dict)
    ]
    supplied_rows = {
        str(row.get("method") or ""): row
        for row in supplied_list
    }
    if len(supplied_list) != len(raw_supplied_list):
        errors.append("open discovery method reviews contain malformed rows")
    if len(supplied_rows) != len(supplied_list) or "" in supplied_rows:
        errors.append("open discovery method reviews must use unique nonblank methods")
    if set(supplied_rows) != set(expected_rows):
        errors.append("open discovery method reviews must cover every method exactly once")
    locked_fields = (
        "method",
        "scan_status",
        "comparison_ids",
        "candidate_object_keys",
        "review_scope_object_keys",
        "source_scope_sha256",
    )
    for method, expected_row in expected_rows.items():
        review = supplied_rows.get(method)
        if not review:
            continue
        errors.extend(
            f"open discovery method {method}: generated field {field} changed"
            for field in locked_fields
            if review.get(field) != expected_row.get(field)
        )
        if review.get("review_status") != "complete":
            errors.append(f"open discovery method {method}: review is incomplete")
        if set(as_list(review.get("reviewed_comparison_ids"))) != set(
            as_list(expected_row.get("comparison_ids"))
        ):
            errors.append(f"open discovery method {method}: not every candidate was reviewed")
        if set(as_list(review.get("reviewed_object_keys"))) != set(records_by_key):
            errors.append(f"open discovery method {method}: source object coverage is incomplete")
        additional_values = [
            str(value) for value in as_list(review.get("additional_discovery_ids"))
        ]
        additional = set(additional_values)
        if len(additional) != len(additional_values) or "" in additional:
            errors.append(
                f"open discovery method {method}: added comparison IDs must be unique and nonblank"
            )
        expected_additional = {
            comparison_id
            for comparison_id, methods in discovered_methods_by_id.items()
            if method in methods
        }
        if additional != expected_additional:
            errors.append(
                f"open discovery method {method}: added comparison IDs do not match "
                "the discoveries attributed to this method"
            )
        conclusion = str(review.get("conclusion") or "")
        candidate_keys = [
            key
            for key in as_list(expected_row.get("candidate_object_keys"))
            if key in records_by_key
        ]
        scope_keys = candidate_keys or list(records_by_key)
        source_terms = compact_terms(
            [
                value
                for key in scope_keys
                for value in (
                    records_by_key[key].get("object_name"),
                    records_by_key[key].get("object_key"),
                    *as_list(records_by_key[key].get("specificity_tokens")),
                )
            ],
            160,
        )
        lowered_conclusion = conclusion.lower()
        method_label = method.replace("_", " ")
        source_hits = sum(term in lowered_conclusion for term in source_terms)
        if (
            not specific_text(conclusion, 8)
            or method_label not in lowered_conclusion
            or source_hits < min(2, len(source_terms))
        ):
            errors.append(
                f"open discovery method {method}: conclusion is not tied to its source scan"
            )
    return errors


def validate_zero_discovery(
    attestation: dict[str, Any], records_by_key: dict[str, dict[str, Any]]
) -> list[str]:
    rationale = str(attestation.get("zero_discovery_rationale") or "")
    source_terms = compact_terms(
        [
            value
            for record in records_by_key.values()
            for value in (
                record.get("object_name"),
                record.get("object_key"),
                *as_list(record.get("specificity_tokens")),
            )
        ]
    )
    lowered = rationale.lower()
    methods_complete = all(
        method.replace("_", " ") in lowered for method in OPEN_DISCOVERY_METHODS
    )
    if (
        specific_text(rationale, 20)
        and methods_complete
        and sum(term in lowered for term in source_terms) >= min(3, len(source_terms))
    ):
        return []
    return [
        "zero open discoveries require a source-specific rationale naming every discovery "
        "method and at least three source object facts"
    ]


def validate_discovery(
    supplied: dict[str, Any],
    expected: dict[str, Any],
    supplied_comparisons: dict[str, dict[str, Any]],
    discovered_ids: list[str],
    records_by_key: dict[str, dict[str, Any]],
    shared_by_key: dict[str, dict[str, Any]],
    valid_keys: set[str],
    expected_consumers: dict[str, set[str]],
    source_paths_by_key: dict[str, str],
) -> list[str]:
    errors: list[str] = []
    deterministic_rows = as_list(expected.get("comparisons"))
    discovered_methods_by_id = {
        comparison_id: {
            str(value)
            for value in as_list(
                supplied_comparisons[comparison_id].get("discovery_methods")
            )
            if str(value)
        }
        for comparison_id in discovered_ids
    }
    for comparison_id in discovered_ids:
        errors.extend(
            validate_discovered_comparison(
                supplied_comparisons[comparison_id],
                records_by_key,
                valid_keys,
                expected_consumers,
                deterministic_rows,
                shared_by_key,
                source_paths_by_key,
            )
        )
    attestation = supplied.get("open_discovery_attestation") or {}
    if attestation.get("review_status") != "complete":
        errors.append("open relationship discovery attestation must be complete")
    if set(as_list(attestation.get("reviewed_object_keys"))) != set(records_by_key):
        errors.append("open relationship discovery did not review every source object")
    if set(as_list(attestation.get("discovered_comparison_ids"))) != set(discovered_ids):
        errors.append("open relationship discovery IDs do not match added comparisons")
    if supplied.get("discovery_method_coverage") != expected.get("discovery_method_coverage"):
        errors.append("deterministic discovery method coverage differs from source")
    errors.extend(
        validate_method_reviews(
            attestation,
            expected,
            records_by_key,
            discovered_methods_by_id,
        )
    )
    if not discovered_ids:
        errors.extend(validate_zero_discovery(attestation, records_by_key))
    return errors


def validate_review(export_path: Path, review_path: Path) -> tuple[list[str], list[str]]:
    supplied = json.loads(review_path.read_text(encoding="utf-8"))
    expected_context, expected_shared = canonical_review_facts(export_path, supplied)
    expected = scaffold_review(
        export_path,
        expected_shared,
        include_validator_answer_key=True,
    )
    errors: list[str] = []
    warnings: list[str] = []
    descriptor = source_descriptor(export_path)
    valid_keys = object_keys(export_path)
    expected_consumers = object_consumer_map(export_path)
    source_names = object_name_map(export_path)
    source_paths_by_key = object_source_path_map(export_path)
    source_data = json.loads(export_path.read_text(encoding="utf-8"))
    cv = container_version(source_data)
    source_records = object_records(cv, container_root_path(source_data))
    records_by_key = {
        record["object_key"]: record
        for layer_records in source_records.values()
        for record in layer_records
    }
    shared_by_key = {
        str(record.get("object_key") or ""): record
        for record in as_list(expected_shared.get("objects"))
        if isinstance(record, dict)
    }
    errors.extend(
        validate_review_identity(
            supplied, expected, expected_context, descriptor["source_sha256"]
        )
    )
    errors.extend(validate_review_provenance(supplied, expected, "architecture review"))
    errors.extend(
        validate_families(
            supplied,
            expected,
            valid_keys,
            expected_consumers,
            as_list(expected.get("comparisons")),
            source_paths_by_key,
        )
    )
    expected_comparisons, supplied_comparisons, discovered_ids, set_errors = (
        comparison_sets(supplied, expected)
    )
    errors.extend(set_errors)
    errors.extend(
        validate_deterministic_comparisons(
            supplied_comparisons,
            expected_comparisons,
            valid_keys,
            expected_consumers,
            source_paths_by_key,
        )
    )
    errors.extend(
        validate_discovery(
            supplied,
            expected,
            supplied_comparisons,
            discovered_ids,
            records_by_key,
            shared_by_key,
            valid_keys,
            expected_consumers,
            source_paths_by_key,
        )
    )
    semantic_rows = [
        *[
            row
            for row in as_list(supplied.get("families"))
            if isinstance(row, dict)
        ],
        *[
            row
            for row in as_list(supplied.get("comparisons"))
            if isinstance(row, dict)
        ],
    ]
    errors.extend(
        repeated_semantic_template_errors(
            semantic_rows,
            (
                "analyst_rationale",
                "architecture_effect",
                "owner_question",
                "recommended_action",
                "target_architecture",
            ),
            (
                "family_id",
                "family_key",
                "family_label",
                "comparison_id",
            ),
            "architecture review",
        )
    )
    errors.extend(
        validate_operation_set(
            [
                operation
                for collection in (
                    as_list(supplied.get("families")),
                    as_list(supplied.get("comparisons")),
                )
                for row in collection
                if isinstance(row, dict)
                for operation in as_list(row.get("operations"))
                if isinstance(operation, dict)
            ],
            expected_consumers=expected_consumers,
            object_names=source_names,
            label="architecture review operation set",
        )
    )
    return errors, warnings


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    scaffold = subparsers.add_parser("scaffold")
    scaffold.add_argument("export", type=Path)
    scaffold.add_argument("output", type=Path)
    scaffold.add_argument("--pretty", action="store_true")
    validate = subparsers.add_parser("validate")
    validate.add_argument("export", type=Path)
    validate.add_argument("review", type=Path)
    args = parser.parse_args()
    if args.command == "scaffold":
        payload = scaffold_review(args.export)
        write_json(args.output, payload, args.pretty)
        print(
            json.dumps(
                {
                    "output": str(args.output),
                    "families": len(payload["families"]),
                    "comparisons": len(payload["comparisons"]),
                }
            )
        )
        return 0
    errors, warnings = validate_review(args.export, args.review)
    for warning in warnings:
        print(f"WARNING: {warning}")
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(json.dumps({"status": "pass", "review": str(args.review)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
