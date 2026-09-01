#!/usr/bin/env python3
"""Extract internal family and relationship candidate evidence.

This module is an implementation component of the canonical v2 scan.  The
standalone v1 review command was deliberately removed.
"""

from __future__ import annotations

import json
import re
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
)
from gtm_relationships import (
    object_records,
    relationship_candidates,
    tag_business_event_key,
    tag_contract,
)
from gtm_requirement_evidence import object_requirement_links
from gtm_shared_facts import build_shared_facts

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
    "consent_writer_sequence_review",
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
    "consent_writer_sequence_review": {
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


def source_leaf_distinction_terms(shared: dict[str, Any]) -> list[str]:
    """Expose exact non-metadata leaf path/value pairs as a retention fallback."""

    base = str(shared.get("source_json_path") or "")
    ignored_leaves = {
        "accountId",
        "containerId",
        "workspaceId",
        "fingerprint",
        "path",
        "tagManagerUrl",
        "notes",
        "name",
        *ID_KEYS.values(),
    }
    terms: list[str] = []
    for fact in as_list(shared.get("source_leaf_facts")):
        if not isinstance(fact, dict):
            continue
        path = str(fact.get("json_path") or "")
        leaf = re.split(r"[.\[]", path.rstrip("]"))[-1].rstrip("]")
        if leaf in ignored_leaves:
            continue
        relative = path[len(base) :] if base and path.startswith(base) else path
        value = usable_behavior_preview(fact.get("value_preview"))
        if not relative or not value or len(value) > 100:
            continue
        term = usable_distinguishing_term(
            f"source field {relative.lstrip('.')} value {value}"
        )
        if term:
            terms.append(term)
    return compact_terms(terms, 80)


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
            *source_leaf_distinction_terms(shared),
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


def comparison_caution_states(
    comparison: dict[str, Any], shared_by_key: dict[str, dict[str, Any]]
) -> list[dict[str, Any]]:
    """Expose source-visible handoff limits without auditing an unseen server."""

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
        consent_states[key] = str(
            route.get("effective_control_status") or "not_visible"
        )
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


def scaffold_review(
    export_path: Path,
    shared_facts: dict[str, Any] | None = None,
    *,
    requirement_evidence: dict[str, Any] | None = None,
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
    source_records = {
        record["object_key"]: record
        for records in object_records(cv, root_path).values()
        for record in records
    }
    requirement_links_by_key = {
        key: object_requirement_links(
            record["object"],
            str(record.get("object_name") or ""),
            requirement_evidence,
        )
        for key, record in source_records.items()
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
        family["approved_requirement_links"] = sorted(
            {
                str(link.get("requirement_id") or ""): link
                for key in family["chain_object_keys"]
                for link in as_list(requirement_links_by_key.get(key))
                if str(link.get("requirement_id") or "")
            }.values(),
            key=lambda link: str(link.get("requirement_id") or ""),
        )
    comparisons = scaffold_comparisons(cv, root_path)
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
        comparison["approved_requirement_links"] = sorted(
            {
                str(link.get("requirement_id") or ""): link
                for key in comparison["candidate_object_keys"]
                for link in as_list(requirement_links_by_key.get(key))
                if str(link.get("requirement_id") or "")
            }.values(),
            key=lambda link: str(link.get("requirement_id") or ""),
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
    return {
        **descriptor,
        "kind": "gtm_business_architecture_review",
        "schema_version": 4,
        "shared_facts_sha256": shared_facts["shared_facts_sha256"],
        "context_sha256": shared_facts["context_sha256"],
        "audit_context": shared_facts.get("audit_context", {}),
        "inferred_context": shared_facts.get("inferred_context", {}),
        "provided_context": shared_facts.get("provided_context", {}),
        "provided_context_fields": shared_facts.get("provided_context_fields", []),
        "approved_requirement_evidence": requirement_evidence or {},
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
