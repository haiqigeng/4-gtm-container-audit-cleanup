#!/usr/bin/env python3
"""Build immutable deterministic GTM facts shared by all verdict engines."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from gtm_configuration_facts import (
    build_consumers,
    logic_anchors,
    object_consumers,
    reference_trace_requirements,
)
from gtm_consent_model import consent_values, server_route_hosts, tag_consent_route
from gtm_context_model import build_context_model
from gtm_custom_code_extract import extract_export
from gtm_lib import (
    ID_KEYS,
    as_list,
    comparable,
    container_root_path,
    container_version,
    is_system_trigger_reference,
    object_id,
    refs,
    source_descriptor,
    stable_hash,
    system_reference_description,
    trigger_group_members,
    walk_json_fields,
)
from gtm_relationships import (
    business_scope_tokens,
    configured_destinations,
    object_records,
    tag_contract,
    trigger_conditions,
)
from gtm_source_model import build_model


def source_leaf_facts(obj: dict[str, Any], source_path: str) -> list[dict[str, Any]]:
    return [
        {
            "json_path": fact["json_path"],
            "value_hash": fact["value_hash"],
            "value_type": fact["value_type"],
            "value_preview": fact.get("value_preview"),
            "referenced_variables": fact["referenced_variables"],
        }
        for fact in walk_json_fields(obj, source_path)
    ]


def semantic_absence_facts(
    layer: str, obj: dict[str, Any], source_path: str
) -> list[dict[str, Any]]:
    required_fields = {
        "zone": ("childContainer", "boundary", "typeRestriction"),
        "gtagConfig": ("type", "parameter"),
    }.get(layer, ())
    return [
        {
            "json_path": f"{source_path}.{field}",
            "value_hash": stable_hash({"missing_field": field}),
            "value_type": "missing",
            "value_preview": "<missing from exported object>",
            "referenced_variables": [],
        }
        for field in required_fields
        if field not in obj
    ]


def unique_facts(facts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    unique = {
        (str(fact.get("json_path") or ""), str(fact.get("value_hash") or "")): fact
        for fact in facts
    }
    return [unique[key] for key in sorted(unique)]


def selected_record_facts(
    record: dict[str, Any],
    tokens: tuple[str, ...],
    facts: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    facts = (
        facts
        if facts is not None
        else source_leaf_facts(record["object"], record["source_json_path"])
    )
    logic = set(logic_anchors(facts))
    selected = [
        fact
        for fact in facts
        if fact["json_path"] in logic
        and any(token in fact["json_path"].lower() for token in tokens)
    ]
    identity = [
        fact
        for fact in facts
        if fact["json_path"].lower().endswith((".name", ".type", ".paused"))
    ]
    return unique_facts([*identity, *selected])


def dependency_facts_for_record(
    record: dict[str, Any],
    records: dict[str, list[dict[str, Any]]],
    consumers: dict[str, list[dict[str, str]]],
    *,
    records_by_key: dict[str, dict[str, Any]] | None = None,
    triggers_by_id: dict[str, list[dict[str, Any]]] | None = None,
    tags_by_name: dict[str, list[dict[str, Any]]] | None = None,
    source_facts_by_key: dict[str, list[dict[str, Any]]] | None = None,
    contracts_by_key: dict[str, dict[str, Any]] | None = None,
) -> tuple[
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
]:
    """Resolve execution edges and downstream consumer contracts without runtime inference."""
    obj = record["object"]
    layer = record["layer"]
    records_by_key = records_by_key or {
        item["object_key"]: item
        for layer_records in records.values()
        for item in layer_records
    }
    if triggers_by_id is None:
        triggers_by_id = {}
        for item in records.get("trigger", []):
            triggers_by_id.setdefault(str(item["object_id"]), []).append(item)
    if tags_by_name is None:
        tags_by_name = {}
        for item in records.get("tag", []):
            tags_by_name.setdefault(str(item["object_name"]), []).append(item)
    source_facts_by_key = source_facts_by_key or {}
    contracts_by_key = contracts_by_key or {}
    source_facts = source_facts_by_key.get(record["object_key"]) or source_leaf_facts(
        obj, record["source_json_path"]
    )

    def source_paths(relation: str, reference: str) -> list[str]:
        if relation == "trigger_group_member":
            return [
                fact["json_path"]
                for fact in source_facts
                if ".parameter" in fact["json_path"]
                and str(fact.get("value_preview") or "") == reference
            ]
        matching = [
            fact["json_path"]
            for fact in source_facts
            if relation.lower() in fact["json_path"].lower()
            and str(fact.get("value_preview") or "") == reference
        ]
        if matching:
            return matching
        return [
            fact["json_path"]
            for fact in source_facts
            if relation.lower() in fact["json_path"].lower()
        ]

    traces: list[dict[str, Any]] = []
    dependency_facts: list[dict[str, Any]] = []

    def trigger_member_entries(
        trigger: dict[str, Any], source_path: str
    ) -> list[dict[str, Any]]:
        entries: list[dict[str, Any]] = []
        parameters = trigger.get("parameter")
        if not isinstance(parameters, list):
            return entries
        for parameter_index, parameter in enumerate(parameters):
            if not isinstance(parameter, dict) or parameter.get("key") != "triggerIds":
                continue
            members = parameter.get("list")
            list_path = f"{source_path}.parameter[{parameter_index}].list"
            if not isinstance(members, list):
                entries.append(
                    {
                        "reference": f"<malformed-list:{parameter_index}>",
                        "resolution_state": "malformed",
                        "source_reference_paths": [list_path],
                    }
                )
                continue
            for member_index, member in enumerate(members):
                member_path = f"{list_path}[{member_index}]"
                reference = (
                    str(member.get("value") or "").strip()
                    if isinstance(member, dict)
                    else ""
                )
                entries.append(
                    {
                        "reference": reference or f"<malformed-member:{member_index}>",
                        "resolution_state": "pending" if reference else "malformed",
                        "source_reference_paths": [
                            f"{member_path}.value" if reference else member_path
                        ],
                    }
                )
        return entries

    def resolve_trigger(
        reference: str,
        relation: str,
        active: tuple[str, ...],
        reference_paths: list[str] | None = None,
    ) -> dict[str, Any]:
        def traced(result: dict[str, Any]) -> dict[str, Any]:
            result["source_reference_paths"] = list(reference_paths or [])
            return result

        if is_system_trigger_reference(reference):
            return traced({
                "relation": relation,
                "reference": reference,
                "resolution_state": "recognized_system_reference",
                "system_description": system_reference_description("trigger", reference),
                "targets": [],
            })
        if reference in active:
            return traced({
                "relation": relation,
                "reference": reference,
                "resolution_state": "cycle",
                "cycle_path": [*active, reference],
                "targets": [],
            })
        matches = triggers_by_id.get(reference, [])
        if not matches:
            return traced({
                "relation": relation,
                "reference": reference,
                "resolution_state": "missing",
                "targets": [],
            })
        targets = []
        for target in matches:
            target_facts = selected_record_facts(
                target,
                (
                    "filter",
                    "condition",
                    "triggertype",
                    "triggerids",
                    "parameter",
                    ".type",
                ),
                source_facts_by_key.get(target["object_key"]),
            )
            dependency_facts.extend(target_facts)
            children = []
            for child in trigger_member_entries(
                target["object"], target["source_json_path"]
            ):
                if child["resolution_state"] == "malformed":
                    children.append(
                        {
                            "relation": "trigger_group_member",
                            "reference": child["reference"],
                            "resolution_state": "malformed",
                            "source_reference_paths": child["source_reference_paths"],
                            "targets": [],
                        }
                    )
                else:
                    children.append(
                        resolve_trigger(
                            child["reference"],
                            "trigger_group_member",
                            (*active, reference),
                            child["source_reference_paths"],
                        )
                    )
            targets.append(
                {
                    "object_key": target["object_key"],
                    "object_name": target["object_name"],
                    "object_type": target["object_type"],
                    "source_json_path": target["source_json_path"],
                    "conditions": trigger_conditions(target["object"]),
                    "member_traces": children,
                }
            )
        return traced({
            "relation": relation,
            "reference": reference,
            "resolution_state": "unique" if len(matches) == 1 else "ambiguous",
            "targets": targets,
        })

    trigger_relations: list[tuple[str, str]] = []
    if layer == "tag":
        for relation in ("firingTriggerId", "blockingTriggerId"):
            trigger_relations.extend(
                (relation, str(value)) for value in as_list(obj.get(relation))
            )
    elif layer == "trigger":
        for member in trigger_member_entries(obj, record["source_json_path"]):
            if member["resolution_state"] == "malformed":
                traces.append(
                    {
                        "relation": "trigger_group_member",
                        "reference": member["reference"],
                        "resolution_state": "malformed",
                        "source_reference_paths": member["source_reference_paths"],
                        "targets": [],
                    }
                )
            else:
                traces.append(
                    resolve_trigger(
                        member["reference"],
                        "trigger_group_member",
                        (),
                        member["source_reference_paths"],
                    )
                )
    elif layer == "zone":
        boundary = obj.get("boundary") if isinstance(obj.get("boundary"), dict) else {}
        trigger_relations.extend(
            ("customEvaluationTriggerId", str(value))
            for value in as_list(boundary.get("customEvaluationTriggerId"))
        )
    for relation, reference in trigger_relations:
        trace = resolve_trigger(reference, relation, (), source_paths(relation, reference))
        traces.append(trace)

    if layer == "tag":
        def resolve_tag_sequence(
            reference: str,
            relation: str,
            active: tuple[str, ...],
        ) -> dict[str, Any]:
            if reference in active:
                cycle_targets = tags_by_name.get(reference, [])
                for target in cycle_targets:
                    dependency_facts.extend(
                        selected_record_facts(
                            target,
                            (
                                "firingtriggerid",
                                "blockingtriggerid",
                                "setuptag",
                                "teardowntag",
                                "consent",
                                "parameter",
                                "html",
                                "javascript",
                                ".paused",
                                ".type",
                            ),
                            source_facts_by_key.get(target["object_key"]),
                        )
                    )
                return {
                    "relation": relation,
                    "reference": reference,
                    "resolution_state": "cycle",
                    "cycle_path": [*active, reference],
                    "targets": [
                        {
                            "object_key": target["object_key"],
                            "object_name": target["object_name"],
                            "object_type": target["object_type"],
                            "paused": bool(target["paused"]),
                            "source_json_path": target["source_json_path"],
                            "sequence_traces": [],
                        }
                        for target in cycle_targets
                    ],
                }
            matches = tags_by_name.get(reference, []) if reference else []
            targets = []
            for target in matches:
                target_facts = selected_record_facts(
                    target,
                    (
                        "firingtriggerid",
                        "blockingtriggerid",
                        "setuptag",
                        "teardowntag",
                        "consent",
                        "parameter",
                        "html",
                        "javascript",
                        ".paused",
                        ".type",
                    ),
                    source_facts_by_key.get(target["object_key"]),
                )
                dependency_facts.extend(target_facts)
                child_traces = []
                for child_relation in ("setupTag", "teardownTag"):
                    for child in as_list(target["object"].get(child_relation)):
                        if not isinstance(child, dict):
                            continue
                        child_name = str(child.get("tagName") or "")
                        if child_name:
                            child_traces.append(
                                resolve_tag_sequence(
                                    child_name,
                                    child_relation,
                                    (*active, reference),
                                )
                            )
                targets.append(
                    {
                        "object_key": target["object_key"],
                        "object_name": target["object_name"],
                        "object_type": target["object_type"],
                        "paused": bool(target["paused"]),
                        "source_json_path": target["source_json_path"],
                        "sequence_traces": child_traces,
                    }
                )
            return {
                "relation": relation,
                "reference": reference,
                "resolution_state": (
                    "missing"
                    if not matches
                    else "unique"
                    if len(matches) == 1
                    else "ambiguous"
                ),
                "targets": targets,
            }

        for relation in ("setupTag", "teardownTag"):
            for index, item in enumerate(as_list(obj.get(relation))):
                reference = str(item.get("tagName") or "") if isinstance(item, dict) else ""
                if not reference:
                    trace = {
                        "relation": relation,
                        "reference": "",
                        "resolution_state": "malformed",
                        "targets": [],
                    }
                else:
                    trace = resolve_tag_sequence(
                        reference,
                        relation,
                        (str(record.get("object_name") or ""),),
                    )
                item_path = f"{record['source_json_path']}.{relation}[{index}]"
                trace["source_reference_paths"] = [
                    fact["json_path"]
                    for fact in source_facts
                    if fact["json_path"] == item_path
                    or fact["json_path"].startswith(item_path + ".")
                ] or [item_path]
                traces.append(trace)

    consumer_facts: list[dict[str, Any]] = []
    consumer_contexts: list[dict[str, Any]] = []
    for consumer in object_consumers(layer, obj, consumers):
        target = records_by_key.get(str(consumer.get("consumer_key") or ""))
        if not target:
            continue
        contract = (
            contracts_by_key.get(target["object_key"], {})
            if target["layer"] == "tag"
            else {}
        )
        consumer_contexts.append(
            {
                "consumer_key": target["object_key"],
                "consumer_name": target["object_name"],
                "consumer_type": target["object_type"],
                "relation": str(consumer.get("relation") or ""),
                "source_reference_path": str(consumer.get("source_json_path") or ""),
                "events": as_list(contract.get("events")),
                "destinations": as_list(contract.get("destinations")),
                "referenced_variables": sorted(refs(target["object"])),
            }
        )
        candidate_facts = source_facts_by_key.get(
            target["object_key"]
        ) or source_leaf_facts(target["object"], target["source_json_path"])
        reference_path = str(consumer.get("source_json_path") or "")
        consumer_facts.extend(
            fact
            for fact in candidate_facts
            if fact["json_path"] == reference_path
            or any(
                token in fact["json_path"].lower()
                for token in (
                    "eventname",
                    "destination",
                    "measurementid",
                    "pixel",
                    "firingtriggerid",
                    "blockingtriggerid",
                    "setuptag",
                    "teardowntag",
                    "consent",
                    "parameter",
                    "html",
                    "javascript",
                    "currency",
                    "value",
                    "items",
                    ".type",
                )
            )
        )
    return (
        traces,
        unique_facts(dependency_facts),
        unique_facts(consumer_facts),
        sorted(consumer_contexts, key=lambda item: item["consumer_key"]),
    )


def behavior_signatures(
    record: dict[str, Any],
    trace_requirements: list[dict[str, Any]],
    technical: dict[str, Any],
    consent: dict[str, Any],
    execution_dependencies: list[dict[str, Any]],
) -> dict[str, str]:
    obj = record["object"]
    route = {
        "firing": sorted(str(value) for value in as_list(obj.get("firingTriggerId"))),
        "blocking": sorted(str(value) for value in as_list(obj.get("blockingTriggerId"))),
        "setup": as_list(obj.get("setupTag")),
        "teardown": as_list(obj.get("teardownTag")),
    }
    terminals = [
        {
            "reference": row["reference"],
            "states": row["terminal_states"],
            "terminals": row["terminal_requirements"],
        }
        for row in trace_requirements
    ]
    formulas = {
        "return_expressions": technical.get("return_expressions", []),
        "fixed_slot_groups": technical.get("fixed_slot_groups", []),
        "returned_value_type": technical.get("returned_value_type", ""),
    }
    return {
        "configuration": record["config_hash"],
        "execution_route": stable_hash(
            {"direct_route": route, "resolved_dependencies": execution_dependencies}
        ),
        "trigger_logic": stable_hash(trigger_conditions(obj)),
        "terminal_sources": stable_hash(terminals),
        "formula": stable_hash(formulas),
        "consent": stable_hash(consent),
        "business_scope": stable_hash(sorted(business_scope_tokens(record))),
    }


def shared_content_hash(payload: dict[str, Any]) -> str:
    return stable_hash(
        {
            "source_sha256": payload.get("source_sha256"),
            "context_sha256": payload.get("context_sha256"),
            "audit_context": payload.get("audit_context", {}),
            "inferred_context": payload.get("inferred_context", {}),
            "provided_context": payload.get("provided_context", {}),
            "provided_context_fields": payload.get("provided_context_fields", []),
            "unresolved_context_questions": payload.get(
                "unresolved_context_questions", []
            ),
            "objects": payload.get("objects", []),
            "integrity_findings": payload.get("integrity_findings", []),
        },
        32,
    )


def effective_server_route_hosts_by_tag(
    cv: dict[str, Any],
    root_path: str = "$.containerVersion",
    records: dict[str, list[dict[str, Any]]] | None = None,
) -> dict[str, list[str]]:
    """Resolve direct, settings-variable, and destination-owner server routes."""

    records = records or object_records(cv, root_path)
    variables = [
        row for row in as_list(cv.get("variable")) if isinstance(row, dict)
    ]
    route_by_key: dict[str, set[str]] = {}
    destinations_by_key: dict[str, set[str]] = {}
    for record in [*records.get("tag", []), *records.get("gtagConfig", [])]:
        key = str(record.get("object_key") or "")
        route_by_key[key] = set(
            as_list(
                tag_consent_route(
                    record["object"],
                    variables=variables,
                    root_path=root_path,
                ).get("server_routing_hosts")
            )
        )
        destinations_by_key[key] = set(configured_destinations(record))

    route_owners = [
        record
        for record in [*records.get("gtagConfig", []), *records.get("tag", [])]
        if route_by_key.get(str(record.get("object_key") or ""))
        and destinations_by_key.get(str(record.get("object_key") or ""))
        and (
            record.get("layer") == "gtagConfig"
            or str(record.get("object_type") or "").lower() in {"googtag", "gaawc"}
        )
    ]
    result: dict[str, list[str]] = {}
    for tag_record in records.get("tag", []):
        key = str(tag_record.get("object_key") or "")
        destinations = destinations_by_key.get(key, set())
        hosts = set(route_by_key.get(key, set()))
        for owner in route_owners:
            owner_key = str(owner.get("object_key") or "")
            if destinations & destinations_by_key.get(owner_key, set()):
                hosts.update(route_by_key.get(owner_key, set()))
        result[key] = sorted(hosts)
    return result


def build_shared_facts(
    export_path: Path,
    context: dict[str, Any] | None = None,
    technical: dict[str, Any] | None = None,
    navigation: dict[str, Any] | None = None,
) -> dict[str, Any]:
    data = json.loads(export_path.read_text(encoding="utf-8"))
    navigation = navigation or build_model(export_path)
    if navigation.get("coverage_gate") == "blocked_source_integrity":
        finding_types = sorted(
            str(row.get("finding_type") or "source_integrity_error")
            for row in as_list(navigation.get("source_integrity_findings"))
            if row.get("blocking")
        )
        raise ValueError(
            "source integrity gate blocked shared facts"
            + (": " + ", ".join(finding_types) if finding_types else "")
        )
    cv = container_version(data)
    root_path = container_root_path(data)
    context = context or build_context_model(export_path)
    technical = technical or extract_export(export_path)
    consumers = build_consumers(cv, root_path)
    records = object_records(cv, root_path)
    semantic_by_key = {
        record["object_key"]: record
        for layer_records in records.values()
        for record in layer_records
    }
    records_by_key = dict(semantic_by_key)
    triggers_by_id: dict[str, list[dict[str, Any]]] = {}
    for record in records.get("trigger", []):
        triggers_by_id.setdefault(str(record["object_id"]), []).append(record)
    tags_by_name: dict[str, list[dict[str, Any]]] = {}
    for record in records.get("tag", []):
        tags_by_name.setdefault(str(record["object_name"]), []).append(record)
    technical_by_key = {
        f"{row['layer']}:{row['object_id']}": row for row in as_list(technical.get("rows"))
    }
    variables = as_list(cv.get("variable"))
    source_facts_by_key = {
        key: source_leaf_facts(record["object"], record["source_json_path"])
        for key, record in semantic_by_key.items()
    }
    trace_variables_by_name: dict[str, list[tuple[int, dict[str, Any]]]] = {}
    for record in records.get("variable", []):
        trace_variables_by_name.setdefault(str(record["object_name"]), []).append(
            (int(record["index"]), record["object"])
        )
    trace_builtin_names = {
        str(variable.get("name") or "")
        for variable in as_list(cv.get("builtInVariable"))
        if isinstance(variable, dict) and str(variable.get("name") or "")
    }
    absence_facts_by_key = {
        key: semantic_absence_facts(
            record["layer"],
            record["object"],
            record["source_json_path"],
        )
        for key, record in semantic_by_key.items()
    }
    contracts_by_key = {
        key: tag_contract(record)
        for key, record in semantic_by_key.items()
        if record["layer"] == "tag"
    }
    effective_server_routes = effective_server_route_hosts_by_tag(
        cv,
        root_path,
        records,
    )
    consent_routes_by_key = {
        key: tag_consent_route(
            record["object"],
            record["source_json_path"],
            variables=variables,
            root_path=root_path,
            approved_server_consent_hosts=as_list(
                (context.get("context") or {}).get("server_consent_gating_hosts")
            ),
            inherited_server_route_hosts=effective_server_routes.get(key, []),
        )
        for key, record in semantic_by_key.items()
        if record["layer"] in {"tag", "gtagConfig"}
    }
    destination_records = records.get("tag", []) + records.get("gtagConfig", [])
    destinations_by_key = {
        record["object_key"]: set(configured_destinations(record))
        for record in destination_records
    }
    destination_members: dict[str, set[str]] = {}
    for key, destinations in destinations_by_key.items():
        for destination in destinations:
            destination_members.setdefault(destination, set()).add(key)
    destination_peer_contexts: dict[str, list[dict[str, Any]]] = {}
    destination_peer_facts: dict[str, list[dict[str, Any]]] = {}
    for record in destination_records:
        destinations = destinations_by_key[record["object_key"]]
        peers = []
        peer_facts = []
        peer_keys = {
            peer_key
            for destination in destinations
            for peer_key in destination_members.get(destination, set())
            if peer_key != record["object_key"]
        }
        for peer_key in sorted(peer_keys):
            peer = semantic_by_key[peer_key]
            shared_destinations = sorted(
                destinations & destinations_by_key[peer_key]
            )
            peer_contract = contracts_by_key.get(peer_key, {})
            candidate_facts = [
                *source_facts_by_key[peer_key],
                *absence_facts_by_key[peer_key],
            ]
            shared_destination_set = set(shared_destinations)
            destination_anchors = [
                fact["json_path"]
                for fact in candidate_facts
                if str(fact.get("value_preview") or "").lower()
                in shared_destination_set
            ]
            peer_facts.extend(
                fact
                for fact in candidate_facts
                if fact["json_path"] in destination_anchors
                or any(
                    token in fact["json_path"].lower()
                    for token in (
                        "eventname",
                        "measurementid",
                        "destination",
                        "parameter",
                        "consentsettings",
                        "firingtriggerid",
                        "blockingtriggerid",
                        "setuptag",
                        "teardowntag",
                        "schedulestartms",
                        "scheduleendms",
                        "tagfiringoption",
                        ".paused",
                        ".type",
                    )
                )
            )
            peer_route = consent_routes_by_key.get(peer_key, {})
            peers.append(
                {
                    "object_key": peer["object_key"],
                    "layer": peer["layer"],
                    "object_name": peer["object_name"],
                    "object_type": peer["object_type"],
                    "type_present": "type" in peer["object"],
                    "shared_destinations": shared_destinations,
                    "events": as_list(peer_contract.get("events")),
                    "source_json_path": peer["source_json_path"],
                    "destination_evidence_anchors": destination_anchors,
                    "server_routing_hosts": server_route_hosts(peer["object"]),
                    "effective_control_status": str(
                        peer_route.get("effective_control_status") or ""
                    ),
                    "consent_status": str(peer_route.get("consent_status") or ""),
                }
            )
        destination_peer_contexts[record["object_key"]] = sorted(
            peers, key=lambda item: item["object_key"]
        )
        destination_peer_facts[record["object_key"]] = unique_facts(peer_facts)
    object_rows: list[dict[str, Any]] = []
    for layer, id_key in ID_KEYS.items():
        for index, obj in enumerate(as_list(cv.get(layer))):
            key = f"{layer}:{object_id(obj, id_key)}"
            source_path = f"{root_path}.{layer}[{index}]"
            record = semantic_by_key.get(
                key,
                {
                    "layer": layer,
                    "index": index,
                    "object": obj,
                    "object_key": key,
                    "object_id": object_id(obj, id_key),
                    "object_name": str(obj.get("name") or ""),
                    "object_type": str(obj.get("type") or layer),
                    "paused": bool(obj.get("paused")) if layer == "tag" else False,
                    "config_hash": stable_hash(comparable(obj)),
                    "source_json_path": source_path,
                    "evidence_anchors": [
                        fact["json_path"] for fact in walk_json_fields(obj, source_path)
                    ],
                    "specificity_tokens": [],
                },
            )
            obj = record["object"]
            key = record["object_key"]
            technical_row = technical_by_key.get(key, {})
            traces = (
                reference_trace_requirements(
                    cv,
                    obj,
                    root_path,
                    variables_by_name=trace_variables_by_name,
                    builtin_names=trace_builtin_names,
                    source_path=record["source_json_path"],
                    source_reference_facts=source_facts_by_key.get(key),
                    variable_facts_by_key=source_facts_by_key,
                )
                if layer in records
                else []
            )
            (
                execution_dependencies,
                dependency_facts,
                consumer_dependency_facts,
                consumer_dependency_contexts,
            ) = dependency_facts_for_record(
                record,
                records,
                consumers,
                records_by_key=records_by_key,
                triggers_by_id=triggers_by_id,
                tags_by_name=tags_by_name,
                source_facts_by_key=source_facts_by_key,
                contracts_by_key=contracts_by_key,
            )
            consent_values_for_object = consent_values(obj, record["source_json_path"])
            consent = consent_routes_by_key.get(
                key,
                {"consent_source_values": consent_values_for_object},
            )
            contract = contracts_by_key.get(key, {})
            formula_facts = {
                field: technical_row.get(field)
                for field in (
                    "logical_line_count",
                    "return_expressions",
                    "fixed_slot_groups",
                    "fixed_slot_aggregation",
                    "returned_value_type",
                    "javascript_parser",
                    "javascript_parser_version",
                    "parser_input_normalized",
                    "ast_branch_count",
                    "ast_return_count",
                    "side_effects",
                )
                if field in technical_row
            }
            row = {
                "object_key": key,
                "layer": record["layer"],
                "object_id": record["object_id"],
                "object_name": record["object_name"],
                "object_type": record["object_type"],
                "paused": record["paused"],
                "source_json_path": record["source_json_path"],
                "configuration_hash": record["config_hash"],
                "source_leaf_facts": source_facts_by_key.get(key)
                or source_leaf_facts(obj, record["source_json_path"]),
                "source_absence_facts": absence_facts_by_key.get(key)
                or semantic_absence_facts(
                    record["layer"], obj, record["source_json_path"]
                ),
                "execution_dependency_traces": execution_dependencies,
                "execution_dependency_facts": dependency_facts,
                "consumer_dependency_facts": consumer_dependency_facts,
                "consumer_dependency_contexts": consumer_dependency_contexts,
                "destination_peer_contexts": destination_peer_contexts.get(key, []),
                "destination_peer_facts": destination_peer_facts.get(key, []),
                "referenced_variables": sorted(refs(obj)),
                "consumers": (
                    object_consumers(record["layer"], obj, consumers)
                    if layer in records
                    else []
                ),
                "firing_trigger_ids": sorted(
                    str(value) for value in as_list(obj.get("firingTriggerId"))
                ),
                "blocking_trigger_ids": sorted(
                    str(value) for value in as_list(obj.get("blockingTriggerId"))
                ),
                "trigger_group_member_ids": sorted(trigger_group_members(obj)),
                "setup_tags": as_list(obj.get("setupTag")),
                "teardown_tags": as_list(obj.get("teardownTag")),
                "trigger_conditions": trigger_conditions(obj),
                "business_scope_tokens": sorted(business_scope_tokens(record)),
                "specificity_tokens": as_list(record.get("specificity_tokens")),
                "vendor_event_contract": contract,
                "reference_trace_requirements": traces,
                "consent_facts": consent_values_for_object,
                "effective_consent_route": consent,
                "custom_code_facts": formula_facts,
            }
            row["behavior_signatures"] = behavior_signatures(
                record,
                traces,
                technical_row,
                consent,
                execution_dependencies,
            )
            object_rows.append(row)

    payload = {
        **source_descriptor(export_path),
        "kind": "gtm_shared_deterministic_facts",
        "schema_version": 1,
        "context_sha256": context["context_sha256"],
        "audit_context": context.get("context", {}),
        "inferred_context": context.get("inferred_context", {}),
        "provided_context": context.get("provided_context", {}),
        "provided_context_fields": context.get("provided_fields", []),
        "unresolved_context_questions": context.get("unresolved_questions", []),
        "fact_contract": (
            "Immutable source-derived facts shared across verdict engines; no cleanup verdicts."
        ),
        "counts": {
            "objects": len(object_rows),
            "source_leaves": sum(len(row["source_leaf_facts"]) for row in object_rows),
            "unresolved_edges": navigation["counts"]["unresolved_edges"],
            "source_integrity_findings": len(
                as_list(navigation.get("source_integrity_findings"))
            ),
            "custom_code_objects": navigation["counts"]["custom_code_objects"],
        },
        "integrity_findings": {
            "source": as_list(navigation.get("source_integrity_findings")),
            "unresolved_edges": navigation["unresolved_edges"],
        },
        "coverage_gate": navigation.get("coverage_gate", "blocked_source_integrity"),
        "objects": sorted(object_rows, key=lambda row: row["object_key"]),
    }
    payload["shared_facts_sha256"] = shared_content_hash(payload)
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("export", type=Path)
    parser.add_argument("--context", type=Path)
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()
    context = (
        json.loads(args.context.read_text(encoding="utf-8")) if args.context else None
    )
    result = build_shared_facts(args.export, context=context)
    print(json.dumps(result, ensure_ascii=False, indent=2 if args.pretty else None))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
