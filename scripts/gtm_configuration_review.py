#!/usr/bin/env python3
"""Scaffold and validate source-bound GTM configuration-correctness reviews."""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from gtm_configuration_facts import (
    build_consumers,
    code_line_facts,
    layer_objects,
    logic_anchors,
    object_consumers,
    object_hash,
    object_key,
    object_type,
    parameter_static_values,
    reference_trace_requirements,
    specific_tokens,
    validate_reference_traces,
)
from gtm_consent_model import server_route_hosts
from gtm_custom_code_extract import extract_export
from gtm_lib import (
    ID_KEYS,
    behavior_projection,
    container_root_path,
    container_version,
    refs,
    source_descriptor,
    source_integrity_findings,
    stable_hash,
    walk_json_fields,
)
from gtm_relationships import trigger_conditions
from gtm_review_common import (
    VALID_CONFIDENCE,
    VALID_PRIORITIES,
    VALID_READINESS,
    canonical_review_facts,
    object_consumer_map,
    object_keys,
    object_source_path_map,
    pending_completion_attestation,
    precise_question,
    review_input_contract,
    specific_text,
    validate_challenge,
    validate_review_provenance,
    validate_structured_actions,
)
from gtm_shared_facts import build_shared_facts
from gtm_taxonomy import taxonomy_errors
from gtm_vendor_registry import (
    behavior_bearing_vendor_text,
    vendor_record,
    vendor_records,
)

VALID_VERDICTS = {
    "Correct",
    "Issue",
    "Owner decision needed",
    "Container evidence limit",
    "Not applicable",
}
VENDOR_CONTRACT_LAYERS = {
    "tag",
    "variable",
    "zone",
    "customTemplate",
    "client",
    "gtagConfig",
    "transformation",
}
VALID_DISPOSITIONS = {
    "keep",
    "cleanup_operation",
    "owner_decision_needed",
    "container_evidence_limit",
    "not_applicable",
}
VALID_CONTRACT_VERDICTS = {"Compliant", "Non-compliant", "Not applicable", "Unproven"}
VALID_BRANCH_VERDICTS = {"Correct", "Issue", "Unclear", "Metadata", "Not applicable"}
VALID_EXTERNAL_EVIDENCE_STATUSES = {"none", "runtime_handoff_required"}
GA4_ECOMMERCE_EVENTS = {
    "add_payment_info",
    "add_shipping_info",
    "add_to_cart",
    "add_to_wishlist",
    "begin_checkout",
    "generate_lead",
    "purchase",
    "refund",
    "remove_from_cart",
    "select_item",
    "select_promotion",
    "view_cart",
    "view_item",
    "view_item_list",
    "view_promotion",
}
CONTRACT_RULE_TERMS = {
    "vendor_identity_and_official_setup": ["vendor", "official", "setup"],
    "event_name": ["event", "name"],
    "action_or_event_name": ["action", "event", "name"],
    "destination_or_server_routing": ["destination", "server", "routing"],
    "destination_or_account_id": ["destination", "account", "id"],
    "event_parameter_names_and_types": ["parameter", "name", "type"],
    "payload_names_shapes_and_types": ["payload", "shape", "type"],
    "consent_and_timing": ["consent", "timing"],
    "deduplication_or_event_id": ["deduplication", "event", "id"],
    "ecommerce_event_contract": ["ecommerce", "event", "items"],
    "item_scope_names_and_types": ["item", "name", "type"],
    "transaction_value_currency_and_quantity": [
        "transaction",
        "value",
        "currency",
        "quantity",
    ],
    "purchase_transaction_id_uniqueness": [
        "purchase",
        "transaction_id",
        "unique",
    ],
    "refund_transaction_id_linkage": [
        "refund",
        "transaction_id",
        "purchase",
    ],
    "consumer_value_shape_and_type": ["consumer", "value", "shape", "type"],
    "availability_at_consumer_event": ["availability", "consumer", "event"],
    "consent_state_semantics": ["consent", "state", "semantics"],
    "url_passthrough_and_ads_data_redaction": [
        "url_passthrough",
        "ads_data_redaction",
        "consent",
    ],
    "conversion_linking_coverage": [
        "conversion",
        "linker",
        "google",
        "tag",
        "coverage",
    ],
    "first_party_server_domain_review": [
        "server",
        "first",
        "party",
        "domain",
    ],
}
GENERATED_FIELDS = {
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
    "official_doc_candidates",
    "required_contract_topics",
    "technical_code_facts",
    "required_technical_findings",
    "shared_behavior_signatures",
    "field_evidence_requirements",
    "field_evidence_paths",
    "effective_consent_route_facts",
    "execution_dependency_traces",
    "execution_dependency_facts",
    "consumer_dependency_facts",
    "consumer_dependency_contexts",
    "destination_peer_contexts",
    "destination_peer_facts",
    "source_absence_facts",
    "required_logic_cross_checks",
    "required_configuration_obligations",
}
SEMANTIC_TEXT_FIELDS = (
    "purpose",
    "execution_logic",
    "inputs_and_terminal_sources",
    "configured_output_or_side_effect",
    "consumer_contract",
    "consent_and_sequence",
    "correctness_basis",
)
VALID_LOGIC_CHECK_VERDICTS = {"Aligned", "Issue", "Unclear"}
VALID_TECHNICAL_FINDING_VERDICTS = {
    "Confirmed issue",
    "Cleanup opportunity",
    "No defect after review",
    "False positive",
    "Documented exception",
    "Owner decision needed",
}
DETERMINISTIC_TECHNICAL_SIGNAL_MARKERS = (
    "without an exported <script> wrapper",
    "callback-based cmp read",
    "without an exported remove, once-only",
    "contains a debugger statement",
    "calls datalayer.reset()",
    "internal google_tag_manager object",
    "runs text as javascript",
    "without an exported origin check",
    "unencrypted http://",
    "literal cookie write omits",
    "literal secret-like credential candidate",
)
TECHNICAL_EVIDENCE_BOUNDARY_MARKERS = (
    "no code body was exported",
    "no reviewable executable behavior",
    "literal api-key candidate",
)
PURPOSE_VERBS = {
    "tag": ("send", "load", "set", "route", "record", "fire", "inject", "configure"),
    "trigger": ("match", "listen", "block", "allow", "fire", "activate"),
    "variable": ("read", "return", "calculate", "map", "format", "extract", "look up"),
    "zone": ("restrict", "scope", "allow", "evaluate", "govern"),
    "customTemplate": ("define", "execute", "load", "send", "expose", "permit"),
    "client": ("claim", "parse", "route", "receive"),
    "gtagConfig": ("configure", "route", "set", "govern", "define"),
    "transformation": ("transform", "allow", "redact", "exclude", "rewrite"),
}

GTM_PLATFORM_CONTRACTS = {
    "zone": {
        "vendor": "Google Tag Manager",
        "category": "platform_configuration",
        "official_docs": [
            "https://developers.google.com/tag-platform/tag-manager/api/reference/rest/v2/"
            "accounts.containers.workspaces.zones"
        ],
        "topics": [
            "child_container_scope",
            "boundary_conditions_and_evaluation_triggers",
            "type_restrictions",
        ],
    },
    "gtagConfig": {
        "vendor": "GA4 / Google tag",
        "category": "analytics",
        "official_docs": [
            "https://developers.google.com/tag-platform/tag-manager/api/reference/rest/v2/"
            "accounts.containers.workspaces.gtag_config",
            "https://developers.google.com/tag-platform/gtagjs/reference",
            "https://developers.google.com/tag-platform/gtagjs/configure",
            "https://developers.google.com/tag-platform/security/guides/consent",
        ],
        "topics": [
            "google_tag_configuration_type",
            "destination_or_server_routing",
            "configuration_parameter_names_and_types",
            "consent_and_timing",
        ],
    },
}
BRANCH_EFFECT_TERMS = {
    "Input": ("read", "pass", "use", "source", "input"),
    "Condition": ("match", "compare", "when", "allow", "block"),
    "Transformation": ("transform", "map", "rewrite", "convert"),
    "Output": ("send", "return", "write", "output"),
    "Routing": ("fire", "block", "route", "trigger"),
    "Consent": ("consent", "grant", "deny", "storage", "permission"),
    "Execution control": ("before", "after", "once", "setup", "teardown", "execute"),
}
VENDOR_CODE_EVENT_PATTERNS = {
    "Meta": re.compile(
        r"\bfbq\s*\(\s*['\"](?:track|trackCustom)['\"]\s*,\s*['\"]([^'\"]+)",
        re.I,
    ),
    "TikTok": re.compile(r"\bttq\s*\.\s*track\s*\(\s*['\"]([^'\"]+)", re.I),
    "Snapchat": re.compile(
        r"\bsnaptr\s*\(\s*['\"]track['\"]\s*,\s*['\"]([^'\"]+)", re.I
    ),
    "Pinterest": re.compile(
        r"\bpintrk\s*\(\s*['\"]track['\"]\s*,\s*['\"]([^'\"]+)", re.I
    ),
}


def technical_finding_decision_class(category: str, statement: str) -> str:
    """Separate review prompts from facts that justify action or ownership.

    Pattern presence alone is not a defect. Only the deliberately narrow
    source-visible signals below can force a defect/exception/owner outcome.
    """

    lowered = str(statement or "").lower()
    if category == "parser" or any(
        marker in lowered for marker in TECHNICAL_EVIDENCE_BOUNDARY_MARKERS
    ):
        return "evidence_boundary"
    if any(marker in lowered for marker in DETERMINISTIC_TECHNICAL_SIGNAL_MARKERS):
        return "deterministic_defect"
    return "review_signal"
META_PAYLOAD_RE = re.compile(
    r"\bfbq\s*\(\s*['\"](?:track|trackCustom)['\"]\s*,\s*"
    r"['\"](?P<event>[^'\"]+)['\"]\s*,\s*\{(?P<body>[^{}]*)\}",
    re.I | re.S,
)
JS_OBJECT_FIELD_RE = re.compile(
    r"(?:^|,)\s*(?:['\"](?P<quoted>[A-Za-z_$][\w$]*)['\"]|"
    r"(?P<bare>[A-Za-z_$][\w$]*))\s*:\s*"
    r"(?P<value>['\"][^'\"]*['\"]|[-+]?\d+(?:\.\d+)?|"
    r"\{\{[^{}]+\}\}|[^,}\r\n]+)",
    re.S,
)
CONSENT_INITIALIZATION_TRIGGER_ID = "2147479593"
CONSENT_MANAGEMENT_BEHAVIOR_RE = re.compile(
    r"\b(?:setDefaultConsentState|updateConsentState|setConsentSettings)\b|"
    r"\bgtag\s*\(\s*['\"]consent['\"]",
    re.I,
)
STRONG_SECRET_FIELD_RE = re.compile(
    r"^(?:client[_-]?secret|api[_-]?secret|access[_-]?token|refresh[_-]?token|"
    r"authorization|password|private[_-]?key)$",
    re.I,
)
PUBLIC_KEY_CANDIDATE_FIELD_RE = re.compile(
    r"^(?:api[_-]?key|subscription[_-]?key)$",
    re.I,
)
STRONG_SECRET_NAME_RE = re.compile(
    r"\b(?:client|api)[ _-]?secret\b|\b(?:access|refresh)[ _-]?token\b|"
    r"\bprivate[ _-]?key\b|\bpassword\b",
    re.I,
)
PUBLIC_KEY_CANDIDATE_NAME_RE = re.compile(
    r"\b(?:api|subscription)[ _-]?key\b",
    re.I,
)
JWT_VALUE_RE = re.compile(
    r"^eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}$"
)
PRIVATE_KEY_VALUE_RE = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
    re.I,
)


def as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def compact_evidence_terms(values: list[Any], limit: int = 10) -> list[str]:
    terms = []
    for value in values:
        text = re.sub(r"\s+", " ", str(value or "")).strip().lower()
        if len(text) < 2 or text in terms:
            continue
        terms.append(text[:160])
    return terms[:limit]


def execution_dependency_terms(traces: list[dict[str, Any]]) -> list[str]:
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
    return compact_evidence_terms(values, 40)


def field_evidence_requirements(shared: dict[str, Any]) -> dict[str, list[str]]:
    contract = shared.get("vendor_event_contract") or {}
    traces = as_list(shared.get("reference_trace_requirements"))
    terminal_values = [
        terminal.get("configured_source")
        for trace in traces
        for terminal in as_list(trace.get("terminal_requirements"))
    ]
    code = shared.get("custom_code_facts") or {}
    expressions = [
        row.get("expression") for row in as_list(code.get("return_expressions"))
    ]
    consumers = as_list(shared.get("consumers"))
    consumer_contexts = as_list(shared.get("consumer_dependency_contexts"))
    destination_peers = as_list(shared.get("destination_peer_contexts"))
    consent = as_list(shared.get("consent_facts"))
    consent_route = shared.get("effective_consent_route") or {}
    dependency_terms = execution_dependency_terms(
        as_list(shared.get("execution_dependency_traces"))
    )
    decisive_paths = (
        "schedulestartms",
        "scheduleendms",
        "tagfiringoption",
        "setuptag",
        "teardowntag",
        "boundary",
        "childcontainer",
        "typerestriction",
        "consentsettings",
    )
    decisive_values = [
        fact.get("value_preview")
        for fact in [
            *as_list(shared.get("source_leaf_facts")),
            *as_list(shared.get("source_absence_facts")),
            *as_list(shared.get("execution_dependency_facts")),
        ]
        if any(token in str(fact.get("json_path") or "").lower() for token in decisive_paths)
    ]
    dependency_values = [
        fact.get("value_preview")
        for fact in as_list(shared.get("execution_dependency_facts"))
    ]
    audit_context = shared.get("audit_context") or {}
    requirements = {
        "purpose": compact_evidence_terms(
            [
                shared.get("object_name"),
                shared.get("object_type"),
                *as_list(contract.get("events")),
            ]
        ),
        "execution_logic": compact_evidence_terms(
            [
                *as_list(shared.get("firing_trigger_ids")),
                *as_list(shared.get("blocking_trigger_ids")),
                *dependency_terms,
                *decisive_values,
                *dependency_values,
                *[
                    part
                    for condition in as_list(shared.get("trigger_conditions"))
                    for part in str(condition).split("|")
                    if part
                ],
            ]
        ),
        "inputs_and_terminal_sources": compact_evidence_terms(
            [*as_list(shared.get("referenced_variables")), *terminal_values]
        ),
        "configured_output_or_side_effect": compact_evidence_terms(
            [
                *as_list(contract.get("events")),
                *as_list(contract.get("destinations")),
                *expressions,
                code.get("returned_value_type"),
                *as_list(code.get("side_effects")),
            ]
        ),
        "consumer_contract": compact_evidence_terms(
            [
                value
                for consumer in consumers
                for value in (consumer.get("consumer_key"), consumer.get("consumer_name"))
            ]
            + [
                value
                for context in consumer_contexts
                for value in (
                    context.get("consumer_key"),
                    context.get("consumer_name"),
                    *as_list(context.get("events")),
                    *as_list(context.get("destinations")),
                )
            ]
            + [
                value
                for peer in destination_peers
                for value in (
                    peer.get("object_key"),
                    peer.get("object_name"),
                    *as_list(peer.get("shared_destinations")),
                    *as_list(peer.get("events")),
                )
            ]
        ),
        "consent_and_sequence": compact_evidence_terms(
            [
                *as_list(shared.get("blocking_trigger_ids")),
                *[item.get("value_preview") for item in consent],
                consent_route.get("consent_status"),
                consent_route.get("effective_control_status"),
                *as_list(consent_route.get("consent_variable_references")),
                *as_list(consent_route.get("server_consent_forwarding_variables")),
                *as_list(consent_route.get("detected_consent_payload_purposes")),
                *as_list(consent_route.get("forwarded_consent_purposes")),
                *as_list(consent_route.get("server_routing_hosts")),
                *dependency_terms,
            ]
        ),
    }
    identity_terms = compact_evidence_terms(
        [
            shared.get("object_name"),
            shared.get("object_key"),
            shared.get("object_type"),
            shared.get("layer"),
        ]
    )
    if len(requirements["purpose"]) < 2:
        requirements["purpose"] = compact_evidence_terms(
            [*requirements["purpose"], *identity_terms]
        )
    if not requirements["execution_logic"]:
        requirements["execution_logic"] = [
            "not directly event-triggered",
            str(shared.get("object_type") or "configured object"),
        ]
    if not requirements["inputs_and_terminal_sources"]:
        requirements["inputs_and_terminal_sources"] = [
            "no referenced gtm variable",
            str(shared.get("object_type") or "configured source"),
        ]
    if not requirements["configured_output_or_side_effect"]:
        requirements["configured_output_or_side_effect"] = [
            str(shared.get("object_type") or "configured output"),
            str(shared.get("object_name") or "source object"),
        ]
    if not requirements["consumer_contract"]:
        requirements["consumer_contract"] = [
            "no export consumer",
            str(shared.get("object_name") or "source object"),
        ]
    if not requirements["consent_and_sequence"]:
        requirements["consent_and_sequence"] = [
            "no explicit consent control",
            str(shared.get("object_type") or "configured object"),
        ]
    cmp_values = as_list(audit_context.get("cmp"))
    if cmp_values and shared.get("layer") == "tag":
        requirements["consent_and_sequence"] = compact_evidence_terms(
            [*requirements["consent_and_sequence"], *cmp_values]
        )
    requirements["correctness_basis"] = compact_evidence_terms(
        [
            shared.get("object_name"),
            shared.get("object_type"),
            *as_list(contract.get("events")),
            *as_list(contract.get("destinations")),
        ]
    )
    if len(requirements["correctness_basis"]) < 2:
        requirements["correctness_basis"] = compact_evidence_terms(
            [*requirements["correctness_basis"], *identity_terms]
        )
    return requirements


def logic_cross_check_requirements(
    shared: dict[str, Any],
    requirements: dict[str, list[str]],
    paths: dict[str, list[str]],
    has_code: bool,
    has_vendor_contract: bool,
) -> list[dict[str, Any]]:
    definitions = [
        (
            "purpose_output_alignment",
            "Does the configured output or side effect implement the object's stated purpose?",
            ("purpose", "configured_output_or_side_effect"),
        ),
        (
            "execution_scope_alignment",
            "Do firing, blocking, conditions, and sequencing execute only in the intended scope?",
            ("purpose", "execution_logic", "consent_and_sequence"),
        ),
        (
            "input_output_consumer_alignment",
            "Do recursive terminal inputs produce the type and shape consumed downstream?",
            (
                "inputs_and_terminal_sources",
                "configured_output_or_side_effect",
                "consumer_contract",
            ),
        ),
        (
            "consent_sequence_alignment",
            "Is the effective consent and setup or teardown sequence coherent with this object?",
            ("consent_and_sequence", "execution_logic"),
        ),
    ]
    if has_code:
        definitions.append(
            (
                "custom_code_behavior_alignment",
                "Does every custom-code behavior block implement the configured return or side effect safely?",
                ("inputs_and_terminal_sources", "configured_output_or_side_effect"),
            )
        )
    if has_vendor_contract:
        definitions.append(
            (
                "vendor_contract_alignment",
                "Do the exported names, values, types, route, and consent match the official vendor contract?",
                (
                    "configured_output_or_side_effect",
                    "inputs_and_terminal_sources",
                    "consent_and_sequence",
                ),
            )
        )
    rows = []
    for check_key, question, fields in definitions:
        allowed_anchors = list(
            dict.fromkeys(path for field in fields for path in paths.get(field, []))
        )
        if check_key == "vendor_contract_alignment":
            own_facts = [
                *as_list(shared.get("source_leaf_facts")),
                *as_list(shared.get("source_absence_facts")),
            ]
            allowed_anchors = list(
                dict.fromkeys([*allowed_anchors, *logic_anchors(own_facts)])
            )
        rows.append(
            {
                "check_key": check_key,
                "question": question,
                "required_terms": compact_evidence_terms(
                    [value for field in fields for value in requirements.get(field, [])],
                    20,
                ),
                "allowed_evidence_anchors": allowed_anchors[:160],
                "object_key": str(shared.get("object_key") or ""),
            }
        )
    return rows


def field_evidence_paths(shared: dict[str, Any]) -> dict[str, list[str]]:
    own_facts = [
        *as_list(shared.get("source_leaf_facts")),
        *as_list(shared.get("source_absence_facts")),
    ]
    execution_facts = as_list(shared.get("execution_dependency_facts"))
    consumer_facts = as_list(shared.get("consumer_dependency_facts"))
    destination_facts = as_list(shared.get("destination_peer_facts"))
    facts = [*own_facts, *execution_facts, *consumer_facts, *destination_facts]
    all_paths = [str(fact.get("json_path") or "") for fact in facts]

    def matching(*tokens: str, references: bool = False) -> list[str]:
        result = []
        for fact in facts:
            path = str(fact.get("json_path") or "")
            lowered = path.lower()
            if any(token in lowered for token in tokens) or (
                references and as_list(fact.get("referenced_variables"))
            ):
                result.append(path)
        return result

    identity = matching(".name", ".type")
    logic = [
        path
        for path in all_paths
        if not path.lower().endswith(
            (
                ".accountid",
                ".containerid",
                ".workspaceid",
                ".fingerprint",
                ".path",
                ".tagmanagerurl",
                ".notes",
                ".parentfolderid",
                ".tagid",
                ".triggerid",
                ".variableid",
                ".templateid",
                ".clientid",
                ".zoneid",
                ".gtagconfigid",
                ".transformationid",
                ".name",
            )
        )
    ]
    mapping = {
        "purpose": matching(
            ".name",
            ".type",
            "eventname",
            "action",
            "destination",
            "measurementid",
            "pixel",
        ),
        "execution_logic": matching(
            "firingtriggerid",
            "blockingtriggerid",
            "triggerids",
            "filter",
            "condition",
            "setuptag",
            "teardowntag",
            "tagfiringoption",
        ),
        "inputs_and_terminal_sources": matching(
            "parameter", "javascript", "templatedata", references=True
        ),
        "configured_output_or_side_effect": matching(
            "eventname",
            "destination",
            "measurementid",
            "pixel",
            "html",
            "javascript",
            "templatedata",
            "currency",
            "value",
        ),
        "consumer_contract": list(
            dict.fromkeys(
                [
                    str(fact.get("json_path") or "")
                    for fact in [*own_facts, *consumer_facts, *destination_facts]
                ]
            )
        ),
        "consent_and_sequence": matching(
            "consent",
            "storage",
            "blockingtriggerid",
            "setuptag",
            "teardowntag",
        ),
        "correctness_basis": logic,
    }
    fallback = identity or logic or all_paths
    for field, paths in mapping.items():
        unique = list(dict.fromkeys(paths or fallback))
        mapping[field] = unique[:80]
    return mapping


def vendor_contexts_for_objects(
    cv: dict[str, Any], consumers: dict[str, list[dict[str, str]]]
) -> dict[str, list[dict[str, Any]]]:
    objects = {object_key(layer, obj): obj for layer, _, obj in layer_objects(cv)}
    direct_consumers = {
        key: {
            str(item.get("consumer_key") or "")
            for item in object_consumers(key.split(":", 1)[0], obj, consumers)
            if item.get("relation") in {"variable_reference", "custom_template"}
        }
        for key, obj in objects.items()
    }
    own_vendors: dict[str, list[dict[str, Any]]] = {}
    for key, obj in objects.items():
        layer = key.split(":", 1)[0]
        serialized = behavior_bearing_vendor_text(obj, layer)
        vendors = vendor_records(serialized)
        transport_hosts = (
            set(server_route_hosts(obj)) if vendors or layer == "gtagConfig" else set()
        )
        hosts = sorted(
            {
                urlparse(match).netloc.lower()
                for match in re.findall(r"https?://[^\s\"'<>\\)]+", serialized, re.I)
                if urlparse(match).netloc
            }
        )
        unmatched_hosts = [
            host
            for host in hosts
            if host not in transport_hosts and not vendor_records(host)
        ]
        vendors.extend(
            {
                "name": f"Unclassified external integration ({host})",
                "category": "unknown_vendor",
                "official_docs": [],
                "detection_evidence": [host],
            }
            for host in unmatched_hosts
        )
        if not vendors and layer == "customTemplate":
            cue = str(obj.get("name") or obj.get("type") or key)
            vendors.append(
                {
                    "name": f"Unclassified external integration ({cue})",
                    "category": "unknown_vendor",
                    "official_docs": [],
                    "detection_evidence": [cue],
                }
            )
        own_vendors[key] = vendors
    research_owners: dict[str, str] = {}
    for object_key_value in sorted(own_vendors):
        if object_key_value.split(":", 1)[0] not in VENDOR_CONTRACT_LAYERS:
            continue
        for vendor in own_vendors[object_key_value]:
            if str(vendor.get("category") or "") != "unknown_vendor":
                continue
            name = str(vendor.get("name") or "Unclassified")
            research_owners.setdefault(name, object_key_value)
    result: dict[str, list[dict[str, Any]]] = {}
    for source_key in objects:
        queue = [source_key]
        seen: set[str] = set()
        contexts: dict[str, dict[str, Any]] = {}
        while queue:
            current = queue.pop(0)
            if current in seen:
                continue
            seen.add(current)
            for vendor in own_vendors.get(current, []):
                name = str(vendor.get("name") or "Unclassified")
                category = str(vendor.get("category") or "unclassified")
                if current != source_key and category == "unknown_vendor":
                    # Research the integration once where its host/template cue is
                    # configured. Downstream variables still retain their consumer
                    # and destination-peer contract facts without cloning the same
                    # vendor-identification task into every dependency.
                    continue
                research_key = (
                    f"vendor-research:{name}" if category == "unknown_vendor" else ""
                )
                research_owner = research_owners.get(name, "")
                contexts[name] = {
                    "vendor": name,
                    "category": category,
                    "official_docs": list(vendor.get("official_docs") or []),
                    "research_required": (
                        not bool(vendor.get("official_docs"))
                        and (not research_owner or source_key == research_owner)
                    ),
                    "research_dependency_key": research_key,
                    "research_owner_object_key": research_owner,
                    "detection_evidence": list(vendor.get("detection_evidence") or []),
                    "unsupported_standard_events": list(
                        vendor.get("unsupported_standard_events") or []
                    ),
                    "event_replacements": list(vendor.get("event_replacements") or []),
                    "contract_version": str(vendor.get("contract_version") or ""),
                    "contracts": [
                        dict(contract)
                        for contract in as_list(vendor.get("contracts"))
                        if isinstance(contract, dict)
                    ],
                    "context_object_keys": sorted(
                        key
                        for key in seen
                        if any(
                            str(item.get("name") or "") == name
                            for item in own_vendors.get(key, [])
                        )
                    ),
                }
            queue.extend(sorted(direct_consumers.get(current, set()) - seen))
        result[source_key] = [contexts[name] for name in sorted(contexts)]
    return result


def configured_parameter_terms(obj: dict[str, Any]) -> set[str]:
    terms: set[str] = set()

    def visit(value: Any) -> None:
        if isinstance(value, dict):
            key = str(value.get("key") or "").strip().lower()
            if key and any(field in value for field in ("value", "list", "map")):
                terms.add(key)
            for child in value.values():
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)

    visit(obj.get("parameter", []))
    return terms


def configured_field_values(obj: dict[str, Any], field: str) -> list[str]:
    """Return source-visible scalar values for a configured parameter key."""
    values: list[str] = []
    target = field.strip().lower()

    def visit(value: Any) -> None:
        if isinstance(value, dict):
            key = str(value.get("key") or "").strip().lower()
            raw = value.get("value")
            if key == target and raw is not None and not isinstance(raw, (dict, list)):
                values.append(str(raw))
            for child in value.values():
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)

    visit(obj.get("parameter", []))
    return list(dict.fromkeys(values))


def custom_code_text(obj: dict[str, Any]) -> str:
    return " ".join(
        str(parameter.get("value") or "")
        for parameter in as_list(obj.get("parameter"))
        if isinstance(parameter, dict)
        and str(parameter.get("key") or "") in {"html", "javascript"}
    )


def meta_payload_fields(
    obj: dict[str, Any],
    event: str,
) -> dict[str, list[str]]:
    """Extract only top-level source-visible fields from a Meta event payload."""
    fields: dict[str, list[str]] = {}
    for call in META_PAYLOAD_RE.finditer(custom_code_text(obj)):
        if str(call.group("event") or "").casefold() != event.casefold():
            continue
        for match in JS_OBJECT_FIELD_RE.finditer(call.group("body")):
            key = str(match.group("quoted") or match.group("bare") or "").lower()
            raw_value = str(match.group("value") or "").strip()
            quoted = (
                len(raw_value) >= 2
                and raw_value[:1] == raw_value[-1:]
                and raw_value[0] in {
                "'",
                '"',
                }
            )
            if quoted:
                raw_value = raw_value[1:-1]
            elif not re.fullmatch(r"[-+]?\d+(?:\.\d+)?|\{\{[^{}]+\}\}", raw_value):
                raw_value = "__dynamic__:" + raw_value
            fields.setdefault(key, []).append(raw_value)
    return {key: list(dict.fromkeys(values)) for key, values in fields.items()}


def registry_contract_topics(
    obj: dict[str, Any],
    context: dict[str, Any],
    configured_events: list[str],
    configured_terms: set[str],
) -> list[dict[str, Any]]:
    """Turn versioned official registry rules into locked Run-2 topics."""
    vendor = str(context.get("vendor") or "")
    configured_event_set = {value.casefold() for value in configured_events}
    serialized = json.dumps(behavior_projection(obj), ensure_ascii=False)
    topics: list[dict[str, Any]] = []
    for contract in as_list(context.get("contracts")):
        if not isinstance(contract, dict):
            continue
        contract_id = str(contract.get("id") or "").strip()
        event = str(contract.get("event") or "").strip()
        if event and event.casefold() not in configured_event_set:
            continue
        status = str(contract.get("status") or "supported").strip().lower()
        code_fields = meta_payload_fields(obj, event) if vendor == "Meta" and event else {}
        contract_terms = configured_terms | set(code_fields)
        required_fields = {
            str(value).strip().lower()
            for field in (
                "required_fields",
                "deduplication_fields",
                "required_consent_fields",
                "required_routing_fields",
            )
            for value in as_list(contract.get(field))
            if str(value).strip()
        }
        missing_fields = sorted(required_fields - contract_terms)
        violations: list[str] = []
        unproven: list[str] = []

        for rule in as_list(contract.get("field_rules")):
            if not isinstance(rule, dict):
                continue
            field = str(rule.get("field") or "").strip()
            if not field:
                continue
            values = configured_field_values(obj, field)
            if not values and vendor == "Meta":
                values = code_fields.get(field.lower(), [])
            if not values:
                continue
            for value in values:
                if refs(value) or value.startswith("__dynamic__:"):
                    unproven.append(f"{field} has a dynamic exported value")
                    continue
                expected_type = str(rule.get("value_type") or "").lower()
                if expected_type == "number":
                    try:
                        float(value)
                    except ValueError:
                        violations.append(f"{field} is not a number")
                elif expected_type == "boolean" and value.lower() not in {
                    "true",
                    "false",
                }:
                    violations.append(f"{field} is not a boolean")
                exact_length = rule.get("exact_length")
                if isinstance(exact_length, int) and len(value) != exact_length:
                    violations.append(
                        f"{field} length is {len(value)}, expected {exact_length}"
                    )
                pattern = str(rule.get("pattern") or "")
                if pattern and not re.fullmatch(pattern, value):
                    violations.append(f"{field} does not match registry pattern")

        deprecated_hits = sorted(
            {
                endpoint
                for endpoint in as_list(contract.get("deprecated_endpoints"))
                if str(endpoint) and str(endpoint).lower() in serialized.lower()
            }
        )
        if deprecated_hits:
            violations.append(
                "deprecated endpoint(s) configured: "
                + ", ".join(str(value) for value in deprecated_hits)
            )

        replacement = str(contract.get("replacement") or "").strip()
        if status in {"deprecated", "unsupported"}:
            violations.append(
                f"event {event!r} is {status}"
                + (f"; registry replacement is {replacement!r}" if replacement else "")
            )

        deterministic_state = (
            "known_noncompliant"
            if missing_fields or violations
            else "unproven_from_container"
            if unproven
            else "source_check_required"
        )
        rule_terms = [
            vendor,
            f"registry_contract_{contract_id}",
            event or contract_id,
            status,
            *sorted(required_fields),
            *[
                str(rule.get("field") or "")
                for rule in as_list(contract.get("field_rules"))
                if isinstance(rule, dict)
            ],
        ]
        topics.append(
            {
                "topic_key": f"{vendor}:registry_contract:{contract_id}",
                "vendor": vendor,
                "category": str(context.get("category") or "unclassified"),
                "topic": f"registry_contract_{contract_id}",
                "required_rule_terms": [
                    term.lower()
                    for term in dict.fromkeys(rule_terms)
                    if str(term).strip()
                ],
                "official_doc_candidates": list(context.get("official_docs") or []),
                "research_required": False,
                "research_dependency_key": "",
                "research_owner_object_key": "",
                "detection_evidence": list(context.get("detection_evidence") or []),
                "required_configuration_terms": sorted(required_fields),
                "configuration_presence_state": (
                    "missing" if missing_fields else "present"
                ),
                "applicability_state": "applicable",
                "configured_event_values": configured_events,
                "unsupported_event_values": (
                    [event] if status in {"deprecated", "unsupported"} else []
                ),
                "event_replacements": (
                    [f"{event}=>{replacement}"] if event and replacement else []
                ),
                "deterministic_contract_state": deterministic_state,
                "contract_version": str(context.get("contract_version") or ""),
                "registry_contract": dict(contract),
                "contract_violations": violations,
                "contract_unproven_reasons": unproven,
            }
        )
    return topics


def vendor_event_values(
    cv: dict[str, Any], obj: dict[str, Any], vendor: str
) -> list[str]:
    pattern = VENDOR_CODE_EVENT_PATTERNS.get(vendor)
    if pattern:
        code = " ".join(
            str(value)
            for key in ("html", "javascript")
            for value in [
                next(
                    (
                        parameter.get("value")
                        for parameter in as_list(obj.get("parameter"))
                        if parameter.get("key") == key
                    ),
                    "",
                )
            ]
            if value
        )
        return sorted({match.group(1) for match in pattern.finditer(code)})
    return sorted(
        {
            value
            for value in parameter_static_values(cv, obj, "eventName")
            if value.strip()
        }
    )


def google_linking_coverage(cv: dict[str, Any]) -> dict[str, Any]:
    """Describe source-visible linking coverage without requiring a legacy linker."""
    conversion_linkers = []
    all_pages_google_tags = []
    for tag in as_list(cv.get("tag")):
        if bool(tag.get("paused")):
            continue
        trigger_ids = {str(value) for value in as_list(tag.get("firingTriggerId"))}
        if "2147479553" not in trigger_ids:
            continue
        tag_type = str(tag.get("type") or "").lower()
        key = f"tag:{tag.get('tagId') or tag.get('name') or ''}"
        if tag_type == "gclidw":
            conversion_linkers.append(key)
        vendor = str(
            vendor_record(behavior_bearing_vendor_text(tag, "tag")).get("name") or ""
        )
        if vendor == "GA4 / Google tag" and tag_type in {
            "googtag",
            "gaawc",
            "ua",
        }:
            all_pages_google_tags.append(key)
    return {
        "conversion_linker_all_pages_keys": sorted(conversion_linkers),
        "google_tag_all_pages_keys": sorted(all_pages_google_tags),
        "source_visible_coverage": (
            "conversion_linker_all_pages"
            if conversion_linkers
            else "google_tag_all_pages"
            if all_pages_google_tags
            else "no_source_visible_all_pages_linker_or_google_tag"
        ),
    }


def supplemental_contract_topic(
    context: dict[str, Any],
    vendor: str,
    topic: str,
    configured_events: list[str],
    *,
    presence_state: str,
    deterministic_state: str = "source_check_required",
    required_terms: list[str] | None = None,
    detection_evidence: list[str] | None = None,
    official_docs: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "topic_key": f"{vendor}:{topic}",
        "vendor": vendor,
        "category": str(context.get("category") or "unclassified"),
        "topic": topic,
        "required_rule_terms": CONTRACT_RULE_TERMS.get(topic, []),
        "official_doc_candidates": list(
            dict.fromkeys(
                [
                    *as_list(context.get("official_docs")),
                    *(official_docs or []),
                ]
            )
        ),
        "research_required": False,
        "research_dependency_key": "",
        "research_owner_object_key": "",
        "detection_evidence": [
            *as_list(context.get("detection_evidence")),
            *(detection_evidence or []),
        ],
        "required_configuration_terms": required_terms or [],
        "configuration_presence_state": presence_state,
        "applicability_state": "applicable",
        "configured_event_values": configured_events,
        "unsupported_event_values": [],
        "event_replacements": [],
        "deterministic_contract_state": deterministic_state,
    }


def required_contract_topics(
    cv: dict[str, Any],
    layer: str,
    obj: dict[str, Any],
    contexts: list[dict[str, Any]],
    effective_consent_route: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    if layer not in VENDOR_CONTRACT_LAYERS:
        return []
    event_names = {
        value.strip().lower()
        for value in parameter_static_values(cv, obj, "eventName")
        if value.strip()
    }
    obligations: list[dict[str, Any]] = []
    configured_terms = configured_parameter_terms(obj)
    effective_consent_route = effective_consent_route or {}
    platform_contract = GTM_PLATFORM_CONTRACTS.get(layer)
    if platform_contract:
        contexts = [
            {
                "vendor": platform_contract["vendor"],
                "category": platform_contract["category"],
                "official_docs": platform_contract["official_docs"],
                "research_required": False,
                "detection_evidence": [f"official GTM {layer} entity layer"],
                "platform_topics": platform_contract["topics"],
            }
        ]
    for context in contexts:
        vendor = str(context.get("vendor") or "")
        category = str(context.get("category") or "unclassified")
        configured_events = vendor_event_values(cv, obj, vendor)
        obligations.extend(
            registry_contract_topics(
                obj,
                context,
                configured_events,
                configured_terms,
            )
        )
        topics: list[str]
        if context.get("platform_topics"):
            topics = list(context["platform_topics"])
        elif layer == "customTemplate":
            topics = ["template_behavior_and_permissions", "vendor_contract_surface"]
        elif layer == "client":
            topics = ["request_claiming_and_routing", "payload_and_consent_handling"]
        elif layer == "transformation":
            topics = ["transformation_scope", "field_allowlist_or_redaction"]
        elif layer == "variable":
            topics = ["consumer_value_shape_and_type", "availability_at_consumer_event"]
            if re.search(r"consent|storage|ad_user_data|personalization", json.dumps(obj), re.I):
                topics.append("consent_state_semantics")
        elif category == "unknown_vendor":
            topics = [
                "vendor_identity_and_official_setup",
                "action_or_event_name",
                "destination_or_account_id",
                "payload_names_shapes_and_types",
                "consent_and_timing",
            ]
        elif category == "cmp":
            topics = ["consent_mapping", "default_and_update_timing", "downstream_gating"]
        elif vendor == "GA4 / Google tag":
            topics = [
                "event_name",
                "destination_or_server_routing",
                "event_parameter_names_and_types",
                "consent_and_timing",
            ]
            if event_names & GA4_ECOMMERCE_EVENTS:
                topics.extend(
                    [
                        "ecommerce_event_contract",
                        "item_scope_names_and_types",
                        "transaction_value_currency_and_quantity",
                    ]
                )
            if "purchase" in event_names:
                topics.append("purchase_transaction_id_uniqueness")
            if "refund" in event_names:
                topics.append("refund_transaction_id_linkage")
        elif category in {"media", "affiliate"}:
            topics = [
                "event_name",
                "destination_or_account_id",
                "payload_names_shapes_and_types",
                "consent_and_timing",
                "deduplication_or_event_id",
            ]
        else:
            topics = [
                "action_or_event_name",
                "destination_or_account_id",
                "payload_names_shapes_and_types",
                "consent_and_timing",
            ]
        for topic in topics:
            required_configuration_terms = {
                "purchase_transaction_id_uniqueness": ["transaction_id"],
                "refund_transaction_id_linkage": ["transaction_id"],
            }.get(topic, [])
            unsupported = {
                value.lower(): value
                for value in as_list(context.get("unsupported_standard_events"))
            }
            unsupported_events = [
                value for value in configured_events if value.lower() in unsupported
            ]
            presence_state = (
                "present"
                if required_configuration_terms
                and all(term.lower() in configured_terms for term in required_configuration_terms)
                else "missing"
                if required_configuration_terms
                else "not_applicable"
            )
            runtime_topics = {
                "event_parameter_names_and_types",
                "payload_names_shapes_and_types",
                "ecommerce_event_contract",
                "item_scope_names_and_types",
                "transaction_value_currency_and_quantity",
                "consumer_value_shape_and_type",
                "availability_at_consumer_event",
                "deduplication_or_event_id",
            }
            route_status = str(
                effective_consent_route.get("effective_control_status") or ""
            )
            if presence_state == "missing" or (
                unsupported_events and topic in {"event_name", "action_or_event_name"}
            ):
                deterministic_state = "known_noncompliant"
            elif context.get("research_dependency_key") and not context.get(
                "official_docs"
            ) or (
                topic in runtime_topics
                and (
                    refs(obj)
                    or layer == "variable"
                    and str(obj.get("type") or "").lower() not in {"c"}
                )
                or topic == "consent_and_timing"
                and route_status
                in {
                    "unproven_export_control",
                    "server_contract_unproven",
                    "blocker_control_candidate",
                    "consent_signal_review",
                    "unrecognized_consent_status",
                }
                or topic == "destination_or_server_routing"
                and route_status == "server_contract_unproven"
            ):
                deterministic_state = "unproven_from_container"
            else:
                deterministic_state = "source_check_required"
            obligations.append(
                {
                    "topic_key": f"{vendor}:{topic}",
                    "vendor": vendor,
                    "category": category,
                    "topic": topic,
                    "required_rule_terms": CONTRACT_RULE_TERMS.get(
                        topic,
                        [part for part in topic.split("_") if part not in {"and", "or"}],
                    ),
                    "official_doc_candidates": list(context.get("official_docs") or []),
                    "research_required": bool(context.get("research_required"))
                    and topic == "vendor_identity_and_official_setup",
                    "research_dependency_key": (
                        str(context.get("research_dependency_key") or "")
                    ),
                    "research_owner_object_key": str(
                        context.get("research_owner_object_key") or ""
                    ),
                    "detection_evidence": list(context.get("detection_evidence") or []),
                    "required_configuration_terms": required_configuration_terms,
                    "configuration_presence_state": presence_state,
                    "applicability_state": "applicable",
                    "configured_event_values": configured_events,
                    "unsupported_event_values": unsupported_events,
                    "event_replacements": list(context.get("event_replacements") or []),
                    "deterministic_contract_state": deterministic_state,
                }
            )
        consent_mode_terms = sorted(
            configured_terms & {"url_passthrough", "ads_data_redaction"}
        )
        if vendor in {"GA4 / Google tag", "Google Ads", "Floodlight"} and consent_mode_terms:
            obligations.append(
                supplemental_contract_topic(
                    context,
                    vendor,
                    "url_passthrough_and_ads_data_redaction",
                    configured_events,
                    presence_state="present",
                    required_terms=consent_mode_terms,
                    detection_evidence=[
                        "configured parameter(s): " + ", ".join(consent_mode_terms)
                    ],
                    official_docs=[
                        "https://developers.google.com/tag-platform/security/guides/"
                        "consent"
                    ],
                )
            )
        if vendor in {"Google Ads", "Floodlight"}:
            linking = google_linking_coverage(cv)
            obligations.append(
                supplemental_contract_topic(
                    context,
                    vendor,
                    "conversion_linking_coverage",
                    configured_events,
                    presence_state=str(linking["source_visible_coverage"]),
                    detection_evidence=[
                        "linking coverage: "
                        + str(linking["source_visible_coverage"]),
                        *as_list(linking["conversion_linker_all_pages_keys"]),
                        *as_list(linking["google_tag_all_pages_keys"]),
                    ],
                    official_docs=[
                        "https://support.google.com/tagmanager/answer/7549390?hl=en"
                    ],
                )
            )
        route_hosts = sorted(
            {
                *server_route_hosts(obj),
                *[
                    str(value)
                    for value in as_list(
                        effective_consent_route.get("server_routing_hosts")
                    )
                    if str(value)
                ],
            }
        )
        run_app_hosts = [host for host in route_hosts if host.endswith(".run.app")]
        if run_app_hosts:
            obligations.append(
                supplemental_contract_topic(
                    context,
                    vendor,
                    "first_party_server_domain_review",
                    configured_events,
                    presence_state="run_app_route_configured",
                    detection_evidence=[
                        "default Cloud Run route(s): " + ", ".join(run_app_hosts)
                    ],
                    official_docs=[
                        "https://developers.google.com/tag-platform/tag-manager/"
                        "server-side/custom-domain"
                    ],
                )
            )
    unique = {item["topic_key"]: item for item in obligations}
    return [unique[key] for key in sorted(unique)]


def required_configuration_obligations(
    layer: str,
    obj: dict[str, Any],
    shared: dict[str, Any],
    technical: dict[str, Any],
    source_facts: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    obligations: dict[str, dict[str, Any]] = {}
    available = {str(fact.get("json_path") or "") for fact in source_facts}
    own_prefix = str(shared.get("source_json_path") or "")
    facts_by_path = {
        str(fact.get("json_path") or ""): fact for fact in source_facts
    }
    metadata_suffixes = tuple(
        f".{field}"
        for field in (
            "accountId",
            "containerId",
            "workspaceId",
            "fingerprint",
            "path",
            "tagManagerUrl",
            "notes",
            "parentFolderId",
            "tagId",
            "triggerId",
            "variableId",
            "templateId",
            "clientId",
            "zoneId",
            "gtagConfigId",
            "transformationId",
            "name",
        )
    )

    def anchors_for(*tokens: str) -> list[str]:
        return [
            path
            for path in sorted(available)
            if path.startswith(own_prefix)
            and not path.endswith(metadata_suffixes)
            and any(
                token.lower()
                in f"{path} {facts_by_path[path].get('value_preview') or ''}".lower()
                for token in tokens
            )
        ]

    def add(
        key: str,
        outcome: str,
        statement: str,
        anchors: list[str],
        checks: tuple[str, ...],
        contract_topics: tuple[str, ...] = (),
    ) -> None:
        usable = sorted(set(anchors) & available)
        if not usable:
            return
        conclusion_terms = [
            token.lower()
            for token in re.findall(r"[A-Za-z0-9][A-Za-z0-9_.:-]{2,}", f"{key} {statement}")
            if token.lower()
            not in {
                "the",
                "and",
                "with",
                "from",
                "that",
                "this",
                "exported",
                "object",
                "configuration",
                "required",
                "field",
                "contains",
            }
        ]
        obligations[key] = {
            "obligation_key": key,
            "required_outcome": outcome,
            "statement": statement,
            "evidence_anchors": usable,
            "affected_logic_checks": list(checks),
            "affected_contract_topics": list(contract_topics),
            "required_conclusion_terms": list(dict.fromkeys(conclusion_terms))[:12],
        }

    for fact in as_list(shared.get("source_absence_facts")):
        path = str(fact.get("json_path") or "")
        field = path.rsplit(".", 1)[-1]
        add(
            f"missing_required_field:{field}",
            "Issue",
            f"Required {layer} field {field!r} is absent from the exported object.",
            [path],
            ("purpose_output_alignment", "vendor_contract_alignment"),
            (
                ("google_tag_configuration_type",)
                if layer == "gtagConfig" and field == "type"
                else ()
            ),
        )

    if layer == "tag" and str(obj.get("type") or "").lower() == "html":
        parameters = as_list(obj.get("parameter"))
        html_index = next(
            (
                index
                for index, parameter in enumerate(parameters)
                if isinstance(parameter, dict) and parameter.get("key") == "html"
            ),
            -1,
        )
        support_index = next(
            (
                index
                for index, parameter in enumerate(parameters)
                if isinstance(parameter, dict)
                and parameter.get("key") == "supportDocumentWrite"
            ),
            -1,
        )
        html = str(
            parameters[html_index].get("value") or ""
            if html_index >= 0
            else ""
        )
        support_enabled = bool(
            support_index >= 0
            and str(parameters[support_index].get("value") or "").lower() == "true"
        )
        document_write = bool(
            re.search(r"\bdocument\s*\.\s*write\s*\(", html, re.I)
        )
        html_anchors = anchors_for(
            f"parameter[{html_index}]" if html_index >= 0 else "html",
            "html",
        )
        support_anchors = anchors_for(
            f"parameter[{support_index}]"
            if support_index >= 0
            else "supportDocumentWrite",
            "supportDocumentWrite",
        )
        if document_write and not support_enabled:
            add(
                "document_write_support_missing",
                "Issue",
                (
                    "Custom HTML calls document.write() but does not export an enabled "
                    "Support document.write setting."
                ),
                [*html_anchors, *support_anchors],
                ("purpose_output_alignment", "custom_code_behavior_alignment"),
            )
            if "document_write_support_missing" in obligations:
                obligations["document_write_support_missing"][
                    "source_known_repair"
                ] = (
                    {
                        "mode": "change",
                        "object_key": str(shared.get("object_key") or ""),
                        "json_path": (
                            f"{own_prefix}.parameter[{support_index}].value"
                        ),
                        "before": str(
                            parameters[support_index].get("value") or ""
                        ),
                        "after": "true",
                    }
                    if support_index >= 0
                    else {
                        "mode": "append",
                        "object_key": str(shared.get("object_key") or ""),
                        "json_path": f"{own_prefix}.parameter",
                        "value": {
                            "type": "BOOLEAN",
                            "key": "supportDocumentWrite",
                            "value": "true",
                        },
                    }
                )
        elif support_enabled and not document_write:
            add(
                "unused_document_write_support",
                "Issue",
                (
                    "Custom HTML enables Support document.write although the exported "
                    "code contains no document.write() call."
                ),
                [*support_anchors, *html_anchors],
                ("purpose_output_alignment", "custom_code_behavior_alignment"),
            )
            if "unused_document_write_support" in obligations:
                obligations["unused_document_write_support"][
                    "source_known_repair"
                ] = {
                    "mode": "change",
                    "object_key": str(shared.get("object_key") or ""),
                    "json_path": (
                        f"{own_prefix}.parameter[{support_index}].value"
                    ),
                    "before": str(
                        parameters[support_index].get("value") or ""
                    ),
                    "after": "false",
                }

    if (
        layer == "tag"
        and CONSENT_INITIALIZATION_TRIGGER_ID
        in {str(value) for value in as_list(obj.get("firingTriggerId"))}
    ):
        behavior_text = behavior_bearing_vendor_text(obj, layer)
        vendor = vendor_record(behavior_text)
        manages_consent = (
            str(vendor.get("category") or "") == "cmp"
            or bool(CONSENT_MANAGEMENT_BEHAVIOR_RE.search(behavior_text))
        )
        if not manages_consent:
            add(
                "consent_initialization_non_consent_tag",
                "Issue",
                (
                    "Tag uses the Consent Initialization system trigger without "
                    "container-visible behavior that sets or updates consent state."
                ),
                anchors_for("firingTriggerId", CONSENT_INITIALIZATION_TRIGGER_ID),
                ("execution_scope_alignment", "consent_sequence_alignment"),
                ("consent_and_timing",),
            )

    def inspect_secret_fields(value: Any, path: str) -> None:
        if isinstance(value, dict):
            configured_name = str(value.get("key") or "").strip()
            configured_value = value.get("value")
            if (
                configured_name
                and configured_value is not None
                and not isinstance(configured_value, (dict, list))
                and str(configured_value).strip()
                and not refs(str(configured_value))
            ):
                literal_value = str(configured_value).strip()
                object_name = str(obj.get("name") or "")
                value_slot = configured_name.lower() in {
                    "value",
                    "defaultvalue",
                    "default_value",
                }
                strong_candidate = bool(
                    STRONG_SECRET_FIELD_RE.fullmatch(configured_name)
                    or value_slot and STRONG_SECRET_NAME_RE.search(object_name)
                    or JWT_VALUE_RE.fullmatch(literal_value)
                    or PRIVATE_KEY_VALUE_RE.search(literal_value)
                )
                public_candidate = bool(
                    PUBLIC_KEY_CANDIDATE_FIELD_RE.fullmatch(configured_name)
                    or value_slot
                    and PUBLIC_KEY_CANDIDATE_NAME_RE.search(object_name)
                )
                if strong_candidate:
                    add(
                        f"embedded_secret:{stable_hash({'path': path, 'class': configured_name.lower()})}",
                        "Issue",
                        (
                            "A literal secret-like credential is stored in a "
                            f"{configured_name!r} field; the value is redacted."
                        ),
                        [f"{path}.key", f"{path}.value"],
                        ("input_output_consumer_alignment", "vendor_contract_alignment"),
                    )
                elif public_candidate:
                    add(
                        f"embedded_public_key_candidate:{stable_hash({'path': path, 'class': configured_name.lower()})}",
                        "Unclear",
                        (
                            "A literal API-key candidate is stored in the container; "
                            "the value is redacted. Confirm that it is intentionally "
                            "browser-public and origin-restricted."
                        ),
                        [f"{path}.key", f"{path}.value"],
                        ("input_output_consumer_alignment", "vendor_contract_alignment"),
                    )
            for key, child in value.items():
                inspect_secret_fields(child, f"{path}.{key}")
        elif isinstance(value, list):
            for index, child in enumerate(value):
                inspect_secret_fields(child, f"{path}[{index}]")

    inspect_secret_fields(obj, own_prefix)
    for signal in as_list(technical.get("secret_like_credential_signals")):
        signal_text = str(signal)
        outcome = (
            "Unclear" if signal_text == "literal_api_key_candidate" else "Issue"
        )
        add(
            f"embedded_code_credential:{signal_text}",
            outcome,
            (
                f"Custom code contains redacted credential signal {signal_text!r}; "
                "confirm ownership and remove/rotate any non-public credential."
            ),
            anchors_for("html", "javascript", "templateData"),
            ("custom_code_behavior_alignment", "vendor_contract_alignment"),
        )

    if layer == "variable" and str(obj.get("type") or "").lower() in {"smm", "remm"}:
        variable_type = str(obj.get("type") or "").lower()
        table_kind = "lookup" if variable_type == "smm" else "regex"
        parameters = as_list(obj.get("parameter"))

        def parameter_with_index(key: str) -> tuple[int, dict[str, Any] | None]:
            for index, parameter in enumerate(parameters):
                if isinstance(parameter, dict) and parameter.get("key") == key:
                    return index, parameter
            return -1, None

        input_index, input_parameter = parameter_with_index("input")
        input_value = (
            str(input_parameter.get("value") or "").strip()
            if input_parameter
            else ""
        )
        if not input_value:
            add(
                f"{table_kind}_table_missing_input",
                "Issue",
                f"{table_kind.title()} table has no nonblank exported input.",
                anchors_for(
                    f"parameter[{input_index}]" if input_index >= 0 else "type",
                    "input",
                    variable_type,
                ),
                ("purpose_output_alignment", "input_output_consumer_alignment"),
            )

        map_index, map_parameter = parameter_with_index("map")
        raw_rows: Any = None
        row_container = "list"
        if map_parameter:
            if "list" in map_parameter:
                raw_rows = map_parameter.get("list")
            elif "map" in map_parameter:
                raw_rows = map_parameter.get("map")
                row_container = "map"
        if not isinstance(raw_rows, list) or not raw_rows:
            add(
                f"{table_kind}_table_missing_or_invalid_rows",
                "Issue",
                f"{table_kind.title()} table does not export a nonempty row array.",
                anchors_for(
                    f"parameter[{map_index}]" if map_index >= 0 else "type",
                    "map",
                    variable_type,
                ),
                ("purpose_output_alignment", "input_output_consumer_alignment"),
            )
            raw_rows = []

        extracted_rows: list[tuple[int, str, str, list[str]]] = []
        for row_index, row in enumerate(raw_rows):
            row_path = (
                f"{own_prefix}.parameter[{map_index}].{row_container}[{row_index}]"
            )
            row_anchors = [
                path
                for path in available
                if path == row_path or path.startswith(row_path + ".")
            ]
            entries = (
                as_list(row.get("map"))
                if isinstance(row, dict)
                else []
            )
            fields = {
                str(entry.get("key") or ""): str(entry.get("value") or "")
                for entry in entries
                if isinstance(entry, dict) and entry.get("key")
            }
            key_value = fields.get("key")
            output_value = fields.get("value")
            if (
                not isinstance(row, dict)
                or not isinstance(row.get("map"), list)
                or key_value is None
                or output_value is None
            ):
                add(
                    f"{table_kind}_table_malformed_row:{row_index}",
                    "Issue",
                    (
                        f"{table_kind.title()} table row {row_index} does not contain "
                        "exactly addressable key and value entries."
                    ),
                    row_anchors,
                    ("purpose_output_alignment", "input_output_consumer_alignment"),
                )
                continue
            if not key_value.strip() or not output_value.strip():
                blank_parts = [
                    label
                    for label, value in (
                        ("match key/pattern", key_value),
                        ("output", output_value),
                    )
                    if not value.strip()
                ]
                add(
                    f"{table_kind}_table_blank_row_value:{row_index}",
                    "Unclear",
                    (
                        f"{table_kind.title()} table row {row_index} has a blank "
                        f"{' and '.join(blank_parts)}; intentional empty-value semantics "
                        "are not proven by the export."
                    ),
                    row_anchors,
                    ("purpose_output_alignment", "input_output_consumer_alignment"),
                )
            extracted_rows.append((row_index, key_value, output_value, row_anchors))

        by_match_value: dict[str, list[tuple[int, list[str]]]] = {}
        for row_index, key_value, _output_value, row_anchors in extracted_rows:
            by_match_value.setdefault(key_value, []).append((row_index, row_anchors))
        for match_value, duplicates in sorted(by_match_value.items()):
            if not match_value or len(duplicates) < 2:
                continue
            add(
                f"{table_kind}_table_duplicate_match:{stable_hash(match_value)}",
                "Issue",
                (
                    f"{table_kind.title()} table repeats match value {match_value!r} "
                    f"at row indexes {[index for index, _anchors in duplicates]!r}."
                ),
                [
                    anchor
                    for _index, row_anchors in duplicates
                    for anchor in row_anchors
                ],
                ("purpose_output_alignment", "input_output_consumer_alignment"),
            )

        if variable_type == "remm":
            universal_patterns = {".*", "^.*$", ".+", "^.+$"}
            for row_index, pattern, _output_value, row_anchors in extracted_rows:
                try:
                    re.compile(pattern)
                except re.error as exc:
                    add(
                        f"regex_table_invalid_pattern:{row_index}",
                        "Issue",
                        f"Regex table row {row_index} has invalid pattern {pattern!r}: {exc}.",
                        row_anchors,
                        ("purpose_output_alignment", "input_output_consumer_alignment"),
                    )
                    continue
                if pattern in universal_patterns:
                    add(
                        f"regex_table_permissive_pattern:{row_index}",
                        "Unclear",
                        (
                            f"Regex table row {row_index} uses broadly permissive pattern "
                            f"{pattern!r}; row order and intended fallback behavior require review."
                        ),
                        row_anchors,
                        ("purpose_output_alignment", "input_output_consumer_alignment"),
                    )
                    if row_index < len(extracted_rows) - 1:
                        add(
                            f"regex_table_shadowed_rows:{row_index}",
                            "Unclear",
                            (
                                f"Broad regex row {row_index} precedes later rows and may "
                                "capture their inputs before they are evaluated."
                            ),
                            [
                                anchor
                                for later_index, _pattern, _output, later_anchors in extracted_rows
                                if later_index >= row_index
                                for anchor in later_anchors
                            ],
                            (
                                "purpose_output_alignment",
                                "input_output_consumer_alignment",
                            ),
                        )

        default_index, default_enabled = parameter_with_index("setDefaultValue")
        default_is_enabled = bool(
            default_enabled
            and str(default_enabled.get("value") or "").strip().lower() == "true"
        )
        default_value_index, default_value = parameter_with_index("defaultValue")
        if default_is_enabled and (
            not default_value
            or not str(default_value.get("value") or "").strip()
        ):
            add(
                f"{table_kind}_table_enabled_default_missing",
                "Issue",
                (
                    f"{table_kind.title()} table enables its default output but exports "
                    "no nonblank defaultValue."
                ),
                anchors_for(
                    f"parameter[{default_index}]",
                    f"parameter[{default_value_index}]"
                    if default_value_index >= 0
                    else "defaultValue",
                    "setDefaultValue",
                ),
                ("purpose_output_alignment", "input_output_consumer_alignment"),
            )

    portability_patterns = (
        (
            "hard_coded_container_identifier",
            re.compile(
                r"\bGTM-(?=[A-Z0-9]{4,12}\b)(?=[A-Z0-9]*\d)[A-Z0-9]+\b",
                re.I,
            ),
            "A behavior-bearing value hard-codes a GTM container public ID.",
        ),
        (
            "hard_coded_gtm_admin_reference",
            re.compile(
                r"(?:tagmanager\.google\.com/[^\s\"']*(?:accounts|containers|workspaces)"
                r"|(?:account|container|workspace)(?:Id)?\s*[:=]\s*['\"]?\d{2,})",
                re.I,
            ),
            "A behavior-bearing value embeds a GTM admin/account/container/workspace reference.",
        ),
        (
            "environment_specific_endpoint_candidate",
            re.compile(
                r"(?:https?://)?(?:localhost|127\.0\.0\.1|"
                r"(?:dev|development|stage|staging|qa|uat|sandbox|preprod)"
                r"(?:[-.][A-Za-z0-9-]+)+)(?::\d+)?(?:[/\s\"']|$)",
                re.I,
            ),
            "A behavior-bearing value contains an environment-specific endpoint candidate.",
        ),
    )
    projected_facts = walk_json_fields(behavior_projection(obj), own_prefix)
    for fact in projected_facts:
        path = str(fact.get("json_path") or "")
        if path not in available or path.endswith(metadata_suffixes):
            continue
        value = str(fact.get("value_preview") or "")
        for finding_key, pattern, statement in portability_patterns:
            matches = sorted(set(pattern.findall(value)))
            if not matches:
                continue
            add(
                f"portability:{finding_key}:{stable_hash({'path': path, 'matches': matches})}",
                "Unclear",
                (
                    f"{statement} Confirm whether {matches!r} is intentionally fixed for "
                    "this container or must be parameterized/remapped for the target environment."
                ),
                [path],
                (
                    "purpose_output_alignment",
                    "execution_scope_alignment",
                    "vendor_contract_alignment",
                ),
            )

    def inspect_trace(trace: dict[str, Any], inherited_paths: list[str]) -> None:
        relation = str(trace.get("relation") or "dependency")
        reference = str(trace.get("reference") or "")
        state = str(trace.get("resolution_state") or "")
        paths = [str(value) for value in as_list(trace.get("source_reference_paths"))]
        paths = paths or inherited_paths
        outcome_by_state = {
            "missing": "Issue",
            "malformed": "Issue",
            "cycle": "Issue",
            "ambiguous": "Unclear",
        }
        if state in outcome_by_state:
            trace_identity = stable_hash(
                {
                    "relation": relation,
                    "reference": reference,
                    "state": state,
                    "paths": sorted(paths),
                }
            )
            add(
                f"dependency:{relation}:{reference or '<blank>'}:{state}:{trace_identity}",
                outcome_by_state[state],
                f"Execution dependency {relation}={reference!r} resolves as {state}.",
                paths,
                ("execution_scope_alignment", "consent_sequence_alignment"),
            )
        for target in as_list(trace.get("targets")):
            if target.get("paused") and relation in {"setupTag", "teardownTag"}:
                paused_identity = stable_hash(
                    {
                        "relation": relation,
                        "target": target.get("object_key"),
                        "paths": sorted(paths),
                    }
                )
                add(
                    f"paused_sequence_target:{relation}:{target.get('object_key')}:{paused_identity}",
                    "Issue",
                    f"{relation} targets paused object {target.get('object_key')!r}.",
                    paths,
                    ("execution_scope_alignment", "consent_sequence_alignment"),
                )
            for child_field in ("member_traces", "sequence_traces"):
                for child in as_list(target.get(child_field)):
                    if isinstance(child, dict):
                        inspect_trace(child, paths)

    for trace in as_list(shared.get("execution_dependency_traces")):
        if isinstance(trace, dict):
            inspect_trace(trace, [])

    if layer == "trigger":
        parameters = obj.get("parameter")
        for parameter_index, parameter in enumerate(as_list(parameters)):
            if not isinstance(parameter, dict) or parameter.get("key") != "triggerIds":
                continue
            members = parameter.get("list")
            list_path = f"{own_prefix}.parameter[{parameter_index}].list"
            if not isinstance(members, list):
                add(
                    f"invalid_trigger_group_list:{parameter_index}",
                    "Issue",
                    "Trigger-group triggerIds does not export an array of member references.",
                    anchors_for(f"parameter[{parameter_index}]", "triggerIds"),
                    ("purpose_output_alignment", "execution_scope_alignment"),
                )
                continue
            for member_index, member in enumerate(members):
                member_path = f"{list_path}[{member_index}]"
                member_value = (
                    str(member.get("value") or "").strip()
                    if isinstance(member, dict)
                    else ""
                )
                if not isinstance(member, dict) or not member_value:
                    add(
                        f"invalid_trigger_group_member:{parameter_index}:{member_index}",
                        "Issue",
                        f"Trigger-group member at list index {member_index} is malformed or blank.",
                        [
                            path
                            for path in available
                            if path == member_path or path.startswith(member_path + ".")
                        ],
                        ("purpose_output_alignment", "execution_scope_alignment"),
                    )

    condition_source: Any = None
    condition_subject = ""
    condition_contract_topics: tuple[str, ...] = ()
    if layer == "trigger":
        condition_source = obj
        condition_subject = "Trigger"
    elif layer == "zone" and isinstance(obj.get("boundary"), dict):
        condition_source = obj["boundary"]
        condition_subject = "Zone boundary"
        condition_contract_topics = ("boundary_conditions_and_evaluation_triggers",)
    if condition_source is not None:
        constraints: dict[str, list[tuple[str, str]]] = {}
        for condition in trigger_conditions(condition_source):
            operator, left, right, _modifiers = condition.split("|", 3)
            if left and right:
                constraints.setdefault(left, []).append((operator, right))
        for left, values in sorted(constraints.items()):
            value_set = set(values)
            equals_values = sorted(
                {right for operator, right in values if operator == "EQUALS"}
            )
            contradictions: list[tuple[str, list[str]]] = []
            if len(equals_values) > 1:
                contradictions.append(
                    (
                        f"requires {left!r} to equal mutually exclusive values {equals_values!r}",
                        equals_values,
                    )
                )
            for positive, negative in (
                ("EQUALS", "NOT_EQUALS"),
                ("CONTAINS", "DOES_NOT_CONTAIN"),
                ("MATCH_REGEX", "DOES_NOT_MATCH_REGEX"),
            ):
                opposed = sorted(
                    right
                    for operator, right in value_set
                    if operator == positive and (negative, right) in value_set
                )
                if opposed:
                    contradictions.append(
                        (f"uses both {positive} and {negative} for {opposed!r}", opposed)
                    )
            for equals_value in equals_values:
                if "{{" in equals_value:
                    continue
                for operator, right in values:
                    if not right or "{{" in right:
                        continue
                    impossible = (
                        operator == "CONTAINS" and right not in equals_value
                        or operator == "DOES_NOT_CONTAIN" and right in equals_value
                        or operator == "STARTS_WITH" and not equals_value.startswith(right)
                        or operator == "ENDS_WITH" and not equals_value.endswith(right)
                    )
                    if impossible:
                        contradictions.append(
                            (
                                f"requires {left!r} to equal {equals_value!r} and also "
                                f"{operator} {right!r}",
                                [equals_value, right],
                            )
                        )
            greater_values = []
            lesser_values = []
            for operator, right in values:
                if operator not in {"GREATER_THAN", "LESS_THAN"}:
                    continue
                try:
                    numeric = float(right)
                except ValueError:
                    continue
                (greater_values if operator == "GREATER_THAN" else lesser_values).append(
                    numeric
                )
            if (
                greater_values
                and lesser_values
                and max(greater_values) >= min(lesser_values)
            ):
                contradictions.append(
                    (
                        f"requires {left!r} greater than {max(greater_values)} and less "
                        f"than {min(lesser_values)}",
                        [str(max(greater_values)), str(min(lesser_values))],
                    )
                )
            for detail, right_values in contradictions:
                key_prefix = (
                    "contradictory_equals"
                    if "mutually exclusive values" in detail
                    else "contradictory_condition"
                )
                add(
                    f"{key_prefix}:{stable_hash({'subject': condition_subject, 'detail': detail})}",
                    "Issue",
                    f"{condition_subject} {detail}.",
                    anchors_for(left, *right_values),
                    ("purpose_output_alignment", "execution_scope_alignment"),
                    condition_contract_topics,
                )

    if layer == "tag":
        start_raw = obj.get("scheduleStartMs")
        end_raw = obj.get("scheduleEndMs")

        def integer_or_none(value: Any) -> int | None:
            try:
                return int(str(value)) if value not in {None, ""} else None
            except (TypeError, ValueError):
                return None

        start = integer_or_none(start_raw)
        end = integer_or_none(end_raw)
        if (start_raw not in {None, ""} and start is None) or (
            end_raw not in {None, ""} and end is None
        ):
            add(
                "invalid_schedule_timestamp",
                "Issue",
                "Tag schedule contains a non-integer exported boundary.",
                anchors_for("scheduleStartMs", "scheduleEndMs"),
                ("execution_scope_alignment",),
            )
        if start is not None and end is not None and start >= end:
            add(
                "invalid_schedule_order",
                "Issue",
                f"Tag schedule starts at {start} and ends at {end}.",
                anchors_for("scheduleStartMs", "scheduleEndMs"),
                ("execution_scope_alignment",),
            )
        firing_option = str(obj.get("tagFiringOption") or "")
        normalized_option = re.sub(r"[^A-Z]", "", firing_option.upper())
        if firing_option and normalized_option not in {
            "UNLIMITED",
            "ONCEPEREVENT",
            "ONCEPERLOAD",
        }:
            add(
                "invalid_tag_firing_option",
                "Issue",
                f"Tag exports unrecognized tagFiringOption {firing_option!r}.",
                anchors_for("tagFiringOption"),
                ("execution_scope_alignment",),
            )

    if layer == "zone":
        children = obj.get("childContainer")
        child_rows = as_list(children)
        if children is not None and not isinstance(children, list):
            add(
                "invalid_zone_child_shape",
                "Issue",
                "Zone childContainer is not an array.",
                anchors_for("childContainer"),
                ("purpose_output_alignment", "execution_scope_alignment"),
                ("child_container_scope",),
            )
        child_ids = [
            str(child.get("publicId") or "")
            for child in child_rows
            if isinstance(child, dict)
        ]
        invalid_children = [
            index
            for index, child in enumerate(child_rows)
            if not isinstance(child, dict) or not str(child.get("publicId") or "").strip()
        ]
        if not child_rows or invalid_children:
            invalid_child_anchors = [
                path
                for index in invalid_children
                for path in anchors_for(f"childContainer[{index}]")
            ] or anchors_for("childContainer")
            add(
                "invalid_zone_child_identity",
                "Issue",
                f"Zone child entries {invalid_children!r} do not identify a child container.",
                invalid_child_anchors,
                ("purpose_output_alignment", "execution_scope_alignment"),
                ("child_container_scope",),
            )
        duplicate_child_ids = {
            value for value in child_ids if value and child_ids.count(value) > 1
        }
        if duplicate_child_ids:
            duplicate_anchors = [
                path
                for path, fact in facts_by_path.items()
                if path.startswith(own_prefix)
                and str(fact.get("value_preview") or "") in duplicate_child_ids
            ]
            add(
                "duplicate_zone_child_identity",
                "Issue",
                "Zone repeats an exported child-container public ID.",
                duplicate_anchors,
                ("purpose_output_alignment", "execution_scope_alignment"),
                ("child_container_scope",),
            )
        boundary = obj.get("boundary")
        if boundary is not None and not isinstance(boundary, dict):
            add(
                "invalid_zone_boundary_shape",
                "Issue",
                "Zone boundary is not an object.",
                anchors_for("boundary"),
                ("execution_scope_alignment",),
                ("boundary_conditions_and_evaluation_triggers",),
            )
        if isinstance(boundary, dict):
            for field in ("condition", "customEvaluationTriggerId"):
                if field in boundary and not isinstance(boundary.get(field), list):
                    add(
                        f"invalid_zone_boundary_field:{field}",
                        "Issue",
                        f"Zone boundary field {field!r} is not an array.",
                        anchors_for(f"boundary.{field}"),
                        ("execution_scope_alignment",),
                        ("boundary_conditions_and_evaluation_triggers",),
                    )
        restrictions = obj.get("typeRestriction")
        if restrictions is not None and not isinstance(restrictions, dict):
            add(
                "invalid_zone_type_restriction_shape",
                "Issue",
                "Zone typeRestriction is not an object.",
                anchors_for("typeRestriction"),
                ("execution_scope_alignment",),
                ("type_restrictions",),
            )
        if isinstance(restrictions, dict):
            allowlist = restrictions.get("whitelistedTypeId")
            if allowlist is not None and not isinstance(allowlist, list):
                add(
                    "invalid_zone_type_allowlist_shape",
                    "Issue",
                    "Zone whitelistedTypeId is not an array.",
                    anchors_for("whitelistedTypeId"),
                    ("execution_scope_alignment",),
                    ("type_restrictions",),
                )
            if restrictions.get("enable") and not as_list(allowlist):
                add(
                    "empty_enabled_zone_type_allowlist",
                    "Unclear",
                    "Zone enables type restriction with an empty exported allowlist; an "
                    "intentional deny-all policy is not provable from the container.",
                    anchors_for("typeRestriction"),
                    ("execution_scope_alignment",),
                    ("type_restrictions",),
                )

    route = shared.get("effective_consent_route") or {}
    route_status = str(route.get("effective_control_status") or "")
    if route_status == "server_contract_unproven":
        add(
            "server_consent_contract_unproven",
            "Unclear",
            "A server route is exported without a complete visible consent-forwarding contract.",
            anchors_for(
                "server_container_url",
                "transport_url",
                "endpoint",
                *as_list(route.get("server_routing_hosts")),
            ),
            ("consent_sequence_alignment", "vendor_contract_alignment"),
            ("destination_or_server_routing", "consent_and_timing"),
        )
    if route.get("requires_media_consent_review") and route_status in {
        "unproven_export_control",
        "blocker_control_candidate",
        "consent_signal_review",
    }:
        add(
            "media_consent_control_unproven",
            "Unclear",
            f"Media delivery has effective consent-control status {route_status!r}.",
            anchors_for(
                "consent",
                "blockingTriggerId",
                "html",
                "javascript",
                "fbq",
                "ttq",
                "snaptr",
                "pintrk",
            ),
            ("consent_sequence_alignment", "vendor_contract_alignment"),
            ("consent_and_timing",),
        )

    for peer in as_list(shared.get("destination_peer_contexts")):
        if not isinstance(peer, dict):
            continue
        peer_key = str(peer.get("object_key") or "")
        peer_hosts = [str(value) for value in as_list(peer.get("server_routing_hosts"))]
        missing_type = not bool(peer.get("type_present", True))
        if not peer_hosts and not missing_type:
            continue
        peer_prefix = str(peer.get("source_json_path") or "")
        peer_anchors = [
            str(fact.get("json_path") or "")
            for fact in as_list(shared.get("destination_peer_facts"))
            if str(fact.get("json_path") or "").startswith(peer_prefix)
            and (
                any(
                    token in str(fact.get("json_path") or "").lower()
                    for token in (
                        "server_container_url",
                        "transport_url",
                        "endpoint",
                        "consent",
                        ".type",
                    )
                )
                or any(
                    host in str(fact.get("value_preview") or "").lower()
                    for host in peer_hosts
                )
            )
        ]
        details = []
        if peer_hosts:
            details.append("server route " + ", ".join(peer_hosts))
        if missing_type:
            details.append("missing Google tag configuration type")
        add(
            f"peer_destination_contract_unproven:{stable_hash({'peer': peer_key, 'details': details})}",
            "Unclear",
            f"Destination peer {peer_key!r} exposes {' and '.join(details)}, so inheritance "
            "by this object is not proven from the shared destination alone.",
            peer_anchors,
            ("consent_sequence_alignment", "vendor_contract_alignment"),
            ("destination_or_server_routing", "consent_and_timing"),
        )

    if technical.get("behavior_can_be_understood_from_export") == "opaque":
        add(
            "opaque_custom_template_behavior",
            "Unclear",
            "The custom-template export does not expose reviewable executable behavior.",
            anchors_for("templateData"),
            ("purpose_output_alignment", "custom_code_behavior_alignment"),
            ("template_behavior_and_permissions",),
        )
    return [obligations[key] for key in sorted(obligations)]


def scaffold_review(
    export_path: Path,
    technical_payload: dict[str, Any] | None = None,
    shared_facts: dict[str, Any] | None = None,
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
            "source integrity gate blocked configuration review: "
            + ", ".join(finding_types)
        )
    cv = container_version(data)
    root_path = container_root_path(data)
    consumers = build_consumers(cv, root_path)
    downstream_vendor_contexts = vendor_contexts_for_objects(cv, consumers)
    technical_by_key = {
        f"{row.get('layer')}:{row.get('object_id')}": row
        for row in as_list((technical_payload or extract_export(export_path)).get("rows"))
    }
    shared_facts = shared_facts or build_shared_facts(
        export_path,
        technical=technical_payload,
    )
    shared_by_key = {
        str(row.get("object_key") or ""): row
        for row in as_list(shared_facts.get("objects"))
    }
    rows: list[dict[str, Any]] = []
    for number, (layer, index, obj) in enumerate(layer_objects(cv), start=1):
        base_path = f"{root_path}.{layer}[{index}]"
        current_key = object_key(layer, obj)
        shared = shared_by_key.get(current_key, {})
        own_facts = [
            *(as_list(shared.get("source_leaf_facts")) or walk_json_fields(obj, base_path)),
            *as_list(shared.get("source_absence_facts")),
        ]
        # Branch ownership is local to the source object. Cross-object execution,
        # consumer, and destination facts remain available below as D3/contract
        # context, but must not be re-attested as this object's own source leaves.
        facts = list(
            {
                (str(fact.get("json_path") or ""), str(fact.get("value_hash") or "")): fact
                for fact in own_facts
            }.values()
        )
        facts.sort(key=lambda fact: (fact["json_path"], fact["value_hash"]))
        evidence_facts = list(
            {
                (str(fact.get("json_path") or ""), str(fact.get("value_hash") or "")): fact
                for fact in [
                    *facts,
                    *as_list(shared.get("execution_dependency_facts")),
                    *as_list(shared.get("consumer_dependency_facts")),
                    *as_list(shared.get("destination_peer_facts")),
                ]
            }.values()
        )
        evidence_facts.sort(key=lambda fact: (fact["json_path"], fact["value_hash"]))
        required_paths = logic_anchors(facts)
        required_path_set = set(required_paths)
        lines = code_line_facts(layer, obj)
        vendor = vendor_record(behavior_bearing_vendor_text(obj, layer))
        contexts = downstream_vendor_contexts.get(current_key, [])
        topics = required_contract_topics(
            cv,
            layer,
            obj,
            contexts,
            shared.get("effective_consent_route", {}),
        )
        official_docs = sorted(
            {
                str(url)
                for context in contexts
                for url in as_list(context.get("official_docs"))
                if str(url)
            }
            | {
                str(url)
                for topic in topics
                for url in as_list(topic.get("official_doc_candidates"))
                if str(url)
            }
        )
        technical = technical_by_key.get(current_key, {})
        evidence_requirements = field_evidence_requirements(shared)
        evidence_paths = field_evidence_paths(shared)
        required_technical_findings = []
        for category, field in (
            ("health", "technical_code_health_findings"),
            ("security", "technical_code_security_findings"),
            ("optimization", "technical_code_optimization_findings"),
        ):
            for position, statement in enumerate(as_list(technical.get(field)), start=1):
                required_technical_findings.append(
                    {
                        "finding_key": f"{category}:{position}",
                        "category": category,
                        "statement": str(statement),
                        "decision_class": technical_finding_decision_class(
                            category, str(statement)
                        ),
                    }
                )
        parser_status = str(technical.get("javascript_parser") or "")
        parser_errors = [
            str(value) for value in as_list(technical.get("ast_parse_errors")) if str(value)
        ]
        if parser_status == "not_installed_static_review_still_required":
            required_technical_findings.append(
                {
                    "finding_key": "parser:coverage",
                    "category": "parser",
                    "decision_class": "evidence_boundary",
                    "statement": (
                        "JavaScript AST parser was unavailable; line-by-line behavior review "
                        "must carry the code assessment without claiming AST coverage."
                    ),
                }
            )
        elif parser_status == "esprima_parse_failed" or parser_errors:
            required_technical_findings.append(
                {
                    "finding_key": "parser:coverage",
                    "category": "parser",
                    "decision_class": "evidence_boundary",
                    "statement": (
                        f"JavaScript parser status is {parser_status or 'unknown'}"
                        + (f" with errors: {'; '.join(parser_errors[:3])}" if parser_errors else "")
                        + "; parser-level coverage is incomplete until this is resolved or "
                        "explicitly bounded."
                    ),
                }
            )
        configuration_obligations = required_configuration_obligations(
            layer,
            obj,
            shared,
            technical,
            evidence_facts,
        )
        logic_requirements = logic_cross_check_requirements(
            shared,
            evidence_requirements,
            evidence_paths,
            bool(lines),
            bool(topics),
        )
        logic_by_key = {item["check_key"]: item for item in logic_requirements}
        for obligation in configuration_obligations:
            for check_key in obligation["affected_logic_checks"]:
                check = logic_by_key.get(check_key)
                if not check:
                    continue
                check["allowed_evidence_anchors"] = list(
                    dict.fromkeys(
                        [
                            *check["allowed_evidence_anchors"],
                            *obligation["evidence_anchors"],
                        ]
                    )
                )[:160]
        rows.append(
            {
                "review_id": f"CFG-{number:05d}",
                "object_key": current_key,
                "layer": layer,
                "object_id": str(shared.get("object_id") or obj.get(ID_KEYS[layer]) or ""),
                "object_name": str(shared.get("object_name") or obj.get("name") or ""),
                "object_type": str(shared.get("object_type") or object_type(layer, obj)),
                "paused": bool(shared.get("paused")),
                "config_hash": str(shared.get("configuration_hash") or object_hash(obj)),
                "source_json_path": str(shared.get("source_json_path") or base_path),
                "source_facts": facts,
                "available_evidence_anchors": [
                    item["json_path"] for item in evidence_facts
                ],
                "required_logic_anchors": required_paths,
                "required_branch_reviews": [
                    fact for fact in facts if fact["json_path"] in required_path_set
                ],
                "code_line_facts": lines,
                "required_code_line_hashes": [item["line_hash"] for item in lines],
                "referenced_variables": as_list(shared.get("referenced_variables"))
                or sorted(refs(obj)),
                "reference_trace_requirements": as_list(
                    shared.get("reference_trace_requirements")
                )
                or reference_trace_requirements(cv, obj, root_path),
                "export_consumers": as_list(shared.get("consumers"))
                or object_consumers(layer, obj, consumers),
                "specificity_tokens": as_list(shared.get("specificity_tokens"))
                or specific_tokens(obj),
                "detected_vendor": vendor.get("name"),
                "vendor_category": vendor.get("category"),
                "vendor_contexts": contexts,
                "official_doc_candidates": official_docs,
                "required_contract_topics": topics,
                "technical_code_facts": technical,
                "required_technical_findings": required_technical_findings,
                "shared_behavior_signatures": shared.get("behavior_signatures", {}),
                "field_evidence_requirements": evidence_requirements,
                "field_evidence_paths": evidence_paths,
                "effective_consent_route_facts": shared.get("effective_consent_route", {}),
                "execution_dependency_traces": as_list(
                    shared.get("execution_dependency_traces")
                ),
                "execution_dependency_facts": as_list(
                    shared.get("execution_dependency_facts")
                ),
                "consumer_dependency_facts": as_list(
                    shared.get("consumer_dependency_facts")
                ),
                "consumer_dependency_contexts": as_list(
                    shared.get("consumer_dependency_contexts")
                ),
                "destination_peer_contexts": as_list(
                    shared.get("destination_peer_contexts")
                ),
                "destination_peer_facts": as_list(
                    shared.get("destination_peer_facts")
                ),
                "source_absence_facts": as_list(shared.get("source_absence_facts")),
                "required_logic_cross_checks": logic_requirements,
                "required_configuration_obligations": configuration_obligations,
                "review_status": "pending",
                "purpose": "",
                "execution_logic": "",
                "inputs_and_terminal_sources": "",
                "configured_output_or_side_effect": "",
                "consumer_contract": "",
                "consent_and_sequence": "",
                "correctness_verdict": "",
                "correctness_basis": "",
                "defects": [],
                "contract_checks": [],
                "code_behavior_blocks": [],
                "technical_facts_assessment": "",
                "technical_finding_reviews": [],
                "logic_cross_checks": [],
                "configuration_branch_reviews": [],
                "evidence_anchors": [],
                "consumer_evidence_keys": [],
                "reference_traces": [],
                "disposition": "",
                "owner_question": "",
                "recommended_action": "",
                "external_evidence_status": "none",
                "external_evidence_summary": "",
                "external_evidence_next_action": "",
                "consumer_specific_code_basis": "",
                "operation": {},
                "confidence": "",
                "evidence_citations": {},
            }
        )
    input_contract = review_input_contract(
        "configuration_correctness",
        descriptor["source_sha256"],
        shared_facts["context_sha256"],
        shared_facts["shared_facts_sha256"],
    )
    return {
        **descriptor,
        "kind": "gtm_configuration_correctness_review",
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
        "rows": rows,
    }


def semantic_text_errors(row: dict[str, Any], label: str) -> list[str]:
    errors: list[str] = []
    for field in SEMANTIC_TEXT_FIELDS:
        if not specific_text(row.get(field), 6):
            errors.append(f"{label}: {field} lacks object-specific analysis")
        requirements = [
            str(value).lower()
            for value in as_list(
                (row.get("field_evidence_requirements") or {}).get(field)
            )
            if str(value).strip()
        ]
        field_text = str(row.get(field) or "").lower()
        required_hits = min(2, len(requirements))
        if required_hits and sum(value in field_text for value in requirements) < required_hits:
            errors.append(
                f"{label}: {field} does not name enough source-derived behavior facts"
            )
    combined = " ".join(
        str(row.get(field) or "") for field in SEMANTIC_TEXT_FIELDS
    ).lower()
    tokens = [str(token).lower() for token in as_list(row.get("specificity_tokens"))]
    required_hits = min(2, len(tokens))
    hits = sum(1 for token in tokens if token and token in combined)
    if required_hits and hits < required_hits:
        errors.append(f"{label}: analysis does not use enough source-specific tokens")
    purpose_text = str(row.get("purpose") or "").lower()
    purpose_verbs = PURPOSE_VERBS.get(str(row.get("layer") or ""), ())
    if purpose_verbs and not any(verb in purpose_text for verb in purpose_verbs):
        errors.append(f"{label}: purpose does not state the concrete {row.get('layer')} action")
    return errors


def citation_errors(row: dict[str, Any], label: str) -> list[str]:
    errors: list[str] = []
    citations = row.get("evidence_citations") or {}
    if set(citations) != set(SEMANTIC_TEXT_FIELDS):
        errors.append(f"{label}: evidence_citations must cover every semantic field")
    available = set(as_list(row.get("available_evidence_anchors")))
    allowed_by_field = row.get("field_evidence_paths") or {}
    for field in SEMANTIC_TEXT_FIELDS:
        field_citations = {str(value) for value in as_list(citations.get(field))}
        allowed = {str(value) for value in as_list(allowed_by_field.get(field))}
        minimum = min(2, len(allowed)) if field == "correctness_basis" else min(1, len(allowed))
        if len(field_citations) < minimum:
            errors.append(f"{label}: {field} lacks source-path citations")
        for anchor in sorted(field_citations - available):
            errors.append(f"{label}: {field} cites unknown source path {anchor!r}")
        for anchor in sorted(field_citations - allowed):
            errors.append(
                f"{label}: {field} cites source path {anchor!r}, which is unrelated to that claim"
            )
    return errors


def review_text_errors(row: dict[str, Any], label: str) -> list[str]:
    return [*semantic_text_errors(row, label), *citation_errors(row, label)]


def branch_required_role(path: str) -> str | None:
    lowered = path.lower()
    if any(token in lowered for token in ("consent", "storage")):
        return "Consent"
    if any(token in lowered for token in ("filter", "condition", "operator")):
        return "Condition"
    if any(token in lowered for token in ("firingtriggerid", "blockingtriggerid", "triggerids")):
        return "Routing"
    if any(
        token in lowered
        for token in (
            "setuptag",
            "teardowntag",
            "tagfiringoption",
            "schedulestartms",
            "scheduleendms",
        )
    ):
        return "Execution control"
    if any(token in lowered for token in ("childcontainer", "typerestriction")):
        return "Condition"
    return None


def branch_specificity_tokens(source: dict[str, Any]) -> list[str]:
    ignored = {
        "containerVersion",
        "parameter",
        "value",
        "type",
        "list",
        "map",
        "tag",
        "trigger",
        "variable",
    }
    values = " ".join([str(source.get("json_path") or ""), str(source.get("value_preview") or "")])
    return sorted(
        {
            token.lower()
            for token in re.findall(r"[A-Za-z_][A-Za-z0-9_.:/{}\[\]-]{2,}", values)
            if token not in ignored and not token.isdigit()
        }
    )


def contract_topic_maps(
    row: dict[str, Any], checks: list[dict[str, Any]], label: str
) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]], list[str]]:
    required = {
        str(item.get("topic_key") or ""): item
        for item in as_list(row.get("required_contract_topics"))
    }
    supplied_rows = [item for item in checks if isinstance(item, dict)]
    supplied = {
        str(item.get("contract_topic") or ""): item
        for item in supplied_rows
    }
    errors = []
    if len(supplied_rows) != len(checks):
        errors.append(f"{label}: official contract checks contain malformed rows")
    if len(supplied) != len(supplied_rows) or "" in supplied:
        errors.append(
            f"{label}: official contract checks must use unique nonblank topic keys"
        )
    if set(supplied) != set(required):
        errors.append(
            f"{label}: official contract checks must cover every generated topic exactly once"
        )
    return required, supplied, errors


def validate_contract_text(
    check: dict[str, Any], topic: dict[str, Any], prefix: str
) -> list[str]:
    errors: list[str] = []
    for field in ("contract_field", "configured_value", "expected_rule"):
        minimum = 1 if field == "configured_value" else 2
        if not specific_text(check.get(field), minimum):
            errors.append(f"{prefix} has incomplete {field}")
    if check.get("verdict") != "Unproven" and not specific_text(check.get("source"), 2):
        errors.append(f"{prefix} has incomplete source")
    if topic.get("research_required"):
        if not specific_text(check.get("identified_vendor"), 2):
            errors.append(f"{prefix} must identify the external vendor or integration")
        if not specific_text(check.get("official_source_basis"), 5):
            errors.append(
                f"{prefix} must explain why the cited page is the vendor's official source"
            )
    expected_rule = str(check.get("expected_rule") or "").lower()
    required_terms = [
        str(value).lower() for value in as_list(topic.get("required_rule_terms"))
    ]
    required_hits = min(2, len(required_terms))
    if required_hits and sum(term in expected_rule for term in required_terms) < required_hits:
        errors.append(f"{prefix} expected_rule does not state the topic-specific contract")
    if check.get("verdict") not in VALID_CONTRACT_VERDICTS:
        errors.append(f"{prefix} has invalid verdict")
    if (
        topic.get("applicability_state") == "applicable"
        and check.get("verdict") == "Not applicable"
    ):
        errors.append(f"{prefix} is a generated applicable contract and cannot be skipped")
    presence_state = str(topic.get("configuration_presence_state") or "")
    required_configuration_terms = as_list(topic.get("required_configuration_terms"))
    if (
        required_configuration_terms
        and presence_state == "missing"
        and check.get("verdict") != "Non-compliant"
    ):
        errors.append(
            f"{prefix} must be Non-compliant because required exported configuration "
            f"terms {required_configuration_terms!r} are absent"
        )
    deterministic_state = str(topic.get("deterministic_contract_state") or "")
    if deterministic_state == "known_noncompliant" and check.get("verdict") != "Non-compliant":
        errors.append(
            f"{prefix} must be Non-compliant because the exported contract has a "
            "deterministic missing or unsupported value"
        )
    if deterministic_state == "unproven_from_container" and check.get("verdict") not in {
        "Unproven",
        "Non-compliant",
    }:
        errors.append(
            f"{prefix} cannot be certified from container-only dynamic, consent, or "
            "server evidence"
        )
    configured_events = [
        str(value).lower() for value in as_list(topic.get("configured_event_values"))
    ]
    configured_value = str(check.get("configured_value") or "").lower()
    if configured_events and not all(value in configured_value for value in configured_events):
        errors.append(f"{prefix} does not name every vendor-specific configured event value")
    return errors


def validate_contract_source(
    check: dict[str, Any], topic: dict[str, Any], prefix: str
) -> list[str]:
    source_url = str(check.get("source") or "")
    official_domains = {
        urlparse(str(url)).netloc.lower()
        for url in as_list(topic.get("official_doc_candidates"))
        if str(url).startswith("https://")
    }
    errors: list[str] = []
    if (
        topic.get("research_dependency_key")
        and not topic.get("research_required")
        and not source_url
        and check.get("verdict") == "Unproven"
    ):
        return errors
    if topic.get("research_required"):
        hostname = (urlparse(source_url).hostname or "").lower()
        reserved_bases = {
            "example.com",
            "example.org",
            "example.net",
        }
        if (
            hostname in reserved_bases
            or any(hostname.endswith("." + base) for base in reserved_bases)
            or hostname.endswith((".example", ".invalid", ".localhost", ".test"))
        ):
            errors.append(
                f"{prefix} uses a placeholder or reserved or non-production "
                "documentation hostname"
            )
        if source_url:
            errors.append(
                f"{prefix} cannot certify an unregistered vendor source; add the verified "
                "official domain to the versioned registry and rebuild the review"
            )
        if check.get("verdict") != "Unproven":
            errors.append(
                f"{prefix} must remain Unproven while the vendor and official domain are unregistered"
            )
        if not specific_text(check.get("research_status"), 8):
            errors.append(
                f"{prefix} must document the unsuccessful official-source identification"
            )
        research_status = str(check.get("research_status") or "").lower()
        if "official" not in research_status or not re.search(
            r"\b(?:search|searched|check|checked|review|reviewed|investigat(?:e|ed|ion))\b",
            research_status,
        ):
            errors.append(
                f"{prefix} must record the attempted official-source research before "
                "falling back to an unresolved owner or evidence decision"
            )
        return errors
    if not source_url.startswith("https://"):
        errors.append(f"{prefix} source must be an official HTTPS documentation URL")
    elif official_domains and urlparse(source_url).netloc.lower() not in official_domains:
        errors.append(f"{prefix} source domain is not registered for the detected vendor")
    return errors


def validate_contract_evidence(
    row: dict[str, Any],
    check: dict[str, Any],
    topic: dict[str, Any],
    available: set[str],
    prefix: str,
) -> tuple[set[str], list[str]]:
    anchors = {str(value) for value in as_list(check.get("evidence_anchors"))}
    errors: list[str] = []
    if not anchors:
        errors.append(f"{prefix} has no configuration evidence")
    errors.extend(
        f"{prefix} references unknown evidence anchor {anchor!r}"
        for anchor in sorted(anchors - available)
    )
    logic_anchors = {
        str(value) for value in as_list(row.get("required_logic_anchors"))
    }
    for anchor in sorted(anchors - logic_anchors):
        errors.append(
            f"{prefix} cites metadata rather than configuration logic branch {anchor!r}"
        )
    configured_tokens = {
        token
        for fact in as_list(row.get("source_facts"))
        if str(fact.get("json_path") or "") in anchors
        for token in branch_specificity_tokens(fact)
    }
    configured_text = str(check.get("configured_value") or "").lower()
    if configured_tokens and not any(token in configured_text for token in configured_tokens):
        errors.append(f"{prefix} does not state the actual exported configuration value")
    configured_events = [
        str(value).lower() for value in as_list(topic.get("configured_event_values"))
    ]
    for event in configured_events:
        event_paths = {
            str(fact.get("json_path") or "")
            for fact in as_list(row.get("source_facts"))
            if event in str(fact.get("value_preview") or "").lower()
            and str(fact.get("json_path") or "") in logic_anchors
        }
        if event_paths and not (anchors & event_paths):
            errors.append(
                f"{prefix} does not cite the exported branch containing event {event!r}"
            )
    return anchors, errors


def validate_contract_outcomes(
    row: dict[str, Any],
    noncompliant_anchors: set[str],
    blocking_unproven_anchors: set[str],
    runtime_unproven_anchors: set[str],
    label: str,
) -> list[str]:
    errors: list[str] = []
    if noncompliant_anchors and row.get("correctness_verdict") != "Issue":
        errors.append(f"{label}: non-compliant vendor contract requires overall Issue verdict")
    defect_anchors = {
        str(anchor)
        for defect in as_list(row.get("defects"))
        for anchor in as_list(defect.get("evidence_anchors"))
    }
    if noncompliant_anchors - defect_anchors:
        errors.append(f"{label}: vendor contract failures must be linked to concrete defects")
    if blocking_unproven_anchors and row.get("correctness_verdict") not in {
        "Owner decision needed",
        "Container evidence limit",
        "Issue",
    }:
        errors.append(
            f"{label}: an unproven source/identity contract cannot be marked Correct"
        )
    branches = {
        str(item.get("json_path") or ""): str(item.get("correctness") or "")
        for item in as_list(row.get("configuration_branch_reviews"))
        if isinstance(item, dict)
    }
    for anchor in sorted(noncompliant_anchors):
        if branches.get(anchor) != "Issue":
            errors.append(
                f"{label}: non-compliant contract requires Issue branch verdict at {anchor}"
            )
    for anchor in sorted(blocking_unproven_anchors - noncompliant_anchors):
        if branches.get(anchor) not in {"Unclear", "Issue"}:
            errors.append(
                f"{label}: blocking unproven contract requires Unclear or Issue branch "
                f"verdict at {anchor}"
            )
    logic = {
        str(item.get("check_key") or ""): str(item.get("verdict") or "")
        for item in as_list(row.get("logic_cross_checks"))
        if isinstance(item, dict)
    }
    vendor_verdict = logic.get("vendor_contract_alignment")
    if noncompliant_anchors and vendor_verdict != "Issue":
        errors.append(f"{label}: non-compliant contract contradicts vendor D3 alignment")
    elif blocking_unproven_anchors and vendor_verdict not in {"Unclear", "Issue"}:
        errors.append(f"{label}: unproven contract contradicts vendor D3 alignment")
    elif runtime_unproven_anchors and vendor_verdict not in {
        "Aligned",
        "Unclear",
        "Issue",
    }:
        errors.append(f"{label}: runtime boundary has an invalid vendor D3 conclusion")
    return errors


def validate_contract_checks(row: dict[str, Any], label: str) -> list[str]:
    checks = as_list(row.get("contract_checks"))
    required_topics, _supplied_topics, errors = contract_topic_maps(row, checks, label)
    available = set(as_list(row.get("available_evidence_anchors")))
    noncompliant_anchors: set[str] = set()
    blocking_unproven_anchors: set[str] = set()
    runtime_unproven_anchors: set[str] = set()
    for index, check in enumerate(checks, start=1):
        prefix = f"{label}: contract check {index}"
        topic_key = str(check.get("contract_topic") or "")
        topic = required_topics.get(topic_key)
        if topic is None:
            errors.append(f"{prefix} references an unknown contract topic")
            topic = {}
        errors.extend(validate_contract_text(check, topic, prefix))
        errors.extend(validate_contract_source(check, topic, prefix))
        anchors, evidence_errors = validate_contract_evidence(
            row, check, topic, available, prefix
        )
        errors.extend(evidence_errors)
        if check.get("verdict") == "Non-compliant":
            noncompliant_anchors.update(anchors)
        if check.get("verdict") == "Unproven":
            if topic.get("deterministic_contract_state") == "unproven_from_container":
                runtime_unproven_anchors.update(anchors)
            else:
                blocking_unproven_anchors.update(anchors)
    errors.extend(
        validate_contract_outcomes(
            row,
            noncompliant_anchors,
            blocking_unproven_anchors,
            runtime_unproven_anchors,
            label,
        )
    )
    return errors


CODE_BLOCK_TEXT_FIELDS = (
    "purpose",
    "inputs",
    "outputs",
    "side_effects",
    "health_assessment",
)
CODE_TOKEN_IGNORES = {
    "function",
    "return",
    "const",
    "false",
    "true",
    "undefined",
    "script",
}


def code_block_source_tokens(
    hashes: list[str], required_facts: dict[str, dict[str, Any]]
) -> set[str]:
    return {
        token.lower()
        for line_hash in hashes
        if line_hash in required_facts
        for token in re.findall(
            r"[A-Za-z_$][A-Za-z0-9_.$:/-]{3,}",
            str(required_facts[line_hash].get("line_preview") or ""),
        )
        if token.lower() not in CODE_TOKEN_IGNORES
    }


def validate_segment_behavior_text(
    text: str, fact: dict[str, Any], prefix: str
) -> list[str]:
    lowered = text.lower()
    errors: list[str] = []
    required_signals = [
        signal
        for signal in as_list(fact.get("required_behavior_signals"))
        if isinstance(signal, dict)
    ]
    if required_signals and re.search(
        r"\b(?:dead(?:\s+code)?(?:\s+path|\s+branch)?|unreachable|dormant|inert|"
        r"non[- ]executing)\b|"
        r"\b(?:zero|no)\s+(?:delivery|execution|effect|output|send|request|call|"
        r"mutation)s?\b|"
        r"\b(?:never|not|cannot|does(?:\s+not|n't))\s+"
        r"(?:execute|run|fire|invoke|deliver)\w*\b|"
        r"\b(?:illustrative|example|demonstration|placeholder)\s+only\b",
        lowered,
    ):
        errors.append(f"{prefix} denies the executable effect of source-proven behavior")
    if required_signals and re.search(
        r"\b(?:no|without)\s+(?:configured\s+|source(?:-visible)?\s+|observable\s+)?"
        r"(?:behavior|effect|output|action|request|send|call|mutation)s?\b|"
        r"\b(?:does|do)\s+nothing\b",
        lowered,
    ):
        errors.append(f"{prefix} denies all source-proven segment behavior")
    for signal in required_signals:
        signal_name = str(signal.get("signal") or "source behavior")
        term_groups = [
            [str(term).lower() for term in as_list(group) if str(term)]
            for group in as_list(signal.get("required_term_groups"))
        ]
        if any(group and not any(term in lowered for term in group) for group in term_groups):
            errors.append(
                f"{prefix} does not state required segment behavior {signal_name}"
            )
            continue
        signal_terms = {
            *signal_name.replace("_", " ").split(),
            *(term for group in term_groups for term in group),
        }
        raw_term_pattern = "|".join(
            re.escape(term) for term in sorted(signal_terms, key=len, reverse=True) if term
        )
        term_pattern = rf"(?:{raw_term_pattern})(?:s|es|ing|ed)?" if raw_term_pattern else ""
        if term_pattern and (
            re.search(
                rf"\b(?:no|not|never|without|cannot|does(?:\s+not|n't)|fails?\s+to|"
                rf"neither|inert|rather\s+than|prevent\w*|suppress\w*|omit\w*|"
                rf"skip\w*|disabl\w*|avoid\w*)\b"
                rf"(?:\W+\w+){{0,6}}\W+(?:{term_pattern})\b",
                lowered,
            )
            or re.search(
                rf"\b(?:{term_pattern})\b(?:\W+\w+){{0,4}}\W+\b(?:not|never|absent|"
                rf"none|inert|prevented|suppressed|omitted|skipped|disabled)\b",
                lowered,
            )
            or re.search(
                rf"\b(?:{term_pattern})\b(?:\W+\w+){{0,8}}\W+\brather\s+than\b",
                lowered,
            )
        ):
            errors.append(
                f"{prefix} reverses source-proven segment behavior {signal_name}"
            )
    return errors


def validate_code_block(
    block: dict[str, Any],
    index: int,
    required_facts: dict[str, dict[str, Any]],
    label: str,
) -> tuple[list[str], list[str]]:
    prefix = f"{label}: code block {index}"
    hashes = [str(value) for value in as_list(block.get("line_hashes"))]
    errors: list[str] = []
    if not hashes:
        return hashes, [f"{prefix} covers no code lines"]
    if len(hashes) > 30:
        errors.append(f"{prefix} covers more than 30 nonblank lines")
    errors.extend(
        f"{prefix} references unknown line hash {line_hash!r}"
        for line_hash in hashes
        if line_hash not in required_facts
    )
    errors.extend(
        f"{prefix} has incomplete {field}"
        for field in CODE_BLOCK_TEXT_FIELDS
        if not specific_text(block.get(field), 4)
    )
    block_text = " ".join(
        str(block.get(field) or "") for field in CODE_BLOCK_TEXT_FIELDS
    ).lower()
    source_tokens = code_block_source_tokens(hashes, required_facts)
    if source_tokens and not any(token in block_text for token in source_tokens):
        errors.append(f"{prefix} does not name any identifier or endpoint from its code lines")
    for line_hash in hashes:
        segment_tokens = code_block_source_tokens([line_hash], required_facts)
        if segment_tokens and not any(token in block_text for token in segment_tokens):
            errors.append(
                f"{prefix} does not describe source-specific behavior for segment {line_hash}"
            )
        if line_hash in required_facts:
            errors.extend(
                validate_segment_behavior_text(
                    block_text,
                    required_facts[line_hash],
                    f"{prefix} segment {line_hash}",
                )
            )
    line_numbers = [
        required_facts[value]["line_number"] for value in hashes if value in required_facts
    ]
    if line_numbers and (
        block.get("start_line") != min(line_numbers)
        or block.get("end_line") != max(line_numbers)
    ):
        errors.append(f"{prefix} start/end lines do not match covered hashes")
    return hashes, errors


def validate_code_blocks(row: dict[str, Any], label: str) -> list[str]:
    required_rows = as_list(row.get("code_line_facts"))
    required_facts = {item["line_hash"]: item for item in required_rows}
    required_order = [str(item.get("line_hash") or "") for item in required_rows]
    blocks = as_list(row.get("code_behavior_blocks"))
    if not required_facts:
        return [f"{label}: non-code object must not contain code blocks"] if blocks else []
    errors: list[str] = []
    if not blocks:
        return [f"{label}: custom code requires behavior blocks"]
    expected_minimum = math.ceil(len(required_facts) / 30)
    if len(blocks) < expected_minimum:
        errors.append(
            f"{label}: {len(required_facts)} code lines require at least {expected_minimum} behavior blocks"
        )
    covered: list[str] = []
    for index, block in enumerate(blocks, start=1):
        hashes, block_errors = validate_code_block(block, index, required_facts, label)
        covered.extend(hashes)
        errors.extend(block_errors)
    if covered != required_order:
        errors.append(
            f"{label}: code behavior blocks must cover every exported nonblank line exactly "
            "once and in source order"
        )
    return errors


def validate_logic_cross_checks(row: dict[str, Any], label: str) -> list[str]:
    required = {
        str(item.get("check_key") or ""): item
        for item in as_list(row.get("required_logic_cross_checks"))
    }
    raw_supplied = as_list(row.get("logic_cross_checks"))
    supplied_rows = [
        item
        for item in raw_supplied
        if isinstance(item, dict)
    ]
    supplied = {
        str(item.get("check_key") or ""): item
        for item in supplied_rows
    }
    errors: list[str] = []
    if len(supplied_rows) != len(raw_supplied):
        errors.append(f"{label}: D3 logic checks contain malformed rows")
    if len(supplied) != len(supplied_rows) or "" in supplied:
        errors.append(f"{label}: D3 logic check keys must be unique and nonblank")
    if set(supplied) != set(required):
        errors.append(f"{label}: D3 logic checks must cover every required cross-check exactly once")
    issue_anchors: set[str] = set()
    unclear_keys: set[str] = set()
    for check_key, requirement in required.items():
        review = supplied.get(check_key)
        if not review:
            continue
        verdict = review.get("verdict")
        if verdict not in VALID_LOGIC_CHECK_VERDICTS:
            errors.append(f"{label}: D3 logic check {check_key} has an invalid verdict")
        conclusion = str(review.get("conclusion") or "")
        terms = [
            str(value).lower()
            for value in as_list(requirement.get("required_terms"))
            if str(value).strip()
        ]
        if not specific_text(conclusion, 8) or sum(term in conclusion.lower() for term in terms) < min(
            2, len(terms)
        ):
            errors.append(
                f"{label}: D3 logic check {check_key} lacks a source-specific functional conclusion"
            )
        anchors = {str(value) for value in as_list(review.get("evidence_anchors"))}
        allowed = {
            str(value) for value in as_list(requirement.get("allowed_evidence_anchors"))
        }
        if allowed and not anchors:
            errors.append(f"{label}: D3 logic check {check_key} has no configuration evidence")
        if anchors - allowed:
            errors.append(f"{label}: D3 logic check {check_key} cites unrelated evidence")
        if verdict == "Issue":
            issue_anchors.update(anchors)
        elif verdict == "Unclear":
            unclear_keys.add(check_key)
    defect_anchors = {
        str(anchor)
        for defect in as_list(row.get("defects"))
        for anchor in as_list(defect.get("evidence_anchors"))
    }
    if issue_anchors - defect_anchors:
        errors.append(f"{label}: every failed D3 logic check must be linked to a defect")
    if issue_anchors and row.get("correctness_verdict") != "Issue":
        errors.append(f"{label}: failed D3 logic check requires overall Issue verdict")
    runtime_only_unclear = (
        bool(unclear_keys)
        and unclear_keys <= {"vendor_contract_alignment"}
        and row.get("external_evidence_status") == "runtime_handoff_required"
    )
    if unclear_keys and not runtime_only_unclear and row.get("correctness_verdict") not in {
        "Owner decision needed",
        "Container evidence limit",
        "Issue",
    }:
        errors.append(f"{label}: unclear D3 logic requires an unresolved overall verdict")
    return errors


def validate_required_configuration_obligations(
    row: dict[str, Any], label: str
) -> list[str]:
    branch_reviews = {
        str(item.get("json_path") or ""): str(item.get("correctness") or "")
        for item in as_list(row.get("configuration_branch_reviews"))
        if isinstance(item, dict)
    }
    logic_review_rows = {
        str(item.get("check_key") or ""): item
        for item in as_list(row.get("logic_cross_checks"))
        if isinstance(item, dict)
    }
    logic_reviews = {
        key: str(item.get("verdict") or "")
        for key, item in logic_review_rows.items()
    }
    required_topics = {
        str(item.get("topic_key") or ""): item
        for item in as_list(row.get("required_contract_topics"))
        if isinstance(item, dict)
    }
    supplied_contracts = {
        str(item.get("contract_topic") or ""): item
        for item in as_list(row.get("contract_checks"))
        if isinstance(item, dict)
    }
    contract_verdicts_by_topic: dict[str, list[str]] = {}
    for topic_key, topic in required_topics.items():
        contract_verdicts_by_topic.setdefault(str(topic.get("topic") or ""), []).append(
            str((supplied_contracts.get(topic_key) or {}).get("verdict") or "")
        )
    defect_anchors = {
        str(anchor)
        for defect in as_list(row.get("defects"))
        for anchor in as_list(defect.get("evidence_anchors"))
    }
    errors: list[str] = []
    for obligation in as_list(row.get("required_configuration_obligations")):
        key = str(obligation.get("obligation_key") or "<missing>")
        outcome = str(obligation.get("required_outcome") or "")
        anchors = {
            str(value) for value in as_list(obligation.get("evidence_anchors"))
        }
        if outcome == "Issue":
            if row.get("correctness_verdict") != "Issue":
                errors.append(
                    f"{label}: deterministic obligation {key} requires overall Issue verdict"
                )
            for anchor in sorted(anchors & set(branch_reviews)):
                if branch_reviews.get(anchor) != "Issue":
                    errors.append(
                        f"{label}: deterministic obligation {key} requires Issue at {anchor}"
                    )
            if anchors and not (anchors & defect_anchors):
                errors.append(
                    f"{label}: deterministic obligation {key} must be linked to a concrete defect"
                )
            allowed_logic = {"Issue"}
        elif outcome == "Unclear":
            if row.get("correctness_verdict") not in {
                "Owner decision needed",
                "Container evidence limit",
                "Issue",
            }:
                errors.append(
                    f"{label}: deterministic obligation {key} requires an unresolved overall verdict"
                )
            for anchor in sorted(anchors & set(branch_reviews)):
                if branch_reviews.get(anchor) not in {"Unclear", "Issue"}:
                    errors.append(
                        f"{label}: deterministic obligation {key} requires Unclear or Issue "
                        f"at {anchor}"
                    )
            allowed_logic = {"Unclear", "Issue"}
        else:
            errors.append(f"{label}: deterministic obligation {key} has invalid outcome")
            continue
        for check_key in as_list(obligation.get("affected_logic_checks")):
            if check_key in logic_reviews and logic_reviews[check_key] not in allowed_logic:
                errors.append(
                    f"{label}: deterministic obligation {key} contradicts D3 check {check_key}"
                )
            if check_key in logic_reviews:
                conclusion = str(
                    logic_review_rows[check_key].get("conclusion") or ""
                ).lower()
                terms = [
                    str(value).lower()
                    for value in as_list(obligation.get("required_conclusion_terms"))
                    if str(value)
                ]
                if key.lower() not in conclusion or (
                    terms
                    and sum(term in conclusion for term in terms) < min(2, len(terms))
                ):
                    errors.append(
                        f"{label}: D3 check {check_key} does not name deterministic "
                        f"obligation {key}"
                    )
        for topic in as_list(obligation.get("affected_contract_topics")):
            verdicts = contract_verdicts_by_topic.get(str(topic), [])
            if not verdicts:
                continue
            allowed_contracts = (
                {"Non-compliant"}
                if outcome == "Issue"
                else {"Unproven", "Non-compliant"}
            )
            if any(verdict not in allowed_contracts for verdict in verdicts):
                errors.append(
                    f"{label}: deterministic obligation {key} contradicts official "
                    f"contract topic {topic}"
                )
    return errors


def validate_technical_findings(row: dict[str, Any], label: str) -> list[str]:
    required = {
        str(item.get("finding_key") or ""): item
        for item in as_list(row.get("required_technical_findings"))
    }
    raw_supplied = as_list(row.get("technical_finding_reviews"))
    supplied_rows = [
        item
        for item in raw_supplied
        if isinstance(item, dict)
    ]
    supplied = {
        str(item.get("finding_key") or ""): item
        for item in supplied_rows
    }
    errors: list[str] = []
    if len(supplied_rows) != len(raw_supplied):
        errors.append(f"{label}: static technical findings contain malformed rows")
    if len(supplied) != len(supplied_rows) or "" in supplied:
        errors.append(f"{label}: static technical finding keys must be unique and nonblank")
    if set(supplied) != set(required):
        errors.append(f"{label}: static technical findings must be resolved exactly once")
    if row.get("required_code_line_hashes") and not specific_text(
        row.get("technical_facts_assessment"), 6
    ):
        errors.append(f"{label}: custom code lacks a concrete technical assessment")
    actionable: list[str] = []
    for key, source in required.items():
        review = supplied.get(key)
        if not review:
            continue
        if review.get("source_statement") != source["statement"]:
            errors.append(f"{label}: technical finding {key} source statement changed")
        if review.get("verdict") not in VALID_TECHNICAL_FINDING_VERDICTS:
            errors.append(f"{label}: technical finding {key} has invalid verdict")
        if not specific_text(review.get("rationale"), 5):
            errors.append(f"{label}: technical finding {key} lacks concrete rationale")
        rationale = str(review.get("rationale") or "").lower()
        statement_terms = {
            term
            for term in re.findall(r"[a-z][a-z0-9_-]{3,}", str(source.get("statement") or "").lower())
            if term
            not in {
                "that",
                "this",
                "with",
                "from",
                "when",
                "only",
                "must",
                "keep",
                "check",
                "review",
                "source",
            }
        }
        if statement_terms and sum(term in rationale for term in statement_terms) < min(
            2, len(statement_terms)
        ):
            errors.append(
                f"{label}: technical finding {key} rationale is not tied to its exact "
                "source-proven signal"
            )
        source_proven_signal = source.get("category") in {"health", "security"}
        decision_class = str(
            source.get("decision_class")
            or technical_finding_decision_class(
                str(source.get("category") or ""),
                str(source.get("statement") or ""),
            )
        )
        if source_proven_signal and review.get("verdict") == "False positive":
            errors.append(
                f"{label}: source-proven {source.get('category')} signal {key} cannot be "
                "dismissed as a false positive; use No defect after review when the "
                "pattern is present but the complete source-bound review proves no defect"
            )
        if decision_class == "deterministic_defect" and review.get("verdict") == (
            "No defect after review"
        ):
            errors.append(
                f"{label}: deterministic technical defect {key} cannot be closed as "
                "No defect after review"
            )
        if (
            decision_class == "review_signal"
            and review.get("verdict") == "Owner decision needed"
        ):
            errors.append(
                f"{label}: advisory technical review signal {key} cannot by itself "
                "create an owner decision; conclude No defect after review, identify a "
                "concrete defect/action, or tie the owner question to a separate "
                "source-visible business choice"
            )
        if source_proven_signal and review.get("verdict") in {
            "Cleanup opportunity",
            "Confirmed issue",
        }:
            action = str(review.get("proposed_action") or "").lower()
            if not specific_text(action, 6) or not any(
                term in action
                for term in (
                    "replace",
                    "remove",
                    "scope",
                    "migrate",
                    "restrict",
                    "harden",
                    "refactor",
                    "correct",
                    "validate",
                )
            ):
                errors.append(
                    f"{label}: actionable source-proven risk {key} "
                    "requires one concrete proposed_action"
                )
            signal_action_terms: tuple[tuple[str, tuple[str, ...]], ...] = (
                ("datalayer.reset", ("reset", "event-scoped", "explicit key")),
                ("google_tag_manager", ("google_tag_manager", "supported", "documented")),
                ("gtag()", ("gtag", "native google", "sender", "destination")),
                ("debugger", ("debugger", "remove")),
                ("cookie write", ("secure", "samesite", "cookie")),
                ("event listener", ("once", "remove", "guard", "listener")),
            )
            statement = str(source.get("statement") or "").lower()
            matched_terms = [
                terms for marker, terms in signal_action_terms if marker in statement
            ]
            if matched_terms and not any(
                term in action for terms in matched_terms for term in terms
            ):
                errors.append(
                    f"{label}: proposed_action for {key} does not address its exact "
                    "source-proven code signal"
                )
        if source_proven_signal and review.get("verdict") == "Documented exception":
            exception_basis = str(review.get("exception_basis") or "").lower()
            if (
                not specific_text(exception_basis, 8)
                or sum(term in exception_basis for term in statement_terms)
                < min(2, len(statement_terms))
                or not any(
                    term in exception_basis
                    for term in (
                        "accepted",
                        "constraint",
                        "required",
                        "trusted",
                        "controlled",
                        "mitigation",
                        "risk owner",
                    )
                )
            ):
                errors.append(
                    f"{label}: source-proven risk {key} marked Documented exception "
                    "requires an evidence-bound exception_basis"
                )
        if (
            decision_class in {"deterministic_defect", "evidence_boundary"}
            and review.get("verdict") == "Owner decision needed"
        ):
            owner_question = str(
                review.get("owner_question") or row.get("owner_question") or ""
            ).lower()
            if (
                not precise_question(owner_question, 8)
                or sum(term in owner_question for term in statement_terms) < 1
            ):
                errors.append(
                    f"{label}: source-proven risk {key} marked Owner decision needed "
                    "requires a source-specific owner_question"
                )
        fixed_formula = "fixed numbered value slots" in str(source.get("statement") or "").lower()
        parser_limit = source.get("category") == "parser"
        if parser_limit and review.get("verdict") not in {
            "Confirmed issue",
            "Documented exception",
            "Owner decision needed",
        }:
            errors.append(
                f"{label}: parser coverage limit cannot be dismissed as a false positive "
                "or cleanup opportunity"
            )
        if parser_limit and review.get("verdict") == "Documented exception":
            rationale = str(review.get("rationale") or "").lower()
            if "line-by-line" not in rationale or "parser" not in rationale:
                errors.append(
                    f"{label}: parser exception must explain the substitute code review or "
                    "parser compatibility boundary"
                )
            fallback_hashes = {
                str(value) for value in as_list(review.get("fallback_line_hashes"))
            }
            required_hashes = {
                str(value) for value in as_list(row.get("required_code_line_hashes"))
            }
            if fallback_hashes != required_hashes:
                errors.append(
                    f"{label}: parser exception must attest every exported code segment hash"
                )
            raw_segment_reviews = as_list(review.get("fallback_segment_reviews"))
            segment_review_rows = [
                item
                for item in raw_segment_reviews
                if isinstance(item, dict)
            ]
            segment_reviews = {
                str(item.get("line_hash") or ""): item for item in segment_review_rows
            }
            if (
                len(segment_review_rows) != len(raw_segment_reviews)
                or
                len(segment_reviews) != len(segment_review_rows)
                or "" in segment_reviews
                or set(segment_reviews) != required_hashes
            ):
                errors.append(
                    f"{label}: parser exception must review every exported code segment exactly once"
                )
            code_facts = {
                str(item.get("line_hash") or ""): item
                for item in as_list(row.get("code_line_facts"))
            }
            for line_hash in sorted(required_hashes & set(segment_reviews)):
                behavior = str(segment_reviews[line_hash].get("behavior") or "")
                tokens = code_block_source_tokens([line_hash], code_facts)
                if not specific_text(behavior, 6) or (
                    tokens
                    and sum(token in behavior.lower() for token in tokens)
                    < min(2, len(tokens))
                ):
                    errors.append(
                        f"{label}: parser fallback segment {line_hash} lacks source-specific behavior"
                    )
                errors.extend(
                    validate_segment_behavior_text(
                        behavior,
                        code_facts[line_hash],
                        f"{label}: parser fallback segment {line_hash}",
                    )
                )
            parser_status = str(
                (row.get("technical_code_facts") or {}).get("javascript_parser") or ""
            ).lower()
            boundary = str(review.get("parser_boundary") or "").lower()
            if not specific_text(boundary, 6) or (
                parser_status and parser_status not in boundary
            ):
                errors.append(
                    f"{label}: parser exception must state the exact parser status and syntax boundary"
                )
            method = str(review.get("manual_review_method") or "").lower()
            source_tokens = code_block_source_tokens(
                list(required_hashes),
                {
                    str(item.get("line_hash") or ""): item
                    for item in as_list(row.get("code_line_facts"))
                },
            )
            if (
                not specific_text(method, 8)
                or "line-by-line" not in method
                or sum(token in method for token in source_tokens) < min(2, len(source_tokens))
            ):
                errors.append(
                    f"{label}: parser fallback method must be line-by-line and name "
                    "source-specific code behavior"
                )
        opaque_behavior = "no reviewable executable behavior" in str(
            source.get("statement") or ""
        ).lower()
        if opaque_behavior and review.get("verdict") not in {
            "Confirmed issue",
            "Documented exception",
            "Owner decision needed",
        }:
            errors.append(
                f"{label}: opaque custom-template behavior cannot be dismissed as a false positive"
            )
        if fixed_formula and review.get("verdict") not in {
            "Confirmed issue",
            "Documented exception",
            "Owner decision needed",
        }:
            errors.append(
                f"{label}: fixed-slot business formula must be confirmed, explicitly excepted, "
                "or sent to the owner"
            )
        if fixed_formula and review.get("verdict") == "Documented exception":
            rationale = str(review.get("rationale") or "").lower()
            if not any(
                token in rationale
                for token in ("fixed cardinality", "maximum item", "consumer contract", "business rule")
            ):
                errors.append(
                    f"{label}: fixed-slot exception must name the proven cardinality or consumer rule"
                )
        if review.get("verdict") in {"Confirmed issue", "Cleanup opportunity"}:
            actionable.append(key)
    if actionable and row.get("correctness_verdict") != "Issue":
        errors.append(f"{label}: actionable technical findings require overall Issue verdict")
    if actionable and row.get("disposition") != "cleanup_operation":
        errors.append(
            f"{label}: actionable technical findings require one exact cleanup operation"
        )
    for finding_key in actionable:
        linked_defects = [
            defect
            for defect in as_list(row.get("defects"))
            if finding_key in as_list(defect.get("technical_finding_keys"))
        ]
        if len(linked_defects) != 1:
            errors.append(
                f"{label}: actionable technical finding {finding_key} must link to exactly "
                "one source-bound defect"
            )
    return errors


def validate_defects(row: dict[str, Any], label: str) -> list[str]:
    defects = as_list(row.get("defects"))
    verdict = row.get("correctness_verdict")
    if verdict == "Issue" and not defects:
        return [f"{label}: Issue verdict requires at least one concrete defect"]
    if verdict == "Correct" and defects:
        return [f"{label}: Correct verdict cannot contain defects"]
    errors: list[str] = []
    available = set(as_list(row.get("available_evidence_anchors")))
    line_hashes = set(as_list(row.get("required_code_line_hashes")))
    technical_finding_keys = {
        str(item.get("finding_key") or "")
        for item in as_list(row.get("required_technical_findings"))
        if isinstance(item, dict) and item.get("finding_key")
    }
    seen: set[str] = set()
    for index, defect in enumerate(defects, start=1):
        defect_id = str(defect.get("defect_id") or "")
        prefix = f"{label}: defect {index}"
        if not defect_id or defect_id in seen:
            errors.append(f"{prefix} requires a unique defect_id")
        seen.add(defect_id)
        for field in ("statement", "configured_effect", "expected_behavior"):
            if not specific_text(defect.get(field), 5):
                errors.append(f"{prefix} has incomplete {field}")
        anchors = {str(value) for value in as_list(defect.get("evidence_anchors"))}
        code_evidence = {str(value) for value in as_list(defect.get("code_line_hashes"))}
        linked_technical_findings = [
            str(value) for value in as_list(defect.get("technical_finding_keys"))
        ]
        if len(linked_technical_findings) != len(set(linked_technical_findings)):
            errors.append(f"{prefix} contains duplicate technical_finding_keys")
        for finding_key in sorted(
            set(linked_technical_findings) - technical_finding_keys
        ):
            errors.append(
                f"{prefix} references unknown technical finding {finding_key!r}"
            )
        if not anchors and not code_evidence:
            errors.append(f"{prefix} has no source evidence")
        for anchor in sorted(anchors - available):
            errors.append(f"{prefix} references unknown anchor {anchor!r}")
        for line_hash in sorted(code_evidence - line_hashes):
            errors.append(f"{prefix} references unknown code line hash {line_hash!r}")
    return errors


VALID_LOGIC_ROLES = {
    "Input",
    "Condition",
    "Transformation",
    "Output",
    "Routing",
    "Consent",
    "Execution control",
    "Metadata",
    "Not applicable",
}


def validate_configuration_branch(
    path: str, source: dict[str, Any], review: dict[str, Any], label: str
) -> tuple[str, list[str]]:
    errors: list[str] = []
    if review.get("value_hash") != source["value_hash"]:
        errors.append(f"{label}: branch value hash differs from source at {path}")
    logic_role = str(review.get("logic_role") or "")
    if logic_role not in VALID_LOGIC_ROLES:
        errors.append(f"{label}: invalid logic role at {path}")
    required_role = branch_required_role(path)
    if required_role and logic_role != required_role:
        errors.append(f"{label}: branch {path} must be classified as {required_role}")
    for field in ("interpretation", "configured_effect"):
        if not specific_text(review.get(field), 5):
            errors.append(f"{label}: {field} is not concrete at {path}")
    branch_text = " ".join(
        str(review.get(field) or "") for field in ("interpretation", "configured_effect")
    ).lower()
    tokens = branch_specificity_tokens(source)
    if tokens and not any(token in branch_text for token in tokens):
        errors.append(
            f"{label}: branch explanation does not identify its configured value at {path}"
        )
    effect_terms = BRANCH_EFFECT_TERMS.get(logic_role, ())
    configured_effect = str(review.get("configured_effect") or "").lower()
    if effect_terms and not any(term in configured_effect for term in effect_terms):
        errors.append(
            f"{label}: configured effect at {path} does not explain its {logic_role} behavior"
        )
    verdict = str(review.get("correctness") or "")
    if verdict not in VALID_BRANCH_VERDICTS:
        errors.append(f"{label}: invalid branch correctness at {path}")
    return verdict, errors


def branch_outcome_errors(
    row: dict[str, Any], issue_paths: set[str], unclear_paths: set[str], label: str
) -> list[str]:
    errors: list[str] = []
    if issue_paths and row.get("correctness_verdict") != "Issue":
        errors.append(f"{label}: branch issues require an overall Issue verdict")
    topics = {
        str(item.get("topic_key") or ""): item
        for item in as_list(row.get("required_contract_topics"))
        if isinstance(item, dict)
    }
    runtime_unclear_paths = {
        str(anchor)
        for check in as_list(row.get("contract_checks"))
        if isinstance(check, dict)
        and check.get("verdict") == "Unproven"
        and topics.get(str(check.get("contract_topic") or ""), {}).get(
            "deterministic_contract_state"
        )
        == "unproven_from_container"
        for anchor in as_list(check.get("evidence_anchors"))
    }
    runtime_only_unclear = (
        bool(unclear_paths)
        and unclear_paths <= runtime_unclear_paths
        and row.get("external_evidence_status") == "runtime_handoff_required"
    )
    if unclear_paths and not runtime_only_unclear and row.get("correctness_verdict") not in {
        "Owner decision needed",
        "Container evidence limit",
        "Issue",
    }:
        errors.append(f"{label}: unclear branches require an unresolved overall verdict")
    defect_anchors = {
        str(anchor)
        for defect in as_list(row.get("defects"))
        for anchor in as_list(defect.get("evidence_anchors"))
    }
    if issue_paths - defect_anchors:
        errors.append(f"{label}: each branch issue must be linked to a concrete defect")
    return errors


def validate_configuration_branches(
    row: dict[str, Any], expected: dict[str, Any], label: str
) -> list[str]:
    required = {
        item["json_path"]: item for item in as_list(expected.get("required_branch_reviews"))
    }
    raw_supplied = as_list(row.get("configuration_branch_reviews"))
    supplied_rows = [
        item
        for item in raw_supplied
        if isinstance(item, dict)
    ]
    supplied = {
        str(item.get("json_path") or ""): item
        for item in supplied_rows
    }
    errors: list[str] = []
    if len(supplied_rows) != len(raw_supplied):
        errors.append(f"{label}: branch reviews contain malformed rows")
    if len(supplied) != len(supplied_rows) or "" in supplied:
        errors.append(f"{label}: branch review paths must be unique and nonblank")
    if set(supplied) != set(required):
        errors.append(f"{label}: branch reviews must cover every logic leaf exactly once")
    issue_paths: set[str] = set()
    unclear_paths: set[str] = set()
    for path, source in required.items():
        review = supplied.get(path)
        if not review:
            continue
        verdict, branch_errors = validate_configuration_branch(path, source, review, label)
        errors.extend(branch_errors)
        if verdict == "Issue":
            issue_paths.add(path)
        elif verdict == "Unclear":
            unclear_paths.add(path)
    errors.extend(branch_outcome_errors(row, issue_paths, unclear_paths, label))
    return errors


def validate_operation(
    row: dict[str, Any],
    valid_keys: set[str],
    label: str,
    expected_consumers: dict[str, set[str]],
    source_paths_by_key: dict[str, str],
) -> list[str]:
    operation = row.get("operation")
    if row.get("disposition") != "cleanup_operation":
        return (
            [f"{label}: non-operation disposition cannot contain operation data"]
            if operation
            else []
        )
    if not isinstance(operation, dict):
        return [f"{label}: cleanup disposition requires a structured operation"]
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
        minimum = 2 if field in {"area", "problem_type"} else 3
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


def validate_review_identity(
    supplied: dict[str, Any],
    expected: dict[str, Any],
    expected_context: dict[str, Any],
    source_sha256: str,
) -> list[str]:
    checks = (
        ("source_sha256", source_sha256, "source_sha256 does not match the export"),
        ("kind", "gtm_configuration_correctness_review", "kind is invalid"),
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
        f"configuration review {message}"
        for field, expected_value, message in checks
        if supplied.get(field) != expected_value
    ]


def configuration_row_sets(
    supplied: dict[str, Any], expected: dict[str, Any]
) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]], list[str]]:
    expected_by_key = {row["object_key"]: row for row in expected["rows"]}
    raw_supplied_rows = as_list(supplied.get("rows"))
    supplied_rows = [row for row in raw_supplied_rows if isinstance(row, dict)]
    supplied_by_key = {
        str(row.get("object_key") or ""): row for row in as_list(supplied.get("rows"))
        if isinstance(row, dict)
    }
    errors: list[str] = []
    if len(supplied_rows) != len(raw_supplied_rows):
        errors.append("configuration review contains malformed object rows")
    if len(supplied_by_key) != len(supplied_rows) or "" in supplied_by_key:
        errors.append("configuration rows must use unique nonblank object keys")
    missing = sorted(set(expected_by_key) - set(supplied_by_key))
    unknown = sorted(set(supplied_by_key) - set(expected_by_key))
    if missing:
        errors.append("missing configuration rows: " + ", ".join(missing))
    if unknown:
        errors.append("unknown configuration rows: " + ", ".join(unknown))
    return expected_by_key, supplied_by_key, errors


def validate_row_identity_and_evidence(
    row: dict[str, Any], expected_row: dict[str, Any], label: str
) -> list[str]:
    errors = [
        f"{label}: generated field {field} differs from source"
        for field in GENERATED_FIELDS
        if row.get(field) != expected_row.get(field)
    ]
    for field, valid, message in (
        ("review_status", {"complete"}, "review_status must be complete"),
        ("correctness_verdict", VALID_VERDICTS, "correctness_verdict is invalid"),
        ("disposition", VALID_DISPOSITIONS, "disposition is invalid"),
        ("confidence", VALID_CONFIDENCE, "confidence is invalid"),
    ):
        if row.get(field) not in valid:
            errors.append(f"{label}: {message}")
    errors.extend(review_text_errors(row, label))
    available = set(expected_row["available_evidence_anchors"])
    anchors = {str(value) for value in as_list(row.get("evidence_anchors"))}
    if not anchors:
        errors.append(f"{label}: no source evidence anchors")
    errors.extend(
        f"{label}: unknown evidence anchor {anchor!r}"
        for anchor in sorted(anchors - available)
    )
    missing_logic = set(expected_row["required_logic_anchors"]) - anchors
    if missing_logic:
        errors.append(f"{label}: {len(missing_logic)} logic branches lack evidence")
    expected_consumers = {
        str(item.get("consumer_key") or "") for item in expected_row["export_consumers"]
    }
    supplied_consumers = {
        str(value) for value in as_list(row.get("consumer_evidence_keys"))
    }
    if supplied_consumers != expected_consumers:
        errors.append(f"{label}: consumer evidence must exactly match the source graph")
    return errors


def direct_unique_reference_repairs(row: dict[str, Any]) -> list[dict[str, Any]]:
    repairs: list[dict[str, Any]] = []
    for trace in as_list(row.get("reference_trace_requirements")):
        paths = [
            str(value)
            for value in as_list(trace.get("source_reference_paths"))
            if str(value)
        ]
        for terminal in as_list(trace.get("terminal_requirements")):
            candidates = [
                str(value)
                for value in as_list(terminal.get("normalization_candidate_names"))
                if str(value)
            ]
            if (
                terminal.get("state") == "missing"
                and not str(terminal.get("source_object_key") or "")
                and terminal.get("normalization_resolution") == "unique"
                and len(candidates) == 1
                and paths
            ):
                repairs.append(
                    {
                        "reference": str(terminal.get("reference") or ""),
                        "replacement": candidates[0],
                        "source_reference_paths": paths,
                    }
                )
    return repairs


def reference_repair_is_the_only_known_issue(row: dict[str, Any]) -> bool:
    repairs = direct_unique_reference_repairs(row)
    if not repairs:
        return False
    missing_terminals = [
        terminal
        for trace in as_list(row.get("reference_trace_requirements"))
        for terminal in as_list(trace.get("terminal_requirements"))
        if terminal.get("state") == "missing"
        and not str(terminal.get("source_object_key") or "")
    ]
    if len(missing_terminals) != len(repairs):
        return False
    if any(
        obligation.get("required_outcome") == "Issue"
        for obligation in as_list(row.get("required_configuration_obligations"))
    ):
        return False
    if any(
        check.get("verdict") == "Non-compliant"
        for check in as_list(row.get("contract_checks"))
    ):
        return False
    return not any(
        review.get("verdict") in {"Confirmed issue", "Cleanup opportunity"}
        for review in as_list(row.get("technical_finding_reviews"))
    )


def reference_repair_operation_errors(
    row: dict[str, Any], label: str
) -> list[str]:
    operation = row.get("operation") or {}
    changes = as_list(operation.get("changes"))
    errors: list[str] = []
    for repair in direct_unique_reference_repairs(row):
        before_token = "{{" + repair["reference"] + "}}"
        after_token = "{{" + repair["replacement"] + "}}"
        matched = any(
            str(change.get("object_key") or "") == str(row.get("object_key") or "")
            and str(change.get("json_path") or "")
            in set(repair["source_reference_paths"])
            and before_token in str(change.get("before") or "")
            and after_token in str(change.get("after") or "")
            for change in changes
        )
        if not matched:
            errors.append(
                f"{label}: source-known reference repair {repair['reference']!r} -> "
                f"{repair['replacement']!r} requires one exact field change at its "
                "recorded source path"
            )
    return errors


def source_known_document_write_errors(
    row: dict[str, Any], label: str
) -> list[str]:
    obligation = next(
        (
            item
            for item in as_list(row.get("required_configuration_obligations"))
            if item.get("obligation_key")
            in {
                "unused_document_write_support",
                "document_write_support_missing",
            }
        ),
        None,
    )
    if not obligation:
        return []
    repair = obligation.get("source_known_repair") or {}
    if row.get("disposition") != "cleanup_operation":
        return [
            f"{label}: the exported document.write support mismatch has a "
            "source-known target and requires an exact cleanup operation"
        ]
    operation = row.get("operation") or {}
    mutations = [
        *as_list(operation.get("changes")),
        *as_list(operation.get("additions")),
    ]
    if not any(
        str(item.get("object_key") or "") == str(row.get("object_key") or "")
        and str(item.get("json_path") or "") == str(repair.get("json_path") or "")
        and (
            (
                repair.get("mode") == "change"
                and str(item.get("before") or "")
                == str(repair.get("before") or "")
                and str(item.get("after") or "")
                == str(repair.get("after") or "")
            )
            or (
                repair.get("mode") == "append"
                and item.get("mode") == "append"
                and item.get("value") == repair.get("value")
            )
        )
        for item in mutations
    ):
        return [
            f"{label}: document.write support cleanup must set the exact exported "
            "support field to the source-known target"
        ]
    return []


def validate_row_outcome(row: dict[str, Any], label: str) -> list[str]:
    errors: list[str] = []
    if row.get("disposition") == "owner_decision_needed" and not precise_question(
        row.get("owner_question"), 5
    ):
        errors.append(f"{label}: owner decision requires one precise question")
    if row.get("disposition") in {
        "owner_decision_needed",
        "container_evidence_limit",
    } and not specific_text(row.get("recommended_action"), 6):
        errors.append(
            f"{label}: unresolved outcome requires one concrete recommended_action"
        )
    expected_dispositions = {
        # A confirmed defect should normally become an operation. Some source-
        # proven defects still need an owner to choose the valid replacement
        # value; in that case the handoff must remain decision-ready and cite
        # the affected object plus exact defect evidence below.
        "Issue": {"cleanup_operation", "owner_decision_needed"},
        "Correct": {"keep"},
        "Owner decision needed": {"owner_decision_needed"},
        "Container evidence limit": {"container_evidence_limit"},
        "Not applicable": {"not_applicable"},
    }
    allowed = expected_dispositions.get(str(row.get("correctness_verdict") or ""))
    if allowed and row.get("disposition") not in allowed:
        errors.append(
            f"{label}: {row.get('correctness_verdict')} verdict has incompatible disposition"
        )
    if (
        row.get("correctness_verdict") == "Issue"
        and row.get("disposition") == "owner_decision_needed"
    ):
        recommendation = str(row.get("recommended_action") or "")
        lowered = recommendation.lower()
        object_terms = [
            str(row.get("object_key") or ""),
            str(row.get("object_name") or ""),
        ]
        defect_terms = [
            str(value)
            for defect in as_list(row.get("defects"))
            if isinstance(defect, dict)
            for value in [
                defect.get("defect_id"),
                *as_list(defect.get("evidence_anchors")),
            ]
            if str(value)
        ]
        if not any(term.lower() in lowered for term in object_terms if term):
            errors.append(
                f"{label}: unresolved Issue recommendation must name the affected object"
            )
        if defect_terms and not any(
            term.lower() in lowered for term in defect_terms
        ):
            errors.append(
                f"{label}: unresolved Issue recommendation must cite a defect ID or "
                "exact evidence anchor"
            )
        if not re.search(
            r"\b(?:correct|delete|disable|fix|remap|remove|repair|replace|"
            r"reconfigure|restore|split)\b",
            lowered,
        ):
            errors.append(
                f"{label}: unresolved Issue recommendation must state a concrete "
                "remediation action"
            )
    if (
        row.get("correctness_verdict") == "Issue"
        and reference_repair_is_the_only_known_issue(row)
    ):
        if row.get("disposition") != "cleanup_operation":
            errors.append(
                f"{label}: every missing reference has one exact "
                "Unicode/whitespace-equivalent source target, so the repair must be "
                "an exact cleanup operation rather than an owner decision"
            )
        else:
            errors.extend(reference_repair_operation_errors(row, label))
    errors.extend(source_known_document_write_errors(row, label))
    if row.get("correctness_verdict") == "Container evidence limit":
        boundary = " ".join(
            str(row.get(field) or "")
            for field in ("correctness_basis", "owner_question")
        ).lower()
        if not precise_question(row.get("owner_question"), 5) or not any(
            term in boundary for term in ("not visible", "unseen", "external", "runtime")
        ):
            errors.append(
                f"{label}: container evidence limit must name the precise unseen evidence"
            )
    return errors


def validate_external_evidence_boundary(
    row: dict[str, Any], label: str
) -> list[str]:
    """Keep runtime proof separate from the container-visible verdict."""

    topics = {
        str(item.get("topic_key") or ""): item
        for item in as_list(row.get("required_contract_topics"))
        if isinstance(item, dict)
    }
    runtime_contracts = []
    blocking_contracts = []
    for check in as_list(row.get("contract_checks")):
        if not isinstance(check, dict) or check.get("verdict") != "Unproven":
            continue
        topic_key = str(check.get("contract_topic") or "")
        topic = topics.get(topic_key) or {}
        target = (
            runtime_contracts
            if topic.get("deterministic_contract_state") == "unproven_from_container"
            else blocking_contracts
        )
        target.append(topic_key)

    technical_limits = [
        str(value)
        for value in as_list(
            (row.get("technical_code_facts") or {}).get("container_evidence_limits")
        )
        if str(value)
        and not str(value).startswith("No material external behavior")
        and "does not expose executable behavior" not in str(value).lower()
    ]
    runtime_required = bool(runtime_contracts or technical_limits)
    status = str(row.get("external_evidence_status") or "")
    errors: list[str] = []
    if status not in VALID_EXTERNAL_EVIDENCE_STATUSES:
        errors.append(f"{label}: external_evidence_status is invalid")
    if runtime_required and status != "runtime_handoff_required":
        errors.append(
            f"{label}: runtime-only proof must be recorded as a separate runtime handoff"
        )
    if not runtime_required and status != "none":
        errors.append(
            f"{label}: runtime handoff is declared without a generated external boundary"
        )
    if runtime_required:
        if not specific_text(row.get("external_evidence_summary"), 7):
            errors.append(
                f"{label}: runtime handoff requires a concise, source-specific boundary"
            )
        if not specific_text(row.get("external_evidence_next_action"), 7):
            errors.append(
                f"{label}: runtime handoff requires one exact next test action"
            )
        if (
            not blocking_contracts
            and row.get("correctness_verdict") == "Container evidence limit"
        ):
            errors.append(
                f"{label}: runtime-only uncertainty cannot replace the container-visible "
                "correctness verdict; conclude the exported configuration and keep the "
                "runtime test in the separate handoff"
            )
    elif any(
        str(row.get(field) or "").strip()
        for field in ("external_evidence_summary", "external_evidence_next_action")
    ):
        errors.append(f"{label}: external evidence text is present without a handoff")
    return errors


def validate_configuration_row(
    row: dict[str, Any],
    expected_row: dict[str, Any],
    valid_keys: set[str],
    source_consumer_map: dict[str, set[str]],
    source_paths_by_key: dict[str, str],
) -> list[str]:
    label = f"configuration {expected_row['object_key']}"
    errors = validate_row_identity_and_evidence(row, expected_row, label)
    validators = (
        lambda: validate_reference_traces(row, expected_row, label),
        lambda: validate_configuration_branches(row, expected_row, label),
        lambda: validate_contract_checks(row, label),
        lambda: validate_code_blocks(row, label),
        lambda: validate_technical_findings(row, label),
        lambda: validate_logic_cross_checks(row, label),
        lambda: validate_required_configuration_obligations(row, label),
        lambda: validate_defects(row, label),
        lambda: validate_operation(
            row,
            valid_keys,
            label,
            source_consumer_map,
            source_paths_by_key,
        ),
        lambda: validate_external_evidence_boundary(row, label),
        lambda: validate_row_outcome(row, label),
    )
    for validator in validators:
        errors.extend(validator())
    return errors


def validate_identical_code_decisions(rows: list[dict[str, Any]]) -> list[str]:
    """Require one technical disposition for identical code unless consumers differ."""

    groups: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        code_hash = str((row.get("technical_code_facts") or {}).get("code_hash") or "")
        if code_hash and as_list(row.get("required_technical_findings")):
            groups.setdefault(code_hash, []).append(row)

    errors: list[str] = []
    for code_hash, group in sorted(groups.items()):
        if len(group) < 2:
            continue

        def outcome_signature(row: dict[str, Any]) -> tuple[tuple[str, str, str, str], ...]:
            return tuple(
                sorted(
                    (
                        " ".join(str(item.get("source_statement") or "").lower().split()),
                        str(item.get("verdict") or ""),
                        " ".join(str(item.get("proposed_action") or "").lower().split()),
                        " ".join(str(item.get("exception_basis") or "").lower().split()),
                    )
                    for item in as_list(row.get("technical_finding_reviews"))
                    if isinstance(item, dict)
                )
            )

        signatures = {outcome_signature(row) for row in group}
        if len(signatures) == 1:
            continue
        for row in group:
            label = f"configuration {row.get('object_key')}"
            basis = str(row.get("consumer_specific_code_basis") or "")
            consumer_keys = [
                str(item.get("consumer_key") or "")
                for item in as_list(row.get("export_consumers"))
                if str(item.get("consumer_key") or "")
            ]
            if (
                not specific_text(basis, 8)
                or not consumer_keys
                or not any(key.lower() in basis.lower() for key in consumer_keys)
            ):
                errors.append(
                    f"{label}: code hash {code_hash} has a different technical outcome "
                    "from identical code without a source-specific consumer reason"
                )
    return errors


def validate_review(export_path: Path, review_path: Path) -> tuple[list[str], list[str]]:
    supplied = json.loads(review_path.read_text(encoding="utf-8"))
    expected_context, expected_shared = canonical_review_facts(export_path, supplied)
    expected = scaffold_review(export_path, shared_facts=expected_shared)
    errors: list[str] = []
    warnings: list[str] = []
    descriptor = source_descriptor(export_path)
    valid_keys = object_keys(export_path)
    source_consumer_map = object_consumer_map(export_path)
    source_paths_by_key = object_source_path_map(export_path)
    errors.extend(
        validate_review_identity(
            supplied, expected, expected_context, descriptor["source_sha256"]
        )
    )
    errors.extend(validate_review_provenance(supplied, expected, "configuration review"))
    expected_by_key, supplied_by_key, set_errors = configuration_row_sets(
        supplied, expected
    )
    errors.extend(set_errors)
    for key, expected_row in expected_by_key.items():
        row = supplied_by_key.get(key)
        if not row:
            continue
        errors.extend(
            validate_configuration_row(
                row,
                expected_row,
                valid_keys,
                source_consumer_map,
                source_paths_by_key,
            )
        )
    errors.extend(validate_identical_code_decisions(list(supplied_by_key.values())))
    return errors, warnings


def write_json(path: Path, payload: dict[str, Any], pretty: bool) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2 if pretty else None) + "\n",
        encoding="utf-8",
    )


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
        print(json.dumps({"output": str(args.output), "objects": len(payload["rows"])}))
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
