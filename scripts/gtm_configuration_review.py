#!/usr/bin/env python3
"""Extract internal configuration candidate evidence.

This module is an implementation component of the canonical v2.2 scan.  The
standalone v1 review command was deliberately removed.
"""

from __future__ import annotations

import json
import re
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
)
from gtm_configuration_review_groups import (
    behavior_review_groups,
    coverage_metrics,
    deterministic_branch_reviews,
    deterministic_reference_traces,
    semantic_summaries,
    structured_logic_reviews,
)
from gtm_consent_model import server_route_hosts
from gtm_custom_code_extract import extract_export
from gtm_lib import (
    CONSENT_INITIALIZATION_TRIGGER_ID,
    ID_KEYS,
    as_list,
    behavior_projection,
    container_root_path,
    container_version,
    custom_template_executable_code,
    custom_template_ids,
    custom_template_type_index,
    refs,
    source_descriptor,
    source_integrity_findings,
    stable_hash,
    walk_json_fields,
)
from gtm_relationships import trigger_conditions
from gtm_requirement_evidence import object_requirement_links
from gtm_shared_facts import build_shared_facts
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
    "gtagConfig",
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
    "field_evidence_paths",
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
    "minimum_semantic_review_depth",
    "semantic_review_basis",
    "behavior_review_groups",
    "configuration_coverage_metrics",
    "purpose",
    "execution_logic",
    "inputs_and_terminal_sources",
    "configured_output_or_side_effect",
    "consumer_contract",
    "consent_and_sequence",
    "evidence_citations",
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
    "Optimisation opportunity",
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
    "origin with substring matching",
    "postmessage payload directly into datalayer",
    "unencrypted http://",
    "literal cookie set/update omits",
    "dynamic cookie set/update omits",
    "cookie duration multiplies the declared day count",
    "literal secret-like credential candidate",
    "recursively schedules settimeout",
    "missing input becomes the literal string 'undefined'",
    "name promises an hour value",
)
TECHNICAL_EVIDENCE_BOUNDARY_MARKERS = (
    "no code body was exported",
    "no reviewable executable behavior",
    "literal api-key candidate",
    "cookie deletion has no source-proven matching set/update scope",
)
MATERIAL_REVIEW_SIGNAL_CLOSURE_TERMS: tuple[
    tuple[str, tuple[str, ...]], ...
] = (
    ("registers browser event listeners", ("guard", "remove", "once", "trigger scope")),
    ("writes shared window-level state", ("namespace", "consumer", "guard", "dependency")),
    ("reads the page dom", ("selector", "route", "fallback", "missing element")),
    ("changes the page dom", ("selector", "route", "scope", "visitor input")),
    ("calls gtag() directly", ("destination", "native google", "routing", "consent")),
    ("writes html into the page", ("visitor", "trusted", "escaped", "static html")),
    ("uses cookies or browser storage", ("consent", "cookie", "storage key", "sensitive")),
    ("mixed or unproven return types", ("fallback", "undefined", "return type", "consumer")),
    ("hardcoded container, destination", ("environment", "destination", "portable", "approved id")),
    ("creates or changes script urls", ("trusted", "allowlist", "static", "approved host")),
)
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
def consent_initialization_trigger_ids(cv: dict[str, Any]) -> set[str]:
    """Return system and exported filtered Consent Initialization routes.

    A container may intentionally use a regional/language-scoped
    ``CONSENT_INIT`` trigger instead of the global system route.  Trigger type,
    not one hard-coded identifier, is the evidence that establishes timing.
    """

    trigger_ids = {CONSENT_INITIALIZATION_TRIGGER_ID}
    for trigger in as_list(cv.get("trigger")):
        trigger_type = re.sub(
            r"[^A-Z0-9]+", "_", str(trigger.get("type") or "").upper()
        ).strip("_")
        if trigger_type not in {"CONSENT_INIT", "CONSENT_INITIALIZATION"}:
            continue
        trigger_id = str(trigger.get("triggerId") or "").strip()
        if trigger_id:
            trigger_ids.add(trigger_id)
    return trigger_ids
CONSENT_TEMPLATE_API_NAMES = (
    "setDefaultConsentState",
    "updateConsentState",
    "setConsentSettings",
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


def javascript_scope_map(code: str) -> tuple[list[int], list[bool]]:
    """Return lexical brace-scope IDs and code membership for each offset.

    A unique ID per brace scope prevents a guard in a sibling block or nested
    helper function from being mistaken for a guard that dominates the actual
    ``.includes`` call.
    """

    scope_ids = [0] * (len(code) + 1)
    is_code = [True] * (len(code) + 1)
    scope_stack = [0]
    next_scope_id = 1
    state = "code"
    quote = ""
    escaped = False
    index = 0
    while index < len(code):
        scope_ids[index] = scope_stack[-1]
        char = code[index]
        next_char = code[index + 1] if index + 1 < len(code) else ""
        if state == "line_comment":
            is_code[index] = False
            if char in "\r\n":
                state = "code"
            index += 1
            continue
        if state == "block_comment":
            is_code[index] = False
            if char == "*" and next_char == "/":
                is_code[index + 1] = False
                scope_ids[index + 1] = scope_stack[-1]
                index += 2
                state = "code"
                continue
            index += 1
            continue
        if state == "string":
            is_code[index] = False
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                state = "code"
            index += 1
            continue
        if char == "/" and next_char == "/":
            is_code[index] = False
            is_code[index + 1] = False
            scope_ids[index + 1] = scope_stack[-1]
            index += 2
            state = "line_comment"
            continue
        if char == "/" and next_char == "*":
            is_code[index] = False
            is_code[index + 1] = False
            scope_ids[index + 1] = scope_stack[-1]
            index += 2
            state = "block_comment"
            continue
        if char in {"'", '"', "`"}:
            is_code[index] = False
            quote = char
            state = "string"
            index += 1
            continue
        if char == "{":
            scope_stack.append(next_scope_id)
            next_scope_id += 1
        elif char == "}":
            if len(scope_stack) > 1:
                scope_stack.pop()
        index += 1
    scope_ids[len(code)] = scope_stack[-1]
    return scope_ids, is_code


def local_includes_is_guarded(
    code: str,
    assignment_end: int,
    includes_start: int,
    local_name: str,
    scope_ids: list[int],
    code_positions: list[bool],
) -> bool:
    """Recognize only a guard that dominates one local ``.includes`` call.

    This deliberately prefers a review finding over accepting a guard inside a
    conditional branch, nested function, comment, or unrelated expression.
    """

    escaped = re.escape(local_name)
    use_scope = scope_ids[includes_start]
    before_use = code[assignment_end:includes_start]

    def source_dominating(match: re.Match[str]) -> bool:
        absolute = assignment_end + match.start()
        return code_positions[absolute] and scope_ids[absolute] == use_scope

    def unsafe_reassignment_after(match_end: int) -> bool:
        tail = before_use[match_end:]
        safe_assignment = re.compile(
            rf"\b{escaped}\s*=\s*(?:"
            rf"String\s*\(\s*{escaped}\s*(?:\|\||\?\?)|"
            rf"{escaped}\s*(?:\|\||\?\?)\s*['\"]|"
            rf"Array\.isArray\s*\(\s*{escaped}\s*\)\s*\?\s*{escaped}\s*:\s*\[|"
            rf"['\"]|\[\s*\])",
            re.I,
        )
        for reassignment in re.finditer(
            rf"\b{escaped}\s*(?:=(?!=)|\+=|-=|\*=|/=|\?\?=|\|\|=)",
            tail,
        ):
            absolute = assignment_end + match_end + reassignment.start()
            if not code_positions[absolute] or scope_ids[absolute] != use_scope:
                continue
            if safe_assignment.match(tail, reassignment.start()):
                continue
            return True
        return False

    short_circuit = re.search(
        rf"(?:\b{escaped}\b|"
        rf"typeof\s+{escaped}\s*===?\s*['\"]string['\"]|"
        rf"Array\.isArray\s*\(\s*{escaped}\s*\))\s*&&\s*$",
        before_use,
        re.I,
    )
    if (
        short_circuit
        and source_dominating(short_circuit)
        and not unsafe_reassignment_after(short_circuit.end())
    ):
        return True

    patterns = (
        rf"if\s*\(\s*!\s*{escaped}\s*\)\s*"
        rf"(?:\{{\s*)?return\b[^;{{}}]*;?\s*(?:\}})?",
        rf"if\s*\(\s*typeof\s+{escaped}\s*!==?\s*['\"]string['\"]\s*\)\s*"
        rf"\{{[^{{}}]*\breturn\b[^{{}}]*\}}",
        rf"if\s*\(\s*typeof\s+{escaped}\s*!==?\s*['\"]string['\"]\s*&&\s*"
        rf"!\s*Array\.isArray\s*\(\s*{escaped}\s*\)\s*\)\s*"
        rf"\{{[^{{}}]*\b{escaped}\s*=\s*\[\s*\][^{{}}]*\}}",
        rf"\b{escaped}\s*=\s*String\s*\(\s*{escaped}\s*(?:\|\||\?\?)",
        rf"\b{escaped}\s*=\s*{escaped}\s*(?:\|\||\?\?)\s*['\"]",
        rf"\b{escaped}\s*=\s*Array\.isArray\s*\(\s*{escaped}\s*\)\s*"
        rf"\?\s*{escaped}\s*:\s*\[\s*\]",
    )
    return any(
        source_dominating(match) and not unsafe_reassignment_after(match.end())
        for pattern in patterns
        for match in re.finditer(pattern, before_use, re.I | re.S)
    )


def has_executable_consent_call(
    code: str, *, template_code: bool, default_only: bool
) -> bool:
    """Require a real consent API call, not a name in prose or a declaration."""

    if not code.strip():
        return False
    _scope_ids, code_positions = javascript_scope_map(code)
    patterns = [
        re.compile(
            r"\bgtag\s*\(\s*['\"]consent['\"]"
            + (r"\s*,\s*['\"]default['\"]" if default_only else ""),
            re.I,
        )
    ]
    if template_code:
        api_names = (
            ("setDefaultConsentState",)
            if default_only
            else CONSENT_TEMPLATE_API_NAMES
        )
        imported_names = {
            api
            for api in api_names
            if re.search(
                rf"\brequire\s*\(\s*['\"]{re.escape(api)}['\"]\s*\)",
                code,
            )
        }
        patterns.extend(
            re.compile(rf"\b{re.escape(api)}\s*\(", re.I)
            for api in imported_names
        )
    for pattern in patterns:
        for match in pattern.finditer(code):
            if not code_positions[match.start()]:
                continue
            prefix = code[max(0, match.start() - 40) : match.start()]
            if re.search(r"\bfunction\s*$", prefix, re.I):
                continue
            return True
    return False


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
    route = shared.get("effective_consent_route") or {}
    contract = shared.get("vendor_event_contract") or {}
    if (
        as_list(contract.get("destinations"))
        or as_list(route.get("server_routing_hosts"))
        or as_list(shared.get("destination_peer_contexts"))
    ):
        definitions.append(
            (
                "destination_route_alignment",
                "Do the configured destination, transport route, peers, and inherited settings form one coherent delivery path?",
                (
                    "configured_output_or_side_effect",
                    "consumer_contract",
                    "consent_and_sequence",
                ),
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
                ".zoneid",
                ".gtagconfigid",
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
        transport_hosts = set(server_route_hosts(obj))
        hosts = sorted(
            {
                (urlparse(match).hostname or "").casefold()
                for match in re.findall(r"https?://[^\s\"'<>\\)]+", serialized, re.I)
                if (urlparse(match).hostname or "")
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
            raw = value.get("value")
            if (
                key in {"parameter", "field"}
                and raw is not None
                and not isinstance(raw, (dict, list))
                and str(raw).strip()
            ):
                terms.add(str(raw).strip().lower())
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
            mapped = {
                str(item.get("key") or "").strip(): item.get("value")
                for item in as_list(value.get("map"))
                if isinstance(item, dict)
                and item.get("value") is not None
                and not isinstance(item.get("value"), (dict, list))
            }
            configured_name = str(
                mapped.get("parameter") or mapped.get("field") or ""
            ).strip().lower()
            if configured_name == target:
                paired = mapped.get("parameterValue", mapped.get("fieldValue"))
                if paired is not None:
                    values.append(str(paired))
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
            elif (
                context.get("research_dependency_key") and not context.get("official_docs")
            ) or (
                (
                    topic in runtime_topics
                    and (
                        refs(obj)
                        or (
                            layer == "variable"
                            and str(obj.get("type") or "").lower() not in {"c"}
                        )
                    )
                )
                or (
                    topic == "consent_and_timing"
                    and route_status
                    in {
                        "unproven_export_control",
                        "server_contract_unproven",
                        "blocker_control_candidate",
                        "consent_signal_review",
                        "unrecognized_consent_status",
                    }
                )
                or (
                    topic == "destination_or_server_routing"
                    and route_status == "server_contract_unproven"
                )
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
    cv: dict[str, Any],
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
            "zoneId",
            "gtagConfigId",
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

    def configured_parameter(value: dict[str, Any], key: str) -> Any:
        for parameter in as_list(value.get("parameter")):
            if not isinstance(parameter, dict) or str(parameter.get("key") or "") != key:
                continue
            for field in ("value", "list", "map"):
                if field in parameter:
                    return parameter.get(field)
        return None

    def executable_code(value: dict[str, Any]) -> str:
        return "\n".join(
            str(parameter.get("value") or "")
            for parameter in as_list(value.get("parameter"))
            if isinstance(parameter, dict)
            and str(parameter.get("key") or "") in {"html", "javascript"}
        )

    custom_templates = [
        item
        for item in as_list(cv.get("customTemplate"))
        if isinstance(item, dict)
    ]
    template_type_index = custom_template_type_index(custom_templates)
    templates_by_id = {
        str(template.get("templateId") or ""): template
        for template in custom_templates
        if str(template.get("templateId") or "")
    }

    def resolved_custom_template_code(value: dict[str, Any]) -> str:
        template_ids = custom_template_ids(value, template_type_index)
        if len(template_ids) != 1:
            return ""
        template = templates_by_id.get(template_ids[0])
        if not template:
            return ""
        return custom_template_executable_code(template.get("templateData"))

    def consent_behavior(value: dict[str, Any]) -> tuple[bool, bool]:
        behavior_text = behavior_bearing_vendor_text(value, layer)
        tag_code = executable_code(value)
        template_code = resolved_custom_template_code(value)
        vendor = vendor_record(behavior_text)
        manages = (
            str(vendor.get("category") or "") == "cmp"
            or has_executable_consent_call(
                tag_code, template_code=False, default_only=False
            )
            or has_executable_consent_call(
                template_code, template_code=True, default_only=False
            )
        )
        command = str(configured_parameter(value, "command") or "").strip().lower()
        sets_default = manages and (
            command == "default"
            or has_executable_consent_call(
                tag_code, template_code=False, default_only=True
            )
            or has_executable_consent_call(
                template_code, template_code=True, default_only=True
            )
        )
        return manages, sets_default

    variable_records = {
        str(variable.get("name") or ""): (index, variable)
        for index, variable in enumerate(as_list(cv.get("variable")))
        if str(variable.get("name") or "")
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
        document_write = bool(re.search(
            r"\bdocument\s*(?:\.\s*write|\[\s*['\"]write['\"]\s*\])\s*\(",
            html,
            re.I,
        ))
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
                        "mode": "change",
                        "object_key": str(shared.get("object_key") or ""),
                        "json_path": f"{own_prefix}.parameter",
                        "before": parameters,
                        "after": [
                            *parameters,
                            {
                                "type": "BOOLEAN",
                                "key": "supportDocumentWrite",
                                "value": "true",
                            },
                        ],
                    }
                )
        elif support_enabled and not document_write:
            add(
                "unused_document_write_support",
                "Review",
                (
                    "Custom HTML enables Support document.write and the direct exported "
                    "code scan found no document.write call. Code review must determine "
                    "whether an indirect call or generated code still requires it."
                ),
                [*support_anchors, *html_anchors],
                ("purpose_output_alignment", "custom_code_behavior_alignment"),
            )

    consent_initialization_ids = consent_initialization_trigger_ids(cv)
    firing_trigger_ids = {
        str(value) for value in as_list(obj.get("firingTriggerId"))
    }
    consent_initialization_routes = firing_trigger_ids & consent_initialization_ids
    if layer == "tag" and consent_initialization_routes:
        manages_consent, _sets_default = consent_behavior(obj)
        if not manages_consent:
            add(
                "consent_initialization_non_consent_tag",
                "Issue",
                (
                    "Tag uses a Consent Initialization execution route without "
                    "container-visible behavior that sets or updates consent state."
                ),
                anchors_for("firingTriggerId", *sorted(consent_initialization_routes)),
                ("execution_scope_alignment", "consent_sequence_alignment"),
                ("consent_and_timing",),
            )

    if layer == "tag":
        firing_ids = [str(value) for value in as_list(obj.get("firingTriggerId"))]
        _manages_consent, sets_default_consent = consent_behavior(obj)
        if sets_default_consent and not (
            set(firing_ids) & consent_initialization_ids
        ):
            add(
                "consent_default_wrong_initialization_trigger",
                "Issue",
                (
                    "Tag exports a default consent command but does not fire on the "
                    "system or an exported filtered Consent Initialization route, so "
                    "later tags can evaluate "
                    "before the default state is established."
                ),
                [
                    *anchors_for("command", "default", "setDefaultConsentState"),
                    *anchors_for("firingTriggerId"),
                ],
                ("execution_scope_alignment", "consent_sequence_alignment"),
                ("consent_and_timing",),
            )

    if layer in {"tag", "variable"}:
        code = executable_code(obj)
        scope_ids, code_positions = javascript_scope_map(code)
        for reference in sorted(refs(code)):
            record = variable_records.get(reference)
            if not record:
                continue
            variable_index, variable = record
            if str(variable.get("type") or "").lower() != "v":
                continue
            set_default = str(
                configured_parameter(variable, "setDefaultValue") or ""
            ).lower() == "true"
            if set_default:
                continue
            escaped_reference = re.escape(reference)
            direct_use = any(
                code_positions[match.start()]
                for match in re.finditer(
                    rf"\{{\{{\s*{escaped_reference}\s*\}}\}}\s*\.\s*includes\s*\(",
                    code,
                    re.I,
                )
            )
            assigned_uses: list[tuple[str, re.Match[str]]] = []
            for assignment in re.finditer(
                rf"\b(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*"
                rf"\{{\{{\s*{escaped_reference}\s*\}}\}}",
                code,
                re.I,
            ):
                if not code_positions[assignment.start()]:
                    continue
                local_name = assignment.group(1)
                calls = [
                    match
                    for match in re.finditer(
                        rf"\b{re.escape(local_name)}\s*\.\s*includes\s*\(",
                        code[assignment.end() :],
                        re.I,
                    )
                    if code_positions[assignment.end() + match.start()]
                ]
                if calls:
                    assigned_uses.append((local_name, assignment))
            unsafe_assigned = []
            for local_name, assignment in assigned_uses:
                calls = [
                    match
                    for match in re.finditer(
                        rf"\b{re.escape(local_name)}\s*\.\s*includes\s*\(",
                        code[assignment.end() :],
                        re.I,
                    )
                    if code_positions[assignment.end() + match.start()]
                ]
                if any(
                    not local_includes_is_guarded(
                        code,
                        assignment.end(),
                        assignment.end() + call.start(),
                        local_name,
                        scope_ids,
                        code_positions,
                    )
                    for call in calls
                ):
                    unsafe_assigned.append(local_name)
            if direct_use or unsafe_assigned:
                variable_prefix = f"{own_prefix.rsplit('.', 1)[0]}.variable[{variable_index}]"
                peer_anchors = [
                    path
                    for path in available
                    if path.startswith(variable_prefix)
                    and any(
                        token in path
                        for token in ("setDefaultValue", ".name", "dataLayerVersion")
                    )
                ]
                add(
                    f"nullable_dlv_includes:{stable_hash({'reference': reference})}",
                    "Issue",
                    (
                        f"Code calls .includes() on Data Layer Variable {reference!r}, "
                        "whose exported setDefaultValue is false, without a local null/type "
                        "guard; an absent dataLayer value throws before the consent result "
                        "can be returned."
                    ),
                    [
                        *anchors_for("html", "javascript", reference),
                        *peer_anchors,
                    ],
                    (
                        "input_output_consumer_alignment",
                        "custom_code_behavior_alignment",
                        "consent_sequence_alignment",
                    ),
                    ("consumer_value_shape_and_type", "consent_state_semantics"),
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
                    or (value_slot and STRONG_SECRET_NAME_RE.search(object_name))
                    or JWT_VALUE_RE.fullmatch(literal_value)
                    or PRIVATE_KEY_VALUE_RE.search(literal_value)
                )
                public_candidate = bool(
                    PUBLIC_KEY_CANDIDATE_FIELD_RE.fullmatch(configured_name)
                    or (
                        value_slot
                        and PUBLIC_KEY_CANDIDATE_NAME_RE.search(object_name)
                    )
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
                        (operator == "CONTAINS" and right not in equals_value)
                        or (operator == "DOES_NOT_CONTAIN" and right in equals_value)
                        or (operator == "STARTS_WITH" and not equals_value.startswith(right))
                        or (operator == "ENDS_WITH" and not equals_value.endswith(right))
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

    ecommerce_families = {
        "add_to_cart": {"add"},
        "remove_from_cart": {"remove"},
        "view_item": {"detail"},
        "view_item_list": {"impressions"},
        "select_item": {"impressions"},
        "begin_checkout": {"checkout"},
        "add_shipping_info": {"checkout"},
        "add_payment_info": {"checkout"},
        "purchase": {"purchase"},
        "refund": {"refund"},
    }
    configured_events = {
        value.strip().lower()
        for value in parameter_static_values(cv, obj, "eventName")
        if value.strip()
    }
    expected_families = set().union(
        *(ecommerce_families[event] for event in configured_events if event in ecommerce_families)
    ) if configured_events & ecommerce_families.keys() else set()
    if layer == "tag" and str(obj.get("type") or "").lower() == "gaawe" and expected_families:
        root_path = own_prefix.split(".tag[", 1)[0]
        for parameter_index, parameter in enumerate(as_list(obj.get("parameter"))):
            if not isinstance(parameter, dict) or str(parameter.get("key") or "") != "eventSettingsTable":
                continue
            for setting_index, setting in enumerate(as_list(parameter.get("list"))):
                if not isinstance(setting, dict):
                    continue
                setting_parameters = {"parameter": as_list(setting.get("map"))}
                setting_names = configured_field_values(
                    setting_parameters, "parameter"
                )
                setting_values = configured_field_values(
                    setting_parameters, "parameterValue"
                )
                setting_name = setting_names[0] if setting_names else "event parameter"
                for reference in sorted({name for value in setting_values for name in refs(value)}):
                    variable_record = variable_records.get(reference)
                    if not variable_record:
                        continue
                    variable_index, variable = variable_record
                    if str(variable.get("type") or "").lower() != "v":
                        continue
                    for data_layer_path in configured_field_values(variable, "name"):
                        match = re.search(r"(?:^|\.)ecommerce\.([A-Za-z0-9_]+)", data_layer_path, re.I)
                        if not match:
                            continue
                        observed_family = match.group(1).lower()
                        legacy_families = {
                            "add", "remove", "detail", "impressions", "checkout",
                            "purchase", "refund",
                        }
                        if observed_family not in legacy_families or observed_family in expected_families:
                            continue
                        setting_path = (
                            f"{own_prefix}.parameter[{parameter_index}]"
                            f".list[{setting_index}]"
                        )
                        variable_prefix = f"{root_path}.variable[{variable_index}]"
                        anchors = [
                            path
                            for path in available
                            if path.startswith(setting_path) or path.startswith(variable_prefix)
                        ]
                        key = (
                            "ecommerce_scope_mismatch:"
                            + stable_hash(
                                {
                                    "event": sorted(configured_events),
                                    "setting": setting_name,
                                    "reference": reference,
                                    "path": data_layer_path,
                                }
                            )
                        )
                        add(
                            key,
                            "Review",
                            (
                                f"GA4 event {', '.join(sorted(configured_events))!r} maps "
                                f"{setting_name!r} through {reference!r} to legacy dataLayer "
                                f"scope {data_layer_path!r}. Its {observed_family!r} path "
                                f"differs from the event's {', '.join(sorted(expected_families))!r} "
                                "family; review the parameter's source meaning before deciding "
                                "whether this is intentional or should change."
                            ),
                            anchors,
                            ("purpose_output_alignment", "input_output_consumer_alignment", "vendor_contract_alignment"),
                            ("ecommerce_event_contract", "transaction_value_currency_and_quantity"),
                        )
    return [obligations[key] for key in sorted(obligations)]


def simple_review_eligibility(
    row: dict[str, Any], obj: dict[str, Any]
) -> tuple[bool, list[str]]:
    """Select only source-provably simple objects after exhaustive fact acquisition."""

    layer = str(row.get("layer") or "")
    variable_type = str(obj.get("type") or "")
    allowed_shape = layer in {"folder", "builtInVariable"} or (
        layer == "variable" and variable_type in {"c", "v"}
    )
    reasons = [
        "complete source leaves and absence facts were collected",
        "recursive dependencies and consumers were collected",
    ]
    blockers: list[str] = []
    if not allowed_shape:
        blockers.append("object type requires deep semantic review")
    for field, message in (
        ("required_code_line_hashes", "custom or executable code is present"),
        ("required_technical_findings", "a technical finding is present"),
        ("required_contract_topics", "an official contract review is required"),
        ("required_configuration_obligations", "a configuration obligation is present"),
        ("reference_trace_requirements", "a recursive reference chain is present"),
        ("execution_dependency_traces", "execution dependencies are present"),
        ("destination_peer_contexts", "destination peer routing is present"),
        ("vendor_contexts", "vendor behavior context is present"),
        ("approved_requirement_links", "approved requirement context is present"),
    ):
        if as_list(row.get(field)):
            blockers.append(message)
    if len(as_list(row.get("export_consumers"))) > 4:
        blockers.append("the object is heavily shared")
    risk_text = " ".join(
        [
            str(row.get("object_name") or ""),
            str(row.get("object_type") or ""),
            *[
                str(fact.get("json_path") or "")
                + " "
                + str(fact.get("value_preview") or "")
                for fact in as_list(row.get("source_facts"))
                if isinstance(fact, dict)
            ],
        ]
    ).lower()
    if re.search(
        r"\b(?:consent|cmp|cookie|tcf|optanon|didomi|axeptio|secret|password|"
        r"authorization|private[ _-]?key|lookup|regex|formula|javascript|html)\b",
        risk_text,
    ):
        blockers.append("source content has consent, security, code, or formula risk")
    if blockers:
        return False, list(dict.fromkeys(blockers))
    reasons.extend(
        [
            "no code, contract, formula, consent, routing, or ambiguity signal is present",
            "consumer fan-out is below the high-sharing threshold",
        ]
    )
    return True, reasons


def scaffold_review(
    export_path: Path,
    technical_payload: dict[str, Any] | None = None,
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
            cv,
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
        row = {
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
                "approved_requirement_links": object_requirement_links(
                    obj,
                    str(shared.get("object_name") or obj.get("name") or ""),
                    requirement_evidence,
                ),
                "required_logic_cross_checks": [
                    {
                        key: value
                        for key, value in requirement.items()
                        if key != "required_terms"
                    }
                    for requirement in logic_requirements
                ]
                if not include_validator_answer_key
                else logic_requirements,
                "required_configuration_obligations": configuration_obligations,
                "minimum_semantic_review_depth": "",
                "semantic_review_basis": [],
                "behavior_review_groups": [],
                "configuration_coverage_metrics": {},
                "semantic_review_depth": "",
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
        eligible, review_basis = simple_review_eligibility(row, obj)
        row["minimum_semantic_review_depth"] = (
            "structured_simple" if eligible else "deep"
        )
        row["semantic_review_basis"] = review_basis
        row["semantic_review_depth"] = row["minimum_semantic_review_depth"]
        semantics, citations = semantic_summaries(row, evidence_requirements)
        row.update(
            {
                field: semantics[field]
                for field in SEMANTIC_TEXT_FIELDS
                if field != "correctness_basis"
            }
        )
        row["evidence_citations"] = citations
        if eligible:
            row["correctness_basis"] = semantics["correctness_basis"]
        row["configuration_branch_reviews"] = deterministic_branch_reviews(row)
        row["reference_traces"] = deterministic_reference_traces(row)
        row["behavior_review_groups"] = behavior_review_groups(row)
        row["configuration_coverage_metrics"] = coverage_metrics(row)
        row["logic_cross_checks"] = structured_logic_reviews(
            row["behavior_review_groups"],
            logic_requirements,
            str(row.get("object_name") or row.get("object_key") or "source object"),
        )
        if include_validator_answer_key:
            row["field_evidence_requirements"] = evidence_requirements
        rows.append(row)
    return {
        **descriptor,
        "kind": "gtm_configuration_correctness_review",
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
        "rows": rows,
    }
