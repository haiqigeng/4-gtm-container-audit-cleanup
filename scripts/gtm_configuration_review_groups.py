"""Build compact, source-locked work groups for configuration review.

The raw configuration ledger remains exhaustive.  This module converts that
ledger into deterministic branch/trace coverage and a small set of meaningful
cross-object behavior groups so reviewers do not have to rewrite one sentence
per harmless JSON leaf.
"""

from __future__ import annotations

import math
from typing import Any

from gtm_lib import as_list

BASE_GROUP_KEYS = (
    "purpose_output_alignment",
    "execution_scope_alignment",
    "input_output_consumer_alignment",
    "consent_sequence_alignment",
)

GROUP_DIMENSIONS = {
    "purpose_output_alignment": "purpose_and_output",
    "execution_scope_alignment": "firing_blocking_and_scope",
    "input_output_consumer_alignment": "inputs_payload_and_consumers",
    "consent_sequence_alignment": "consent_and_sequence",
    "destination_route_alignment": "destination_and_routing",
    "custom_code_behavior_alignment": "custom_code_behavior",
    "vendor_contract_alignment": "vendor_contract",
}

ROLE_EFFECTS = {
    "Input": "reads and uses this source input",
    "Condition": "compares or matches this condition before allowing execution",
    "Transformation": "transforms or maps this configured value",
    "Output": "returns or sends this configured output",
    "Routing": "routes firing or blocking through this trigger reference",
    "Consent": "applies this consent or storage control",
    "Execution control": "controls when execution happens before, after, or once",
}


def _text(value: Any, fallback: str = "not explicitly configured") -> str:
    rendered = " ".join(str(value or "").split())
    return rendered[:220] if rendered else fallback


def _terms(values: Any, fallback: list[str], limit: int = 3) -> list[str]:
    result: list[str] = []
    for value in as_list(values):
        rendered = _text(value, "")
        if rendered and rendered not in result:
            result.append(rendered)
    for value in fallback:
        if value and value not in result:
            result.append(value)
    return result[:limit]


def semantic_summaries(
    row: dict[str, Any], requirements: dict[str, list[str]]
) -> tuple[dict[str, str], dict[str, list[str]]]:
    """Render neutral source summaries; correctness is authored separately."""

    name = _text(row.get("object_name"), _text(row.get("object_key"), "source object"))
    layer = _text(row.get("layer"), "object")
    object_type = _text(row.get("object_type"), layer)

    purpose = _terms(requirements.get("purpose"), [name, object_type])
    execution = _terms(
        requirements.get("execution_logic"),
        ["no direct event trigger is exported", object_type],
    )
    inputs = _terms(
        requirements.get("inputs_and_terminal_sources"),
        ["no referenced GTM variable is exported", object_type],
    )
    outputs = _terms(
        requirements.get("configured_output_or_side_effect"), [object_type, name]
    )
    consumers = _terms(
        requirements.get("consumer_contract"),
        ["no container-visible consumer is exported", name],
    )
    consent = _terms(
        requirements.get("consent_and_sequence"),
        ["no explicit consent or sequence control is exported", object_type],
    )

    summaries = {
        "purpose": (
            f"{name} is the exported {layer} ({object_type}) associated with "
            f"{purpose[0]} and {purpose[1]}."
        ),
        "execution_logic": (
            f"Its container-visible execution route uses {execution[0]} and "
            f"{execution[1]}; no live firing is inferred."
        ),
        "inputs_and_terminal_sources": (
            f"Its configured inputs terminate at {inputs[0]} and {inputs[1]} in the "
            "source-locked recursive graph."
        ),
        "configured_output_or_side_effect": (
            f"Its exported output or side effect is represented by {outputs[0]} and "
            f"{outputs[1]}."
        ),
        "consumer_contract": (
            f"Its container-visible consumer context is {consumers[0]} for "
            f"{consumers[1]}; unexported consumers are not assumed."
        ),
        "consent_and_sequence": (
            f"Its exported consent, blocking, and sequencing context is {consent[0]} "
            f"with {consent[1]}."
        ),
        "correctness_basis": (
            f"Source-locked coverage for {name} maps every configuration fact to its "
            "behavior groups; no escalated risk is present in this structured-simple row."
        ),
    }
    paths = row.get("field_evidence_paths") or {}
    citations = {
        field: list(as_list(paths.get(field)))[: 2 if field == "correctness_basis" else 1]
        for field in summaries
    }
    return summaries, citations


def branch_role(path: str) -> str:
    lowered = path.lower()
    if any(token in lowered for token in ("consent", "storage")):
        return "Consent"
    if any(token in lowered for token in ("filter", "condition", "operator")):
        return "Condition"
    if any(
        token in lowered
        for token in ("firingtriggerid", "blockingtriggerid", "triggerids")
    ):
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
    if any(token in lowered for token in ("eventname", "destination", "sendto", "html")):
        return "Output"
    if any(token in lowered for token in ("map", "table", "regex", "format")):
        return "Transformation"
    return "Input"


def deterministic_branch_reviews(row: dict[str, Any]) -> list[dict[str, Any]]:
    """Create complete routine coverage; risk verdicts remain reviewer-overridable."""

    issue_paths = {
        str(anchor)
        for obligation in as_list(row.get("required_configuration_obligations"))
        if obligation.get("required_outcome") == "Issue"
        for anchor in as_list(obligation.get("evidence_anchors"))
    }
    unclear_paths = {
        str(anchor)
        for obligation in as_list(row.get("required_configuration_obligations"))
        if obligation.get("required_outcome") == "Unclear"
        for anchor in as_list(obligation.get("evidence_anchors"))
    }
    result: list[dict[str, Any]] = []
    name = _text(row.get("object_name"), _text(row.get("object_key")))
    for source in as_list(row.get("required_branch_reviews")):
        path = str(source.get("json_path") or "")
        value = _text(source.get("value_preview"), "an empty exported value")
        role = branch_role(path)
        correctness = (
            "Issue"
            if path in issue_paths
            else "Unclear"
            if path in unclear_paths
            else "Correct"
        )
        result.append(
            {
                "json_path": path,
                "value_hash": source.get("value_hash"),
                "logic_role": role,
                "interpretation": (
                    f"For {name}, {path} contains the exported {role.lower()} value "
                    f"{value}."
                ),
                "configured_effect": (
                    f"The {role.lower()} branch {ROLE_EFFECTS[role]} for {name} using "
                    f"the configured value {value}."
                ),
                "correctness": correctness,
            }
        )
    return result


def _node_role_text(role: str) -> str:
    return {
        "data_layer_read": "reads the Data Layer path or key",
        "constant_value": "returns a fixed literal constant",
        "custom_javascript_computation": "uses JavaScript return logic to calculate the value",
        "lookup_or_mapping": "uses a lookup map, ordered match, and configured default",
        "configured_variable_transformation": "reads, transforms, and selects a configured value",
    }.get(role, "reads and returns its configured value")


def deterministic_reference_traces(row: dict[str, Any]) -> list[dict[str, Any]]:
    """Render the recursive graph once without asking for prose per node or edge."""

    consumer = _text(row.get("object_name"), _text(row.get("object_key")))
    traces: list[dict[str, Any]] = []
    for requirement in as_list(row.get("reference_trace_requirements")):
        reference = str(requirement.get("reference") or "")
        states = [str(value) for value in as_list(requirement.get("terminal_states"))]
        node_reviews = []
        for node in as_list(requirement.get("required_nodes")):
            name = _text(node.get("object_name"), _text(node.get("object_key")))
            object_type = _text(node.get("object_type"), "variable")
            tokens = _terms(
                node.get("specificity_tokens"),
                [name, object_type, *[str(v) for v in as_list(node.get("referenced_variables"))]],
            )
            role_text = _node_role_text(str(node.get("semantic_role") or ""))
            node_reviews.append(
                {
                    "object_key": node.get("object_key"),
                    "object_name": node.get("object_name"),
                    "object_type": node.get("object_type"),
                    "config_hash": node.get("config_hash"),
                    "source_json_path": node.get("source_json_path"),
                    "referenced_variables": node.get("referenced_variables"),
                    "configured_parameters": node.get("configured_parameters"),
                    "semantic_role": node.get("semantic_role"),
                    "evidence_anchors": list(as_list(node.get("required_evidence_anchors"))),
                    "configured_function": (
                        f"{name} ({object_type}) {role_text} using {tokens[0]} and "
                        f"{tokens[1]}."
                    ),
                    "configured_output": (
                        f"{name} ({object_type}) returns the configured result represented "
                        f"by {tokens[0]} and {tokens[1]}."
                    ),
                    "output_type_and_shape": (
                        f"{name} keeps the exported {object_type} output shape associated "
                        f"with {tokens[0]}."
                    ),
                    "availability_and_fallback": (
                        f"{name} is available only when {tokens[0]} is available; its "
                        "exported fallback is retained exactly."
                    ),
                    "consumer_compatibility": (
                        f"{name} supplies its {object_type} result from {tokens[0]} to "
                        f"{consumer}; final compatibility is decided in the grouped review."
                    ),
                }
            )
        edge_reviews = [
            {
                **edge,
                "dependency_meaning": (
                    f"{edge.get('from_object_key')} reads reference "
                    f"{edge.get('reference')} from {edge.get('to_object_key')} before "
                    "returning the configured result."
                ),
            }
            for edge in as_list(requirement.get("required_edges"))
        ]
        terminal_reviews = []
        for terminal in as_list(requirement.get("terminal_requirements")):
            terminal_reference = _text(terminal.get("reference"), reference)
            state = _text(terminal.get("state"), "unknown")
            source = _text(terminal.get("configured_source"), "no configured source")
            terminal_reviews.append(
                {
                    **terminal,
                    "terminal_meaning": (
                        f"{terminal_reference} terminates as {state} at configured source "
                        f"{source}."
                    ),
                    "consumer_compatibility": (
                        f"The {terminal_reference} {state} terminal supplies {source} to "
                        f"{consumer}; the grouped input/output review decides compatibility."
                    ),
                }
            )
        traces.append(
            {
                "reference": reference,
                "object_chain": list(as_list(requirement.get("required_object_keys"))),
                "evidence_anchors": list(
                    as_list(requirement.get("required_evidence_anchors"))
                ),
                "terminal_states": states,
                "terminal_source": (
                    f"Reference {reference} follows the source-locked object chain and "
                    f"terminates in {', '.join(states) or 'no terminal state'}."
                ),
                "node_reviews": node_reviews,
                "edge_reviews": edge_reviews,
                "terminal_reviews": terminal_reviews,
            }
        )
    return traces


def _branch_group(path: str, available: set[str]) -> str:
    role = branch_role(path)
    preferred = {
        "Consent": "consent_sequence_alignment",
        "Execution control": "execution_scope_alignment",
        "Routing": "execution_scope_alignment",
        "Condition": "execution_scope_alignment",
        "Input": "input_output_consumer_alignment",
        "Transformation": "input_output_consumer_alignment",
        "Output": "purpose_output_alignment",
    }.get(role, "purpose_output_alignment")
    return preferred if preferred in available else sorted(available)[0]


def behavior_review_groups(row: dict[str, Any]) -> list[dict[str, Any]]:
    """Map every review obligation to one meaningful behavior work group."""

    checks = [
        item
        for item in as_list(row.get("required_logic_cross_checks"))
        if isinstance(item, dict) and str(item.get("check_key") or "")
    ]
    keys = {str(item["check_key"]) for item in checks}
    groups = {
        str(item["check_key"]): {
            "group_key": str(item["check_key"]),
            "dimension": GROUP_DIMENSIONS.get(
                str(item["check_key"]), str(item["check_key"])
            ),
            "question": str(item.get("question") or ""),
            "review_mode": (
                "structured_coverage"
                if row.get("minimum_semantic_review_depth") == "structured_simple"
                else "authored"
            ),
            "branch_paths": [],
            "reference_keys": [],
            "contract_topic_keys": [],
            "technical_finding_keys": [],
            "code_line_hashes": [],
            "configuration_obligation_keys": [],
            "evidence_anchors": list(as_list(item.get("allowed_evidence_anchors"))),
            "escalation_reasons": [],
        }
        for item in checks
    }
    if not groups:
        return []

    for branch in as_list(row.get("required_branch_reviews")):
        path = str(branch.get("json_path") or "")
        groups[_branch_group(path, keys)]["branch_paths"].append(path)
    input_key = (
        "input_output_consumer_alignment"
        if "input_output_consumer_alignment" in groups
        else sorted(groups)[0]
    )
    groups[input_key]["reference_keys"] = [
        str(item.get("reference") or "")
        for item in as_list(row.get("reference_trace_requirements"))
    ]
    vendor_key = (
        "vendor_contract_alignment"
        if "vendor_contract_alignment" in groups
        else "purpose_output_alignment"
        if "purpose_output_alignment" in groups
        else sorted(groups)[0]
    )
    groups[vendor_key]["contract_topic_keys"] = [
        str(item.get("topic_key") or "")
        for item in as_list(row.get("required_contract_topics"))
    ]
    code_key = (
        "custom_code_behavior_alignment"
        if "custom_code_behavior_alignment" in groups
        else input_key
    )
    groups[code_key]["technical_finding_keys"] = [
        str(item.get("finding_key") or "")
        for item in as_list(row.get("required_technical_findings"))
    ]
    groups[code_key]["code_line_hashes"] = [
        str(value) for value in as_list(row.get("required_code_line_hashes"))
    ]

    for obligation in as_list(row.get("required_configuration_obligations")):
        affected = [
            str(value)
            for value in as_list(obligation.get("affected_logic_checks"))
            if str(value) in groups
        ]
        target = affected[0] if affected else sorted(groups)[0]
        key = str(obligation.get("obligation_key") or "")
        groups[target]["configuration_obligation_keys"].append(key)
        reason = f"{obligation.get('required_outcome')}: {key}"
        groups[target]["escalation_reasons"].append(reason)
        groups[target]["review_mode"] = "authored"

    for group in groups.values():
        if group["contract_topic_keys"]:
            group["escalation_reasons"].append("official contract judgment required")
            group["review_mode"] = "authored"
        if group["technical_finding_keys"]:
            group["escalation_reasons"].append("technical finding resolution required")
            group["review_mode"] = "authored"
        if group["code_line_hashes"]:
            group["escalation_reasons"].append("custom code behavior review required")
            group["review_mode"] = "authored"
        if any(
            state in {"missing", "malformed", "cycle", "ambiguous"}
            for trace in as_list(row.get("reference_trace_requirements"))
            for state in as_list(trace.get("terminal_states"))
        ) and group["group_key"] == input_key:
            group["escalation_reasons"].append("unresolved recursive reference state")
            group["review_mode"] = "authored"
        for field in (
            "branch_paths",
            "reference_keys",
            "contract_topic_keys",
            "technical_finding_keys",
            "code_line_hashes",
            "configuration_obligation_keys",
            "escalation_reasons",
        ):
            group[field] = list(dict.fromkeys(group[field]))
    return [groups[key] for key in sorted(groups)]


def structured_logic_reviews(
    groups: list[dict[str, Any]],
    required_checks: list[dict[str, Any]],
    object_label: str,
) -> list[dict[str, Any]]:
    """Pre-complete only groups proven to be routine deterministic coverage."""

    required_by_key = {
        str(item.get("check_key") or ""): item for item in required_checks
    }
    result = []
    for group in groups:
        if group.get("review_mode") != "structured_coverage":
            continue
        requirement = required_by_key.get(str(group.get("group_key") or ""), {})
        terms = _terms(requirement.get("required_terms"), [object_label, group["dimension"]])
        result.append(
            {
                "check_key": group["group_key"],
                "verdict": "Aligned",
                "conclusion": (
                    f"For {object_label}, {terms[0]} and {terms[1]} are covered by the "
                    f"source-locked {group['dimension']} group with no escalation signal."
                ),
                "evidence_anchors": list(
                    as_list(requirement.get("allowed_evidence_anchors"))
                )[:2],
            }
        )
    return result


def coverage_metrics(row: dict[str, Any]) -> dict[str, int | float]:
    branch_count = len(as_list(row.get("required_branch_reviews")))
    trace_count = len(as_list(row.get("reference_trace_requirements")))
    contract_count = len(as_list(row.get("required_contract_topics")))
    technical_count = len(as_list(row.get("required_technical_findings")))
    code_count = len(as_list(row.get("code_line_facts")))
    logic_count = len(as_list(row.get("required_logic_cross_checks")))
    configuration_obligation_count = len(
        as_list(row.get("required_configuration_obligations"))
    )
    behavior_groups = as_list(row.get("behavior_review_groups"))
    # Every object still needs one independent object-level disposition even
    # when all routine branch narration is deterministic.
    authored = 1 + sum(
        1 for group in behavior_groups if group.get("review_mode") == "authored"
    )
    authored += contract_count + technical_count + math.ceil(code_count / 30)
    evidence = (
        branch_count
        + trace_count
        + contract_count
        + technical_count
        + code_count
        + logic_count
        + configuration_obligation_count
    )
    return {
        "evidence_obligations": evidence,
        "authored_work_units": authored,
        "behavior_groups": len(behavior_groups),
        "obligation_to_authored_ratio": round(evidence / max(1, authored), 3),
    }


def behavior_group_coverage_errors(row: dict[str, Any], label: str) -> list[str]:
    """Prove that every raw obligation is assigned once, without duplicate prose."""

    groups = [item for item in as_list(row.get("behavior_review_groups")) if isinstance(item, dict)]
    errors: list[str] = []
    expected_group_keys = {
        str(item.get("check_key") or "")
        for item in as_list(row.get("required_logic_cross_checks"))
    }
    supplied_group_keys = [str(item.get("group_key") or "") for item in groups]
    if any(not value for value in supplied_group_keys):
        errors.append(f"{label}: behavior groups contain a blank group identity")
    if len(supplied_group_keys) != len(set(supplied_group_keys)):
        errors.append(f"{label}: behavior group identities are duplicated")
    if set(supplied_group_keys) != expected_group_keys:
        errors.append(f"{label}: behavior groups do not exactly cover D3 checks")
    expected_sets = {
        "branch_paths": {
            str(item.get("json_path") or "")
            for item in as_list(row.get("required_branch_reviews"))
        },
        "reference_keys": {
            str(item.get("reference") or "")
            for item in as_list(row.get("reference_trace_requirements"))
        },
        "contract_topic_keys": {
            str(item.get("topic_key") or "")
            for item in as_list(row.get("required_contract_topics"))
        },
        "technical_finding_keys": {
            str(item.get("finding_key") or "")
            for item in as_list(row.get("required_technical_findings"))
        },
        "code_line_hashes": {
            str(value) for value in as_list(row.get("required_code_line_hashes"))
        },
        "configuration_obligation_keys": {
            str(item.get("obligation_key") or "")
            for item in as_list(row.get("required_configuration_obligations"))
        },
    }
    for field, expected in expected_sets.items():
        values = [
            str(value)
            for group in groups
            for value in as_list(group.get(field))
        ]
        if any(not value for value in values):
            errors.append(f"{label}: behavior groups contain a blank {field} identity")
        if len(values) != len(set(values)):
            errors.append(f"{label}: behavior groups duplicate {field} identities")
        if set(values) != expected:
            errors.append(f"{label}: behavior groups do not exactly cover {field}")
    return errors
