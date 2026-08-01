#!/usr/bin/env python3
"""Shared mechanics for independent GTM review validators.

This module owns only source lookup and validation primitives. It must never
produce an operational, configuration, or architecture verdict.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from gtm_configuration_facts import build_consumers, object_consumers
from gtm_context_model import build_context_model
from gtm_lib import ID_KEYS, as_list, container_root_path, container_version, stable_hash
from gtm_shared_facts import build_shared_facts

VALID_PRIORITIES = {"Critical", "High", "Medium", "Low"}
VALID_CONFIDENCE = {"High", "Medium", "Low"}
VALID_READINESS = {"approval_required", "owner_blocked", "not_actionable"}
MUTATION_FIELDS = (
    "creations",
    "additions",
    "changes",
    "remaps",
    "renames",
    "deletions",
)
SUPPORTED_REMAP_LAYERS = {"trigger", "variable", "tag", "folder"}
JSON_PATH_TOKEN_RE = re.compile(r"\.([^.[\]]+)|\[(\d+)\]")
REVIEW_INPUT_ROLES = {
    "operational_sanitation": {
        "required": (
            "raw_export",
            "run_instructions",
            "run_rules",
            "audit_context",
            "shared_facts",
            "operational_scan",
            "operational_review_scaffold",
        ),
        "optional": ("review_work_units",),
        "prohibited": (
            "configuration_review",
            "architecture_review",
            "reconciled_operations",
            "future_state",
            "workbook",
            "test_fixture",
            "test_helper",
        ),
    },
    "configuration_correctness": {
        "required": (
            "raw_export",
            "run_instructions",
            "run_rules",
            "domain_contracts",
            "audit_context",
            "shared_facts",
            "technical_code_facts",
            "configuration_review_scaffold",
            "vendor_registry",
        ),
        "optional": (
            "official_documentation",
            "approved_requirement_evidence",
            "review_work_units",
        ),
        "prohibited": (
            "operational_review",
            "architecture_review",
            "reconciled_operations",
            "future_state",
            "workbook",
            "test_fixture",
            "test_helper",
        ),
    },
    "business_architecture": {
        "required": (
            "raw_export",
            "run_instructions",
            "run_rules",
            "audit_context",
            "shared_facts",
            "architecture_review_scaffold",
        ),
        "optional": ("approved_requirement_evidence", "review_work_units"),
        "prohibited": (
            "operational_review",
            "configuration_review",
            "reconciled_operations",
            "future_state",
            "workbook",
            "test_fixture",
            "test_helper",
        ),
    },
}

GENERIC_PHRASES = {
    "review configuration",
    "configuration reviewed",
    "choose a canonical object",
    "check in gtm",
    "code inspected",
    "code reviewed",
    "custom code inspected",
    "static scan completed",
    "needs review",
    "optimize as needed",
    "serves one concrete measurement purpose",
    "executes through its configured route",
    "reads the named inputs",
    "produces its configured output",
    "feeds the exact exported consumers",
    "uses the exported consent",
    "internally coherent for this container configuration",
    "fixture value",
    "fixture family",
    "source-bound route, payload, and dependency configuration",
    "through the exact cleanup action indicated by the source evidence",
    "obtain the named owner, runtime, vendor, or code evidence",
    "obtain the named runtime or owner evidence",
    "otherwise prepare one exact repair, consolidation, or retirement operation",
    "candidates retain distinct roles after route and source comparison",
    "keeps separate paths because no common target is proven",
    "members have no proven duplicate firing in this export",
    "given the source-specific condition recorded in this finding",
    "based on the source-specific condition recorded in this finding",
    "resolve the source-specific condition recorded in this finding",
    "review the evidence package for the exact retained route and payload",
    "see the evidence package for each exact retained route and payload",
}


def canonical_review_facts(
    export_path: Path,
    supplied: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Rebuild the exact contextual and deterministic facts claimed by a review."""
    provided = supplied.get("provided_context")
    if not isinstance(provided, dict):
        provided = {}
    context = build_context_model(export_path, provided_context=provided)
    return context, build_shared_facts(export_path, context=context)


def review_input_contract(
    review_run: str,
    source_sha256: str,
    context_sha256: str,
    shared_facts_sha256: str,
) -> dict[str, Any]:
    """Build the immutable allowed-input contract for one independent review."""
    roles = REVIEW_INPUT_ROLES[review_run]
    contract = {
        "review_run": review_run,
        "source_sha256": source_sha256,
        "context_sha256": context_sha256,
        "shared_facts_sha256": shared_facts_sha256,
        "required_artifact_roles": list(roles["required"]),
        "optional_artifact_roles": list(roles["optional"]),
        "prohibited_artifact_roles": list(roles["prohibited"]),
        "verdict_isolation": (
            "Do not read or reuse another review's verdicts, findings, operations, "
            "completion helpers, or reconciled output before reconciliation."
        ),
    }
    contract["contract_sha256"] = stable_hash(contract, 64)
    return contract


def pending_completion_attestation(contract: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": "pending",
        "input_contract_sha256": contract.get("contract_sha256"),
        "used_artifact_roles": [],
        "foreign_verdict_artifacts_used": [],
        "helper_modules": [],
        "decision_authoring_method": "",
        "independent_review_context_id": "",
        "semantic_completion_artifacts": [],
    }


def validate_review_provenance(
    supplied: dict[str, Any],
    expected: dict[str, Any],
    label: str,
) -> list[str]:
    """Reject accidental cross-run leakage and repository-test completion paths."""
    expected_contract = expected.get("input_contract")
    if not isinstance(expected_contract, dict):
        return [f"{label}: source-locked input contract is missing"]
    review_run = str(expected_contract.get("review_run") or "")
    if review_run not in REVIEW_INPUT_ROLES:
        return [f"{label}: input contract has an invalid review run"]
    canonical_contract = review_input_contract(
        review_run,
        str(expected.get("source_sha256") or ""),
        str(expected.get("context_sha256") or ""),
        str(expected.get("shared_facts_sha256") or ""),
    )
    if expected_contract != canonical_contract:
        return [f"{label}: input contract differs from the canonical run contract"]
    if supplied.get("input_contract") != expected_contract:
        return [f"{label}: input contract differs from the source-locked scaffold"]

    attestation = supplied.get("completion_attestation")
    if not isinstance(attestation, dict):
        return [f"{label}: completion attestation is missing"]

    errors: list[str] = []
    if attestation.get("status") != "complete":
        errors.append(f"{label}: completion attestation must be complete")
    if attestation.get("input_contract_sha256") != expected_contract.get(
        "contract_sha256"
    ):
        errors.append(f"{label}: completion attestation uses another input contract")

    raw_roles = as_list(attestation.get("used_artifact_roles"))
    roles = [str(value) for value in raw_roles]
    if any(not role for role in roles) or len(roles) != len(set(roles)):
        errors.append(f"{label}: used artifact roles must be unique and nonblank")
    required = set(as_list(expected_contract.get("required_artifact_roles")))
    optional = set(as_list(expected_contract.get("optional_artifact_roles")))
    prohibited = set(as_list(expected_contract.get("prohibited_artifact_roles")))
    used = set(roles)
    if missing := sorted(required - used):
        errors.append(f"{label}: completion omitted required input roles: {', '.join(missing)}")
    if unknown := sorted(used - required - optional):
        errors.append(f"{label}: completion used undeclared input roles: {', '.join(unknown)}")
    if blocked := sorted(used & prohibited):
        errors.append(f"{label}: completion used prohibited input roles: {', '.join(blocked)}")
    requirement_role = "approved_requirement_evidence"
    has_requirement_evidence = bool(supplied.get(requirement_role))
    if has_requirement_evidence and requirement_role not in used:
        errors.append(
            f"{label}: completion omitted the supplied approved requirement evidence role"
        )
    if not has_requirement_evidence and requirement_role in used:
        errors.append(
            f"{label}: completion attests approved requirement evidence that is not present"
        )

    foreign = [str(value) for value in as_list(attestation.get("foreign_verdict_artifacts_used"))]
    if foreign:
        errors.append(
            f"{label}: completion used foreign verdict artifacts before reconciliation: "
            + ", ".join(foreign)
        )
    helpers = [str(value) for value in as_list(attestation.get("helper_modules"))]
    prohibited_helpers = sorted(
        helper
        for helper in helpers
        if re.search(
            r"(^|[./\\])tests?([./\\]|$)|test_pipeline|test_adversarial|"
            r"complete[_-]?reviews?|semantic[_-]?(?:completion|writer)|bulk[_-]?decision",
            helper,
            re.I,
        )
    )
    if prohibited_helpers:
        errors.append(
            f"{label}: semantic verdicts cannot be written by repository test helpers "
            "or bulk-completion helpers: "
            + ", ".join(prohibited_helpers)
        )
    authoring_method = str(attestation.get("decision_authoring_method") or "")
    if authoring_method not in {
        "independent_agent_review",
        "independent_manual_review",
        "independent_test_fixture_review",
    }:
        errors.append(
            f"{label}: decision_authoring_method must attest one independent semantic review"
        )
    context_id = str(attestation.get("independent_review_context_id") or "").strip()
    if len(context_id) < 12:
        errors.append(f"{label}: independent_review_context_id is missing or too weak")
    semantic_artifacts = [
        str(value)
        for value in as_list(attestation.get("semantic_completion_artifacts"))
        if str(value)
    ]
    if semantic_artifacts:
        errors.append(
            f"{label}: bulk semantic completion artifacts are prohibited: "
            + ", ".join(semantic_artifacts)
        )
    return errors


def words(value: Any) -> int:
    return len(re.findall(r"\b[\w{}.-]+\b", str(value or "")))


def specific_text(value: Any, minimum: int = 5) -> bool:
    text = str(value or "").strip().lower()
    return words(text) >= minimum and not any(phrase in text for phrase in GENERIC_PHRASES)


def precise_question(value: Any, minimum: int = 5) -> bool:
    text = " ".join(str(value or "").split()).strip()
    return bool(
        specific_text(text, minimum)
        and text.endswith("?")
        and text.count("?") == 1
        and re.search(
            r"\b(?:what|which|who|whose|how|why|where|when|should|does|do|"
            r"is|are|can|will|would)\b",
            text,
            re.I,
        )
    )


def source_specific_owner_question_errors(
    question: Any,
    identities: list[Any],
    evidence_terms: list[Any],
    label: str,
) -> list[str]:
    """Require a real decision question tied to the affected source condition."""

    text = " ".join(str(question or "").split()).strip()
    lowered = text.casefold()
    identity_values = [
        " ".join(str(value or "").split()).strip().casefold()
        for value in identities
        if str(value or "").strip()
    ]
    errors: list[str] = []
    if identity_values and not any(value in lowered for value in identity_values):
        errors.append(f"{label}: owner question must name the affected source object")
    ignored = {
        *identity_values,
        "source",
        "configuration",
        "configured",
        "condition",
        "finding",
        "evidence",
        "review",
        "object",
        "owner",
        "decision",
    }
    candidates = []
    for value in evidence_terms:
        term = " ".join(str(value or "").split()).strip().casefold()
        if len(term) < 3 or term in ignored or term in candidates:
            continue
        candidates.append(term)
    if candidates and not any(term in lowered for term in candidates):
        errors.append(
            f"{label}: owner question must name the exact source condition, contract, "
            "reference, route, or defect that needs an answer"
        )
    return errors


def repeated_semantic_template_errors(
    rows: list[dict[str, Any]],
    text_fields: tuple[str, ...],
    identity_fields: tuple[str, ...],
    label: str,
    *,
    threshold: int = 8,
) -> list[str]:
    """Reject bulk-authored judgment prose whose only variation is object identity."""

    groups: dict[tuple[str, str], list[str]] = {}
    for index, row in enumerate(rows, start=1):
        identities = [
            " ".join(str(row.get(field) or "").split()).strip()
            for field in identity_fields
            if str(row.get(field) or "").strip()
        ]
        row_id = str(
            row.get("review_id")
            or row.get("family_id")
            or row.get("comparison_id")
            or row.get("object_key")
            or index
        )
        for field in text_fields:
            text = " ".join(str(row.get(field) or "").split()).strip().casefold()
            if words(text) < 8:
                continue
            skeleton = text
            for identity in sorted(identities, key=len, reverse=True):
                if identity:
                    skeleton = re.sub(re.escape(identity.casefold()), " <object> ", skeleton)
            skeleton = re.sub(r"\$[.\w\[\]-]+", " <path> ", skeleton)
            skeleton = re.sub(
                r"\b(?:cfg|fam|cmp|disc|op|run)[-_]?[a-z0-9_-]+\b",
                " <id> ",
                skeleton,
            )
            skeleton = re.sub(r"\b\d+\b", " <number> ", skeleton)
            skeleton = re.sub(r"\s+", " ", skeleton).strip()
            groups.setdefault((field, skeleton), []).append(row_id)
    errors: list[str] = []
    for (field, _skeleton), row_ids in sorted(groups.items()):
        if len(row_ids) >= threshold:
            errors.append(
                f"{label}: {field} repeats one hollow semantic template across "
                f"{len(row_ids)} records ({', '.join(row_ids[:8])}); author each "
                "judgment from its source condition"
            )
    return errors


def _validate_creations(
    row: dict[str, Any], valid_keys: set[str], label: str
) -> tuple[list[str], set[str]]:
    errors: list[str] = []
    created: set[str] = set()
    for index, creation in enumerate(as_list(row.get("creations")), start=1):
        prefix = f"{label}: creation {index}"
        layer = str(creation.get("layer") or "")
        obj = creation.get("object")
        id_key = ID_KEYS.get(layer)
        if not id_key or not isinstance(obj, dict):
            errors.append(f"{prefix} requires a supported layer and complete object")
            continue
        object_id = str(obj.get(id_key) or obj.get("name") or "")
        key = f"{layer}:{object_id}" if object_id else ""
        if not key:
            errors.append(f"{prefix} requires the layer identity field {id_key}")
        elif key in valid_keys or key in created:
            errors.append(f"{prefix} duplicates existing or planned object {key!r}")
        else:
            created.add(key)
        if not specific_text(creation.get("reason"), 4):
            errors.append(f"{prefix} requires a specific reason")
    return errors, created


class SourcePathMap(dict[str, str]):
    """Object paths plus their locked source values.

    Keeping the source objects on the path map avoids plumbing a second large
    argument through every Run 1/2/3 validator while still making the normal
    export-backed validation path source-exact. Plain dictionaries remain
    accepted by low-level callers and legacy tests.
    """

    def __init__(
        self,
        *args: Any,
        source_objects_by_key: dict[str, dict[str, Any]] | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(*args, **kwargs)
        self.source_objects_by_key = (
            source_objects_by_key if source_objects_by_key is not None else {}
        )


def _relative_source_path(
    json_path: str,
    object_key: str,
    source_paths_by_key: dict[str, str] | None,
) -> str | None:
    base = (source_paths_by_key or {}).get(object_key)
    if not base or not json_path.startswith(base):
        return None
    suffix = json_path[len(base) :]
    if suffix and not suffix.startswith((".", "[")):
        return None
    return "$" + suffix


def _path_tokens(path: str) -> list[str | int]:
    tokens: list[str | int] = []
    consumed = 0
    for match in JSON_PATH_TOKEN_RE.finditer(path[1:]):
        if match.start() != consumed:
            raise ValueError("unsupported JSON path syntax")
        tokens.append(
            match.group(1) if match.group(1) is not None else int(match.group(2))
        )
        consumed = match.end()
    if consumed != len(path) - 1:
        raise ValueError("unsupported JSON path syntax")
    return tokens


def _source_path_value(target: Any, path: str) -> Any:
    current = target
    for token in _path_tokens(path):
        current = current[token]
    return current


def _source_parent_and_leaf(target: Any, path: str) -> tuple[Any, str | int]:
    tokens = _path_tokens(path)
    if not tokens:
        raise ValueError("root path has no parent")
    current = target
    for token in tokens[:-1]:
        current = current[token]
    return current, tokens[-1]


def _source_object(
    source_paths_by_key: dict[str, str] | None, object_key: str
) -> dict[str, Any] | None:
    objects = getattr(source_paths_by_key, "source_objects_by_key", {})
    value = objects.get(object_key) if isinstance(objects, dict) else None
    return value if isinstance(value, dict) else None


def _reference_list_errors(
    path: str,
    value: Any,
    allowed_keys: set[str],
    prefix: str,
    *,
    list_member: bool = False,
) -> list[str]:
    errors: list[str] = []
    if path.endswith((".firingTriggerId", ".blockingTriggerId")):
        if list_member:
            if not isinstance(value, (str, int)):
                return [f"{prefix} requires one trigger ID"]
            values = [value]
        else:
            if not isinstance(value, list) or any(
                not isinstance(item, (str, int)) for item in value
            ):
                return [f"{prefix} requires a complete trigger-ID list"]
            values = value
        unknown = sorted(
            str(item)
            for item in values
            if f"trigger:{item}" not in allowed_keys
        )
        if unknown:
            errors.append(
                f"{prefix} uses trigger names or unknown trigger IDs: {unknown!r}"
            )
    return errors


def _validate_additions(
    row: dict[str, Any],
    allowed_keys: set[str],
    label: str,
    source_paths_by_key: dict[str, str] | None = None,
) -> list[str]:
    errors: list[str] = []
    for index, addition in enumerate(as_list(row.get("additions")), start=1):
        prefix = f"{label}: addition {index}"
        key = str(addition.get("object_key") or "")
        if key not in allowed_keys:
            errors.append(f"{prefix} references unknown object {key!r}")
        if not str(addition.get("json_path") or "").startswith("$"):
            errors.append(f"{prefix} requires an exact parent json_path")
        expected_path = (source_paths_by_key or {}).get(key)
        path = str(addition.get("json_path") or "")
        if expected_path and not (
            path == expected_path
            or path.startswith((expected_path + ".", expected_path + "["))
        ):
            errors.append(f"{prefix} object_key is paired with another object's json_path")
        if "value" not in addition:
            errors.append(f"{prefix} requires a value")
        if addition.get("mode") not in {"set", "append", "insert"}:
            errors.append(f"{prefix} mode must be set, append, or insert")
        if addition.get("mode") == "insert" and not isinstance(addition.get("index"), int):
            errors.append(f"{prefix} insert mode requires an integer index")
        if not specific_text(addition.get("reason"), 4):
            errors.append(f"{prefix} requires a specific reason")
        source_object = _source_object(source_paths_by_key, key)
        relative = _relative_source_path(path, key, source_paths_by_key)
        if source_object is not None and relative is not None:
            try:
                mode = str(addition.get("mode") or "")
                if mode in {"append", "insert"}:
                    destination = _source_path_value(source_object, relative)
                    if not isinstance(destination, list):
                        errors.append(f"{prefix} append/insert target is not a source list")
                    elif destination and "value" in addition and not isinstance(
                        addition.get("value"), type(destination[0])
                    ):
                        errors.append(
                            f"{prefix} value type differs from existing source list members"
                        )
                    elif path.endswith((".firingTriggerId", ".blockingTriggerId")) and any(
                        str(value) == str(addition.get("value")) for value in destination
                    ):
                        errors.append(
                            f"{prefix} trigger-ID list already contains the appended value"
                        )
                elif mode == "set":
                    parent, leaf = _source_parent_and_leaf(source_object, relative)
                    if not isinstance(parent, dict):
                        errors.append(f"{prefix} set parent is not a source object")
                    elif leaf in parent:
                        errors.append(
                            f"{prefix} set target already exists; use an exact before/after change"
                        )
            except (KeyError, IndexError, TypeError, ValueError):
                errors.append(f"{prefix} json_path does not resolve in the locked source")
        errors.extend(
            _reference_list_errors(
                path,
                addition.get("value"),
                allowed_keys,
                prefix,
                list_member=addition.get("mode") in {"append", "insert"},
            )
        )
    return errors


def _validate_changes(
    row: dict[str, Any],
    allowed_keys: set[str],
    label: str,
    source_paths_by_key: dict[str, str] | None = None,
) -> list[str]:
    errors: list[str] = []
    for index, change in enumerate(as_list(row.get("changes")), start=1):
        prefix = f"{label}: change {index}"
        key = str(change.get("object_key") or "")
        if key not in allowed_keys:
            errors.append(f"{prefix} references unknown object {key!r}")
        if not str(change.get("json_path") or "").startswith("$"):
            errors.append(f"{prefix} requires an exact source json_path")
        expected_path = (source_paths_by_key or {}).get(key)
        path = str(change.get("json_path") or "")
        if expected_path and not (
            path == expected_path
            or path.startswith((expected_path + ".", expected_path + "["))
        ):
            errors.append(
                f"{prefix} object_key is paired with another object's json_path"
            )
        if "before" not in change or "after" not in change:
            errors.append(f"{prefix} requires before and after values")
        elif change.get("before") == change.get("after"):
            errors.append(f"{prefix} before and after values are identical")
        else:
            before = change.get("before")
            after = change.get("after")
            if type(before) is not type(after):
                errors.append(
                    f"{prefix} changes value type from {type(before).__name__} to "
                    f"{type(after).__name__}; mutate the typed GTM field explicitly instead"
                )
        source_object = _source_object(source_paths_by_key, key)
        relative = _relative_source_path(path, key, source_paths_by_key)
        if source_object is not None and relative is not None and "before" in change:
            try:
                locked_value = _source_path_value(source_object, relative)
                if locked_value != change.get("before"):
                    errors.append(
                        f"{prefix} before value does not equal the locked source value"
                    )
            except (KeyError, IndexError, TypeError, ValueError):
                errors.append(f"{prefix} json_path does not resolve in the locked source")
        errors.extend(
            _reference_list_errors(path, change.get("after"), allowed_keys, prefix)
        )
    return errors


def _validate_remaps(
    row: dict[str, Any],
    allowed_keys: set[str],
    label: str,
    expected_consumers: dict[str, set[str]] | None,
) -> list[str]:
    errors: list[str] = []
    deleted_keys = {
        str(deletion.get("object_key") or "")
        for deletion in as_list(row.get("deletions"))
    }
    remapped_consumers: dict[str, set[str]] = {}
    detached_consumers: dict[str, set[str]] = {}
    for change in as_list(row.get("changes")):
        consumer = str(change.get("object_key") or "")
        path = str(change.get("json_path") or "")
        before = change.get("before")
        after = change.get("after")
        if not consumer or not isinstance(before, list) or not isinstance(after, list):
            continue
        if path.endswith((".firingTriggerId", ".blockingTriggerId")):
            removed = {str(value) for value in before} - {
                str(value) for value in after
            }
            for object_id in removed:
                detached_consumers.setdefault(f"trigger:{object_id}", set()).add(
                    consumer
                )
        elif path.endswith((".setupTag", ".teardownTag")):
            before_names = {
                str(value.get("tagName") or "")
                for value in before
                if isinstance(value, dict) and str(value.get("tagName") or "")
            }
            after_names = {
                str(value.get("tagName") or "")
                for value in after
                if isinstance(value, dict) and str(value.get("tagName") or "")
            }
            for object_name in before_names - after_names:
                detached_consumers.setdefault(f"tag:{object_name}", set()).add(
                    consumer
                )
    for remap in as_list(row.get("remaps")):
        source = str(remap.get("from_object_key") or "")
        target = str(remap.get("to_object_key") or "")
        if source not in allowed_keys or target not in allowed_keys:
            errors.append(f"{label}: remap must reference existing or planned objects")
        if source == target:
            errors.append(f"{label}: remap source and target cannot be identical")
        consumers = [str(value) for value in as_list(remap.get("consumer_object_keys"))]
        if not consumers:
            errors.append(f"{label}: remap must list every affected consumer")
        for consumer in consumers:
            if consumer not in allowed_keys:
                errors.append(f"{label}: remap references unknown consumer {consumer!r}")
        if len(consumers) != len(set(consumers)):
            errors.append(f"{label}: remap consumer list contains duplicates")
        overlap = remapped_consumers.setdefault(source, set()) & set(consumers)
        if overlap:
            errors.append(
                f"{label}: source consumer appears in multiple remaps: {sorted(overlap)!r}"
            )
        remapped_consumers[source].update(consumers)
    if expected_consumers is not None:
        for source in set(remapped_consumers) | set(detached_consumers):
            expected_live = expected_consumers.get(source, set()) - deleted_keys
            covered_consumers = remapped_consumers.get(
                source, set()
            ) | detached_consumers.get(source, set())
            if covered_consumers != expected_live:
                errors.append(
                    f"{label}: remap or exact reference-removal coverage must exactly "
                    "match every source-graph consumer that remains after the operation"
                )
        for source in deleted_keys:
            expected_live = expected_consumers.get(source, set()) - deleted_keys
            covered_consumers = remapped_consumers.get(
                source, set()
            ) | detached_consumers.get(source, set())
            if expected_live and covered_consumers != expected_live:
                errors.append(
                    f"{label}: deleting consumed object {source!r} requires remap "
                    "coverage or exact reference-removal coverage for every retained "
                    "source-graph consumer"
                )
    return errors


def _dependency_graph(
    expected_consumers: dict[str, set[str]],
) -> dict[str, set[str]]:
    graph: dict[str, set[str]] = {}
    for source, consumers in expected_consumers.items():
        graph.setdefault(source, set())
        for consumer in consumers:
            graph.setdefault(consumer, set()).add(source)
    return graph


def _path_exists(graph: dict[str, set[str]], start: str, target: str) -> bool:
    pending = [start]
    visited: set[str] = set()
    while pending:
        current = pending.pop()
        if current == target:
            return True
        if current in visited:
            continue
        visited.add(current)
        pending.extend(graph.get(current, set()) - visited)
    return False


def _name_collision_pairs(names: dict[str, str]) -> set[tuple[str, str, str, str]]:
    grouped: dict[tuple[str, str], list[str]] = {}
    for key, name in names.items():
        layer = key.partition(":")[0]
        if layer and name:
            grouped.setdefault((layer, name), []).append(key)
    return {
        (layer, name, left, right)
        for (layer, name), keys in grouped.items()
        for index, left in enumerate(sorted(set(keys)))
        for right in sorted(set(keys))[index + 1 :]
    }


def validate_operation_set(
    rows: list[dict[str, Any]],
    expected_consumers: dict[str, set[str]] | None = None,
    object_names: dict[str, str] | None = None,
    label: str = "operation set",
) -> list[str]:
    """Validate mutation semantics that depend on the complete accepted action set."""
    errors: list[str] = []
    deleted_keys = {
        str(item.get("object_key") or "")
        for row in rows
        for item in as_list(row.get("deletions"))
    }
    remaps = [
        remap for row in rows for remap in as_list(row.get("remaps"))
    ]

    # Consumer coverage is a property of the *accepted operation set*, not of
    # one finding row.  For example, an unused child trigger and its unused
    # trigger-group consumer may legitimately be deleted by two separate
    # atomic findings.  Likewise, removing one provably ineffective blocker
    # edge must not require stripping that still-live blocker from every other
    # tag that uses it.  Collect the whole packet before deciding whether a
    # deleted source has every surviving reference covered.
    if expected_consumers is not None:
        remapped_consumers: dict[str, set[str]] = {}
        detached_consumers: dict[str, set[str]] = {}
        for row in rows:
            for remap in as_list(row.get("remaps")):
                source = str(remap.get("from_object_key") or "")
                if source:
                    remapped_consumers.setdefault(source, set()).update(
                        str(value)
                        for value in as_list(remap.get("consumer_object_keys"))
                        if str(value)
                    )
            for change in as_list(row.get("changes")):
                consumer = str(change.get("object_key") or "")
                path = str(change.get("json_path") or "")
                before = change.get("before")
                after = change.get("after")
                if not consumer or not isinstance(before, list) or not isinstance(after, list):
                    continue
                if path.endswith((".firingTriggerId", ".blockingTriggerId")):
                    for object_id in {str(value) for value in before} - {
                        str(value) for value in after
                    }:
                        detached_consumers.setdefault(f"trigger:{object_id}", set()).add(
                            consumer
                        )
                elif path.endswith((".setupTag", ".teardownTag")):
                    before_names = {
                        str(value.get("tagName") or "")
                        for value in before
                        if isinstance(value, dict) and str(value.get("tagName") or "")
                    }
                    after_names = {
                        str(value.get("tagName") or "")
                        for value in after
                        if isinstance(value, dict) and str(value.get("tagName") or "")
                    }
                    for object_name in before_names - after_names:
                        detached_consumers.setdefault(f"tag:{object_name}", set()).add(
                            consumer
                        )

        for source in deleted_keys:
            expected_live = expected_consumers.get(source, set()) - deleted_keys
            covered_consumers = remapped_consumers.get(source, set()) | detached_consumers.get(
                source, set()
            )
            if expected_live and covered_consumers != expected_live:
                errors.append(
                    f"{label}: deleting consumed object {source!r} requires remap "
                    "coverage or exact reference-removal coverage for every retained "
                    "source-graph consumer"
                )

        # A source-wide remap represents a replacement of the source object,
        # so it still must cover every surviving consumer even if the deletion
        # is recorded in another atomic finding.
        for source, consumers in remapped_consumers.items():
            expected_live = expected_consumers.get(source, set()) - deleted_keys
            covered_consumers = consumers | detached_consumers.get(source, set())
            if covered_consumers != expected_live:
                errors.append(
                    f"{label}: remap or exact reference-removal coverage must exactly "
                    "match every source-graph consumer that remains after the operation"
                )
    for remap in remaps:
        source = str(remap.get("from_object_key") or "")
        target = str(remap.get("to_object_key") or "")
        source_layer = source.partition(":")[0]
        target_layer = target.partition(":")[0]
        if source and target and source_layer != target_layer:
            errors.append(f"{label}: remap crosses GTM layers: {source!r} to {target!r}")
        elif source_layer and source_layer not in SUPPORTED_REMAP_LAYERS:
            errors.append(f"{label}: remap is unsupported for layer {source_layer!r}")
        if target and target in deleted_keys:
            errors.append(f"{label}: remap target {target!r} is also deleted")

    if expected_consumers is not None:
        graph = _dependency_graph(expected_consumers)
        new_edges: list[tuple[str, str, str]] = []
        for remap in remaps:
            source = str(remap.get("from_object_key") or "")
            target = str(remap.get("to_object_key") or "")
            for consumer in (
                str(value) for value in as_list(remap.get("consumer_object_keys"))
            ):
                graph.setdefault(consumer, set()).discard(source)
                graph.setdefault(consumer, set()).add(target)
                new_edges.append((consumer, target, source))
        live_graph = {
            key: dependencies - deleted_keys
            for key, dependencies in graph.items()
            if key not in deleted_keys
        }
        for consumer, target, source in new_edges:
            if consumer in deleted_keys or target in deleted_keys:
                continue
            dependencies = live_graph.setdefault(consumer, set())
            dependencies.discard(target)
            creates_cycle = consumer == target or _path_exists(
                live_graph, target, consumer
            )
            dependencies.add(target)
            if creates_cycle:
                errors.append(
                    f"{label}: remap {source!r} to {target!r} creates a dependency cycle "
                    f"through consumer {consumer!r}"
                )

    if object_names is not None:
        baseline_pairs = _name_collision_pairs(object_names)
        final_names = {
            key: name for key, name in object_names.items() if key not in deleted_keys
        }
        renamed: dict[str, str] = {}
        for row in rows:
            for rename in as_list(row.get("renames")):
                key = str(rename.get("object_key") or "")
                after = str(rename.get("after") or "").strip()
                if key in deleted_keys:
                    errors.append(f"{label}: renamed object {key!r} is also deleted")
                previous = renamed.get(key)
                if previous is not None and previous != after:
                    errors.append(f"{label}: object {key!r} has conflicting final names")
                renamed[key] = after
                if key in final_names and after:
                    final_names[key] = after
            for creation in as_list(row.get("creations")):
                layer = str(creation.get("layer") or "")
                obj = creation.get("object")
                id_key = ID_KEYS.get(layer)
                if not id_key or not isinstance(obj, dict):
                    continue
                object_id = str(obj.get(id_key) or obj.get("name") or "")
                name = str(obj.get("name") or "").strip()
                if object_id and name:
                    final_names[f"{layer}:{object_id}"] = name
        introduced_pairs = _name_collision_pairs(final_names) - baseline_pairs
        for layer, name, left, right in sorted(introduced_pairs):
            errors.append(
                f"{label}: duplicate final name {name!r} in {layer} for {left!r} and {right!r}"
            )
    return errors


def _validate_deletions_and_renames(
    row: dict[str, Any],
    allowed_keys: set[str],
    label: str,
    source_paths_by_key: dict[str, str] | None = None,
) -> list[str]:
    errors: list[str] = []
    for deletion in as_list(row.get("deletions")):
        key = str(deletion.get("object_key") or "")
        if key not in allowed_keys:
            errors.append(f"{label}: deletion references unknown object {key!r}")
        if not specific_text(deletion.get("reason"), 3):
            errors.append(f"{label}: deletion requires a specific reason")
    for rename in as_list(row.get("renames")):
        key = str(rename.get("object_key") or "")
        if key not in allowed_keys:
            errors.append(f"{label}: rename references unknown object {key!r}")
        if not str(rename.get("before") or "").strip() or not str(
            rename.get("after") or ""
        ).strip():
            errors.append(f"{label}: rename requires before and after names")
        elif str(rename.get("before")) == str(rename.get("after")):
            errors.append(f"{label}: rename before and after names are identical")
        source_object = _source_object(source_paths_by_key, key)
        if source_object is not None and str(source_object.get("name") or "") != str(
            rename.get("before") or ""
        ):
            errors.append(
                f"{label}: rename before name does not equal the locked source name for {key!r}"
            )
    return errors


def object_keys(export_path: Path) -> set[str]:
    data = json.loads(export_path.read_text(encoding="utf-8"))
    cv = container_version(data)
    keys: set[str] = set()
    for layer, id_key in ID_KEYS.items():
        for obj in as_list(cv.get(layer)):
            value = obj.get(id_key) or obj.get("name")
            if value is not None:
                keys.add(f"{layer}:{value}")
    return keys


def object_consumer_map(export_path: Path) -> dict[str, set[str]]:
    data = json.loads(export_path.read_text(encoding="utf-8"))
    cv = container_version(data)
    consumers = build_consumers(cv, container_root_path(data))
    result: dict[str, set[str]] = {}
    for layer, id_key in ID_KEYS.items():
        for obj in as_list(cv.get(layer)):
            object_id = str(obj.get(id_key) or obj.get("name") or "")
            if not object_id:
                continue
            result[f"{layer}:{object_id}"] = {
                str(item.get("consumer_key") or "")
                for item in object_consumers(layer, obj, consumers)
                if item.get("consumer_key")
            }
    return result


def object_name_map(export_path: Path) -> dict[str, str]:
    data = json.loads(export_path.read_text(encoding="utf-8"))
    cv = container_version(data)
    result: dict[str, str] = {}
    for layer, id_key in ID_KEYS.items():
        for obj in as_list(cv.get(layer)):
            object_id = str(obj.get(id_key) or obj.get("name") or "")
            if object_id:
                result[f"{layer}:{object_id}"] = str(obj.get("name") or "")
    return result


def object_source_path_map(export_path: Path) -> dict[str, str]:
    data = json.loads(export_path.read_text(encoding="utf-8"))
    cv = container_version(data)
    root_path = container_root_path(data)
    source_objects: dict[str, dict[str, Any]] = {}
    result: SourcePathMap = SourcePathMap(source_objects_by_key=source_objects)
    for layer, id_key in ID_KEYS.items():
        for index, obj in enumerate(as_list(cv.get(layer))):
            object_id = str(obj.get(id_key) or obj.get("name") or "")
            if object_id:
                key = f"{layer}:{object_id}"
                result[key] = f"{root_path}.{layer}[{index}]"
                source_objects[key] = obj
    return result


def validate_structured_actions(
    row: dict[str, Any],
    valid_keys: set[str],
    label: str,
    expected_consumers: dict[str, set[str]] | None = None,
    source_paths_by_key: dict[str, str] | None = None,
) -> list[str]:
    errors: list[str] = []
    action_count = sum(len(as_list(row.get(field))) for field in MUTATION_FIELDS)
    if action_count == 0:
        errors.append(f"{label}: cleanup operation has no structured change")
    creation_errors, created = _validate_creations(row, valid_keys, label)
    errors.extend(creation_errors)
    allowed_keys = valid_keys | created
    errors.extend(_validate_additions(row, allowed_keys, label, source_paths_by_key))
    errors.extend(_validate_changes(row, allowed_keys, label, source_paths_by_key))
    errors.extend(_validate_remaps(row, allowed_keys, label, expected_consumers))
    errors.extend(
        _validate_deletions_and_renames(
            row,
            allowed_keys,
            label,
            source_paths_by_key,
        )
    )
    errors.extend(
        validate_operation_set(
            [row],
            expected_consumers=expected_consumers,
            label=label,
        )
    )

    if row.get("minimum_aggressiveness") not in {None, ""}:
        errors.append(
            f"{label}: minimum_aggressiveness is deprecated; propose the best safe action "
            "and control execution through explicit operation approval"
        )

    canonical = str(row.get("canonical_object_key") or "")
    if canonical and canonical not in allowed_keys:
        errors.append(f"{label}: canonical_object_key is unknown")
    if canonical:
        canonical_basis = str(row.get("canonical_selection_rationale") or "")
        if not specific_text(canonical_basis, 7):
            errors.append(
                f"{label}: canonical selection requires a concrete source-based rationale"
            )
        else:
            lowered_basis = canonical_basis.lower()
            if canonical.lower() not in lowered_basis:
                errors.append(
                    f"{label}: canonical selection rationale must identify {canonical!r}"
                )
            if not re.search(
                r"\b(?:active|paused|consumer|reference|route|trigger|configuration|"
                r"consent|sequence|folder|name|owner|destination|payload)\b",
                lowered_basis,
            ):
                errors.append(
                    f"{label}: canonical selection rationale must use container-visible "
                    "activity, consumer, route, configuration, consent, sequence, folder, "
                    "name, destination, or ownership evidence"
                )
            if re.search(r"\b(?:oldest|newest|created|creation date|age)\b", lowered_basis) and not re.search(
                r"\b(?:active|paused|consumer|reference|route|trigger|configuration|"
                r"consent|sequence|folder|name|owner|destination|payload)\b",
                lowered_basis,
            ):
                errors.append(
                    f"{label}: object age alone cannot select the canonical object"
                )
    deleted_keys = {str(item.get("object_key") or "") for item in as_list(row.get("deletions"))}
    if canonical and canonical in deleted_keys:
        errors.append(f"{label}: canonical object cannot also be deleted")
    if row.get("deterministic_action_candidate") == "consolidate_candidate":
        source_keys = {
            str(value)
            for value in as_list(row.get("shared_fact_object_keys"))
            if str(value)
        }
        all_candidates_deleted = bool(source_keys) and source_keys <= deleted_keys
        if not canonical and not all_candidates_deleted:
            errors.append(
                f"{label}: consolidation requires an explicit canonical object unless every "
                "candidate is removed as inactive lifecycle cleanup"
            )
        if not as_list(row.get("deletions")):
            errors.append(f"{label}: consolidation requires deletion of non-canonical objects")
    return errors


def validate_challenge(
    row: dict[str, Any],
    label: str,
    source_paths_by_key: dict[str, str] | None = None,
) -> list[str]:
    if row.get("priority") not in {"Critical", "High"}:
        return []
    challenge = row.get("challenge_review")
    if not isinstance(challenge, dict):
        return [f"{label}: High/Critical operation requires a challenge review"]
    errors = []
    for field in (
        "source_recheck",
        "status_and_scope_check",
        "alternative_explanation",
    ):
        if not specific_text(challenge.get(field), 5):
            errors.append(f"{label}: challenge review field {field} is incomplete")
    if challenge.get("challenge_verdict") not in {
        "confirmed",
        "downgraded",
        "rejected",
        "blocked",
    }:
        errors.append(f"{label}: challenge_verdict is invalid")
    neutral = challenge.get("neutral_recheck")
    if not isinstance(neutral, dict):
        errors.append(
            f"{label}: High/Critical challenge requires a neutral source-only recheck"
        )
        return errors
    context_id = str(neutral.get("recheck_context_id") or "").strip()
    if len(context_id) < 12:
        errors.append(f"{label}: neutral recheck has no fresh context identity")
    coordinates = [
        str(value)
        for value in as_list(neutral.get("source_coordinates"))
        if str(value)
    ]
    if not coordinates or any(not value.startswith("$") for value in coordinates):
        errors.append(
            f"{label}: neutral recheck must list exact source JSON coordinates"
        )
    elif source_paths_by_key:
        source_roots = tuple(str(value) for value in source_paths_by_key.values())
        unresolved = [
            coordinate
            for coordinate in coordinates
            if not any(
                coordinate == root
                or coordinate.startswith((root + ".", root + "["))
                for root in source_roots
            )
        ]
        if unresolved:
            errors.append(
                f"{label}: neutral recheck coordinates do not resolve in the locked source: "
                f"{unresolved!r}"
            )
    question = str(neutral.get("neutral_question") or "")
    if not precise_question(question, 7) or re.search(
        r"\b(?:confirm|downgrade|reject|expected outcome|should be|correct verdict)\b",
        question,
        re.I,
    ):
        errors.append(
            f"{label}: neutral recheck question must ask only what the listed source facts prove"
        )
    if neutral.get("expected_outcome_disclosed") is not False:
        errors.append(f"{label}: neutral recheck disclosed an expected outcome")
    foreign = [
        str(value)
        for value in as_list(neutral.get("foreign_rationale_artifacts_used"))
        if str(value)
    ]
    if foreign:
        errors.append(f"{label}: neutral recheck used foreign rationale artifacts")
    if neutral.get("recheck_verdict") != challenge.get("challenge_verdict"):
        errors.append(
            f"{label}: challenge verdict must be the independently rechecked verdict"
        )
    return errors


def validate_neutral_recheck_contexts(
    review: dict[str, Any], parent_context_id: str, label: str
) -> list[str]:
    """Ensure material rechecks are fresh relative to their scan context."""

    errors: list[str] = []

    def visit(value: Any) -> None:
        if isinstance(value, list):
            for child in value:
                visit(child)
            return
        if not isinstance(value, dict):
            return
        challenge = value.get("challenge_review")
        if value.get("priority") in {"High", "Critical"} and isinstance(
            challenge, dict
        ):
            recheck_id = str(
                ((challenge.get("neutral_recheck") or {}).get("recheck_context_id"))
                or ""
            ).strip()
            if recheck_id and recheck_id == parent_context_id:
                errors.append(
                    f"{label}: a High/Critical neutral recheck reused the scan context"
                )
        for child in value.values():
            visit(child)

    visit(review)
    return errors
