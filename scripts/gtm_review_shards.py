#!/usr/bin/env python3
"""Split and merge source-locked GTM review artifacts without losing obligations."""

from __future__ import annotations

import argparse
import copy
import json
import re
import sys
from pathlib import Path
from typing import Any

from gtm_lib import as_list, load_json, stable_hash, write_json

COLLECTIONS_BY_KIND = {
    "gtm_operational_sanitation_review": (("findings", "finding_id"),),
    "gtm_configuration_correctness_review": (("rows", "object_key"),),
    "gtm_business_architecture_review": (
        ("families", "family_id"),
        ("comparisons", "comparison_id"),
    ),
}
LOCK_FIELDS = (
    "review_kind",
    "schema_version",
    "source_file",
    "source_sha256",
    "shared_facts_sha256",
    "context_sha256",
    "input_contract_sha256",
)
CONFIGURATION_OBLIGATION_SPECS = (
    ("required_branch_reviews", "configuration_branch_reviews", "json_path", "json_path"),
    ("reference_trace_requirements", "reference_traces", "reference", "reference"),
    ("required_contract_topics", "contract_checks", "topic_key", "contract_topic"),
    (
        "required_technical_findings",
        "technical_finding_reviews",
        "finding_key",
        "finding_key",
    ),
)
DEFAULT_MAX_ITEMS = 40
DEFAULT_MAX_OBLIGATIONS = 30
DEFAULT_MAX_AUTHORED_WORK_UNITS = 120
CONFIGURATION_PRIMARY_OBLIGATION_FIELDS = ("required_logic_cross_checks",)
CONFIGURATION_OVERLAY_REPRESENTATION = "configuration_completion_overlay"
CONFIGURATION_OVERLAY_IDENTITY_FIELDS = (
    "review_id",
    "object_key",
    "layer",
    "object_id",
    "object_name",
    "object_type",
    "paused",
)
CONFIGURATION_OVERLAY_EDITABLE_FIELDS = (
    "semantic_review_depth",
    "review_status",
    "correctness_verdict",
    "correctness_basis",
    "defects",
    "contract_checks",
    "code_behavior_blocks",
    "technical_facts_assessment",
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
)


def configuration_completion_overlay(row: dict[str, Any]) -> dict[str, Any]:
    """Keep only reviewer-owned fields; evidence stays in the locked base row."""

    fields = (*CONFIGURATION_OVERLAY_IDENTITY_FIELDS, *CONFIGURATION_OVERLAY_EDITABLE_FIELDS)
    return {
        **{field: copy.deepcopy(row.get(field)) for field in fields},
        "source_row_sha256": stable_hash(row, 64),
    }


def validate_configuration_overlay(
    overlay: dict[str, Any], source: dict[str, Any], label: str
) -> None:
    expected_fields = {
        *CONFIGURATION_OVERLAY_IDENTITY_FIELDS,
        *CONFIGURATION_OVERLAY_EDITABLE_FIELDS,
        "source_row_sha256",
    }
    if set(overlay) != expected_fields:
        raise ValueError(f"{label} configuration overlay fields are incomplete or unknown")
    if overlay.get("source_row_sha256") != stable_hash(source, 64):
        raise ValueError(f"{label} configuration overlay uses another source row")
    for field in CONFIGURATION_OVERLAY_IDENTITY_FIELDS:
        if overlay.get(field) != source.get(field):
            raise ValueError(f"{label} configuration overlay changed locked field {field}")


def restore_configuration_overlay(
    overlay: dict[str, Any], source: dict[str, Any], label: str
) -> dict[str, Any]:
    validate_configuration_overlay(overlay, source, label)
    restored = copy.deepcopy(source)
    for field in CONFIGURATION_OVERLAY_EDITABLE_FIELDS:
        restored[field] = copy.deepcopy(overlay.get(field))
    return restored


def safe_shard_path(directory: Path, filename: str) -> Path:
    if not filename or Path(filename).name != filename:
        raise ValueError(f"unsafe shard filename: {filename!r}")
    root = directory.resolve()
    path = (directory / filename).resolve()
    if path.parent != root:
        raise ValueError(f"shard path escapes its directory: {filename!r}")
    return path


def filename_token(value: str) -> str:
    token = re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("._")
    return token[:100] or "object"


def review_collections(review: dict[str, Any]) -> tuple[tuple[str, str], ...]:
    kind = str(review.get("kind") or "")
    if kind not in COLLECTIONS_BY_KIND:
        raise ValueError(f"unsupported review kind: {kind!r}")
    return COLLECTIONS_BY_KIND[kind]


def review_lock(review: dict[str, Any]) -> dict[str, Any]:
    return {
        "review_kind": review["kind"],
        "schema_version": review.get("schema_version"),
        "source_file": review.get("source_file"),
        "source_sha256": review.get("source_sha256"),
        "shared_facts_sha256": review.get("shared_facts_sha256"),
        "context_sha256": review.get("context_sha256"),
        "input_contract_sha256": (review.get("input_contract") or {}).get(
            "contract_sha256"
        ),
    }


def review_workload(review: dict[str, Any]) -> dict[str, Any]:
    collections = review_collections(review)
    collection_counts = {
        collection: len(as_list(review.get(collection)))
        for collection, _id_field in collections
    }
    workload = {
        "collection_counts": collection_counts,
        "review_items": sum(collection_counts.values()),
    }
    if review.get("kind") != "gtm_configuration_correctness_review":
        return workload

    if int(review.get("schema_version") or 0) >= 4:
        row_metrics = [
            row.get("configuration_coverage_metrics") or {}
            for row in as_list(review.get("rows"))
        ]
        evidence = sum(
            int(metrics.get("evidence_obligations") or 0) for metrics in row_metrics
        )
        authored = sum(
            int(metrics.get("authored_work_units") or 0) for metrics in row_metrics
        )
        workload.update(
            {
                "configuration_obligations": evidence,
                "configuration_evidence_obligations": evidence,
                "authored_behavior_work_units": authored,
                "largest_configuration_obligation_group": max(
                    (
                        int(metrics.get("evidence_obligations") or 0)
                        for metrics in row_metrics
                    ),
                    default=0,
                ),
                "largest_authored_behavior_workload": max(
                    (
                        int(metrics.get("authored_work_units") or 0)
                        for metrics in row_metrics
                    ),
                    default=0,
                ),
                "obligation_to_authored_ratio": round(
                    evidence / max(1, authored), 3
                ),
            }
        )
        return workload

    source_fields = [
        source_field
        for source_field, _completion, _source_id, _completion_id in (
            CONFIGURATION_OBLIGATION_SPECS
        )
    ]
    group_counts = [
        len(as_list(row.get(field)))
        for row in as_list(review.get("rows"))
        for field in (
            *source_fields,
            "code_line_facts",
            *CONFIGURATION_PRIMARY_OBLIGATION_FIELDS,
        )
    ]
    workload.update(
        {
            "configuration_obligations": sum(group_counts),
            "largest_configuration_obligation_group": max(group_counts, default=0),
        }
    )
    return workload


def review_requires_sharding(
    review: dict[str, Any],
    max_items: int = DEFAULT_MAX_ITEMS,
    max_obligations: int = DEFAULT_MAX_OBLIGATIONS,
) -> bool:
    if max_items < 1:
        raise ValueError("max_items must be at least 1")
    if max_obligations < 1 or max_obligations > DEFAULT_MAX_OBLIGATIONS:
        raise ValueError(
            f"max_obligations must be between 1 and {DEFAULT_MAX_OBLIGATIONS}"
        )
    workload = review_workload(review)
    if (
        review.get("kind") == "gtm_configuration_correctness_review"
        and int(review.get("schema_version") or 0) >= 4
    ):
        return (
            workload["review_items"] > max_items
            or workload.get("authored_behavior_work_units", 0)
            > DEFAULT_MAX_AUTHORED_WORK_UNITS
        )
    return (
        workload["review_items"] > max_items
        or (
            workload.get("largest_configuration_obligation_group", 0)
            > max_obligations
        )
    )


def obligation_manifest_row(
    filename: str,
    object_key: str,
    source_field: str,
    completion_field: str,
    source_ids: list[str],
) -> dict[str, Any]:
    return {
        "filename": filename,
        "object_key": object_key,
        "source_field": source_field,
        "completion_field": completion_field,
        "source_ids": source_ids,
    }


def generic_obligation_shards_for_row(
    review_path: Path,
    row: dict[str, Any],
    output_dir: Path,
    max_obligations: int,
    pretty: bool,
    lock: dict[str, Any],
) -> list[dict[str, Any]]:
    object_key = str(row.get("object_key") or "")
    manifest_rows: list[dict[str, Any]] = []
    for source_field, completion_field, source_id, completion_id in (
        CONFIGURATION_OBLIGATION_SPECS
    ):
        source_items = as_list(row.get(source_field))
        completed_by_id = {
            str(item.get(completion_id) or ""): item
            for item in as_list(row.get(completion_field))
            if isinstance(item, dict)
        }
        for index, start in enumerate(
            range(0, len(source_items), max_obligations), start=1
        ):
            chunk = source_items[start : start + max_obligations]
            source_ids = [str(item.get(source_id) or "") for item in chunk]
            filename = (
                f"{review_path.stem}.obligation.{filename_token(object_key)}."
                f"{source_field}.{index:04d}.json"
            )
            shard = {
                **lock,
                "kind": "gtm_configuration_obligation_shard",
                "object_key": object_key,
                "source_field": source_field,
                "completion_field": completion_field,
                "source_id_field": source_id,
                "completion_id_field": completion_id,
                "source_ids": source_ids,
                "source_items": chunk,
                "completed_items": [
                    completed_by_id[item_id]
                    for item_id in source_ids
                    if item_id in completed_by_id
                ],
            }
            write_json(output_dir / filename, shard, pretty)
            manifest_rows.append(
                obligation_manifest_row(
                    filename,
                    object_key,
                    source_field,
                    completion_field,
                    source_ids,
                )
            )
    return manifest_rows


def code_block_groups(
    code_facts: list[dict[str, Any]],
    blocks: list[dict[str, Any]],
    max_obligations: int,
) -> list[tuple[list[dict[str, Any]], list[dict[str, Any]]]]:
    if not blocks:
        return [
            (code_facts[start : start + max_obligations], [])
            for start in range(0, len(code_facts), max_obligations)
        ]
    groups: list[tuple[list[dict[str, Any]], list[dict[str, Any]]]] = []
    facts_by_hash = {str(item.get("line_hash") or ""): item for item in code_facts}
    covered: set[str] = set()
    for block in blocks:
        hashes = [str(value) for value in as_list(block.get("line_hashes"))]
        facts = [facts_by_hash[value] for value in hashes if value in facts_by_hash]
        for start in range(0, len(facts), max_obligations):
            chunk = facts[start : start + max_obligations]
            chunk_block = copy.deepcopy(block)
            chunk_block["line_hashes"] = [
                str(item.get("line_hash") or "") for item in chunk
            ]
            groups.append((chunk, [chunk_block]))
        covered.update(hashes)
    uncovered = [
        item
        for item in code_facts
        if str(item.get("line_hash") or "") not in covered
    ]
    groups.extend(
        (uncovered[start : start + max_obligations], [])
        for start in range(0, len(uncovered), max_obligations)
    )
    return groups


def code_obligation_shards_for_row(
    review_path: Path,
    row: dict[str, Any],
    output_dir: Path,
    max_obligations: int,
    pretty: bool,
    lock: dict[str, Any],
) -> list[dict[str, Any]]:
    code_facts = as_list(row.get("code_line_facts"))
    if not code_facts:
        return []
    object_key = str(row.get("object_key") or "")
    manifest_rows = []
    groups = code_block_groups(
        code_facts, as_list(row.get("code_behavior_blocks")), max_obligations
    )
    for index, (facts, completed_blocks) in enumerate(groups, start=1):
        if not facts:
            continue
        hashes = [str(item.get("line_hash") or "") for item in facts]
        filename = (
            f"{review_path.stem}.obligation.{filename_token(object_key)}."
            f"code_line_facts.{index:04d}.json"
        )
        shard = {
            **lock,
            "kind": "gtm_configuration_obligation_shard",
            "object_key": object_key,
            "source_field": "code_line_facts",
            "completion_field": "code_behavior_blocks",
            "source_id_field": "line_hash",
            "completion_id_field": "line_hashes",
            "source_ids": hashes,
            "source_items": facts,
            "completed_items": completed_blocks,
        }
        write_json(output_dir / filename, shard, pretty)
        manifest_rows.append(
            obligation_manifest_row(
                filename,
                object_key,
                "code_line_facts",
                "code_behavior_blocks",
                hashes,
            )
        )
    return manifest_rows


def configuration_obligation_shards(
    review_path: Path,
    rows: list[dict[str, Any]],
    output_dir: Path,
    max_obligations: int,
    pretty: bool,
    lock: dict[str, Any],
) -> list[dict[str, Any]]:
    manifest_rows: list[dict[str, Any]] = []
    for row in rows:
        manifest_rows.extend(
            generic_obligation_shards_for_row(
                review_path, row, output_dir, max_obligations, pretty, lock
            )
        )
        manifest_rows.extend(
            code_obligation_shards_for_row(
                review_path, row, output_dir, max_obligations, pretty, lock
            )
        )
    return manifest_rows


def split_review(
    review_path: Path,
    output_dir: Path,
    max_items: int,
    pretty: bool = True,
    max_obligations: int = DEFAULT_MAX_OBLIGATIONS,
) -> dict[str, Any]:
    if max_items < 1:
        raise ValueError("max_items must be at least 1")
    if max_obligations < 1 or max_obligations > DEFAULT_MAX_OBLIGATIONS:
        raise ValueError(
            f"max_obligations must be between 1 and {DEFAULT_MAX_OBLIGATIONS}"
        )
    review = load_json(review_path)
    collections = review_collections(review)
    lock = review_lock(review)
    output_dir.mkdir(parents=True, exist_ok=True)
    manifest_rows: list[dict[str, Any]] = []
    obligation_manifest_rows: list[dict[str, Any]] = []
    sharded_review = copy.deepcopy(review)
    legacy_configuration = (
        review.get("kind") == "gtm_configuration_correctness_review"
        and int(review.get("schema_version") or 0) < 4
    )
    if legacy_configuration:
        obligation_manifest_rows = configuration_obligation_shards(
            review_path,
            as_list(review.get("rows")),
            output_dir,
            max_obligations,
            pretty,
            lock,
        )
        for row in as_list(sharded_review.get("rows")):
            for source_field, completion_field, _source_id, _completion_id in (
                CONFIGURATION_OBLIGATION_SPECS
            ):
                row[source_field] = []
                row[completion_field] = []
            row["code_line_facts"] = []
            row["required_code_line_hashes"] = []
            row["code_behavior_blocks"] = []
    for collection, id_field in collections:
        items = as_list(sharded_review.get(collection))
        identifiers = [str(item.get(id_field) or "") for item in items]
        if any(not identifier for identifier in identifiers):
            raise ValueError(f"{collection} contains an item without {id_field}")
        if len(identifiers) != len(set(identifiers)):
            raise ValueError(f"{collection} contains duplicate {id_field} values")
        chunks: list[list[dict[str, Any]]] = []
        if (
            review.get("kind") == "gtm_configuration_correctness_review"
            and collection == "rows"
            and int(review.get("schema_version") or 0) >= 4
        ):
            current: list[dict[str, Any]] = []
            current_work = 0
            for item in items:
                item_work = max(
                    1,
                    int(
                        (item.get("configuration_coverage_metrics") or {}).get(
                            "authored_work_units"
                        )
                        or 0
                    ),
                )
                if current and (
                    len(current) >= max_items
                    or current_work + item_work > DEFAULT_MAX_AUTHORED_WORK_UNITS
                ):
                    chunks.append(current)
                    current = []
                    current_work = 0
                current.append(item)
                current_work += item_work
            if current:
                chunks.append(current)
        else:
            chunks = [
                items[start : start + max_items]
                for start in range(0, len(items), max_items)
            ]
        for shard_index, shard_items in enumerate(chunks, start=1):
            configuration_overlay = (
                review.get("kind") == "gtm_configuration_correctness_review"
                and collection == "rows"
                and int(review.get("schema_version") or 0) >= 4
            )
            output_items = (
                [configuration_completion_overlay(item) for item in shard_items]
                if configuration_overlay
                else shard_items
            )
            filename = f"{review_path.stem}.{collection}.{shard_index:04d}.json"
            shard = {
                **lock,
                "kind": "gtm_review_shard",
                "collection": collection,
                "id_field": id_field,
                "shard_index": shard_index,
                "item_ids": [str(item[id_field]) for item in shard_items],
                "representation": (
                    CONFIGURATION_OVERLAY_REPRESENTATION
                    if configuration_overlay
                    else "complete_items"
                ),
                "items": output_items,
            }
            write_json(output_dir / filename, shard, pretty)
            manifest_rows.append(
                {
                    "filename": filename,
                    "collection": collection,
                    "id_field": id_field,
                    "item_ids": shard["item_ids"],
                    "representation": shard["representation"],
                    "authored_work_units": sum(
                        int(
                            (item.get("configuration_coverage_metrics") or {}).get(
                                "authored_work_units"
                            )
                            or 0
                        )
                        for item in shard_items
                    ),
                }
            )
    discovery_filename = ""
    if review.get("kind") == "gtm_business_architecture_review":
        discovery_filename = f"{review_path.stem}.open_discovery.0001.json"
        discovery = {
            **lock,
            "kind": "gtm_architecture_discovery_shard",
            "base_comparison_ids": [
                str(item.get("comparison_id") or "")
                for item in as_list(review.get("comparisons"))
            ],
            "discovered_comparisons": [],
            "open_discovery_attestation": review.get(
                "open_discovery_attestation", {}
            ),
        }
        write_json(output_dir / discovery_filename, discovery, pretty)
    manifest = {
        **lock,
        "kind": "gtm_review_shard_manifest",
        "base_review_file": review_path.name,
        "max_items": max_items,
        "max_obligations": max_obligations,
        "max_authored_work_units": DEFAULT_MAX_AUTHORED_WORK_UNITS,
        "collection_counts": {
            collection: len(as_list(review.get(collection))) for collection, _ in collections
        },
        "shards": manifest_rows,
        "obligation_shards": obligation_manifest_rows,
        "discovery_shard": discovery_filename,
    }
    write_json(output_dir / "shard_manifest.json", manifest, pretty)
    return manifest


def lock_value(review: dict[str, Any], field: str) -> Any:
    if field == "review_kind":
        return review.get("kind")
    if field == "input_contract_sha256":
        return (review.get("input_contract") or {}).get("contract_sha256")
    return review.get(field)


def validate_lock_fields(
    payload: dict[str, Any], base: dict[str, Any], label: str
) -> None:
    for field in LOCK_FIELDS:
        if payload.get(field) != lock_value(base, field):
            raise ValueError(f"{label} {field} differs from the base review")


def manifest_entry(
    manifest: dict[str, Any], filename: str
) -> tuple[str, dict[str, Any]]:
    matches: list[tuple[str, dict[str, Any]]] = []
    for kind, field in (("review", "shards"), ("obligation", "obligation_shards")):
        matches.extend(
            (kind, row)
            for row in as_list(manifest.get(field))
            if str(row.get("filename") or "") == filename
        )
    if str(manifest.get("discovery_shard") or "") == filename:
        matches.append(("discovery", {"filename": filename}))
    if not matches:
        raise ValueError(f"shard is not declared by the manifest: {filename}")
    if len(matches) != 1:
        raise ValueError(f"shard filename is declared more than once: {filename}")
    return matches[0]


def check_primary_shard(
    base: dict[str, Any], manifest_row: dict[str, Any], shard: dict[str, Any], filename: str
) -> int:
    if shard.get("kind") != "gtm_review_shard":
        raise ValueError(f"invalid review shard kind: {filename}")
    validate_lock_fields(shard, base, filename)
    collection = str(shard.get("collection") or "")
    id_field = str(shard.get("id_field") or "")
    if (collection, id_field) not in review_collections(base):
        raise ValueError(f"invalid shard collection or ID field in {filename}")
    for field in ("collection", "id_field"):
        if shard.get(field) != manifest_row.get(field):
            raise ValueError(f"{filename} {field} differs from the manifest")
    if shard.get("representation") != manifest_row.get("representation"):
        raise ValueError(f"{filename} representation differs from the manifest")
    items = as_list(shard.get("items"))
    item_ids = [str(item.get(id_field) or "") for item in items]
    expected_ids = [str(value) for value in as_list(manifest_row.get("item_ids"))]
    if any(not value for value in item_ids) or len(item_ids) != len(set(item_ids)):
        raise ValueError(f"{filename} contains blank or duplicate item IDs")
    if item_ids != [str(value) for value in as_list(shard.get("item_ids"))]:
        raise ValueError(f"{filename} item_ids do not match its items")
    if item_ids != expected_ids:
        raise ValueError(f"{filename} item_ids differ from the manifest")
    base_ids = {
        str(item.get(id_field) or "") for item in as_list(base.get(collection))
    }
    if not set(item_ids) <= base_ids:
        raise ValueError(f"{filename} contains an item absent from the base review")
    if shard.get("representation") == CONFIGURATION_OVERLAY_REPRESENTATION:
        base_by_id = {
            str(item.get(id_field) or ""): item
            for item in as_list(base.get(collection))
        }
        for item_id, item in zip(item_ids, items, strict=True):
            validate_configuration_overlay(
                item,
                base_by_id[item_id],
                f"{filename}:{item_id}",
            )
    pending = [value for value, item in zip(item_ids, items, strict=True) if item.get("review_status") != "complete"]
    if pending:
        raise ValueError(f"{filename} contains pending items: {pending!r}")
    return len(items)


def obligation_identity_fields(source_field: str) -> tuple[str, str]:
    if source_field == "code_line_facts":
        return "line_hash", "line_hashes"
    for source, _completion, source_id, completion_id in CONFIGURATION_OBLIGATION_SPECS:
        if source == source_field:
            return source_id, completion_id
    raise ValueError(f"unsupported configuration obligation field: {source_field!r}")


def check_obligation_shard(
    base: dict[str, Any], manifest_row: dict[str, Any], shard: dict[str, Any], filename: str
) -> int:
    if shard.get("kind") != "gtm_configuration_obligation_shard":
        raise ValueError(f"invalid configuration obligation shard: {filename}")
    validate_lock_fields(shard, base, filename)
    object_key = str(shard.get("object_key") or "")
    source_field = str(shard.get("source_field") or "")
    for field in ("object_key", "source_field", "completion_field"):
        if shard.get(field) != manifest_row.get(field):
            raise ValueError(f"{filename} {field} differs from the manifest")
    source_id_field, completion_id_field = obligation_identity_fields(source_field)
    if shard.get("source_id_field") != source_id_field:
        raise ValueError(f"{filename} source identity field is invalid")
    if shard.get("completion_id_field") != completion_id_field:
        raise ValueError(f"{filename} completion identity field is invalid")
    original_row = next(
        (
            row
            for row in as_list(base.get("rows"))
            if str(row.get("object_key") or "") == object_key
        ),
        None,
    )
    if not original_row:
        raise ValueError(f"{filename} references unknown object {object_key!r}")
    source_items = as_list(shard.get("source_items"))
    source_ids = [str(item.get(source_id_field) or "") for item in source_items]
    expected_ids = [str(value) for value in as_list(manifest_row.get("source_ids"))]
    if any(not value for value in source_ids) or len(source_ids) != len(set(source_ids)):
        raise ValueError(f"{filename} contains blank or duplicate source IDs")
    if source_ids != [str(value) for value in as_list(shard.get("source_ids"))]:
        raise ValueError(f"{filename} source IDs do not match its source items")
    if source_ids != expected_ids:
        raise ValueError(f"{filename} source IDs differ from the manifest")
    original_by_id = {
        str(item.get(source_id_field) or ""): item
        for item in as_list(original_row.get(source_field))
    }
    if source_items != [original_by_id.get(value) for value in source_ids]:
        raise ValueError(f"{filename} source obligations differ from the base review")
    completed_items = as_list(shard.get("completed_items"))
    if any(not isinstance(item, dict) for item in completed_items):
        raise ValueError(f"{filename} contains a non-object completion")
    if completion_id_field == "line_hashes":
        if any(not as_list(item.get(completion_id_field)) for item in completed_items):
            raise ValueError(f"{filename} contains an empty code completion block")
        completed_ids = [
            str(value)
            for item in completed_items
            for value in as_list(item.get(completion_id_field))
        ]
        if any(len(as_list(item.get(completion_id_field))) > 30 for item in completed_items):
            raise ValueError(f"{filename} contains a code block above 30 lines")
        if completed_ids != source_ids:
            raise ValueError(
                f"{filename} code completions must cover every source line "
                "exactly once and in order"
            )
    else:
        completed_ids = [
            str(item.get(completion_id_field) or "") for item in completed_items
        ]
        if any(not value for value in completed_ids) or len(completed_ids) != len(
            set(completed_ids)
        ):
            raise ValueError(f"{filename} contains blank or duplicate completion IDs")
        if set(completed_ids) != set(source_ids):
            raise ValueError(
                f"{filename} completions must cover every source obligation exactly once"
            )
    return len(source_ids)


def check_shard(
    base_review_path: Path, shard_dir: Path, shard_filename: str
) -> dict[str, Any]:
    base = load_json(base_review_path)
    review_collections(base)
    manifest = load_json(shard_dir / "shard_manifest.json")
    validate_lock_fields(manifest, base, "shard manifest")
    filename = Path(shard_filename).name
    if filename != shard_filename:
        raise ValueError(f"unsafe shard filename: {shard_filename!r}")
    shard_kind, row = manifest_entry(manifest, filename)
    path = safe_shard_path(shard_dir, filename)
    if not path.is_file():
        raise ValueError(f"missing review shard: {filename}")
    shard = load_json(path)
    if shard_kind == "review":
        completed_count = check_primary_shard(base, row, shard, filename)
    elif shard_kind == "obligation":
        completed_count = check_obligation_shard(base, row, shard, filename)
    else:
        copy_base = copy.deepcopy(base)
        merge_architecture_discovery(copy_base, manifest, shard_dir)
        completed_count = len(as_list(shard.get("discovered_comparisons"))) + 1
    return {
        "kind": "gtm_review_shard_check",
        "status": "pass",
        "shard": filename,
        "shard_kind": shard_kind,
        "completed_items": completed_count,
        "source_sha256": base.get("source_sha256"),
        "shared_facts_sha256": base.get("shared_facts_sha256"),
        "context_sha256": base.get("context_sha256"),
    }


def merge_primary_shards(
    base: dict[str, Any],
    collections: tuple[tuple[str, str], ...],
    manifest: dict[str, Any],
    shard_dir: Path,
) -> dict[str, dict[str, dict[str, Any]]]:
    merged = {collection: {} for collection, _ in collections}
    manifest_rows = as_list(manifest.get("shards"))
    if any(not str(row.get("filename") or "") for row in manifest_rows):
        raise ValueError("shard manifest contains a blank filename")

    for manifest_row in manifest_rows:
        filename = str(manifest_row["filename"])
        path = safe_shard_path(shard_dir, filename)
        if not path.is_file():
            raise ValueError(f"missing review shard: {filename}")
        shard = load_json(path)
        collection = str(shard.get("collection") or "")
        id_field = str(shard.get("id_field") or "")
        if (collection, id_field) not in collections:
            raise ValueError(f"invalid shard collection or ID field in {filename}")
        validate_lock_fields(shard, base, filename)
        items = as_list(shard.get("items"))
        item_ids = [str(item.get(id_field) or "") for item in items]
        if item_ids != [str(value) for value in as_list(shard.get("item_ids"))]:
            raise ValueError(f"{filename} item_ids do not match its items")
        if item_ids != [str(value) for value in as_list(manifest_row.get("item_ids"))]:
            raise ValueError(f"{filename} item_ids differ from the manifest")
        if shard.get("representation") != manifest_row.get("representation"):
            raise ValueError(f"{filename} representation differs from the manifest")
        base_by_id = {
            str(item.get(id_field) or ""): item
            for item in as_list(base.get(collection))
        }
        target = merged[collection]
        for item_id, item in zip(item_ids, items, strict=True):
            if item_id in target:
                raise ValueError(f"duplicate completed item {item_id!r} in {collection}")
            if item.get("review_status") != "complete":
                raise ValueError(f"pending completed item {item_id!r} in {collection}")
            target[item_id] = (
                restore_configuration_overlay(
                    item,
                    base_by_id[item_id],
                    f"{filename}:{item_id}",
                )
                if shard.get("representation")
                == CONFIGURATION_OVERLAY_REPRESENTATION
                else item
            )
    return merged


def restore_primary_collections(
    base: dict[str, Any],
    collections: tuple[tuple[str, str], ...],
    merged: dict[str, dict[str, dict[str, Any]]],
) -> None:
    for collection, id_field in collections:
        expected_ids = [
            str(item.get(id_field) or "") for item in as_list(base.get(collection))
        ]
        supplied = merged[collection]
        if set(supplied) != set(expected_ids):
            missing = sorted(set(expected_ids) - set(supplied))
            unknown = sorted(set(supplied) - set(expected_ids))
            raise ValueError(
                f"{collection} shard coverage mismatch; "
                f"missing={missing!r}, unknown={unknown!r}"
            )
        base[collection] = [supplied[item_id] for item_id in expected_ids]


def read_configuration_obligations(
    base: dict[str, Any],
    original_by_key: dict[str, dict[str, Any]],
    manifest: dict[str, Any],
    shard_dir: Path,
) -> tuple[
    dict[tuple[str, str], list[dict[str, Any]]],
    dict[tuple[str, str], list[str]],
]:
    completed: dict[tuple[str, str], list[dict[str, Any]]] = {}
    seen_sources: dict[tuple[str, str], list[str]] = {}
    for manifest_row in as_list(manifest.get("obligation_shards")):
        filename = str(manifest_row.get("filename") or "")
        path = safe_shard_path(shard_dir, filename)
        if not path.is_file():
            raise ValueError(f"missing configuration obligation shard: {filename}")
        shard = load_json(path)
        if shard.get("kind") != "gtm_configuration_obligation_shard":
            raise ValueError(f"invalid configuration obligation shard: {filename}")
        validate_lock_fields(shard, base, filename)
        object_key = str(shard.get("object_key") or "")
        source_field = str(shard.get("source_field") or "")
        completion_field = str(shard.get("completion_field") or "")
        source_id_field = str(shard.get("source_id_field") or "")
        source_items = as_list(shard.get("source_items"))
        source_ids = [str(item.get(source_id_field) or "") for item in source_items]
        if source_ids != [str(value) for value in as_list(shard.get("source_ids"))]:
            raise ValueError(f"{filename} source IDs do not match its source items")
        original_row = original_by_key.get(object_key)
        if not original_row:
            raise ValueError(f"{filename} references unknown object {object_key!r}")
        original_items = as_list(original_row.get(source_field))
        original_by_id = {
            str(item.get(source_id_field) or ""): item for item in original_items
        }
        if source_items != [original_by_id.get(value) for value in source_ids]:
            raise ValueError(f"{filename} source obligations differ from the base review")
        seen_sources.setdefault((object_key, source_field), []).extend(source_ids)
        completed.setdefault((object_key, completion_field), []).extend(
            as_list(shard.get("completed_items"))
        )
    return completed, seen_sources


def restore_configuration_obligations(
    original_by_key: dict[str, dict[str, Any]],
    merged_by_key: dict[str, dict[str, Any]],
    completed: dict[tuple[str, str], list[dict[str, Any]]],
    seen_sources: dict[tuple[str, str], list[str]],
) -> None:
    for object_key, original_row in original_by_key.items():
        merged_row = merged_by_key[object_key]
        for source_field, completion_field, source_id, _completion_id in (
            CONFIGURATION_OBLIGATION_SPECS
        ):
            expected_ids = [
                str(item.get(source_id) or "")
                for item in as_list(original_row.get(source_field))
            ]
            if seen_sources.get((object_key, source_field), []) != expected_ids:
                raise ValueError(
                    f"configuration obligation coverage mismatch for "
                    f"{object_key} {source_field}"
                )
            merged_row[source_field] = copy.deepcopy(original_row.get(source_field, []))
            merged_row[completion_field] = completed.get(
                (object_key, completion_field), []
            )
        restore_code_obligations(
            object_key, original_row, merged_row, completed, seen_sources
        )


def restore_code_obligations(
    object_key: str,
    original_row: dict[str, Any],
    merged_row: dict[str, Any],
    completed: dict[tuple[str, str], list[dict[str, Any]]],
    seen_sources: dict[tuple[str, str], list[str]],
) -> None:
    code_ids = [
        str(item.get("line_hash") or "")
        for item in as_list(original_row.get("code_line_facts"))
    ]
    if not code_ids:
        return
    if seen_sources.get((object_key, "code_line_facts"), []) != code_ids:
        raise ValueError(
            f"configuration obligation coverage mismatch for {object_key} code lines"
        )
    merged_row["code_line_facts"] = copy.deepcopy(
        original_row.get("code_line_facts", [])
    )
    merged_row["required_code_line_hashes"] = copy.deepcopy(
        original_row.get("required_code_line_hashes", [])
    )
    merged_row["code_behavior_blocks"] = completed.get(
        (object_key, "code_behavior_blocks"), []
    )


def merge_configuration_obligations(
    base: dict[str, Any],
    base_review_path: Path,
    manifest: dict[str, Any],
    shard_dir: Path,
) -> None:
    original = load_json(base_review_path)
    original_by_key = {
        str(row.get("object_key") or ""): row for row in as_list(original.get("rows"))
    }
    merged_by_key = {
        str(row.get("object_key") or ""): row for row in as_list(base.get("rows"))
    }
    completed, seen_sources = read_configuration_obligations(
        base, original_by_key, manifest, shard_dir
    )
    restore_configuration_obligations(
        original_by_key, merged_by_key, completed, seen_sources
    )


def merge_architecture_discovery(
    base: dict[str, Any], manifest: dict[str, Any], shard_dir: Path
) -> None:
    filename = str(manifest.get("discovery_shard") or "")
    if not filename:
        raise ValueError("architecture shard manifest has no discovery shard")
    path = safe_shard_path(shard_dir, filename)
    if not path.is_file():
        raise ValueError(f"missing architecture discovery shard: {filename}")
    discovery = load_json(path)
    if discovery.get("kind") != "gtm_architecture_discovery_shard":
        raise ValueError("architecture discovery shard kind is invalid")
    validate_lock_fields(discovery, base, "architecture discovery shard")
    base_ids = [
        str(item.get("comparison_id") or "")
        for item in as_list(base.get("comparisons"))
    ]
    if as_list(discovery.get("base_comparison_ids")) != base_ids:
        raise ValueError("architecture discovery shard base comparisons changed")
    discovered = as_list(discovery.get("discovered_comparisons"))
    discovered_ids = [str(item.get("comparison_id") or "") for item in discovered]
    if any(not value.startswith("DISC-") for value in discovered_ids):
        raise ValueError("all discovered comparison IDs must start with DISC-")
    if len(discovered_ids) != len(set(discovered_ids)) or set(discovered_ids) & set(
        base_ids
    ):
        raise ValueError("architecture discovery comparison IDs are duplicate")
    if any(item.get("review_status") != "complete" for item in discovered):
        raise ValueError("all discovered comparisons must be complete")
    attestation = discovery.get("open_discovery_attestation") or {}
    if attestation.get("review_status") != "complete":
        raise ValueError("architecture discovery attestation must be complete")
    if set(as_list(attestation.get("discovered_comparison_ids"))) != set(
        discovered_ids
    ):
        raise ValueError("architecture discovery IDs do not match its attestation")
    base["comparisons"] = [*as_list(base.get("comparisons")), *discovered]
    base["open_discovery_attestation"] = attestation


def merge_review(
    base_review_path: Path,
    shard_dir: Path,
    output_path: Path,
    pretty: bool = True,
) -> dict[str, Any]:
    base = load_json(base_review_path)
    collections = review_collections(base)
    manifest = load_json(shard_dir / "shard_manifest.json")
    validate_lock_fields(manifest, base, "shard manifest")
    merged = merge_primary_shards(base, collections, manifest, shard_dir)
    restore_primary_collections(base, collections, merged)
    if (
        base.get("kind") == "gtm_configuration_correctness_review"
        and int(base.get("schema_version") or 0) < 4
    ):
        merge_configuration_obligations(base, base_review_path, manifest, shard_dir)

    if base.get("kind") == "gtm_business_architecture_review":
        merge_architecture_discovery(base, manifest, shard_dir)
    base["run_status"] = "complete"
    write_json(output_path, base, pretty)
    return base


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    split = subparsers.add_parser("split")
    split.add_argument("review", type=Path)
    split.add_argument("output_dir", type=Path)
    split.add_argument("--max-items", type=int, default=DEFAULT_MAX_ITEMS)
    split.add_argument(
        "--max-obligations", type=int, default=DEFAULT_MAX_OBLIGATIONS
    )
    split.add_argument("--compact", action="store_true")
    merge = subparsers.add_parser("merge")
    merge.add_argument("base_review", type=Path)
    merge.add_argument("shard_dir", type=Path)
    merge.add_argument("output", type=Path)
    merge.add_argument("--compact", action="store_true")
    check = subparsers.add_parser("check")
    check.add_argument("base_review", type=Path)
    check.add_argument("shard_dir", type=Path)
    check.add_argument("shard", help="Completed shard filename declared in the manifest")
    args = parser.parse_args()
    try:
        if args.command == "split":
            result = split_review(
                args.review,
                args.output_dir,
                args.max_items,
                not args.compact,
                args.max_obligations,
            )
            print(
                json.dumps(
                    {
                        "output_dir": str(args.output_dir),
                        "shards": len(result["shards"]),
                    }
                )
            )
        elif args.command == "merge":
            result = merge_review(
                args.base_review,
                args.shard_dir,
                args.output,
                not args.compact,
            )
            print(
                json.dumps(
                    {
                        "output": str(args.output),
                        "run_status": result["run_status"],
                    }
                )
            )
        else:
            result = check_shard(args.base_review, args.shard_dir, args.shard)
            print(json.dumps(result))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
