#!/usr/bin/env python3
"""Validate and simulate exact GTM operations on an in-memory container copy."""

from __future__ import annotations

import copy
import re
from collections import defaultdict, deque
from typing import Any

from gtm_audit_contract import OPERATION_ACTION_FIELDS
from gtm_lib import ID_KEYS, as_list, container_version, stable_hash

JSON_PATH_TOKEN_RE = re.compile(r"\.([^.[\]]+)|\[(\d+)\]")


def object_catalog(data: dict[str, Any]) -> dict[str, dict[str, Any]]:
    cv = container_version(data)
    catalog: dict[str, dict[str, Any]] = {}
    for layer, id_key in ID_KEYS.items():
        for index, obj in enumerate(as_list(cv.get(layer))):
            if not isinstance(obj, dict):
                continue
            identity = str(obj.get(id_key) or "")
            if not identity:
                continue
            catalog[f"{layer}:{identity}"] = {
                "layer": layer,
                "id_key": id_key,
                "index": index,
                "object": obj,
            }
    return catalog


def _path_tokens(path: str) -> list[str | int]:
    if path == "$":
        return []
    if not path.startswith("$"):
        raise ValueError("operation json_path must be relative and start with $")
    tokens: list[str | int] = []
    consumed = 0
    body = path[1:]
    for match in JSON_PATH_TOKEN_RE.finditer(body):
        if match.start() != consumed:
            raise ValueError(f"unsupported operation JSON path: {path}")
        tokens.append(
            match.group(1) if match.group(1) is not None else int(match.group(2))
        )
        consumed = match.end()
    if consumed != len(body):
        raise ValueError(f"unsupported operation JSON path: {path}")
    return tokens


def get_json_path(target: Any, path: str) -> Any:
    current = target
    for token in _path_tokens(path):
        if isinstance(token, int):
            if not isinstance(current, list) or token >= len(current):
                raise KeyError(path)
            current = current[token]
        else:
            if not isinstance(current, dict) or token not in current:
                raise KeyError(path)
            current = current[token]
    return current


def set_json_path(target: Any, path: str, value: Any, *, allow_create: bool = False) -> None:
    tokens = _path_tokens(path)
    if not tokens:
        raise ValueError("an operation cannot replace the complete source object")
    current = target
    for token in tokens[:-1]:
        if isinstance(token, int):
            if not isinstance(current, list) or token >= len(current):
                raise KeyError(path)
            current = current[token]
        else:
            if not isinstance(current, dict) or token not in current:
                raise KeyError(path)
            current = current[token]
    final = tokens[-1]
    if isinstance(final, int):
        if not isinstance(current, list) or final >= len(current):
            raise KeyError(path)
        current[final] = copy.deepcopy(value)
    else:
        if not isinstance(current, dict):
            raise KeyError(path)
        if not allow_create and final not in current:
            raise KeyError(path)
        current[final] = copy.deepcopy(value)


def delete_json_path(target: Any, path: str) -> None:
    """Remove one existing object field; list-item deletion is intentionally unsupported."""

    tokens = _path_tokens(path)
    if not tokens or isinstance(tokens[-1], int):
        raise ValueError("field removal must target one named object property")
    current = target
    for token in tokens[:-1]:
        if isinstance(token, int):
            if not isinstance(current, list) or token >= len(current):
                raise KeyError(path)
            current = current[token]
        else:
            if not isinstance(current, dict) or token not in current:
                raise KeyError(path)
            current = current[token]
    final = tokens[-1]
    if not isinstance(current, dict) or final not in current:
        raise KeyError(path)
    del current[final]


def _object_name(catalog: dict[str, dict[str, Any]], key: str) -> str:
    return str((catalog.get(key) or {}).get("object", {}).get("name") or "")


def _replace_reference(value: Any, before: str, after: str) -> Any:
    if isinstance(value, dict):
        return {key: _replace_reference(item, before, after) for key, item in value.items()}
    if isinstance(value, list):
        return [_replace_reference(item, before, after) for item in value]
    if isinstance(value, str):
        return value.replace(before, after)
    return value


def _remap_consumer(
    consumer: dict[str, Any],
    layer: str,
    from_key: str,
    to_key: str,
    catalog: dict[str, dict[str, Any]],
) -> None:
    from_id = from_key.split(":", 1)[1]
    to_id = to_key.split(":", 1)[1]
    if layer == "trigger":
        for field in ("firingTriggerId", "blockingTriggerId"):
            if isinstance(consumer.get(field), list):
                consumer[field] = [
                    to_id if str(value) == from_id else value
                    for value in consumer[field]
                ]
        consumer.update(_replace_reference(consumer, f'"{from_id}"', f'"{to_id}"'))
        return
    if layer == "variable":
        before = "{{" + _object_name(catalog, from_key) + "}}"
        after = "{{" + _object_name(catalog, to_key) + "}}"
        consumer.update(_replace_reference(consumer, before, after))
        return
    if layer == "tag":
        before_name = _object_name(catalog, from_key)
        after_name = _object_name(catalog, to_key)
        for field in ("setupTag", "teardownTag"):
            for item in as_list(consumer.get(field)):
                if isinstance(item, dict) and str(item.get("tagName") or "") == before_name:
                    item["tagName"] = after_name
        return
    if layer == "folder":
        if str(consumer.get("parentFolderId") or "") == from_id:
            consumer["parentFolderId"] = to_id
        return
    consumer.update(_replace_reference(consumer, from_id, to_id))


def dependency_order(operations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_id = {str(row.get("operation_id") or ""): row for row in operations}
    if "" in by_id or len(by_id) != len(operations):
        raise ValueError("operation IDs must be unique and nonblank")
    incoming = {key: 0 for key in by_id}
    outgoing: dict[str, set[str]] = defaultdict(set)
    for operation_id, operation in by_id.items():
        for dependency in as_list(operation.get("depends_on")):
            dependency_id = str(dependency)
            if dependency_id not in by_id:
                raise ValueError(
                    f"operation {operation_id} depends on unknown {dependency_id}"
                )
            if operation_id not in outgoing[dependency_id]:
                outgoing[dependency_id].add(operation_id)
                incoming[operation_id] += 1
    ready = deque(sorted(key for key, value in incoming.items() if value == 0))
    ordered = []
    while ready:
        operation_id = ready.popleft()
        ordered.append(by_id[operation_id])
        for child in sorted(outgoing.get(operation_id, set())):
            incoming[child] -= 1
            if incoming[child] == 0:
                ready.append(child)
    if len(ordered) != len(operations):
        raise ValueError("operation dependency graph contains a cycle")
    return ordered


def _action_targets(operation: dict[str, Any]) -> set[str]:
    targets = set()
    for field in (
        "additions",
        "changes",
        "removals",
        "renames",
        "pauses",
        "deletions",
    ):
        for action in as_list(operation.get(field)):
            if isinstance(action, dict) and str(action.get("object_key") or ""):
                targets.add(str(action["object_key"]))
    for action in as_list(operation.get("remaps")):
        if not isinstance(action, dict):
            continue
        targets.update(
            str(value)
            for value in (
                action.get("from_object_key"),
                action.get("to_object_key"),
                *as_list(action.get("consumer_object_keys")),
            )
            if str(value or "")
        )
    return targets


def operation_action_identity(operation: dict[str, Any]) -> str:
    """Return the identity of executable action fields only."""

    return stable_hash(
        {field: operation.get(field, []) for field in OPERATION_ACTION_FIELDS}, 64
    )


def normalize_operation(
    proposal: dict[str, Any],
    canonical_decision_id: str,
    decision: dict[str, Any],
) -> dict[str, Any]:
    """Bind one reviewed proposal to its canonical semantic decision."""

    operation = copy.deepcopy(proposal)
    operation["source_reconciled_decision_ids"] = [canonical_decision_id]
    operation.pop("source_decision_id", None)
    operation["decision_class"] = decision.get("decision_class")
    operation["priority"] = decision.get("priority")
    operation["confidence"] = decision.get("confidence")
    operation.setdefault("depends_on", [])
    for field in OPERATION_ACTION_FIELDS:
        operation.setdefault(field, [])
    operation["action_payload_sha256"] = operation_action_identity(operation)
    return operation


def merge_exact_operation_ids(
    operations: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Merge repeated IDs only when their executable payloads are identical."""

    by_id: dict[str, dict[str, Any]] = {}
    for operation in operations:
        operation_id = str(operation.get("operation_id") or "")
        previous = by_id.get(operation_id)
        if previous is None:
            by_id[operation_id] = copy.deepcopy(operation)
            continue
        if previous.get("action_payload_sha256") != operation.get(
            "action_payload_sha256"
        ):
            raise ValueError(
                f"operation ID {operation_id} carries contradictory action payloads"
            )
        previous["source_reconciled_decision_ids"] = sorted(
            {
                *as_list(previous.get("source_reconciled_decision_ids")),
                *as_list(operation.get("source_reconciled_decision_ids")),
            }
        )
        previous["depends_on"] = sorted(
            {
                *as_list(previous.get("depends_on")),
                *as_list(operation.get("depends_on")),
            }
        )
    return list(by_id.values())


def operation_write_conflicts(operations: list[dict[str, Any]]) -> list[str]:
    """Detect contradictory writes and writes to objects scheduled for deletion."""

    writes: dict[tuple[str, str], tuple[str, str, Any]] = {}
    deleted: dict[str, str] = {}
    errors: list[str] = []
    for operation in operations:
        operation_id = str(operation.get("operation_id") or "")
        for field in ("additions", "changes", "removals"):
            for action in as_list(operation.get(field)):
                if not isinstance(action, dict):
                    continue
                key = (
                    str(action.get("object_key") or ""),
                    str(action.get("json_path") or ""),
                )
                value = (
                    action.get("value")
                    if field == "additions"
                    else action.get("after")
                    if field == "changes"
                    else None
                )
                previous = writes.get(key)
                if previous:
                    errors.append(
                        f"{operation_id} and {previous[0]} both write {key}"
                    )
                writes[key] = (operation_id, field, value)
        for field, json_path, value_field in (
            ("renames", "$.name", "after"),
            ("pauses", "$.paused", "after"),
        ):
            for action in as_list(operation.get(field)):
                if not isinstance(action, dict):
                    continue
                key = (str(action.get("object_key") or ""), json_path)
                previous = writes.get(key)
                if previous:
                    errors.append(
                        f"{operation_id} and {previous[0]} both write {key}"
                    )
                writes[key] = (operation_id, field, action.get(value_field))
        for action in as_list(operation.get("deletions")):
            if isinstance(action, dict):
                deleted[str(action.get("object_key") or "")] = operation_id
    for (object_key, json_path), (operation_id, _field, _value) in writes.items():
        if object_key in deleted:
            errors.append(
                f"{operation_id} writes {object_key} {json_path}, which is deleted by "
                f"{deleted[object_key]}"
            )
    return errors


def validate_operations(
    data: dict[str, Any],
    operations: list[dict[str, Any]],
    *,
    do_not_touch: set[str] | None = None,
) -> list[str]:
    errors: list[str] = []
    try:
        ordered = dependency_order(operations)
    except ValueError as exc:
        return [str(exc)]
    catalog = object_catalog(data)
    valid_keys = set(catalog)
    protected_keys = set(do_not_touch or set())
    for unknown_key in sorted(protected_keys - valid_keys):
        errors.append(f"do_not_touch identifies unknown source object {unknown_key}")
    planned_creations: set[str] = set()
    deleted: dict[str, str] = {}
    writes: dict[tuple[str, str], tuple[str, str, Any]] = {}
    for operation in ordered:
        operation_id = str(operation.get("operation_id") or "")
        if _action_targets(operation) & protected_keys:
            errors.append(f"{operation_id}: operation touches a do_not_touch object")
        for field in OPERATION_ACTION_FIELDS:
            if not isinstance(operation.get(field), list):
                errors.append(f"{operation_id}: {field} must be a list")
        for action in as_list(operation.get("creations")):
            if not isinstance(action, dict):
                errors.append(f"{operation_id}: creation is malformed")
                continue
            layer = str(action.get("layer") or "")
            obj = action.get("object")
            id_key = ID_KEYS.get(layer)
            if not id_key or not isinstance(obj, dict):
                errors.append(f"{operation_id}: creation layer or object is invalid")
                continue
            key = f"{layer}:{obj.get(id_key) or ''}"
            if key.endswith(":") or key in valid_keys or key in planned_creations:
                errors.append(f"{operation_id}: creation identity is missing or duplicated: {key}")
            planned_creations.add(key)
        for field in ("additions", "changes"):
            for action in as_list(operation.get(field)):
                if not isinstance(action, dict):
                    errors.append(f"{operation_id}: {field} action is malformed")
                    continue
                key = str(action.get("object_key") or "")
                path = str(action.get("json_path") or "")
                if key not in valid_keys and key not in planned_creations:
                    errors.append(f"{operation_id}: {field} targets unknown {key}")
                    continue
                write_key = (key, path)
                value = action.get("value") if field == "additions" else action.get("after")
                previous = writes.get(write_key)
                if previous:
                    errors.append(
                        f"{operation_id}: conflicting writes to {key} {path} with {previous[0]}"
                    )
                writes[write_key] = (operation_id, field, value)
                if key in catalog:
                    obj = catalog[key]["object"]
                    try:
                        if field == "changes" and get_json_path(obj, path) != action.get("before"):
                            errors.append(f"{operation_id}: change before value differs at {key} {path}")
                        if field == "additions":
                            try:
                                get_json_path(obj, path)
                            except KeyError:
                                pass
                            else:
                                errors.append(f"{operation_id}: addition target already exists at {key} {path}")
                    except (KeyError, ValueError):
                        errors.append(f"{operation_id}: invalid source path {key} {path}")
        for action in as_list(operation.get("removals")):
            if not isinstance(action, dict):
                errors.append(f"{operation_id}: removal action is malformed")
                continue
            key = str(action.get("object_key") or "")
            path = str(action.get("json_path") or "")
            if key not in catalog:
                errors.append(f"{operation_id}: removal targets unknown {key}")
                continue
            write_key = (key, path)
            previous = writes.get(write_key)
            if previous:
                errors.append(
                    f"{operation_id}: conflicting writes to {key} {path} with {previous[0]}"
                )
            writes[write_key] = (operation_id, "removals", None)
            record = catalog[key]
            try:
                tokens = _path_tokens(path)
                if not tokens or isinstance(tokens[-1], int):
                    raise ValueError("removal must target a named field")
                if tokens == [record["id_key"]] or tokens == ["name"]:
                    errors.append(
                        f"{operation_id}: removal cannot delete identity field {key} {path}"
                    )
                if get_json_path(record["object"], path) != action.get("before"):
                    errors.append(
                        f"{operation_id}: removal before value differs at {key} {path}"
                    )
            except (KeyError, ValueError):
                errors.append(f"{operation_id}: invalid removal path {key} {path}")
        for action in as_list(operation.get("renames")):
            if not isinstance(action, dict):
                errors.append(f"{operation_id}: rename is malformed")
                continue
            key = str(action.get("object_key") or "")
            if key not in catalog:
                errors.append(f"{operation_id}: rename targets unknown {key}")
            elif str(catalog[key]["object"].get("name") or "") != str(action.get("before") or ""):
                errors.append(f"{operation_id}: rename before value differs for {key}")
            if not str(action.get("after") or "").strip():
                errors.append(f"{operation_id}: rename target is blank")
            if str(action.get("before") or "") == str(action.get("after") or ""):
                errors.append(f"{operation_id}: rename is a no-op")
            write_key = (key, "$.name")
            previous = writes.get(write_key)
            if previous:
                errors.append(
                    f"{operation_id}: conflicting writes to {key} $.name with {previous[0]}"
                )
            writes[write_key] = (operation_id, "renames", action.get("after"))
        for action in as_list(operation.get("pauses")):
            if not isinstance(action, dict):
                errors.append(f"{operation_id}: pause is malformed")
                continue
            key = str(action.get("object_key") or "")
            if key not in catalog or catalog[key]["layer"] != "tag":
                errors.append(f"{operation_id}: pause targets unknown non-tag {key}")
            elif bool(catalog[key]["object"].get("paused")) != bool(action.get("before")):
                errors.append(f"{operation_id}: pause before value differs for {key}")
            if not isinstance(action.get("after"), bool):
                errors.append(f"{operation_id}: pause after must be Boolean")
            if isinstance(action.get("before"), bool) and action.get("before") == action.get("after"):
                errors.append(f"{operation_id}: pause is a no-op")
            write_key = (key, "$.paused")
            previous = writes.get(write_key)
            if previous:
                errors.append(
                    f"{operation_id}: conflicting writes to {key} $.paused with {previous[0]}"
                )
            writes[write_key] = (operation_id, "pauses", action.get("after"))
        for action in as_list(operation.get("remaps")):
            if not isinstance(action, dict):
                errors.append(f"{operation_id}: remap is malformed")
                continue
            source = str(action.get("from_object_key") or "")
            target = str(action.get("to_object_key") or "")
            if source not in catalog or target not in catalog | {key: {} for key in planned_creations}:
                errors.append(f"{operation_id}: remap source or target is unknown")
            elif source.split(":", 1)[0] != target.split(":", 1)[0]:
                errors.append(f"{operation_id}: remap crosses incompatible layers")
            for consumer in as_list(action.get("consumer_object_keys")):
                if str(consumer) not in catalog:
                    errors.append(f"{operation_id}: remap consumer is unknown: {consumer}")
        for action in as_list(operation.get("deletions")):
            if not isinstance(action, dict):
                errors.append(f"{operation_id}: deletion is malformed")
                continue
            key = str(action.get("object_key") or "")
            if key not in valid_keys:
                errors.append(f"{operation_id}: deletion targets unknown {key}")
            if key in deleted:
                errors.append(f"{operation_id}: deletion duplicates {deleted[key]} for {key}")
            deleted[key] = operation_id
    for (key, _path), (operation_id, _field, _value) in writes.items():
        if key in deleted:
            errors.append(
                f"{operation_id}: writes {key}, which is also deleted by {deleted[key]}"
            )
    if not errors:
        try:
            projected_catalog = object_catalog(apply_operations(data, ordered))
        except (KeyError, TypeError, ValueError) as exc:
            errors.append(f"operation simulation failed: {exc}")
        else:
            for key in sorted(protected_keys):
                projected = projected_catalog.get(key)
                if projected is None:
                    errors.append(f"do_not_touch object {key} would be removed")
                    continue
                if stable_hash(catalog[key]["object"], 64) != stable_hash(
                    projected["object"], 64
                ):
                    errors.append(
                        f"do_not_touch object {key} would change through an explicit or implicit operation"
                    )
    return errors


def apply_operations(
    data: dict[str, Any],
    operations: list[dict[str, Any]],
) -> dict[str, Any]:
    projected = copy.deepcopy(data)
    cv = container_version(projected)
    for operation in dependency_order(operations):
        catalog = object_catalog(projected)
        for action in as_list(operation.get("creations")):
            layer = str(action["layer"])
            cv.setdefault(layer, []).append(copy.deepcopy(action["object"]))
        catalog = object_catalog(projected)
        for action in as_list(operation.get("additions")):
            set_json_path(
                catalog[str(action["object_key"])]["object"],
                str(action["json_path"]),
                action.get("value"),
                allow_create=True,
            )
        for action in as_list(operation.get("changes")):
            target = catalog[str(action["object_key"])]["object"]
            if get_json_path(target, str(action["json_path"])) != action.get("before"):
                raise ValueError(
                    f"{operation['operation_id']}: change before value drifted for "
                    f"{action['object_key']} {action['json_path']}"
                )
            set_json_path(target, str(action["json_path"]), action.get("after"))
        for action in as_list(operation.get("removals")):
            target = catalog[str(action["object_key"])]["object"]
            if get_json_path(target, str(action["json_path"])) != action.get("before"):
                raise ValueError(
                    f"{operation['operation_id']}: removal before value drifted for "
                    f"{action['object_key']} {action['json_path']}"
                )
            delete_json_path(target, str(action["json_path"]))
        for action in as_list(operation.get("remaps")):
            source = str(action["from_object_key"])
            target = str(action["to_object_key"])
            layer = source.split(":", 1)[0]
            for consumer_key in as_list(action.get("consumer_object_keys")):
                consumer = catalog[str(consumer_key)]["object"]
                _remap_consumer(consumer, layer, source, target, catalog)
        for action in as_list(operation.get("renames")):
            key = str(action["object_key"])
            target = catalog[key]["object"]
            before = str(action["before"])
            after = str(action["after"])
            if str(target.get("name") or "") != before:
                raise ValueError(f"{operation['operation_id']}: rename before value drifted for {key}")
            layer = catalog[key]["layer"]
            if layer in {"variable", "tag"}:
                for other_key, record in catalog.items():
                    if other_key == key:
                        continue
                    if layer == "variable":
                        record["object"].update(
                            _replace_reference(
                                record["object"], "{{" + before + "}}", "{{" + after + "}}"
                            )
                        )
                    else:
                        for field in ("setupTag", "teardownTag"):
                            for item in as_list(record["object"].get(field)):
                                if isinstance(item, dict) and item.get("tagName") == before:
                                    item["tagName"] = after
            target["name"] = after
        for action in as_list(operation.get("pauses")):
            catalog[str(action["object_key"])]["object"]["paused"] = bool(action["after"])
        deletion_keys = {
            str(action.get("object_key") or "")
            for action in as_list(operation.get("deletions"))
        }
        if deletion_keys:
            for layer, id_key in ID_KEYS.items():
                if layer not in cv:
                    continue
                cv[layer] = [
                    obj
                    for obj in as_list(cv.get(layer))
                    if f"{layer}:{obj.get(id_key) or ''}" not in deletion_keys
                ]
    return projected


def operation_packet_sha256(operations: list[dict[str, Any]]) -> str:
    return stable_hash(
        [
            {
                **operation,
                "operation_id": str(operation.get("operation_id") or ""),
            }
            for operation in dependency_order(operations)
        ],
        64,
    )
