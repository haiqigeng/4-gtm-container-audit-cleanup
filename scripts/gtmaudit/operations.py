"""Apply proposed operations to a copy of the export and validate the resulting target.

Paths address one object: `firingTriggerId`, `tagFiringOption`, `parameter:eventName.value`,
`parameter:eventSettingsTable.list.row:parameter=currency.map:parameterValue.value`, `consentSettings.consentStatus`.
Segments: plain dict key, `[i]` list index, `parameter:<key>` / `map:<key>` (list item whose `key` matches),
`row:<field>=<value>` (MAP list item whose entry <field> has <value>).
"""

from __future__ import annotations

import copy
import json
import re
from collections import defaultdict
from dataclasses import dataclass

from .paths import item_identity, segments
from .source import (
    CODE_FIELDS,
    EXPORT_KEYS,
    LAYERS,
    Model,
    SourceError,
    consent_controls,
    consent_routes,
    from_raw,
    has_consent_control,
)

ID_FIELDS = LAYERS


class OperationError(ValueError):
    pass


def _find_item(container: list, seg: str):
    if seg.startswith("[") and seg.endswith("]"):
        i = int(seg[1:-1])
        return i if i < len(container) else None
    if seg.startswith(("parameter:", "map:")):
        key = seg.split(":", 1)[1]
        for i, item in enumerate(container):
            if isinstance(item, dict) and item.get("key") == key:
                return i
        return None
    if seg.startswith("row:"):
        field, _, value = seg[4:].partition("=")
        for i, item in enumerate(container):
            entries = {m.get("key"): m.get("value") for m in (item or {}).get("map", []) or []} \
                if isinstance(item, dict) else {}
            if entries.get(field) == value:
                return i
        return None
    raise OperationError(f"segment {seg!r} cannot address a list")


def _walk(root: dict, path: str, create: bool):
    """Return (parent, slot) for the final segment."""
    segs = segments(path)
    node = root
    for n, seg in enumerate(segs):
        last = n == len(segs) - 1
        if seg.startswith(("parameter:", "map:")) and isinstance(node, dict):
            node = node.setdefault(seg.split(":")[0], []) if create else node.get(seg.split(":")[0], [])
        if isinstance(node, list):
            idx = _find_item(node, seg)
            if idx is None:
                if create and seg.startswith(("parameter:", "map:")):
                    node.append({"type": "TEMPLATE", "key": seg.split(":", 1)[1]})
                    idx = len(node) - 1
                else:
                    raise OperationError(f"path {path!r}: {seg!r} not found")
            if last:
                return node, idx
            node = node[idx]
        elif isinstance(node, dict):
            if last:
                return node, seg
            if seg not in node:
                if not create:
                    raise OperationError(f"path {path!r}: {seg!r} not found")
                node[seg] = {}
            node = node[seg]
        else:
            raise OperationError(f"path {path!r}: cannot descend into {type(node).__name__} at {seg!r}")
    raise OperationError(f"path {path!r} is empty")


def _code_text(value) -> str:
    """Code held by a field: a string, or the value of a written parameter object."""
    if isinstance(value, dict):
        value = value.get("value", "")
    return value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)


class Target:
    """A mutable copy of the export plus the bookkeeping needed for validation."""

    def __init__(self, model: Model):
        self.model = model
        self.raw = copy.deepcopy(model.raw)
        self.cv = self.raw.get("containerVersion", self.raw)
        self.refs: dict[str, str] = {}
        self.writes: dict[tuple[str, tuple[str, ...]], str] = {}
        self.prior: dict[str, set[str]] = {}  # operation -> itself and its declared prerequisites
        self.created: list[str] = []
        self.deleted: list[str] = []
        self.renamed: dict[str, tuple[str, str]] = {}
        self.remaps: list[tuple[str, str]] = []

    def resolve(self, ref: str) -> str:
        return self.refs.get(ref, ref)

    def items(self, layer: str) -> list[dict]:
        return self.cv.setdefault(EXPORT_KEYS.get(layer, layer), [])

    def obj(self, key: str) -> dict:
        key = self.resolve(key)
        layer, _, ident = key.partition(":")
        if layer not in ID_FIELDS:
            raise OperationError(f"{key}: unsupported layer")
        for item in self.items(layer):
            if str(item.get(ID_FIELDS[layer])) == ident:
                return item
        raise OperationError(f"{key} does not exist in the target")

    def _claim(self, op_id: str, key: str, path: str, item: str = "") -> None:
        """Two operations conflict when one writes a field that contains, or lies inside, what the other writes,
        unless one depends on the other. An `add` writes only its own item, so independent rows added to one
        table do not conflict."""
        key, segs = self.resolve(key), tuple(segments(path)) + ((item,) if item else ())
        for (other_key, other), owner in self.writes.items():
            if other_key == key and owner not in self.prior.get(op_id, {op_id}) and segs[:len(other)] == other[:len(segs)]:
                raise OperationError(f"{op_id} and {owner} both write {key} {path}")
        self.writes[(key, segs)] = op_id

    def _replace_refs(self, value, mapping: dict[str, str]):
        if isinstance(value, str):
            return re.sub(r"new:[a-z]+:[\w-]+", lambda m: mapping.get(m.group(0), m.group(0)).split(":", 1)[-1]
                          if m.group(0) in mapping else m.group(0), value)
        if isinstance(value, list):
            return [self._replace_refs(v, mapping) for v in value]
        if isinstance(value, dict):
            return {k: self._replace_refs(v, mapping) for k, v in value.items()}
        return value

    def apply(self, op_id: str, action: dict) -> None:
        kind = action["do"]
        value = self._replace_refs(copy.deepcopy(action.get("value")), self.refs)
        if kind == "create":
            layer = action["layer"]
            ids = [int(i.get(ID_FIELDS[layer])) for i in self.items(layer) if str(i.get(ID_FIELDS[layer])).isdigit()]
            new_id = str(max(ids, default=0) + 1)
            obj = self._replace_refs(copy.deepcopy(action["object"]), self.refs)
            obj[ID_FIELDS[layer]] = new_id
            self.items(layer).append(obj)
            self.refs[action["ref"]] = f"{layer}:{new_id}"
            self.created.append(f"{layer}:{new_id}")
            return
        if kind == "remap":
            self._remap(op_id, self.resolve(action["from"]), self.resolve(action["to"]))
            return
        key = self.resolve(action["object"])
        obj = self.obj(key)
        if kind in ("set", "add", "remove"):
            self._claim(op_id, key, action["path"], item_identity(value) if kind == "add" else "")
            parent, slot = _walk(obj, action["path"], create=kind != "remove")
            if kind == "set":
                parent[slot] = value
            elif kind == "add":
                target = parent[slot] if isinstance(parent, (list, dict)) and (
                    isinstance(slot, int) or slot in parent) else None
                if target is None:
                    parent[slot] = target = []
                if not isinstance(target, list):
                    raise OperationError(f"{op_id}: add needs a list at {action['path']}")
                target.append(value)
            else:
                del parent[slot]
        elif kind == "delete":
            layer = key.split(":")[0]
            self.items(layer).remove(obj)
            self.deleted.append(key)
        elif kind in ("pause", "unpause"):
            self._claim(op_id, key, "paused")
            if kind == "pause":
                obj["paused"] = True
            else:
                obj.pop("paused", None)
        elif kind == "rename":
            self._claim(op_id, key, "name")
            old = obj.get("name", "")
            obj["name"] = action["name"]
            self.renamed[key] = (old, action["name"])
            layer = key.split(":")[0]
            if layer == "variable":
                self._rewrite_strings(f"{{{{{old}}}}}", f"{{{{{action['name']}}}}}")
            if layer == "tag":
                for t in self.items("tag"):
                    for seq in ("setupTag", "teardownTag"):
                        for s in t.get(seq, []) or []:
                            if s.get("tagName") == old:
                                s["tagName"] = action["name"]

    def try_apply(self, op_id: str, action: dict) -> None:
        """Apply one action as the simulation does; an action that fails leaves the state as it was (the
        simulation reports the failure)."""
        try:
            self.apply(op_id, action)
        except (OperationError, KeyError, ValueError, TypeError, IndexError):
            pass

    def names(self) -> dict[str, str]:
        """The current name of every object, and of every `new:` reference created so far."""
        out = {f"{layer}:{item.get(field)}": str(item.get("name", ""))
               for layer, field in ID_FIELDS.items() for item in self.items(layer) if isinstance(item, dict)}
        out.update({ref: out.get(key, ref) for ref, key in self.refs.items()})
        return out

    def consumers(self, key: str) -> list[str]:
        """The objects that use `key` in the current state."""
        try:
            return [k for k, _ in from_raw(self.raw).consumers(self.resolve(key))]
        except SourceError:
            return []

    def code(self, action: dict, after: bool = False) -> str | None:
        """The code an action writes, read from the current state; None when the action writes no code."""
        if action["do"] == "create":
            field = next((p.get("key") for p in action["object"].get("parameter", []) or []
                          if p.get("key") in CODE_FIELDS and isinstance(p.get("value"), str)), None)
            if field is None:
                return None
            if not after or action["ref"] not in self.refs:
                return ""
            return _code_text(next((p for p in self.obj(action["ref"]).get("parameter", []) or []
                                    if p.get("key") == field), {}))
        if action["do"] not in ("set", "add") or segments(action["path"])[0].removeprefix("parameter:") not in CODE_FIELDS:
            return None
        try:
            parent, slot = _walk(self.obj(action["object"]), action["path"], create=False)
            return _code_text(parent[slot])
        except (OperationError, KeyError, IndexError, TypeError):
            return ""

    def _rewrite_strings(self, old: str, new: str) -> None:
        def walk(node):
            if isinstance(node, dict):
                for k, v in node.items():
                    if isinstance(v, str) and old in v:
                        node[k] = v.replace(old, new)
                    else:
                        walk(v)
            elif isinstance(node, list):
                for i, v in enumerate(node):
                    if isinstance(v, str) and old in v:
                        node[i] = v.replace(old, new)
                    else:
                        walk(v)
        for layer in ("tag", "trigger", "variable", "zone"):
            walk(self.items(layer))

    def _remap(self, op_id: str, src: str, dst: str) -> None:
        self.remaps.append((src, dst))
        layer, sid = src.split(":", 1)
        dlayer, did = dst.split(":", 1)
        if layer != dlayer:
            raise OperationError(f"{op_id}: remap needs two objects of the same layer")
        if layer == "trigger":
            for t in self.items("tag"):
                for f in ("firingTriggerId", "blockingTriggerId"):
                    ids = [str(x) for x in t.get(f, []) or []]
                    if sid in ids:
                        t[f] = list(dict.fromkeys(did if x == sid else x for x in ids))
            for tr in self.items("trigger"):
                for p in tr.get("parameter", []) or []:
                    if p.get("key") == "triggerIds":
                        for item in p.get("list", []) or []:
                            if str(item.get("value")) == sid:
                                item["value"] = did
        elif layer == "variable":
            self._rewrite_strings(f"{{{{{self.obj(src).get('name')}}}}}", f"{{{{{self.obj(dst).get('name')}}}}}")
        elif layer == "tag":
            old, new = self.obj(src).get("name"), self.obj(dst).get("name")
            for t in self.items("tag"):
                for seq in ("setupTag", "teardownTag"):
                    for s in t.get(seq, []) or []:
                        if s.get("tagName") == old:
                            s["tagName"] = new
        else:
            raise OperationError(f"{op_id}: remap supports triggers, variables and tags")


def execution_order(operations: list[dict]) -> list[dict]:
    """Operations ordered so every declared prerequisite comes first (stable otherwise)."""
    by_id = {o["id"]: o for o in operations}
    done, out, visiting = set(), [], set()

    def visit(op):
        if op["id"] in done:
            return
        if op["id"] in visiting:
            raise OperationError(f"dependency cycle at {op['id']}")
        visiting.add(op["id"])
        for dep in op.get("depends_on", []) or []:
            if dep not in by_id:
                raise OperationError(f"{op['id']} depends on unknown {dep}")
            visit(by_id[dep])
        visiting.discard(op["id"])
        done.add(op["id"])
        out.append(op)
    for op in operations:
        visit(op)
    return out


def simulate(model: Model, operations: list[dict], context: dict | None = None) -> dict:
    """Apply every operation; return errors, warnings and a per-object diff."""
    context = context or {}
    errors, warnings = [], []
    target = Target(model)
    try:
        ordered = execution_order(operations)
    except OperationError as exc:
        return {"ok": False, "errors": [str(exc)], "warnings": [], "diff": {}}
    by_id = {o["id"]: o for o in ordered}
    target.prior = {o["id"]: {p["id"] for p in closure(o, by_id)} for o in ordered}
    for op in ordered:
        for i, action in enumerate(op["actions"]):
            try:
                target.apply(op["id"], action)
            except (OperationError, KeyError, ValueError, TypeError) as exc:
                errors.append(f"{op['id']} action {i} ({action.get('do')}): {exc}")
    try:
        after = from_raw(target.raw)
    except SourceError as exc:
        return {"ok": False, "errors": errors + [f"target is not a valid container: {exc}"], "warnings": [],
                "diff": {}}
    before_unresolved = {(s, n) for s, n, _ in model.unresolved}
    for src, name, kind in after.unresolved:
        if (src, name) not in before_unresolved:
            errors.append(f"{src} references missing {kind} {name!r} after the operations")
    for layer in ("tag", "trigger", "variable"):
        counts = defaultdict(list)
        for o in after.layer(layer):
            counts[o.name].append(o.key)
        before = defaultdict(int)
        for o in model.layer(layer):
            before[o.name] += 1
        for name, keys in counts.items():
            if len(keys) > 1 and len(keys) > before.get(name, 0):
                errors.append(f"name {name!r} is used by {keys} in the target")
    for t in model.layer("tag"):
        if t.paused or t.key not in after.objects or after.objects[t.key].paused:
            continue
        had = has_consent_control(consent_controls(model, t))
        has = has_consent_control(consent_controls(after, after.objects[t.key]))
        if had and not has and not consent_approved(after, after.objects[t.key], context):
            errors.append(f"{t.key} loses every visible consent predicate; this is allowed only for a destination "
                          f"in context.consent_mode_destinations or a host in context.consent_owned_hosts")
    diff = {}
    for key in sorted(set(model.objects) | set(after.objects)):
        a, b = model.objects.get(key), after.objects.get(key)
        if a and not b:
            diff[key] = {"change": "deleted", "name": a.name}
        elif b and not a:
            diff[key] = {"change": "created", "name": b.name}
        elif a and b and a.raw != b.raw:
            fields = sorted(k for k in set(a.raw) | set(b.raw) if a.raw.get(k) != b.raw.get(k))
            params_changed = []
            if "parameter" in fields:
                pa = {p.get("key"): p for p in a.raw.get("parameter", []) or []}
                pb = {p.get("key"): p for p in b.raw.get("parameter", []) or []}
                params_changed = sorted(k for k in set(pa) | set(pb) if pa.get(k) != pb.get(k))
            diff[key] = {"change": "changed", "name": b.name, "fields": fields, "parameters": params_changed}
            if key in target.renamed:
                diff[key]["renamed_from"] = target.renamed[key][0]
    for key in sorted(set(context.get("do_not_touch") or []) & set(diff)):
        errors.append(f"{key} is protected (context.do_not_touch) but the operations {diff[key]['change']} it")
    refs_without_vars = sorted({n for s, n, k in after.unresolved if k == "variable"} -
                               {n for s, n, k in model.unresolved if k == "variable"})
    if refs_without_vars:
        warnings.append(f"new unresolved variable names: {refs_without_vars}")
    return {"ok": not errors, "errors": errors, "warnings": warnings, "diff": diff, "created": target.created,
            "refs": target.refs, "target": target.raw if not errors else None,
            "applied": target, "after": after}


def consent_approved(model: Model, tag, context: dict) -> bool:
    dests, hosts = consent_routes(model, tag)
    return bool(dests & set(context.get("consent_mode_destinations") or []) or
                hosts & {h.lower() for h in context.get("consent_owned_hosts") or []})


def closure(op: dict, by_id: dict[str, dict]) -> list[dict]:
    out, pending = {}, [op["id"]]
    while pending:
        current = by_id.get(pending.pop())
        if current and current["id"] not in out:
            out[current["id"]] = current
            pending += current.get("depends_on", []) or []
    return list(out.values())


@dataclass
class Step:
    """One action of one operation and the state it applies to: the source after exactly the operation's declared
    prerequisites and its own preceding actions. `before`/`after` hold code for code-field writes and code creates."""
    op: str
    index: int
    action: dict
    names: dict[str, str]
    consumers: list[str]
    before: str | None
    after: str | None


def trace(model: Model, operations: list[dict]) -> dict[str, list[Step]]:
    """Every operation's actions in order, each with the state it applies to. Uses the simulation's `Target.apply`,
    so instructions describe exactly what the simulation applies."""
    by_id = {o["id"]: o for o in operations}
    prior_of = {o["id"]: {p["id"] for p in closure(o, by_id)} for o in operations}
    out: dict[str, list[Step]] = {}
    for op in operations:
        target = Target(model)
        target.prior = prior_of
        try:
            prior = [o for o in execution_order(closure(op, by_id)) if o["id"] != op["id"]]
        except OperationError:
            prior = []
        for p in prior:
            for a in p["actions"]:
                target.try_apply(p["id"], a)
        steps = []
        for i, a in enumerate(op["actions"], 1):
            names = target.names()
            consumers = target.consumers(a["from"]) if a["do"] == "remap" else []
            before = target.code(a)
            target.try_apply(op["id"], a)
            steps.append(Step(op["id"], i, a, names, consumers, before, target.code(a, after=True)))
        out[op["id"]] = steps
    return out
