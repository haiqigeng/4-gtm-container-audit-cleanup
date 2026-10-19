"""D5 families: exact duplicates, near-duplicates and finite consolidation candidates."""

from __future__ import annotations

import json
import re
from collections import defaultdict

from ..source import Model, conditions, group_members, normalized_signature, params, pval

D = "D5"
RULES = {
    "D01": (D, "A05", "Low", "Objects with identical configuration (tags: Medium)."),
    "D02": (D, "A05", "Medium", "Tags identical except their triggers (merge candidates)."),
    "D03": (D, "A05", "Low", "Triggers with identical type and conditions."),
    "D05": (D, "A05", "Medium", "Active Custom HTML tags with identical code."),
    "D09": (D, "A05", "Low", "Data Layer Variables reading the same path and version."),
    "D11": (D, "A05", "Low", "Tag fired by several single-event Custom Event triggers (finite union candidate)."),
    "D12": (D, "A05", "Low", "Tags of one type that differ in one or two parameter values (near-duplicates)."),
}
# Rules whose every emission is its own candidate (one group of objects); other rules gather all their
# emissions into one candidate.
CLUSTERS = {"D01", "D02", "D03", "D05", "D11", "D12"}


def _param_values(raw: dict) -> dict[str, str]:
    return {k: json.dumps(p, sort_keys=True, ensure_ascii=False) for k, p in params(raw).items()}


def run(model: Model, emit, fact) -> None:
    tags, trigs, variables = model.layer("tag"), model.layer("trigger"), model.layer("variable")
    for layer, objs in (("tag", tags), ("trigger", trigs), ("variable", variables)):
        groups = defaultdict(list)
        for o in objs:
            groups[normalized_signature(o.raw)].append(o.key)
        for keys in groups.values():
            if len(keys) > 1:
                emit("D01", f"{len(keys)} {layer}s with identical configuration", keys,
                     severity="Medium" if layer == "tag" else "Low")
    by_config = defaultdict(list)
    for t in tags:
        by_config[normalized_signature(t.raw, {"firingTriggerId", "blockingTriggerId"})].append(t)
    for same in by_config.values():
        if len(same) > 1 and len({json.dumps(sorted(t.raw.get("firingTriggerId") or [])) for t in same}) > 1:
            emit("D02", f"{len(same)} tags identical except triggers", [t.key for t in same])
    code_groups = defaultdict(list)
    for t in tags:
        if t.type == "html" and not t.paused:
            body = re.sub(r"\s+", " ", pval(t.raw, "html")).strip()
            if body:
                code_groups[body].append(t.key)
    for keys in code_groups.values():
        if len(keys) > 1:
            emit("D05", f"{len(keys)} active Custom HTML tags with identical code", keys)
    trigger_groups = defaultdict(list)
    for tr in trigs:
        trigger_groups[json.dumps([tr.type, sorted(json.dumps(c, sort_keys=True) for c in conditions(tr.raw)),
                                   sorted(group_members(tr.raw))])].append(tr.key)
    for keys in trigger_groups.values():
        if len(keys) > 1:
            emit("D03", f"{len(keys)} triggers with identical type and conditions", keys)
    paths = defaultdict(list)
    for v in variables:
        if v.type == "v":
            paths[(pval(v.raw, "name"), pval(v.raw, "dataLayerVersion") or "2")].append(v.key)
    for (path, _), keys in paths.items():
        if len(keys) > 1:
            emit("D09", f"{len(keys)} Data Layer Variables read {path!r}", keys)
    for t in tags:
        singles = []
        for tid in t.raw.get("firingTriggerId") or []:
            tr = model.trigger(str(tid))
            cs = conditions(tr.raw) if tr else []
            if tr and tr.type == "CUSTOM_EVENT" and len(cs) == 1 and cs[0]["arg0"] == "{{_event}}" and \
                    cs[0]["op"] == "EQUALS" and not cs[0]["negate"]:
                singles.append(tr.key)
        if len(singles) >= 3:
            emit("D11", f"Tag fired by {len(singles)} single-event Custom Event triggers", [t.key] + singles)
    by_type = defaultdict(list)
    for t in tags:
        if not t.paused and t.type != "html":
            by_type[t.type].append(t)
    for kind, same in by_type.items():
        if len(same) < 2:
            continue
        values = {t.key: _param_values(t.raw) for t in same}
        parent = {t.key: t.key for t in same}
        differing: dict[str, set[str]] = defaultdict(set)

        def root(key: str, parent: dict[str, str] = parent) -> str:
            while parent[key] != key:
                parent[key] = parent[parent[key]]
                key = parent[key]
            return key
        for i, a in enumerate(same):
            for b in same[i + 1:]:
                va, vb = values[a.key], values[b.key]
                if set(va) != set(vb) or len(va) < 3:
                    continue
                diff = [k for k in va if va[k] != vb[k]]
                if 1 <= len(diff) <= 2:
                    parent[root(a.key)] = root(b.key)
                    differing[a.key].update(diff)
                    differing[b.key].update(diff)
        clusters = defaultdict(list)
        for t in same:
            clusters[root(t.key)].append(t.key)
        for members in clusters.values():
            if len(members) > 1:
                keys = sorted(set().union(*(differing[m] for m in members)))
                emit("D12", f"{len(members)} {kind} tags differ only in {keys[:6]}", members)
