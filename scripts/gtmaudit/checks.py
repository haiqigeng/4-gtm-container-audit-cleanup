"""Per-operation judgment of proposed changes, on top of their application (operations.py).

`applicability` applies each operation with exactly its declared prerequisites and judges the result: what the
closure breaks, whether a vendor tag gains a collection path without a consent predicate, what tags newly send or
stop sending, and whether ready work still lists preconditions.
"""

from __future__ import annotations

import json
import re
from collections import defaultdict

from .operations import Target, closure, consent_approved, simulate
from .source import (
    GOOGLE_TAG_TYPES,
    SETTINGS_VARIABLES,
    Model,
    code_of,
    consent_controls,
    destinations,
    effective_parameters,
    group_members,
    has_consent_control,
    is_cmp_tag,
    normalized_signature,
    reads_closure,
    sends_third_party,
    sent_variables,
)

TRIGGER_CONDITION_FIELDS = ("filter", "customEventFilter", "autoEventFilter", "parameter", "type")


def _trigger_closure(model: Model, tag) -> set[str]:
    """Firing triggers of a tag, including trigger-group members, as keys."""
    out, pending = set(), [f"trigger:{t}" for t in tag.raw.get("firingTriggerId", []) or []]
    while pending:
        key = pending.pop()
        if key in out:
            continue
        out.add(key)
        tr = model.objects.get(key)
        if tr is not None:
            pending += [f"trigger:{m}" for m in group_members(tr.raw)]
    return out


def _parents(model: Model, tag) -> list:
    return [model.objects[src] for src, dst, kind in model.edges if dst == tag.key and kind in ("setupTag", "teardownTag")]


def _controlled(model: Model, tag, context: dict, seen: frozenset = frozenset()) -> bool:
    """A visible consent predicate, an approved route, or (for a sequence-only tag) every parent controlled."""
    if has_consent_control(consent_controls(model, tag)) or consent_approved(model, tag, context):
        return True
    parents = [p for p in _parents(model, tag) if p.key not in seen]
    return bool(parents) and not tag.raw.get("firingTriggerId") and all(
        _controlled(model, p, context, seen | {tag.key}) for p in parents)


def _executes(tag) -> bool:
    """An HTML tag executes only through a script element with code or a script source."""
    if tag.type != "html":
        return True
    return bool(re.search(r"<script\b[^>]*(\bsrc\s*=[^>]*>|>\s*[^<\s])", code_of(tag), re.I))


def _changed_routes(before: Model, after: Model, diff: dict, target: Target, context: dict) -> list[str]:
    """Vendor tags given a collection path they did not have, without a consent control in the resulting state.

    A new path: the tag is created, unpaused, newly reachable, newly executing, gains a firing trigger that neither
    it nor a tag merged into it had, or a trigger on its route has its conditions changed. Merging equivalent tags
    or triggers keeps existing paths and is not a new path.
    """
    moved = defaultdict(set)
    for src, dst in target.remaps:
        moved[dst].add(src)
    names = [(before.objects[s].name, after.objects[d].name) for s, d in target.remaps
             if s.startswith("variable:") and s in before.objects and d in after.objects]
    names += [old_new for k, old_new in target.renamed.items() if k.startswith("variable:")]

    def same_after_renames(key: str) -> bool:
        text = json.dumps(before.objects[key].raw, sort_keys=True, ensure_ascii=False)
        for old, new in names:
            text = text.replace("{{" + old + "}}", "{{" + new + "}}")
        return text == json.dumps(after.objects[key].raw, sort_keys=True, ensure_ascii=False)

    def inherited(key: str) -> set[str]:
        out, pending = set(), [key]
        while pending:
            k = pending.pop()
            if k not in out:
                out.add(k)
                pending += list(moved.get(k, ()))
        return out
    conditions_changed = {k for k, v in diff.items() if k.startswith("trigger:") and v["change"] == "changed"
                          and set(v.get("fields", [])) & set(TRIGGER_CONDITION_FIELDS) and not same_after_renames(k)}
    new_paths = {}
    for tag in after.layer("tag"):
        if tag.paused or is_cmp_tag(after, tag) or not (tag.type in GOOGLE_TAG_TYPES or sends_third_party(after, tag)):
            continue
        sources = [before.objects[k] for k in inherited(tag.key) if k in before.objects]
        old_paths = set()
        for old in sources:
            for trig in _trigger_closure(before, old):
                old_paths |= inherited(trig)
        paths = _trigger_closure(after, tag)
        own = before.objects.get(tag.key)
        new_paths[tag.key] = (
            (own is None and not sources) or (own is not None and (own.paused or own.key not in before.reachable
                                                                    or (not _executes(own) and _executes(tag))))
            or bool({p for p in paths if not (inherited(p) & old_paths)})
            or bool(paths & conditions_changed))
    for key in list(new_paths):
        tag = after.objects[key]
        parents = _parents(after, tag)
        if parents and not tag.raw.get("firingTriggerId"):
            # A sequence-only tag fires through its parents: it gains an ungated path only through a parent
            # that gains a path without its own consent control.
            new_paths[key] = any(new_paths.get(p.key) and not _controlled(after, p, context) for p in parents)
    return [k for k, new in new_paths.items()
            if new and k in after.reachable and not _controlled(after, after.objects[k], context)]


def _sends(model: Model, tag) -> tuple[set[str], set[str]]:
    """(variables a tag sends, settings it sends); a paused tag sends nothing."""
    if tag is None or tag.paused:
        return set(), set()
    return sent_variables(model, tag), set(effective_parameters(model, tag))


def payload_changes(before: Model, after: Model | None, edited: set[str], changed: set[str]) -> tuple[set[str], dict]:
    """What the operations change in what tags send, compared tag by tag on effective payloads.

    A settings variable is a container: its rows are the tag's own values. Any other variable is a value, and a
    value a tag newly sends relies on everything it reads; an exact alias of a value it already sent is not new. Returns the source variables those new values rely on,
    and for tags the operations do not edit themselves, the settings they stop sending (setting -> tags). Only
    tags whose payload sources changed are compared.
    """
    if after is None:
        return set(), {}
    googtags = set().union(*(destinations(m, t) for m in (before, after) for t in m.layer("tag")
                             if t.type == "googtag" and t.key in changed))
    new, lost = set(), defaultdict(list)
    for tag in after.layer("tag"):
        old = before.objects.get(tag.key)
        was_sent, was_set = _sends(before, old)
        if not ({tag.key} | was_sent) & changed and not (destinations(after, tag) & googtags):
            continue
        sent, settings = _sends(after, tag)
        aliases = {normalized_signature(before.objects[k].raw) for k in was_sent}
        values = {k for k in sent - was_sent if after.objects[k].type not in SETTINGS_VARIABLES
                  and normalized_signature(after.objects[k].raw) not in aliases}
        new |= {k for k in values | set(reads_closure(after, sorted(values))) if k in before.objects}
        if old and tag.key not in edited:
            for name in sorted(was_set - settings):
                lost[name].append(tag.key)
    return new, dict(lost)


def applicability(model: Model, operations: list[dict], context: dict | None = None) -> dict[str, dict]:
    """Each operation applied with exactly its declared prerequisite closure.

    Errors: the closure alone breaks references, names, writes, protected objects or consent controls; a
    ready operation opens a vendor collection path that has no consent predicate within its closure; or a
    ready operation still lists preconditions.
    The same route gap on conditional or blocked work is a warning: its question must name that prerequisite.
    Each result also carries `sends`, the source variables the closure newly makes some tag send, and warns
    about settings that tags it does not edit stop sending.
    """
    context = context or {}
    by_id = {o["id"]: o for o in operations}
    results = {}
    for op in operations:
        applied = closure(op, by_id)
        sim = simulate(model, applied, context)
        errors = list(sim["errors"])
        edited = {sim.get("refs", {}).get(a["object"], a["object"]) for o in applied for a in o["actions"]
                  if isinstance(a.get("object"), str)}
        changed = set(sim.get("diff", {})) | set(sim.get("created", []) or [])
        sends, lost = payload_changes(model, sim.get("after"), edited, changed)
        route_issues = [f"enables or changes the route of {k} without a consent predicate in its declared closure "
                        f"(add the consent operation to depends_on, or make the work conditional)"
                        for k in (_changed_routes(model, sim["after"], sim["diff"], sim["applied"], context)
                                  if sim.get("applied") is not None else [])]
        warnings = []
        if op.get("readiness", "ready") == "ready":
            errors += route_issues
            if (op.get("preconditions") or "").strip():
                errors.append("is ready but lists preconditions; preconditions are work or facts outside this "
                              "operation that must hold first, which makes it conditional. Move notes to "
                              "verification, or make the finding conditional and name the prerequisite in its question")
        else:
            warnings += route_issues
        warnings += [f"{', '.join(tags[:8])}{' and more' if len(tags) > 8 else ''} stop sending {name}, which they "
                     f"inherited or shared; give them their own value in a declared prerequisite, or say in the "
                     f"finding that this is intended" for name, tags in lost.items()]
        results[op["id"]] = {"errors": errors, "warnings": warnings, "sends": sends}
    return results
