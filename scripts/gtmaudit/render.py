"""Readable, masked text views of source objects (packs, show, siblings)."""

from __future__ import annotations

import json
import re
from collections import defaultdict

from .privacy import mask_structure, redact
from .source import (
    GOOGLE_TAG_TYPES,
    TEMPLATE_CODE,
    TEMPLATE_INFO,
    TEMPLATE_PERMISSIONS,
    Model,
    Obj,
    code_of,
    conditions,
    consent_controls,
    consent_evidence,
    group_members,
    params,
    pval,
    strip_template,
    template_sections,
    trigger_events,
    vendors_of,
)

SKIP_TOP = {"accountId", "containerId", "fingerprint", "path", "tagManagerUrl", "parameter", "name", "type",
            "tagId", "triggerId", "variableId", "folderId", "templateId", "zoneId", "parentFolderId",
            "firingTriggerId", "blockingTriggerId", "setupTag", "teardownTag", "consentSettings", "paused",
            "customEventFilter", "filter", "autoEventFilter", "monitoringMetadata", "templateData", "notes",
            "tagFiringOption", "priority", "galleryReference", "formatValue"}


def _value(node: dict) -> str:
    return node.get("value", "") if isinstance(node, dict) else str(node)


def render_param(node: dict, indent: str = "  ", key_hint: str = "") -> list[str]:
    """Lines for one parameter node already passed through privacy.mask_structure."""
    key = node.get("key", key_hint)
    kind = node.get("type", "")
    if kind == "LIST":
        items = node.get("list", []) or []
        if items and all(isinstance(i, dict) and i.get("type") == "MAP" for i in items):
            rows = [{m.get("key"): m.get("value", json.dumps(m.get("list", ""), ensure_ascii=False))
                     for m in i.get("map", []) or []} for i in items]
            cols = list(dict.fromkeys(k for r in rows for k in r))
            out = [f"{indent}{key} (table, {len(rows)} rows): " + " | ".join(cols)]
            for r in rows:
                out.append(f"{indent}  - " + " | ".join(str(r.get(c, "")) for c in cols))
            return out
        values = [_value(i) for i in items]
        return [f"{indent}{key} (list) = {values}"]
    if kind == "MAP":
        out = [f"{indent}{key} (map):"]
        for m in node.get("map", []) or []:
            out += render_param(m, indent + "  ")
        return out
    value = node.get("value", "")
    suffix = "" if kind in ("TEMPLATE", "") else f" [{kind.lower()}]"
    text = str(value)
    if "\n" in text and len(text) > 200:
        return [f"{indent}{key}{suffix}: ({len(text)} chars, see code block)"]
    return [f"{indent}{key}{suffix} = {text}"]


def _trigger_line(model: Model, tid: str) -> str:
    events = sorted(trigger_events(model, tid))
    return f"{model.label('trigger:' + str(tid))} ({', '.join(events[:4])}{'...' if len(events) > 4 else ''})"


VARIABLE_SOURCE = {
    "v": lambda o: f"dataLayer {pval(o.raw, 'name')!r} (v{pval(o.raw, 'dataLayerVersion') or '2'})",
    "c": lambda o: f"constant {redact(pval(o.raw, 'value'))!r}",
    "k": lambda o: f"cookie {pval(o.raw, 'name')!r}",
    "j": lambda o: f"JavaScript global {pval(o.raw, 'name')!r}",
    "u": lambda o: f"URL {pval(o.raw, 'component') or 'full'}",
    "d": lambda o: f"DOM {pval(o.raw, 'selectorType') or ''} {pval(o.raw, 'elementId') or pval(o.raw, 'elementSelector')!r}",
    "jsm": lambda o: f"custom JavaScript, {len(pval(o.raw, 'javascript'))} chars",
    "smm": lambda o: f"lookup table of {pval(o.raw, 'input')}",
    "remm": lambda o: f"regex table of {pval(o.raw, 'input')}",
}


def variable_source(model: Model, key: str) -> str:
    """One line: a variable, where its value comes from, and the variables it reads."""
    v = model.objects[key]
    reads = [model.objects[d].name for d, kind in model.dependencies(key) if kind == "variable"]
    source = VARIABLE_SOURCE.get(v.type, lambda o: o.type)(v)
    return f"{{{{{v.name}}}}} ({key}): {source}" + (f"; reads {', '.join('{{' + r + '}}' for r in reads)}" if reads else "")


def value_chain(model: Model, key: str, depth: int = 0, seen: frozenset = frozenset()) -> list[str]:
    """Each variable an object reads, followed to its producers (one line per variable)."""
    lines = []
    for dep, kind in model.dependencies(key):
        if kind != "variable" or dep in seen or depth > 4:
            continue
        lines.append("  " * (depth + 1) + variable_source(model, dep))
        lines += value_chain(model, dep, depth + 1, seen | {key, dep})
    return lines


def render(model: Model, obj: Obj, full: bool = True, chains: bool = True) -> str:
    """Readable object view. Packs pass chains=False and list value sources once per variable instead."""
    lines = [f"### {obj.key} · {obj.type} · \"{obj.name}\""]
    status = ["paused" if obj.paused else "active"]
    if obj.key not in model.reachable and obj.layer in ("tag", "trigger", "variable"):
        status.append("not reachable from active tags")
    if obj.raw.get("tagFiringOption"):
        status.append(f"option {obj.raw['tagFiringOption']}")
    if "priority" in obj.raw:
        status.append(f"priority {_value(obj.raw['priority'])}")
    folder = obj.raw.get("parentFolderId")
    if folder:
        status.append(f"folder {model.label('folder:' + str(folder))}")
    lines.append("status: " + " | ".join(status))
    if obj.layer == "tag":
        fires = [_trigger_line(model, t) for t in obj.raw.get("firingTriggerId", []) or []]
        blocks = [_trigger_line(model, t) for t in obj.raw.get("blockingTriggerId", []) or []]
        lines.append("fires on: " + ("; ".join(fires) if fires else "-"))
        if blocks:
            lines.append("blocked by: " + "; ".join(blocks))
        for kind in ("setupTag", "teardownTag"):
            for s in obj.raw.get(kind, []) or []:
                stop = s.get("stopOnSetupFailure", s.get("stopTeardownOnFailure", ""))
                lines.append(f"{kind}: \"{s.get('tagName')}\" stopOnFailure={stop}")
        ctl = consent_controls(model, obj)
        parts = [f"status {ctl['status']}"]
        if ctl["additional_check"]:
            parts.append("additional " + ",".join(ctl["additional_check"]))
        if ctl["positive_trigger"]:
            parts.append("predicate in firing trigger " + ",".join(ctl["positive_trigger"]))
        if ctl["blocker"]:
            parts.append("predicate in blocker " + ",".join(ctl["blocker"]))
        if ctl["hints"]:
            parts.append("consent event or earlier group member only, no current predicate: " + ",".join(ctl["hints"]))
        if obj.type in GOOGLE_TAG_TYPES:
            parts.append("Google built-in consent checks")
        lines.append("consent: " + " | ".join(parts))
        lines.append("vendors: " + ", ".join(vendors_of(model, obj)))
    if obj.layer == "trigger":
        lines.append("events: " + ", ".join(sorted(trigger_events(model, obj.id))))
        ev = consent_evidence(model, obj.id)
        if any(ev.values()):
            lines.append("consent evidence: " + "; ".join(
                f"{kind}: {', '.join(items)}" for kind, items in ev.items() if items))
        for c in conditions(obj.raw):
            flags = " ".join(f for f, on in (("negate", c["negate"]), ("ignore_case", c["ignore_case"])) if on)
            lines.append(f"  [{c['family']}] {c['arg0']} {c['op']} {redact(c['arg1'])!r} {flags}".rstrip())
        members = group_members(obj.raw)
        if members:
            lines.append("group members: " + "; ".join(_trigger_line(model, m) for m in members))
    if obj.layer in ("trigger", "variable", "template", "folder"):
        users = model.consumers(obj.key)
        lines.append(f"used by ({len(users)}): " + ("; ".join(f"{model.label(k)} [{kind}]" for k, kind in users[:25])
                                                     + (" ..." if len(users) > 25 else "") if users else "nothing"))
    chain = value_chain(model, obj.key) if chains and obj.layer in ("tag", "variable") else []
    if chain:
        lines.append("value sources:")
        lines += chain
    if not full:
        return "\n".join(lines)
    for key, value in obj.raw.items():
        if key not in SKIP_TOP and value not in (None, "", [], {}):
            text = _value(value) if isinstance(value, dict) else json.dumps(value, ensure_ascii=False)
            lines.append(f"{key} = {redact(str(text))[:300]}")
    ps = obj.raw.get("parameter", []) or []
    if ps:
        lines.append("parameters:")
        for p in ps:
            if obj.layer == "tag" and obj.type == "html" and p.get("key") == "html":
                continue
            if obj.layer == "variable" and obj.type == "jsm" and p.get("key") == "javascript":
                continue
            lines += render_param(mask_structure(p))
    code = code_of(obj)
    if code:
        lang = "html" if obj.type == "html" else "javascript"
        lines.append(f"code ({len(code)} chars):\n```{lang}\n{redact(code)}\n```")
    if obj.layer == "template":
        sections = template_sections(strip_template(obj.raw))
        gallery = obj.raw.get("galleryReference") or {}
        if gallery:
            lines.append("gallery: " + ", ".join(f"{k}={v}" for k, v in gallery.items() if k != "signature"))
        info = sections.get(TEMPLATE_INFO, "")
        if info:
            lines.append("info: " + redact(info.strip())[:800])
        perms = sections.get(TEMPLATE_PERMISSIONS, "")
        if perms:
            public_ids = sorted(set(re.findall(r'"publicId":\s*"([^"]+)"', perms)))
            lines.append("permissions: " + ", ".join(public_ids))
        js = sections.get(TEMPLATE_CODE, "")
        if js:
            lines.append(f"sandboxed code ({len(js)} chars):\n```javascript\n{redact(js.strip())}\n```")
    if obj.raw.get("notes"):
        lines.append(f"notes: {redact(obj.raw['notes'])[:400]}")
    return "\n".join(lines)


def siblings(model: Model, key: str) -> dict[str, list[str]]:
    """Objects sharing a behavioural pattern with `key` (follow a finding across its whole family)."""
    obj = model.objects[key]
    out: dict[str, list[str]] = defaultdict(list)
    same_layer = [o for o in model.layer(obj.layer) if o.key != key]
    if obj.layer == "tag":
        fires = set(map(str, obj.raw.get("firingTriggerId", []) or []))
        events = set()
        for t in fires:
            events |= trigger_events(model, t)
        vendors = set(vendors_of(model, obj))
        pkeys = set(params(obj.raw))
        for o in same_layer:
            ofires = set(map(str, o.raw.get("firingTriggerId", []) or []))
            oevents = set()
            for t in ofires:
                oevents |= trigger_events(model, t)
            if fires & ofires:
                out["shares a firing trigger"].append(o.key)
            elif events - {"*"} and events & oevents:
                out["fires on the same event"].append(o.key)
            if obj.raw.get("tagFiringOption") and o.raw.get("tagFiringOption") == obj.raw.get("tagFiringOption") \
                    and events & oevents:
                out[f"same firing option ({obj.raw.get('tagFiringOption')}) on the same event"].append(o.key)
            if o.type == obj.type and obj.type not in ("html", "img") and pkeys and set(params(o.raw)) == pkeys:
                out["same type and parameter keys"].append(o.key)
            if vendors - {"Other", "Custom HTML"} and vendors & set(vendors_of(model, o)):
                out["same vendor"].append(o.key)
            if set(map(str, o.raw.get("blockingTriggerId", []) or [])) == set(
                    map(str, obj.raw.get("blockingTriggerId", []) or [])) and obj.raw.get("blockingTriggerId"):
                out["same blocking triggers"].append(o.key)
    elif obj.layer == "trigger":
        events = trigger_events(model, obj.id)
        for o in same_layer:
            if o.type == obj.type and trigger_events(model, o.id) == events and events != {"*"}:
                out["same type and events"].append(o.key)
            elif o.type == obj.type:
                ops = {(c["arg0"], c["op"]) for c in conditions(obj.raw)}
                if ops and ops == {(c["arg0"], c["op"]) for c in conditions(o.raw)}:
                    out["same condition shape"].append(o.key)
    elif obj.layer == "variable":
        name_key = params(obj.raw).get("name", {}).get("value", "")
        for o in same_layer:
            if o.type == obj.type:
                other = params(o.raw).get("name", {}).get("value", "")
                if name_key and other and (other == name_key or other.split(".")[0] == name_key.split(".")[0]):
                    out["same type and data path root"].append(o.key)
                elif o.type in ("smm", "remm", "jsm", "awec", "gtes", "gtcs"):
                    out["same type"].append(o.key)
    return {k: sorted(v) for k, v in out.items()}
