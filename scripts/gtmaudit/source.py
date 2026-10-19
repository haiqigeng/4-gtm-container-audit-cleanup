"""Load one GTM web-container export and build the shared source model.

Every later stage (rules, packs, show, simulate) reads this model, so references,
trigger events, consent controls and reachability are computed in one place.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

LAYERS = {
    "tag": "tagId",
    "trigger": "triggerId",
    "variable": "variableId",
    "folder": "folderId",
    "template": "templateId",
    "zone": "zoneId",
    "gtagConfig": "gtagConfigId",
}
EXPORT_KEYS = {"template": "customTemplate"}
SERVER_LAYERS = ("client", "transformation")

ALL_PAGES, CONSENT_INIT, INIT = "2147479553", "2147479572", "2147479573"
SYSTEM_TRIGGERS = {ALL_PAGES: "gtm.js", CONSENT_INIT: "gtm.init_consent", INIT: "gtm.init"}
SYSTEM_TRIGGER_NAMES = {ALL_PAGES: "All Pages", CONSENT_INIT: "Consent Initialization - All Pages",
                        INIT: "Initialization - All Pages"}
TRIGGER_EVENTS = {
    "PAGEVIEW": "gtm.js", "DOM_READY": "gtm.dom", "WINDOW_LOADED": "gtm.load", "CONSENT_INIT": "gtm.init_consent",
    "INIT": "gtm.init", "CLICK": "gtm.click", "LINK_CLICK": "gtm.linkClick", "FORM_SUBMISSION": "gtm.formSubmit",
    "TIMER": "gtm.timer", "SCROLL_DEPTH": "gtm.scrollDepth", "ELEMENT_VISIBILITY": "gtm.elementVisibility",
    "TRIGGER_GROUP": "gtm.triggerGroup", "YOU_TUBE_VIDEO": "gtm.video", "HISTORY_CHANGE": "gtm.historyChange",
    "JS_ERROR": "gtm.pageError",
}
PAGE_LOAD_EVENTS = {"gtm.js", "gtm.init", "gtm.init_consent", "gtm.dom", "gtm.load"}
GOOGLE_TAG_TYPES = {"googtag", "gaawe", "gaawc", "awct", "awcc", "awc", "awj", "awud", "sp", "gclidw", "flc", "fls", "ua"}
GOOGLE_ADS_TYPES = {"awct", "awcc", "awud", "sp", "flc", "fls", "gclidw"}
REF_RE = re.compile(r"\{\{([^{}]+)\}\}")
CONSENT_WORDS = re.compile(
    r"consent|didomi|onetrust|optanon|axeptio|cookiebot|tarteaucitron|sirdata|usercentrics|activegroups|"
    r"vendorsenabled|vendorsconsent|purposes?|c000\d|cmp|rgpd|gdpr", re.I)
CONSENT_VAR_RE = re.compile(r"consent|didomi|optanon|onetrust|axeptio|cookiebot|vendors|gdpr|rgpd|cmp", re.I)
NEUTRAL_KEYS = {"accountId", "containerId", "fingerprint", "tagId", "triggerId", "variableId", "templateId", "name",
                "parentFolderId", "notes", "path", "tagManagerUrl", "monitoringMetadata", "uniqueTriggerId"}

TAG_VENDORS = {
    "googtag": "Google tag", "gaawe": "GA4", "gaawc": "GA4", "ua": "Universal Analytics", "awct": "Google Ads",
    "awcc": "Google Ads", "awc": "Google Ads", "awj": "Google Ads", "awud": "Google Ads", "sp": "Google Ads",
    "gclidw": "Google Conversion Linker", "flc": "Floodlight", "fls": "Floodlight", "baut": "Microsoft UET",
    "crto": "Criteo", "img": "Custom Image", "html": "Custom HTML", "hjtc": "Hotjar", "pntr": "Pinterest",
    "bzi": "LinkedIn", "twitter_website_tag": "X/Twitter", "fsl": "Facebook (legacy)", "cegg": "Crazy Egg",
    "qcm": "Quantcast", "tdc": "Tradedoubler", "awc_": "Awin",
}
CODE_VENDORS = {
    "Meta": r"fbq\s*\(|connect\.facebook\.net", "TikTok": r"ttq\.|analytics\.tiktok\.com",
    "Microsoft UET": r"bat\.bing\.com|uetq", "LinkedIn": r"snap\.licdn\.com|_linkedin_partner_id|lintrk",
    "Pinterest": r"pintrk|s\.pinimg\.com", "Snapchat": r"snaptr|sc-static\.net", "Criteo": r"criteo",
    "X/Twitter": r"twq\(|static\.ads-twitter\.com", "Taboola": r"_tfa\.|taboola", "Outbrain": r"obApi|outbrain",
    "Matomo": r"matomo|_paq\.push|piwik", "Amazon": r"amzn\(|amazon-adsystem", "Awin": r"awin1\.com|dwin1\.com",
    "Hotjar": r"hotjar|_hjSettings", "Microsoft Clarity": r"clarity\.ms|clarity\(", "Didomi": r"didomi",
    "OneTrust": r"onetrust|optanon", "Axeptio": r"axeptio", "Cookiebot": r"cookiebot", "Usercentrics": r"usercentrics",
    "Piano": r"piano|pa\.sendEvent|_pac\b", "Reddit": r"rdt\(|redditstatic",
    "Google Ads": r"googleadservices|gtag\(\s*['\"]event['\"]\s*,\s*['\"]conversion",
}
CODE_VENDOR_RES = {name: re.compile(rx, re.I) for name, rx in CODE_VENDORS.items()}
THIRD_PARTY_HTML_RE = re.compile(
    r"<script[^>]+src\s*=|<img[^>]+src\s*=\s*['\"](?:https?:)?//|createElement\(\s*['\"](?:script|img|iframe)['\"]|"
    r"new\s+Image\s*\(|fbq\(|ttq\.|uetq|criteo_q|amzn\(|snaptr|pintrk|_paq|obApi|navigator\.sendBeacon|fetch\s*\(|"
    r"XMLHttpRequest", re.I)
CMP_NAME_RE = re.compile(r"consent|cmp|didomi|onetrust|axeptio|cookiebot|usercentrics|tarteaucitron|sirdata", re.I)


class SourceError(ValueError):
    """The export cannot be audited as one complete web container."""


@dataclass
class Obj:
    key: str
    layer: str
    id: str
    name: str
    type: str
    raw: dict
    path: str

    @property
    def paused(self) -> bool:
        return bool(self.raw.get("paused"))


@dataclass
class Model:
    raw: dict
    cv: dict
    sha256: str
    source_path: str
    objects: dict[str, Obj] = field(default_factory=dict)
    builtins: set[str] = field(default_factory=set)
    edges: list[tuple[str, str, str]] = field(default_factory=list)
    unresolved: list[tuple[str, str, str]] = field(default_factory=list)

    # ---------- lookups ----------
    def layer(self, layer: str) -> list[Obj]:
        return [o for o in self.objects.values() if o.layer == layer]

    def get(self, key: str) -> Obj | None:
        return self.objects.get(key)

    def by_name(self, layer: str, name: str) -> list[Obj]:
        return [o for o in self.layer(layer) if o.name == name]

    def trigger(self, trigger_id: str) -> Obj | None:
        return self.objects.get(f"trigger:{trigger_id}")

    def consumers(self, key: str) -> list[tuple[str, str]]:
        return sorted({(src, kind) for src, dst, kind in self.edges if dst == key and kind != "folder"})

    def dependencies(self, key: str) -> list[tuple[str, str]]:
        return sorted({(dst, kind) for src, dst, kind in self.edges if src == key})

    def label(self, key: str) -> str:
        if key.startswith("trigger:") and key.split(":", 1)[1] in SYSTEM_TRIGGER_NAMES:
            return f"{key} \"{SYSTEM_TRIGGER_NAMES[key.split(':', 1)[1]]}\""
        o = self.objects.get(key)
        return f"{key} \"{o.name}\"" if o else key

    # ---------- derived facts (filled by build) ----------
    reachable: set[str] = field(default_factory=set)
    trigger_events_cache: dict[str, set[str]] = field(default_factory=dict)


# ---------- typed parameter helpers ----------

def params(obj: dict) -> dict[str, dict]:
    return {p.get("key"): p for p in (obj or {}).get("parameter", []) or [] if isinstance(p, dict)}


def pval(obj: dict, key: str, default: str = "") -> str:
    p = params(obj).get(key)
    return p.get("value", default) if isinstance(p, dict) else default


def table_rows(obj: dict, key: str) -> list[dict[str, str]]:
    p = params(obj).get(key)
    rows = []
    for item in (p or {}).get("list", []) or []:
        if isinstance(item, dict) and item.get("type") == "MAP":
            rows.append({m.get("key"): m.get("value", "") for m in item.get("map", []) or [] if isinstance(m, dict)})
    return rows


def conditions(trigger: dict, families=("customEventFilter", "filter", "autoEventFilter")) -> list[dict]:
    out = []
    for fam in families:
        for f in (trigger or {}).get(fam, []) or []:
            ps = {p.get("key"): p.get("value") for p in f.get("parameter", []) or []}
            out.append({"family": fam, "op": f.get("type"), "arg0": ps.get("arg0", "") or "",
                        "arg1": ps.get("arg1", "") or "", "negate": ps.get("negate") == "true",
                        "ignore_case": ps.get("ignore_case") == "true"})
    return out


def group_members(trigger: dict) -> list[str]:
    out = []
    for p in (trigger or {}).get("parameter", []) or []:
        if p.get("key") == "triggerIds":
            out += [str(x.get("value")) for x in p.get("list", []) or [] if isinstance(x, dict)]
    return out


def code_of(obj: Obj) -> str:
    if obj.layer == "tag" and obj.type == "html":
        return pval(obj.raw, "html")
    if obj.layer == "variable" and obj.type == "jsm":
        return pval(obj.raw, "javascript")
    return ""


def strip_template(template: dict) -> dict:
    """Template copy without raster thumbnails or other embedded images (kept as size + hash)."""
    data = template.get("templateData", "") or ""

    def repl(m: re.Match) -> str:
        blob = m.group(0)
        return f"<embedded image {len(blob)} chars sha:{hashlib.sha256(blob.encode()).hexdigest()[:8]}>"
    clean = re.sub(r"data:image/[a-z+]+;base64,(?:[A-Za-z0-9+/=]|\\u003d)+", repl, data)
    return {**template, "templateData": clean}


TEMPLATE_INFO, TEMPLATE_CODE, TEMPLATE_PERMISSIONS = "INFO", "SANDBOXED_JS_FOR_WEB_TEMPLATE", "WEB_PERMISSIONS"


def template_sections(template: dict) -> dict[str, str]:
    """Template sections keyed by their export identity (for example SANDBOXED_JS_FOR_WEB_TEMPLATE)."""
    data = template.get("templateData", "") or ""
    sections, current = {}, None
    for line in data.splitlines():
        m = re.match(r"^___([A-Z_ ]+)___\s*$", line)
        if m:
            current = re.sub(r"[ _]+", "_", m.group(1).strip())
            sections[current] = ""
        elif current:
            sections[current] += line + "\n"
    return sections


def normalized_signature(raw: dict, drop: set[str] = frozenset()) -> str:
    def clean(x):
        if isinstance(x, dict):
            return {k: clean(v) for k, v in sorted(x.items()) if k not in NEUTRAL_KEYS and k not in drop}
        if isinstance(x, list):
            return [clean(v) for v in x]
        return x
    return json.dumps(clean(raw), sort_keys=True, ensure_ascii=False)


# ---------- loading ----------

def load(path: str | Path) -> Model:
    path = Path(path)
    text = path.read_bytes()
    try:
        raw = json.loads(text.decode("utf-8"), object_pairs_hook=_no_duplicate_keys)
    except UnicodeDecodeError as exc:
        raise SourceError(f"Export is not UTF-8: {exc}") from exc
    return from_raw(raw, hashlib.sha256(text).hexdigest(), str(path.resolve()))


def from_raw(raw: dict, sha256: str = "", source_path: str = "") -> Model:
    """Model of an export already parsed (the source, or a simulated target)."""
    cv = raw.get("containerVersion", raw) if isinstance(raw, dict) else None
    if not isinstance(cv, dict):
        raise SourceError("No containerVersion object found.")
    container = cv.get("container") or {}
    contexts = container.get("usageContext") or []
    if any(cv.get(layer) for layer in SERVER_LAYERS) or (contexts and "WEB" not in contexts):
        raise SourceError("Only web containers are supported; this export is a server or non-web container.")
    root = "$.containerVersion" if "containerVersion" in raw else "$"
    model = Model(raw=raw, cv=cv, sha256=sha256, source_path=source_path)
    for layer, id_key in LAYERS.items():
        export_key = EXPORT_KEYS.get(layer, layer)
        items = cv.get(export_key, []) or []
        if not isinstance(items, list):
            raise SourceError(f"{export_key} is not a list.")
        for index, item in enumerate(items):
            if not isinstance(item, dict) or not str(item.get(id_key, "")).strip():
                raise SourceError(f"{export_key}[{index}] has no {id_key}.")
            key = f"{layer}:{item[id_key]}"
            if key in model.objects:
                raise SourceError(f"Duplicate identifier {key}.")
            model.objects[key] = Obj(key, layer, str(item[id_key]), str(item.get("name", "")),
                                     str(item.get("type", layer)), item, f"{root}.{export_key}[{index}]")
    model.builtins = {str(b.get("name")) for b in cv.get("builtInVariable", []) or [] if isinstance(b, dict)}
    _build_graph(model)
    _build_reachability(model)
    return model


def _no_duplicate_keys(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise SourceError(f"Duplicate JSON key {k!r}.")
        out[k] = v
    return out


def _template_type_ids(model: Model) -> dict[str, str]:
    container_id = str((model.cv.get("container") or {}).get("containerId") or model.cv.get("containerId") or "")
    out = {}
    for t in model.layer("template"):
        out[f"cvt_{container_id}_{t.id}"] = t.key
        gallery = t.raw.get("galleryReference") or {}
        if gallery.get("galleryTemplateId"):
            out[f"cvt_{gallery['galleryTemplateId']}"] = t.key
    return out


def template_of(model: Model, obj: Obj) -> Obj | None:
    key = _template_type_ids(model).get(obj.type)
    return model.objects.get(key) if key else None


def _build_graph(model: Model) -> None:
    variables = defaultdict(list)
    for v in model.layer("variable"):
        variables[v.name].append(v.key)
    tags_by_name = defaultdict(list)
    for t in model.layer("tag"):
        tags_by_name[t.name].append(t.key)
    template_ids = _template_type_ids(model)
    edges, unresolved = set(), set()
    for o in model.objects.values():
        if o.layer in ("tag", "trigger", "variable", "zone"):
            for name in set(REF_RE.findall(json.dumps(o.raw, ensure_ascii=False))):
                name = name.strip()
                if name in variables:
                    for target in variables[name]:
                        if target != o.key:
                            edges.add((o.key, target, "variable"))
                elif name not in model.builtins and not name.startswith("_"):
                    unresolved.add((o.key, name, "variable"))
        folder = o.raw.get("parentFolderId")
        if folder:
            if f"folder:{folder}" in model.objects:
                edges.add((o.key, f"folder:{folder}", "folder"))
            else:
                unresolved.add((o.key, str(folder), "folder"))
        if o.type in template_ids:
            edges.add((o.key, template_ids[o.type], "template"))
        elif o.layer in ("tag", "variable") and o.type.startswith("cvt_"):
            unresolved.add((o.key, o.type, "template"))
    for t in model.layer("tag"):
        for kind, field_name in (("firing", "firingTriggerId"), ("blocking", "blockingTriggerId")):
            for tid in t.raw.get(field_name, []) or []:
                tid = str(tid)
                if f"trigger:{tid}" in model.objects:
                    edges.add((t.key, f"trigger:{tid}", kind))
                elif tid not in SYSTEM_TRIGGERS:
                    unresolved.add((t.key, tid, "trigger"))
        for kind in ("setupTag", "teardownTag"):
            for s in t.raw.get(kind, []) or []:
                targets = tags_by_name.get(s.get("tagName"), [])
                if not targets:
                    unresolved.add((t.key, str(s.get("tagName")), "tag"))
                for target in targets:
                    edges.add((t.key, target, kind))
    for tr in model.layer("trigger"):
        for m in group_members(tr.raw):
            if f"trigger:{m}" in model.objects:
                edges.add((tr.key, f"trigger:{m}", "group_member"))
            elif m not in SYSTEM_TRIGGERS:
                unresolved.add((tr.key, m, "trigger"))
    for z in model.layer("zone"):
        for tid in re.findall(r'"(\d+)"', json.dumps(z.raw.get("boundary", {}))):
            if f"trigger:{tid}" in model.objects:
                edges.add((z.key, f"trigger:{tid}", "zone_boundary"))
    model.edges = sorted(edges)
    model.unresolved = sorted(unresolved)


def _build_reachability(model: Model) -> None:
    """Objects reachable from active tags that can fire (directly or through sequencing)."""
    deps = defaultdict(set)
    for src, dst, kind in model.edges:
        if kind != "folder":
            deps[src].add(dst)
    sequenced = {dst for src, dst, kind in model.edges if kind in ("setupTag", "teardownTag")}
    roots = [t.key for t in model.layer("tag") if not t.paused and (t.raw.get("firingTriggerId") or t.key in sequenced)]
    seen, stack = set(), list(roots)
    while stack:
        key = stack.pop()
        if key in seen:
            continue
        o = model.objects.get(key)
        if o and o.paused:
            continue
        seen.add(key)
        stack.extend(deps.get(key, ()))
    model.reachable = seen


# ---------- trigger semantics ----------

def regex_literal_names(pattern: str) -> set[str] | None:
    """Event names a simple alternation regex can match, or None when the regex is open-ended."""
    body = pattern.strip().strip("^$")
    if re.fullmatch(r"\(?[\w.\-|: ]+\)?", body or "-"):
        return {p.strip().replace("\\", "") for p in body.strip("()").split("|") if p.strip()}
    return None


def trigger_events(model: Model, trigger_id: str, depth: int = 0) -> set[str]:
    """dataLayer event names a trigger can fire on; {'*'} when open-ended."""
    trigger_id = str(trigger_id)
    if trigger_id in model.trigger_events_cache:
        return model.trigger_events_cache[trigger_id]
    if trigger_id in SYSTEM_TRIGGERS:
        return {SYSTEM_TRIGGERS[trigger_id]}
    tr = model.trigger(trigger_id)
    if not tr or depth > 6:
        return {"*"}
    result: set[str]
    if tr.type == "CUSTOM_EVENT":
        names: set[str] = set()
        for c in conditions(tr.raw, ("customEventFilter",)):
            if c["arg0"] == "{{_event}}" and not c["negate"]:
                if c["op"] == "EQUALS":
                    names.add(c["arg1"])
                elif c["op"] == "MATCH_REGEX":
                    literal = regex_literal_names(c["arg1"])
                    if literal is None:
                        names = {"*"}
                        break
                    names |= literal
                else:
                    names = {"*"}
                    break
        result = names or {"*"}
    else:
        result = {TRIGGER_EVENTS.get(tr.type, "*")}
    model.trigger_events_cache[trigger_id] = result
    return result


def tag_events(model: Model, tag: Obj) -> set[str]:
    out: set[str] = set()
    for tid in tag.raw.get("firingTriggerId", []) or []:
        out |= trigger_events(model, tid)
    return out


def consent_evidence(model: Model, trigger_id: str, depth: int = 0) -> dict[str, list[str]]:
    """Consent evidence on one trigger, by kind.

    predicates: conditions on this trigger that test a consent state now (the only permission control).
    events: consent-named events the trigger listens to (timing hints, not a permission test).
    group_history: predicates on trigger-group members, which matched on an earlier occurrence.
    """
    tr = model.trigger(str(trigger_id))
    out: dict[str, list[str]] = {"predicates": [], "events": [], "group_history": []}
    if not tr or depth > 6:
        return out
    for c in conditions(tr.raw):
        if c["arg0"] != "{{_event}}" and (CONSENT_VAR_RE.search(c["arg0"]) or CONSENT_WORDS.search(c["arg1"])):
            out["predicates"].append(f"{c['arg0']} {'NOT ' if c['negate'] else ''}{c['op']} {c['arg1']!r}")
    if tr.type == "CUSTOM_EVENT":
        out["events"] = sorted(e for e in trigger_events(model, trigger_id) if e != "*" and CONSENT_WORDS.search(e))
    for m in group_members(tr.raw):
        member = consent_evidence(model, m, depth + 1)
        out["group_history"] += [f"trigger:{m} {p}" for p in member["predicates"] + member["group_history"]]
    return out


def has_consent_evidence(model: Model, trigger_id: str) -> bool:
    """Any consent evidence, including hints: used to find consent-related objects, never as a control."""
    return any(consent_evidence(model, trigger_id).values())


def consent_controls(model: Model, tag: Obj) -> dict[str, Any]:
    """Visible consent controls on one tag (static, no runtime claim). Hints are reported, not counted."""
    settings = tag.raw.get("consentSettings") or {}
    status = settings.get("consentStatus", "NOT_SET")
    types = [x.get("value") for x in ((settings.get("consentType") or {}).get("list") or []) if isinstance(x, dict)]
    fires = [str(t) for t in tag.raw.get("firingTriggerId", []) or []]
    blocks = [str(t) for t in tag.raw.get("blockingTriggerId", []) or []]
    evidence = {t: consent_evidence(model, t) for t in fires + blocks}
    return {
        "positive_trigger": [t for t in fires if evidence[t]["predicates"]],
        "blocker": [t for t in blocks if evidence[t]["predicates"]],
        "additional_check": types if status == "NEEDED" else [],
        "hints": [t for t in fires + blocks
                  if not evidence[t]["predicates"] and (evidence[t]["events"] or evidence[t]["group_history"])],
        "status": status,
        "built_in": tag.type in GOOGLE_TAG_TYPES,
    }


def has_consent_control(controls: dict[str, Any]) -> bool:
    return any(controls[n] for n in ("positive_trigger", "blocker", "additional_check"))


def _literal(model: Model, value: str) -> str:
    """Resolve a single {{Constant}} reference to its literal value; other values are returned unchanged."""
    m = re.fullmatch(r"\{\{([^{}]+)\}\}", value.strip())
    if m:
        for v in model.by_name("variable", m.group(1)):
            if v.type == "c":
                return pval(v.raw, "value")
    return value


def _hosts(values: list[str]) -> set[str]:
    out = set()
    for value in values:
        m = re.match(r"^(?:https?:)?//([^/:?#]+)", value.strip())
        if m:
            out.add(m.group(1).lower())
    return out


def destinations(model: Model, tag: Obj) -> set[str]:
    """Google destination IDs a tag sends to."""
    raw = tag.raw
    dests: set[str] = set()
    if tag.type == "googtag":
        dests.add(_literal(model, pval(raw, "tagId")))
    elif tag.type == "gaawe":
        dests.add(_literal(model, pval(raw, "measurementIdOverride") or pval(raw, "measurementId")))
    elif tag.type in ("awct", "awcc", "awud", "sp"):
        dests.add("AW-" + _literal(model, pval(raw, "conversionId")))
    elif tag.type in ("flc", "fls"):
        dests.add("DC-" + _literal(model, pval(raw, "advertiserId")))
    dests.discard("")
    return dests


SETTINGS = {"googtag": ("configSettingsVariable", "configSettingsTable"),
            "gaawe": ("eventSettingsVariable", "eventSettingsTable")}
SETTINGS_VARIABLES = ("gtes", "gtcs")
CODE_FIELDS = ("html", "javascript", "templateData")  # fields that hold code: Custom HTML, Custom JavaScript, templates  # containers of a Google tag's own settings rows, not values
# Fields of a tag, trigger or variable object itself (not its parameters): export structure, which the analyst sees
# only through its GTM label (steps.FIELDS).
OBJECT_FIELDS = ("firingTriggerId", "blockingTriggerId", "tagFiringOption", "priority", "consentSettings", "setupTag",
                 "teardownTag", "parentFolderId", "notes", "type", "customEventFilter", "filter", "autoEventFilter",
                 "templateData", "waitForTags", "waitForTagsTimeout", "checkValidation")


def _settings(model: Model, raw: dict, kind: str) -> dict[str, str]:
    """A Google tag's settings rows: its settings variable's rows, then its own rows (which win)."""
    variable, table = SETTINGS[kind]
    out: dict[str, str] = {}
    m = re.fullmatch(r"\{\{([^{}]+)\}\}", pval(raw, variable).strip())
    for v in model.by_name("variable", m.group(1)) if m else []:
        out.update({r.get("parameter", ""): r.get("parameterValue", "") for r in table_rows(v.raw, table)})
    out.update({r.get("parameter", ""): r.get("parameterValue", "") for r in table_rows(raw, table)})
    return out


def effective_parameters(model: Model, tag: Obj) -> dict[str, str]:
    """What a tag sends as settings: the Google tags of its destinations, then its own settings variable and rows.

    The one definition of settings inheritance; local values win over shared and inherited ones.
    """
    out: dict[str, str] = {}
    dests = destinations(model, tag)
    for g in model.layer("tag"):
        if g.type == "googtag" and g.key != tag.key and _literal(model, pval(g.raw, "tagId")) in dests:
            out.update(_settings(model, g.raw, "googtag"))
    if tag.type in SETTINGS:
        out.update(_settings(model, tag.raw, tag.type))
    return out


def reads_closure(model: Model, keys: list[str]) -> list[str]:
    """Every variable the given objects read, directly or through other variables, each once."""
    out, pending = [], list(keys)
    while pending:
        for dep, kind in model.dependencies(pending.pop()):
            if kind == "variable" and dep not in out:
                out.append(dep)
                pending.append(dep)
    return sorted(out, key=lambda k: int(k.split(":")[1]) if k.split(":")[1].isdigit() else 0)


def sent_variables(model: Model, tag: Obj) -> set[str]:
    """Every variable whose value a tag sends: what it reads, and what its inherited settings read."""
    inherited = {v.key for name in REF_RE.findall(json.dumps(list(effective_parameters(model, tag).values())))
                 for v in model.by_name("variable", name)}
    return set(reads_closure(model, [tag.key, *sorted(inherited)])) | inherited


def consent_routes(model: Model, tag: Obj) -> tuple[set[str], set[str]]:
    """Google destination IDs a tag sends to, and server hosts its hits are routed through."""
    route_values = [v for k, v in effective_parameters(model, tag).items() if k in ("server_container_url", "transport_url")]
    route_values.append(pval(tag.raw, "server_container_url"))
    return destinations(model, tag), _hosts([_literal(model, v) for v in route_values if v])


def vendors_of(model: Model, obj: Obj) -> list[str]:
    found = []
    if obj.type in TAG_VENDORS and obj.type not in ("html", "img"):
        found.append(TAG_VENDORS[obj.type])
    template = template_of(model, obj) if obj.type.startswith("cvt_") else None
    blob = json.dumps(obj.raw, ensure_ascii=False)
    if template:
        gallery = template.raw.get("galleryReference") or {}
        blob += " " + template.name + " " + str(gallery.get("owner", "")) + " " + str(gallery.get("repository", ""))
    for name, rx in CODE_VENDOR_RES.items():
        if rx.search(blob) and name not in found:
            found.append(name)
    return found or ([TAG_VENDORS[obj.type]] if obj.type in TAG_VENDORS else ["Other"])


def sends_third_party(model: Model, tag: Obj) -> bool:
    if tag.type in GOOGLE_TAG_TYPES:
        return False
    if tag.type == "html":
        return bool(THIRD_PARTY_HTML_RE.search(pval(tag.raw, "html")))
    if tag.type.startswith("cvt_"):
        template = template_of(model, tag)
        data = (template.raw.get("templateData", "") if template else "") or ""
        return not data or bool(re.search(
            r'"publicId":\s*"(inject_script|send_pixel|inject_hidden_iframe|send_beacon)"', data))
    return True


def is_cmp_tag(model: Model, tag: Obj) -> bool:
    if CMP_NAME_RE.search(tag.name):
        return True
    if tag.type.startswith("cvt_"):
        template = template_of(model, tag)
        if template and (CMP_NAME_RE.search(template.name) or re.search(
                r"setDefaultConsentState|updateConsentState", template.raw.get("templateData", "") or "")):
            return True
    return bool(re.search(r"gtag\s*\(\s*['\"]consent['\"]", pval(tag.raw, "html")))
