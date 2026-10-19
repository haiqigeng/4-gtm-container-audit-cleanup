"""D1 consent, privacy and security."""

from __future__ import annotations

import json
import re
from collections import Counter, defaultdict

from ..privacy import (
    CRED_ASSIGN_RE,
    CRED_NAME_RE,
    EMAIL_RE,
    HASH_HINT_RE,
    IMAGE_SUFFIXES,
    PII_NAME_RE,
    PII_VAR_RE,
    mask,
)
from ..source import (
    ALL_PAGES,
    CONSENT_INIT,
    CONSENT_VAR_RE,
    GOOGLE_ADS_TYPES,
    GOOGLE_TAG_TYPES,
    INIT,
    REF_RE,
    Model,
    conditions,
    consent_controls,
    consent_evidence,
    has_consent_control,
    is_cmp_tag,
    pval,
    sends_third_party,
    table_rows,
    template_of,
)

D = "D1"
RULES = {
    "C01": (D, "A09", "High", "Consent default writer that does not fire on Consent Initialization."),
    "C02": (D, "A09", "High", "Consent writer without ad_user_data / ad_personalization (Consent Mode v2)."),
    "C03": (D, "A09", "High", "Google tags present but no Google consent default writer in the container."),
    "C04": (D, "A10", "High", "Active third-party tag with no visible consent control."),
    "C05": (D, "A10", "High", "Non-Google tag set to 'No additional consent required' with no other gate."),
    "C07": (D, "A10", "Medium", "Consent encoded in a positive trigger instead of a reusable denial blocker."),
    "C10": (D, "A10", "High", "Consent condition matches a vendor token as a substring without boundaries."),
    "C11": (D, "A10", "High", "Fail-open consent blocker: blocks only on an explicit refusal."),
    "C12": (D, "A10", "High", "Trigger group presented as a consent route has no consent member."),
    "C13": (D, "A09", "Medium", "The same consent key is spelled with different letter case."),
    "C14": (D, "A10", "Medium", "Advertising vendor gated on analytics consent only."),
    "C15": (D, "A11", "High", "Google tag or linker fires on page load while the container sets no consent default."),
    "C17": (D, "A09", "High", "Consent Mode mapping grants an advertising type from an analytics token."),
    "C18": (D, "A12", "Medium", "Server-routed Google tag: consent forwarding and downstream ownership need review."),
    "G08": (D, "A21", "Critical", "user_id populated from personal data."),
    "P01": (D, "A21", "High", "Literal email-like value in configuration."),
    "P02": (D, "A21", "High", "Parameter or user property that may carry personal data."),
    "P03": (D, "A21", "High", "Personal data placed in a third-party request URL."),
    "P04": (D, "A21", "High", "mailto:/tel: target sent as an analytics parameter."),
    "P05": (D, "A21", "High", "Personal data written to cookies or web storage."),
    "P06": (D, "A21", "Medium", "Form field values pushed to the dataLayer."),
    "P07": (D, "A21", "Medium", "Hashed personal data sent as an ordinary event parameter."),
    "A07": (D, "A21", "Medium", "User-provided data mapping to review: field representation, normalisation, country format."),
    "A08": (D, "A21", "High", "User-provided data collected on unfiltered form submissions without consent gate."),
    "X13": (D, "A21", "Critical", "Credential-like literal in tag configuration or code."),
    "X15": (D, "A21", "High", "Custom JavaScript reads page or form fields that may hold personal data."),
}
# Rules whose every emission is its own candidate (one group of objects); other rules gather all their
# emissions into one candidate.
CLUSTERS = {"C03", "C13"}
AD_VENDOR_HINT = re.compile(r"amazon|data ?circle|criteo|taboola|outbrain|rtb|tiktok|snap|meta|facebook|pinterest|"
                            r"linkedin|twitter|teads|mgid|awin|tradedoubler|trade ?desk|adsrvr|bing|uet|google ads|"
                            r"floodlight|dv360", re.I)


def run(model: Model, emit, fact) -> None:
    tags, trigs, variables = model.layer("tag"), model.layer("trigger"), model.layer("variable")

    # consent conditions on triggers
    for tr in trigs:
        for c in conditions(tr.raw):
            a1 = c["arg1"]
            if c["op"] in ("CONTAINS", "MATCH_REGEX") and CONSENT_VAR_RE.search(c["arg0"]):
                numeric = re.fullmatch(r"(?:iab:)?\d{1,3}", a1)
                generic = a1.lower() in {"didomi", "google", "facebook", "consent", "true", "granted", "1"}
                word = re.fullmatch(r"[a-z][a-z-]{2,14}", a1)
                if numeric or generic or word:
                    emit("C10", f"Consent condition {c['arg0']} {c['op']} {a1!r} has no token boundaries", [tr.key],
                         "Another token containing this text also satisfies the condition.",
                         severity="High" if (numeric or generic) else "Medium")
            if c["op"] == "CONTAINS" and re.search(r":\s*false|=\s*false|:0\b|denied", a1) and \
                    CONSENT_VAR_RE.search(c["arg0"] + a1):
                emit("C11", f"Blocker only matches an explicit refusal ({a1[:40]!r})", [tr.key],
                     "No stored choice (first visit, new vendor) leaves the tag unblocked.")
        if tr.type == "TRIGGER_GROUP" and re.search(r"consent", tr.name, re.I):
            evidence = consent_evidence(model, tr.id)
            if not (evidence["predicates"] or evidence["group_history"]):
                users = [s for s, d, k in model.edges if d == tr.key and k == "firing"]
                emit("C12", "Trigger group named as a consent route has no consent member", [tr.key] + users[:4])
    spelled = defaultdict(set)
    for tr in trigs:
        for c in conditions(tr.raw):
            for m in re.finditer(r'"([A-Za-z_]{3,30})":(?:true|false)|activate_([A-Za-z_]{3,30})', c["arg1"]):
                token = m.group(1) or m.group(2)
                spelled[token.lower()].add((token, tr.key))
    for items in spelled.values():
        if len({t for t, _ in items}) > 1:
            emit("C13", f"Consent key spelled {sorted({t for t, _ in items})}", sorted(k for _, k in items)[:6])

    # consent writers
    def template_data(t) -> str:
        tmpl = template_of(model, t) if t.type.startswith("cvt_") else None
        return (tmpl.raw.get("templateData", "") if tmpl else "") or ""

    writers = []
    for t in tags:
        if t.paused:
            continue
        code, td = pval(t.raw, "html"), template_data(t)
        if re.search(r"gtag\s*\(\s*['\"]consent['\"]\s*,\s*['\"](default|update)", code) or \
                re.search(r"setDefaultConsentState|updateConsentState", td):
            writers.append(t)
            own = code + json.dumps(t.raw, ensure_ascii=False)
            sets_default = bool(re.search(r"['\"]default['\"]|cmType\W+value\W+default|command\W+value\W+default|"
                                          r"defaultSettings|gcmMapping", own))
            on_ci = any(str(x) == CONSENT_INIT or (model.trigger(str(x)) and model.trigger(str(x)).type == "CONSENT_INIT")
                        for x in t.raw.get("firingTriggerId") or [])
            if sets_default and not on_ci:
                emit("C01", "Consent default writer does not fire on Consent Initialization", [t.key])
            blob = code + json.dumps(t.raw.get("parameter"), ensure_ascii=False) + td
            if not ("ad_user_data" in blob and "ad_personalization" in blob):
                emit("C02", "Consent writer without ad_user_data/ad_personalization", [t.key])
    google = [t for t in tags if t.type in GOOGLE_TAG_TYPES and not t.paused]
    google_default = [t for t in writers if re.search(r"ad_storage|analytics_storage",
                                                       json.dumps(t.raw) + template_data(t))]
    if google and not google_default:
        ads = [t for t in google if t.type in GOOGLE_ADS_TYPES]
        emit("C03", f"{len(google)} active Google tags ({len(ads)} Ads/Floodlight) and no Google consent default writer",
             [t.key for t in google], severity="High" if ads else "Medium")
        for t in google:
            fires = {str(x) for x in t.raw.get("firingTriggerId") or []}
            early = bool(fires & {ALL_PAGES, INIT, CONSENT_INIT}) or any(
                (model.trigger(x) and model.trigger(x).type in ("PAGEVIEW", "INIT", "CONSENT_INIT")) for x in fires)
            if early and t.type in {"googtag", "gclidw", "sp"} and not has_consent_control(consent_controls(model, t)):
                emit("C15", f"{t.type} fires on page load without consent and no consent default exists", [t.key])

    # per-tag consent controls
    mix = Counter()
    for t in tags:
        if t.paused:
            continue
        ctl = consent_controls(model, t)
        mechanisms = tuple(n for n in ("positive_trigger", "blocker", "additional_check") if ctl[n])
        mix[mechanisms or ("none",)] += 1
        third = sends_third_party(model, t)
        cmp_tag = is_cmp_tag(model, t) or t in writers
        if third and not mechanisms and not cmp_tag:
            emit("C04", "Active third-party tag with no visible consent control", [t.key])
        if ctl["status"] == "NOT_NEEDED" and t.type not in GOOGLE_TAG_TYPES and not cmp_tag and \
                not (ctl["positive_trigger"] or ctl["blocker"]) and third:
            emit("C05", "Third-party tag set to 'No additional consent required' with no other gate", [t.key])
        if ctl["positive_trigger"] and not ctl["blocker"] and third and not cmp_tag:
            emit("C07", "Consent is encoded in the firing trigger, not a reusable denial blocker",
                 [t.key] + [f"trigger:{x}" for x in ctl["positive_trigger"]])
        if ctl["additional_check"] and set(ctl["additional_check"]) <= {"analytics_storage", "functionality_storage",
                                                                       "personalization_storage"} \
                and AD_VENDOR_HINT.search(t.name + " " + t.type) and t.type not in GOOGLE_TAG_TYPES:
            emit("C14", f"Advertising tag gated only on {ctl['additional_check']}", [t.key])
        if t.type == "googtag" and (pval(t.raw, "server_container_url") or any(
                r.get("parameter") in ("server_container_url", "transport_url")
                for r in table_rows(t.raw, "configSettingsTable"))):
            emit("C18", "Google tag routes hits to a server container", [t.key],
                 "Check the consent value forwarded and whether downstream gating ownership is approved in context.")
    fact("consent_mechanism_mix", {"+".join(k): v for k, v in mix.items()})
    fact("consent_writers", [t.key for t in writers])

    # consent mode mapping tables
    ad_maps, analytics_tokens = [], set()
    for v in variables:
        if v.type not in ("remm", "smm"):
            continue
        rows = table_rows(v.raw, "map")
        if re.search(r"ad_storage|ad_user_data|ad_personalization", v.name):
            ad_maps.append((v, [r.get("key", "") for r in rows if r.get("value") == "granted"]))
        if re.search(r"analytics_storage", v.name):
            for r in rows:
                if r.get("value") == "granted":
                    analytics_tokens |= set(re.findall(r"[A-Za-z][\w:.-]{3,}", re.sub(r"[.*()]", " ", r.get("key", ""))))
    for v, keys in ad_maps:
        hits = sorted({tok for k in keys for tok in analytics_tokens if _safe_search(k, tok)})
        if hits:
            emit("C17", f"{v.name!r} grants on analytics token(s) {hits[:3]}", [v.key])

    # identity and personal data
    for t in tags:
        if t.paused:
            continue
        if t.type == "googtag":
            cfg = {r.get("parameter"): r.get("parameterValue", "") for r in table_rows(t.raw, "configSettingsTable")}
            uid = str(cfg.get("user_id", ""))
            if uid and (PII_VAR_RE.search(uid) or EMAIL_RE.search(uid)):
                emit("G08", f"user_id from {uid if uid.startswith('{{') else mask(uid)}", [t.key])
            for name, value in cfg.items():
                if name and re.search(r"email|phone", str(name), re.I) and value and not HASH_HINT_RE.search(str(value)):
                    emit("P02", f"Config parameter {name!r} from {value if str(value).startswith('{{') else mask(value)}",
                         [t.key])
            for r in table_rows(t.raw, "userProperties"):
                if PII_NAME_RE.search(str(r.get("name"))) or PII_VAR_RE.search(str(r.get("value"))):
                    emit("P02", f"User property {r.get('name')!r} from {r.get('value')!r}", [t.key])
        if t.type == "gaawe":
            rows = table_rows(t.raw, "eventSettingsTable") + table_rows(t.raw, "eventParameters")
            for r in rows:
                name = str(r.get("parameter") or r.get("name") or "")
                value = str(r.get("parameterValue") or r.get("value") or "")
                if HASH_HINT_RE.search(name + value) and re.search(r"phone|mail|tel", name + value, re.I):
                    emit("P07", f"Hashed personal data sent as parameter {name!r}", [t.key])
                elif PII_NAME_RE.search(name) or PII_VAR_RE.search(value):
                    emit("P02", f"Parameter {name!r} from {value if value.startswith('{{') else mask(value)} "
                         "may carry personal data", [t.key])
                if value == "{{Click URL}}" and name in {"link_url", "click_url", "url"} and any(
                        re.search(r"mailto|tel:", json.dumps(conditions(model.trigger(str(x)).raw)))
                        for x in t.raw.get("firingTriggerId") or [] if model.trigger(str(x))):
                    emit("P04", "mailto:/tel: target sent as a GA4 parameter", [t.key])
            for r in table_rows(t.raw, "userProperties"):
                if PII_NAME_RE.search(str(r.get("name"))) or PII_VAR_RE.search(str(r.get("value"))):
                    emit("P02", f"User property {r.get('name')!r} from {r.get('value')!r}", [t.key])
        if t.type in {"flc", "fls"}:
            for r in table_rows(t.raw, "customVariable"):
                if PII_VAR_RE.search(str(r.get("value"))) and not HASH_HINT_RE.search(str(r.get("value"))):
                    emit("P02", f"Floodlight {r.get('key')} from {r.get('value')!r}", [t.key], severity="Medium")
        if t.type == "awud":
            fires = [model.trigger(str(x)) for x in t.raw.get("firingTriggerId") or []]
            if any(f and f.type == "FORM_SUBMISSION" and not conditions(f.raw) for f in fires) and \
                    not has_consent_control(consent_controls(model, t)):
                emit("A08", "User-provided data event on every form submission without consent gate", [t.key])
        if t.type == "html":
            html = pval(t.raw, "html")
            refs = " ".join(REF_RE.findall(html))
            if re.search(r"document\.cookie\s*=", html) and (PII_VAR_RE.search(refs) or
                                                             re.search(r"validEmail|hem_|lead", html)):
                emit("P05", "Cookie written from personal data (or its hash)", [t.key])
            if re.search(r"(localStorage|sessionStorage)\.setItem", html):
                written = " ".join(re.findall(r"setItem\(([^;]+)\)", html))
                if PII_VAR_RE.search(written) or re.search(
                        r"querySelector[^;]*(email|phone|telephone|nom|prenom)", written, re.I):
                    emit("P05", "Web storage written from personal data", [t.key])
            if re.search(r"dataLayer\.push\(\s*\{[^}]*(email|phone|postal|lead)\w*['\"]?\s*:\s*"
                         r"(document\.querySelector|value\b)", html, re.I | re.S):
                emit("P06", "Form field values pushed to the dataLayer", [t.key])
            urls = re.findall(r"(?:https?:)?//[^\s'\"<>]+", html)
            in_url = [u for u in urls if PII_VAR_RE.search(" ".join(REF_RE.findall(u)))]
            pushed = [b for _, b in re.findall(r"push\(\s*\[\s*['\"](\w+)['\"]\s*,\s*['\"]?\{\{([^}]+)\}\}", html)
                      if PII_VAR_RE.search(b) and not HASH_HINT_RE.search(b)]
            if in_url or (pushed and re.search(r"\.join\(\s*['\"]&['\"]\s*\)|\?\"\s*\+\s*qs", html)):
                emit("P03", "Personal data placed in a third-party request URL", [t.key],
                     f"{len(in_url) + len(pushed)} occurrence(s)")
    for v in variables:
        if v.type == "awec":
            fields = {p.get("key"): p.get("value") for p in v.raw.get("parameter", []) or []}
            hashed = [f for f, val in fields.items() if f in {"email", "phone_number", "first_name", "last_name",
                                                              "street", "postal_code", "city"} and
                      HASH_HINT_RE.search(str(val))]
            if hashed:
                emit("A07", f"User-data fields {hashed} read variables named as hashed (mode {fields.get('mode', '?')})", [v.key],
                     "Check what the configured method accepts for each field, and the normalisation before hashing.")
            country = fields.get("country")
            if country and not REF_RE.search(country) and not re.fullmatch(r"[A-Z]{2}", country):
                emit("A07", f"Country {country!r} is not ISO 3166-1 alpha-2", [v.key], severity="Low")
            for name in REF_RE.findall(country or ""):
                for target in model.by_name("variable", name):
                    if target.type == "c" and not re.fullmatch(r"[A-Z]{2}", pval(target.raw, "value")):
                        emit("A07", f"Country from {{{{{name}}}}} = {pval(target.raw, 'value')!r} (not ISO alpha-2)",
                             [v.key, target.key], severity="Low")
        if v.type == "jsm":
            code = pval(v.raw, "javascript")
            if re.search(r"querySelector|getElementBy|\.value\b|innerText|textContent", code) and \
                    re.search(r"mail|phone|tel|nom|name|address|adresse", code, re.I):
                emit("X15", "Custom JavaScript reads page/form content that may contain personal data", [v.key])
            if re.search(r"(sessionStorage|localStorage)\.getItem\(\s*['\"][^'\"]*(email|phone|mail|nom|prenom|tel|lead)",
                         code, re.I):
                emit("P05", "Reads personal data back from web storage", [v.key], severity="Medium")

    # literal personal data and secrets anywhere
    for o in tags + trigs + variables:
        blob = json.dumps(o.raw, ensure_ascii=False)
        for value in _string_values(o.raw):
            emails = [e for e in EMAIL_RE.findall(value) if not e.lower().endswith(IMAGE_SUFFIXES)]
            if emails and not value.strip().startswith("{{"):
                emit("P01", f"Literal email-like value ({mask(emails[0])})", [o.key])
                break
        for p in _param_pairs(o.raw):
            name, value = p
            if CRED_NAME_RE.search(name) and value and not REF_RE.search(value) and len(value) >= 12:
                emit("X13", f"Credential-like parameter {name!r} = {mask(value)}", [o.key])
        for m in CRED_ASSIGN_RE.finditer(blob):
            emit("X13", f"Credential-like assignment {m.group(1).strip(chr(39) + chr(34) + '=: ')!r} = {mask(m.group(2))}",
                 [o.key])


def _safe_search(pattern: str, text: str) -> bool:
    try:
        return re.search(pattern, text) is not None
    except re.error:
        return False


def _string_values(node):
    if isinstance(node, dict):
        if isinstance(node.get("value"), str):
            yield node["value"]
        for v in node.values():
            if isinstance(v, (dict, list)):
                yield from _string_values(v)
    elif isinstance(node, list):
        for v in node:
            yield from _string_values(v)


def _param_pairs(node):
    """(name, value) pairs from MAP rows (key/name/parameter + value) and typed parameters."""
    if isinstance(node, dict):
        if node.get("type") == "MAP":
            entries = {m.get("key"): m.get("value", "") for m in node.get("map", []) or [] if isinstance(m, dict)}
            name = entries.get("name") or entries.get("parameter") or entries.get("key")
            value = entries.get("value") or entries.get("parameterValue")
            if isinstance(name, str) and isinstance(value, str):
                yield name, value
        elif isinstance(node.get("key"), str) and isinstance(node.get("value"), str):
            yield node["key"], node["value"]
        for v in node.values():
            if isinstance(v, (dict, list)):
                yield from _param_pairs(v)
    elif isinstance(node, list):
        for v in node:
            yield from _param_pairs(v)
