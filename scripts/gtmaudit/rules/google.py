"""D2 Google measurement: Google tag settings, GA4 events, ecommerce, Google Ads and Floodlight."""

from __future__ import annotations

import json
import re
from collections import defaultdict

from ..source import ALL_PAGES, PAGE_LOAD_EVENTS, REF_RE, Model, pval, table_rows, trigger_events

D = "D2"
RULES = {
    "G02": (D, "A16", "Medium", "GA4 event sends to a destination with no active Google tag."),
    "G03": (D, "A17", "High", "GA4 event name breaks GA4 naming rules or is reserved."),
    "G04": (D, "A17", "Medium", "GA4 parameter name invalid or reserved, or too many parameters."),
    "G05": (D, "A17", "High", "Reserved user property name set as a user property."),
    "G06": (D, "A17", "Medium", "debug_mode present in production; remove the field (false still sends it)."),
    "G07": (D, "A16", "High", "Google tag with send_page_view also fires on non-page-load events."),
    "G09": (D, "A17", "Low", "Universal Analytics style parameters in GA4 events."),
    "G10": (D, "A18", "High", "Ecommerce event missing required fields."),
    "G11": (D, "A18", "Medium", "Legacy UA enhanced-ecommerce dataLayer paths still feed tags."),
    "G12": (D, "A16", "Medium", "Universal Analytics leftovers (sunset product)."),
    "G13": (D, "A17", "Medium", "GA4 event sends value without currency."),
    "G14": (D, "A16", "High", "Placeholder or fake measurement ID used as a destination."),
    "G15": (D, "A15", "Low", "event_id set at Google tag level: evaluated once and inherited by events."),
    "G16": (D, "A15", "Medium", "Repeated identical parameter rows across GA4 event tags (shared Event Settings candidate)."),
    "G17": (D, "A17", "Low", "User-ID sent as an event parameter or user property instead of the configuration field."),
    "D06": (D, "A16", "High", "Several active Google tags configure one destination."),
    "D07": (D, "A16", "High", "Active GA4 tags send the same event to the same destination on the same triggers."),
    "D08": (D, "A19", "High", "The same ad conversion is sent by several active tags."),
    "A01": (D, "A19", "High", "Ads/Floodlight conversions without an active Conversion Linker on all pages."),
    "A02": (D, "A19", "Low", "Ads conversion without value, with a constant value, or without currency."),
    "A03": (D, "A19", "High", "Google Ads call-conversion tag fired on a click instead of page load."),
    "A05": (D, "A19", "Medium", "Conversion or transaction ID generated randomly: no deduplication on reload."),
}
# Rules whose every emission is its own candidate (one group of objects); other rules gather all their
# emissions into one candidate.
CLUSTERS = {"A01", "D06", "D07", "D08", "G16"}
GA4_NAME_RE = re.compile(r"^[^\W\d_]\w{0,39}$")
GA4_RESERVED_EVENTS = {
    "ad_activeview", "ad_click", "ad_exposure", "ad_query", "ad_reward", "adunit_exposure", "app_background",
    "app_clear_data", "app_exception", "app_remove", "app_store_refund", "app_store_subscription_cancel",
    "app_store_subscription_convert", "app_store_subscription_renew", "app_update", "app_upgrade",
    "dynamic_link_app_open", "dynamic_link_app_update", "dynamic_link_first_open", "error", "first_open",
    "first_visit", "in_app_purchase", "notification_dismiss", "notification_foreground", "notification_open",
    "notification_receive", "os_update", "session_start", "session_start_with_rollout", "user_engagement",
}
GA4_RESERVED_USER_PROPS = {"first_open_time", "first_visit_time", "last_deep_link_referrer", "user_id",
                           "first_open_after_install"}
RESERVED_PREFIXES = ("google_", "ga_", "firebase_", "_")
ECOM_REQUIRED = {"purchase": {"transaction_id", "value", "currency"}, "refund": {"transaction_id"}}
UA_ECOM_RE = re.compile(r"ecommerce\.(purchase|checkout|add|remove|detail|impressions|click|promoView|promoClick|"
                        r"currencyCode|actionField)|actionField", re.I)
UA_PARAM_NAMES = {"event_category", "event_action", "event_label", "eventcategory", "eventaction", "eventlabel",
                  "non_interaction", "noninteraction"}


def _rows(tag) -> list[tuple[str, str]]:
    rows = table_rows(tag.raw, "eventSettingsTable") + table_rows(tag.raw, "eventParameters")
    return [(str(r.get("parameter") or r.get("name") or ""), str(r.get("parameterValue") or r.get("value") or ""))
            for r in rows]


def run(model: Model, emit, fact) -> None:
    tags, variables = model.layer("tag"), model.layer("variable")
    active = [t for t in tags if not t.paused]
    google_tag_ids = {pval(t.raw, "tagId") for t in active if t.type == "googtag"}
    destinations = defaultdict(list)
    for t in active:
        if t.type == "googtag":
            destinations[pval(t.raw, "tagId")].append(t.key)
    fact("google_destinations", {k: v for k, v in destinations.items()})

    for t in active:
        if t.type == "googtag":
            cfg = {r.get("parameter"): r.get("parameterValue", "") for r in table_rows(t.raw, "configSettingsTable")}
            if "debug_mode" in cfg:
                emit("G06", f"Google tag sets debug_mode={cfg['debug_mode']!r}", [t.key],
                     severity="Medium" if str(cfg["debug_mode"]).lower() == "true" else "Low")
            for r in table_rows(t.raw, "userProperties"):
                if r.get("name") in GA4_RESERVED_USER_PROPS:
                    emit("G05", f"Reserved user property {r.get('name')!r} set as user property", [t.key])
            if "event_id" in cfg:
                emit("G15", "event_id configured on the Google tag", [t.key])
            if str(cfg.get("send_page_view", "true")).lower() == "true":
                late = [model.label(f"trigger:{x}") for x in t.raw.get("firingTriggerId") or []
                        if not trigger_events(model, x) & (PAGE_LOAD_EVENTS | {"*", "gtm.historyChange"})]
                if late and len(t.raw.get("firingTriggerId") or []) > 1:
                    emit("G07", f"send_page_view Google tag also fires on {late[:3]}", [t.key])
            if re.fullmatch(r"G-(X+|\d{1,6})", pval(t.raw, "tagId")):
                emit("G14", f"Google tag with placeholder measurement ID {pval(t.raw, 'tagId')}", [t.key])
        if t.type == "gaawe":
            event = pval(t.raw, "eventName")
            if event and not REF_RE.search(event):
                if not GA4_NAME_RE.match(event):
                    emit("G03", f"GA4 event name {event!r} breaks naming rules", [t.key])
                elif event in GA4_RESERVED_EVENTS or event.startswith(RESERVED_PREFIXES):
                    emit("G03", f"GA4 event name {event!r} is reserved", [t.key])
            rows = _rows(t)
            names = [n for n, _ in rows]
            if len(names) > 25:
                emit("G04", f"{len(names)} event parameters (> 25)", [t.key])
            for name, value in rows:
                if name and not REF_RE.search(name) and not GA4_NAME_RE.match(name):
                    emit("G04", f"Invalid GA4 parameter name {name!r}", [t.key])
                if name.lower() in UA_PARAM_NAMES:
                    emit("G09", f"UA-style parameter {name!r}", [t.key])
                if name == "debug_mode":
                    emit("G06", f"GA4 event sets debug_mode={value!r}", [t.key])
                if name == "user_id":
                    emit("G17", "user_id sent as an event parameter", [t.key])
            for r in table_rows(t.raw, "userProperties"):
                if r.get("name") == "user_id":
                    emit("G17", "user_id sent as a user property", [t.key])
            ecommerce = pval(t.raw, "sendEcommerceData") == "true"
            if "value" in names and "currency" not in names and not ecommerce:
                emit("G13", f"Event {event!r} sends value without currency", [t.key])
            if event in ECOM_REQUIRED and not ecommerce:
                missing = sorted(ECOM_REQUIRED[event] - set(names))
                if missing:
                    emit("G10", f"{event} without {missing}", [t.key])
            dest = pval(t.raw, "measurementIdOverride") or pval(t.raw, "measurementId")
            if dest and re.fullmatch(r"G-(X+|\d{1,6})", dest):
                emit("G14", f"Event routed to placeholder measurement ID {dest}", [t.key])
            elif dest and not REF_RE.search(dest) and google_tag_ids and dest not in google_tag_ids:
                emit("G02", f"Event sends to {dest}, which has no active Google tag", [t.key])
        if t.type == "awct":
            value = pval(t.raw, "conversionValue")
            if not value:
                emit("A02", "Google Ads conversion without value", [t.key])
            elif value.strip() in {"0", "1"}:
                emit("A02", f"Google Ads conversion with constant value {value}", [t.key])
            if value and not pval(t.raw, "currencyCode"):
                emit("A02", "Google Ads conversion value without currency", [t.key])
            for name in REF_RE.findall(pval(t.raw, "orderId")):
                for v in model.by_name("variable", name):
                    if v.type == "r" or "Math.random" in pval(v.raw, "javascript"):
                        emit("A05", f"Order ID from random variable {{{{{name}}}}}", [t.key, v.key])
        if t.type == "awcc":
            fires = [model.trigger(str(x)).type for x in t.raw.get("firingTriggerId") or [] if model.trigger(str(x))]
            if any(f in {"LINK_CLICK", "CLICK", "CUSTOM_EVENT", "FORM_SUBMISSION"} for f in fires):
                emit("A03", f"Call-conversion tag fires on {fires}", [t.key])
        if t.type == "html" or t.type.startswith("cvt_") or t.type == "crto":
            blob = json.dumps(t.raw.get("parameter"), ensure_ascii=False)
            for m in re.finditer(r"(?:transaction_?id|conversionId|orderRef)\W+value\W+\{\{([^}]+)\}\}", blob, re.I):
                for v in model.by_name("variable", m.group(1)):
                    if v.type == "r" or "Math.random" in pval(v.raw, "javascript"):
                        emit("A05", f"Transaction ID from random variable {{{{{m.group(1)}}}}}", [t.key, v.key])
            if "Math.random" in pval(t.raw, "html") and re.search(r"trackTransaction|transaction", pval(t.raw, "html")):
                emit("A05", "Transaction ID generated with Math.random in Custom HTML", [t.key])

    # destination ownership and duplicates
    for gid, keys in destinations.items():
        if len(keys) > 1:
            emit("D06", f"{len(keys)} active Google tags for destination {gid}", keys)
    events = defaultdict(list)
    for t in active:
        if t.type == "gaawe":
            events[(pval(t.raw, "eventName"), pval(t.raw, "measurementIdOverride") or pval(t.raw, "measurementId"),
                    json.dumps(sorted(t.raw.get("firingTriggerId") or [])))].append(t.key)
    for (event, dest, _), keys in events.items():
        if len(keys) > 1:
            emit("D07", f"{len(keys)} active GA4 tags send {event!r} to {dest} on the same triggers", keys)
    conversions = defaultdict(list)
    for t in active:
        if t.type == "awct" and not REF_RE.search(pval(t.raw, "conversionLabel")):
            conversions[(pval(t.raw, "conversionId"), pval(t.raw, "conversionLabel"))].append(t)
    for (account, label), same in conversions.items():
        if len(same) > 1:
            sets = [set().union(*([trigger_events(model, x) for x in t.raw.get("firingTriggerId") or []] or [set()]))
                    for t in same]
            overlap = any(a & b or "*" in a or "*" in b for i, a in enumerate(sets) for b in sets[i + 1:])
            emit("D08", f"Conversion {account}/{label[:6]}... sent by {len(same)} active tags"
                 + (" on overlapping events" if overlap else ""), [t.key for t in same],
                 severity="High" if overlap else "Medium")
    common = defaultdict(set)
    gaawe = [t for t in active if t.type == "gaawe"]
    for t in gaawe:
        for row in _rows(t):
            common[row].add(t.key)
    shared = {row: keys for row, keys in common.items() if len(keys) >= 3 and row[0]}
    if shared:
        users = sorted(set().union(*shared.values()))
        emit("G16", f"{len(shared)} parameter rows repeated on 3+ GA4 event tags",
             users[:12], "Rows: " + ", ".join(f"{n}={v}" for n, v in sorted(shared)[:8]))

    # conversion linker
    linkers = [t for t in active if t.type == "gclidw"]
    conv = [t.key for t in active if t.type in {"awct", "flc", "fls"}]
    if conv and not linkers:
        emit("A01", "Ads/Floodlight conversions without an active Conversion Linker", conv[:6])
    for t in linkers:
        fires = t.raw.get("firingTriggerId") or []
        if ALL_PAGES not in fires and not any(model.trigger(str(x)) and model.trigger(str(x)).type in
                                              {"PAGEVIEW", "INIT", "CONSENT_INIT"} for x in fires):
            emit("A01", "Conversion Linker does not fire on all pages", [t.key], severity="Medium")

    # legacy
    for v in variables:
        if v.type == "v" and UA_ECOM_RE.search(pval(v.raw, "name") or ""):
            emit("G11", f"Legacy UA ecommerce path {pval(v.raw, 'name')!r}",
                 [v.key] + [k for k, _ in model.consumers(v.key)])
        if v.type == "gas":
            emit("G12", "Universal Analytics settings variable", [v.key])
        if v.type == "c" and re.fullmatch(r"UA-\d+-\d+", pval(v.raw, "value")):
            emit("G12", "Universal Analytics tracking ID constant", [v.key])
    for t in tags:
        if t.type == "ua":
            emit("G12", "Universal Analytics tag", [t.key])
