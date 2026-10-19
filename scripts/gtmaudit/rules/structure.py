"""D4 structure: references, lifecycle, triggers, firing options, variables, naming facts."""

from __future__ import annotations

import json
import re
from collections import Counter, defaultdict

from ..source import (
    ALL_PAGES,
    CONSENT_INIT,
    INIT,
    REF_RE,
    Model,
    conditions,
    group_members,
    pval,
    trigger_events,
)

D = "D4"
RULES = {
    "R01": (D, "A03", "High", "A {{variable}} reference resolves to nothing and evaluates as undefined."),
    "R02": (D, "A03", "High", "A tag or trigger group references a trigger that no longer exists."),
    "R03": (D, "A03", "High", "Tag sequencing references a missing or paused tag."),
    "R04": (D, "A03", "Medium", "Object references a missing folder or custom template."),
    "H01": (D, "A04", "Low", "Paused tag kept in the container."),
    "H02": (D, "A04", "Medium", "Tag with no firing trigger that is not a setup/teardown tag."),
    "H03": (D, "A04", "Low", "Trigger not used by any tag, trigger group or zone."),
    "H04": (D, "A04", "Low", "Variable not referenced anywhere."),
    "H05": (D, "A04", "Low", "Object only reachable from paused tags."),
    "H08": (D, "A02", "Medium", "Several objects of one layer share a name."),
    "H09": (D, "A04", "Low", "Name suggests a test, copy, legacy or temporary object."),
    "H13": (D, "A14", "Low", "Lookup or regex table without default value."),
    "H14": (D, "A04", "Low", "Custom template not used by any tag or variable."),
    "H15": (D, "A04", "Medium", "Active production tag depends on an object named as a test."),
    "T01": (D, "A07", "High", "Invalid regular expression."),
    "T02": (D, "A07", "High", "Regex syntax used with a literal operator."),
    "T03": (D, "A07", "High", "Catch-all condition on a firing trigger."),
    "T04": (D, "A07", "Medium", "All-elements click trigger without filter."),
    "T05": (D, "A07", "Low", "Link click waits for tags for more than 2 s."),
    "T06": (D, "A07", "Low", "Timer trigger."),
    "T07": (D, "A07", "Low", "Trigger group with a single member (fires once per page)."),
    "T08": (D, "A07", "Medium", "Blocking trigger never evaluates on the tag's firing events, so it never blocks."),
    "T09": (D, "A07", "Medium", "Unescaped '?' in a URL regex."),
    "T10": (D, "A07", "Medium", "Very short 'contains' URL condition."),
    "F01": (D, "A08", "Low", "Explicit tag priority; keep only for a co-eligible start-order need."),
    "F04": (D, "A08", "Medium", "Once-per-page tag on a repeatable event: later occurrences on the page are dropped."),
    "F06": (D, "A08", "Medium", "Unlimited firing option."),
    "F07": (D, "A08", "Medium", "Repeatable event routed through a trigger group (fires once per page)."),
    "F08": (D, "A08", "Medium", "Setup tag that also emits data on its own triggers."),
    "X24": (D, "A14", "High", "Data Layer Variable path uses bracket notation, which GTM does not resolve."),
    "X25": (D, "A14", "Medium", "Variable name and data path disagree."),
    "N01": (D, "A24", "Medium", "Tag label names a different event than the one it sends."),
}
# Rules whose every emission is its own candidate (one group of objects); other rules gather all their
# emissions into one candidate.
CLUSTERS = {"H08"}

REPEATABLE_TYPES = {"CLICK", "LINK_CLICK", "FORM_SUBMISSION", "SCROLL_DEPTH", "ELEMENT_VISIBILITY", "YOU_TUBE_VIDEO",
                    "HISTORY_CHANGE", "CUSTOM_EVENT"}
REPEATABLE_EVENT_RE = re.compile(r"add.?to.?cart|addtocart|cart|remove|impression|click|select_item|view_item|"
                                 r"checkout|form|scroll|video|step", re.I)
JUNK_NAME_RE = re.compile(r"\b(test|tests|testing|old|copy|copie|backup|tmp|temp|draft|ancien|obsolete|deprecated|"
                          r"zold\w*|fake|do not use|ne pas|to delete|à supprimer)\b", re.I)
GA4_EVENT_TOKEN_RE = re.compile(r"\b(page_view|view_item_list|view_item|select_item|add_to_cart|remove_from_cart|"
                                r"view_cart|begin_checkout|add_shipping_info|add_payment_info|purchase|refund|"
                                r"generate_lead|sign_up|login|search|select_promotion|view_promotion)\b")


def run(model: Model, emit, fact) -> None:
    tags, trigs, variables = model.layer("tag"), model.layer("trigger"), model.layer("variable")
    sequenced = {dst for _, dst, kind in model.edges if kind in ("setupTag", "teardownTag")}

    # references
    for src, name, kind in model.unresolved:
        if kind == "variable":
            emit("R01", f"Reference to undefined variable {{{{{name}}}}}", [src])
        elif kind == "trigger":
            emit("R02", f"Reference to missing trigger {name}", [src])
        elif kind == "tag":
            emit("R03", f"Sequencing references missing tag {name!r}", [src])
        else:
            emit("R04", f"Reference to missing {kind} {name}", [src])
    for _, dst, kind in model.edges:
        if kind in ("setupTag", "teardownTag") and model.objects[dst].paused:
            users = [s for s, d, k in model.edges if d == dst and k == kind]
            emit("R03", f"Sequencing depends on paused tag {model.objects[dst].name!r}", users + [dst],
                 severity="Medium")
    for layer, objs in (("tag", tags), ("trigger", trigs), ("variable", variables)):
        for name, count in Counter(o.name for o in objs).items():
            if count > 1:
                emit("H08", f"{count} {layer}s share the name {name!r}", [o.key for o in objs if o.name == name])

    # lifecycle
    for t in tags:
        if t.paused:
            emit("H01", "Paused tag", [t.key])
        if not t.raw.get("firingTriggerId") and t.key not in sequenced:
            emit("H02", "Tag has no firing trigger and is not a setup/teardown tag", [t.key])
    for o in trigs + variables:
        consumers = [c for c, _ in model.consumers(o.key) if c != o.key]
        if not consumers:
            if o.layer == "trigger":
                emit("H03", "Trigger not used by any tag, group or zone", [o.key])
            else:
                emit("H04", "Variable not referenced anywhere", [o.key])
        elif o.key not in model.reachable:
            emit("H05", "Only reachable from paused or unused objects", [o.key] + consumers[:4])
    for o in tags + trigs + variables:
        if JUNK_NAME_RE.search(o.name):
            emit("H09", "Name suggests a test/legacy/copy object", [o.key])
    test_rx = re.compile(r"(?<!A/B )(?<!AB )\btest\b", re.I)
    test_vars = {v.name for v in variables if test_rx.search(v.name)}
    test_tags = {t.name for t in tags if test_rx.search(t.name)}
    for t in tags:
        if t.paused:
            continue
        used = set(REF_RE.findall(json.dumps(t.raw, ensure_ascii=False))) & test_vars
        seq = {s.get("tagName") for s in (t.raw.get("setupTag") or []) + (t.raw.get("teardownTag") or [])} & test_tags
        if used or seq:
            emit("H15", f"Active tag depends on test object(s) {sorted(used | seq)}", [t.key])
        if t.name in test_tags and set(map(str, t.raw.get("firingTriggerId") or [])) & {ALL_PAGES, CONSENT_INIT, INIT}:
            emit("H15", "Active tag named as a test fires on every page", [t.key], severity="High")
    for tmpl in model.layer("template"):
        if not model.consumers(tmpl.key):
            emit("H14", f"Custom template {tmpl.name!r} is not used", [tmpl.key])
    for v in variables:
        if v.type in {"smm", "remm"} and pval(v.raw, "setDefaultValue") != "true":
            emit("H13", "Lookup/regex table without default value", [v.key])
        if v.type == "v":
            path = pval(v.raw, "name")
            if re.search(r"\[\d+\]", path or ""):
                emit("X24", f"Data Layer path {path!r} uses bracket notation", [v.key])
            if (re.search(r"quantit|qty", v.name, re.I) and re.search(r"price", path or "", re.I)) or \
                    (re.search(r"price|prix", v.name, re.I) and re.search(r"quantit", path or "", re.I)):
                emit("X25", f"Name {v.name!r} vs path {path!r}", [v.key])

    # trigger topology
    users_by_trigger = defaultdict(list)
    for src, dst, kind in model.edges:
        if dst.startswith("trigger:") and kind in ("firing", "blocking", "group_member", "zone_boundary"):
            users_by_trigger[dst].append((src, kind))
    for tr in trigs:
        cs = conditions(tr.raw)
        users = users_by_trigger.get(tr.key, [])
        firing_users = [s for s, k in users if k in ("firing", "group_member")]
        blocking_only = bool(users) and not firing_users
        for c in cs:
            a1 = c["arg1"]
            if c["op"] == "MATCH_REGEX" and a1 and not REF_RE.search(a1):
                try:
                    re.compile(a1)
                except re.error as exc:
                    if not re.search(r"\(\?<|\[\^?\]", a1):  # JS-only syntax is not invalid
                        emit("T01", f"Invalid regex {a1[:60]!r}: {exc}", [tr.key])
                if re.search(r"[A-Za-z]\?[A-Za-z_]+=", a1):
                    emit("T09", f"Regex {a1[:60]!r} contains an unescaped '?' before a query key", [tr.key])
            if c["op"] in ("CONTAINS", "EQUALS", "STARTS_WITH", "ENDS_WITH") and \
                    re.search(r"\\b|\\\.|\.\*|\(\?|^\^|\$$", a1):
                emit("T02", f"{c['op']} compares the regex-like literal {a1[:60]!r}", [tr.key],
                     "The operator is literal; it only matches text that contains these regex characters.")
            if c["op"] == "MATCH_REGEX" and a1 in {".*", ".+", "^.*$", ""} and not c["negate"] and firing_users \
                    and not blocking_only:
                emit("T03", f"Firing trigger condition {c['arg0']} matches anything ({a1!r})",
                     [tr.key] + sorted(firing_users)[:4], severity="High" if c["arg0"] == "{{_event}}" else "Medium")
            if c["op"] == "CONTAINS" and c["arg0"] in {"{{Page URL}}", "{{Page Path}}"} and 0 < len(a1) <= 3:
                emit("T10", f"Very short URL 'contains' condition {a1!r}", [tr.key])
        if tr.type == "CLICK" and not [c for c in cs if c["family"] == "filter"] and firing_users:
            emit("T04", "All Elements click trigger without filters", [tr.key])
        if tr.type == "TIMER":
            limit = (tr.raw.get("limit") or {}).get("value")
            emit("T06", f"Timer trigger interval={(tr.raw.get('interval') or {}).get('value')} limit={limit}",
                 [tr.key], severity="Low" if limit else "Medium")
        if tr.type == "TRIGGER_GROUP" and len(group_members(tr.raw)) == 1:
            emit("T07", "Trigger group with one member", [tr.key])
        if tr.type == "LINK_CLICK" and (tr.raw.get("waitForTags") or {}).get("value") == "true":
            timeout = (tr.raw.get("waitForTagsTimeout") or {}).get("value")
            if timeout and str(timeout).isdigit() and int(timeout) > 2000:
                emit("T05", f"Link click waits for tags up to {timeout} ms", [tr.key])

    # firing options and sequencing
    def repeatable(tid: str) -> bool:
        tr = model.trigger(str(tid))
        if not tr or tr.type not in REPEATABLE_TYPES:
            return False
        if tr.type != "CUSTOM_EVENT":
            return True
        text = " ".join(e for e in trigger_events(model, tid) if e != "*") + " " + json.dumps(
            conditions(tr.raw), ensure_ascii=False)
        return bool(REPEATABLE_EVENT_RE.search(text)) and not re.search(r"purchase|confirmation|transaction", text, re.I)

    data_types = {"gaawe", "awct", "flc", "fls", "sp", "awcc", "awud", "baut"}
    for t in tags:
        if "priority" in t.raw:
            emit("F01", f"Explicit firing priority {(t.raw.get('priority') or {}).get('value')}", [t.key])
        if t.paused:
            continue
        option = t.raw.get("tagFiringOption")
        if option == "ONCE_PER_LOAD":
            rep = [str(x) for x in t.raw.get("firingTriggerId") or [] if repeatable(x)]
            if rep:
                emit("F04", "Once-per-page tag on a repeatable event", [t.key] + [f"trigger:{x}" for x in rep],
                     "Use siblings to find every consumer of the same event with the same cap.")
        if option == "UNLIMITED":
            emit("F06", "Unlimited firing option", [t.key])
        for tid in t.raw.get("firingTriggerId") or []:
            tr = model.trigger(str(tid))
            if tr and tr.type == "TRIGGER_GROUP":
                rep = [m for m in group_members(tr.raw) if repeatable(m)]
                if rep:
                    emit("F07", f"Repeatable event routed through trigger group {tr.name!r}", [t.key, tr.key])
        for s in t.raw.get("setupTag") or []:
            for target in model.by_name("tag", s.get("tagName")):
                if target.type in data_types and target.raw.get("firingTriggerId"):
                    emit("F08", f"Setup tag {target.name!r} ({target.type}) also emits data on its own triggers",
                         [t.key, target.key])
        fire_events = set()
        for tid in t.raw.get("firingTriggerId") or []:
            fire_events |= trigger_events(model, tid)
        if fire_events and "*" not in fire_events:
            for b in t.raw.get("blockingTriggerId") or []:
                be = trigger_events(model, b)
                if "*" not in be and not (be & fire_events):
                    emit("T08", f"Blocking trigger {model.label('trigger:' + str(b))} evaluates on {sorted(be)} "
                         f"but the tag fires on {sorted(fire_events)[:4]}", [t.key, f"trigger:{b}"])
        if t.type == "gaawe":
            sent = pval(t.raw, "eventName")
            named = set(GA4_EVENT_TOKEN_RE.findall(t.name.lower()))
            if sent and not REF_RE.search(sent) and named and sent not in named:
                emit("N01", f"Label names {sorted(named)} but the tag sends {sent!r}", [t.key])

    # summary facts
    fact("unused_builtins", sorted(b for b in model.builtins
                                   if b != "Event" and not any(f"{{{{{b}}}}}" in json.dumps(o.raw, ensure_ascii=False)
                                                               for o in tags + trigs + variables)))
    fact("tags_outside_folders", f"{sum(1 for t in tags if not t.raw.get('parentFolderId'))}/{len(tags)}")
    fact("tags_with_notes", f"{sum(1 for t in tags if t.raw.get('notes'))}/{len(tags)}")
    prefixes = Counter(re.split(r"\s*[-|/:]\s*", t.name)[0].strip() for t in tags if t.name)
    fact("tag_name_prefixes", dict(prefixes.most_common(12)))
