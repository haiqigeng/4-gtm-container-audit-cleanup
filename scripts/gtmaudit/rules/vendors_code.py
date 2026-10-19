"""D3 vendors, templates and custom code."""

from __future__ import annotations

import re
from collections import defaultdict

from ..source import ALL_PAGES, CONSENT_INIT, INIT, REF_RE, Model, pval, table_rows, vendors_of

D = "D3"
RULES = {
    "V02": (D, "A06", "Medium", "Template from an archived repository."),
    "V04": (D, "A19", "Medium", "One pixel initialised in several active tags."),
    "V05": (D, "A19", "High", "Several Meta pixels with fbq('track'): every event goes to every initialised pixel."),
    "V07": (D, "A19", "Medium", "Vendor page view sent twice (base code and template or second tag)."),
    "V08": (D, "A19", "High", "Unresolved vendor placeholder in a live tag."),
    "V09": (D, "A19", "Medium", "Tracking request over http://."),
    "V10": (D, "A19", "High", "Advanced matching maps first name and last name to the same source."),
    "X01": (D, "A22", "High", "document.write in Custom HTML."),
    "X02": (D, "A22", "Low", "'Support document.write' enabled but unused."),
    "X04": (D, "A22", "Medium", "Script loaded over http://."),
    "X05": (D, "A22", "Medium", "eval or new Function."),
    "X06": (D, "A22", "Medium", "Dependency on jQuery."),
    "X08": (D, "A22", "High", "Custom HTML with code outside any <script> element: rendered as text, never executed."),
    "X09": (D, "A22", "Low", "setInterval without clearInterval."),
    "X10": (D, "A22", "Medium", "Custom HTML writes cookies."),
    "X11": (D, "A22", "Low", "Custom HTML writes web storage."),
    "X14": (D, "A22", "High", "JavaScript syntax error, or Custom JavaScript variable without return."),
    "X17": (D, "A22", "Low", "console logging left in production code."),
    "X18": (D, "A06", "Medium", "Gallery template modified locally, or template without gallery reference."),
    "X19": (D, "A25", "Medium", "Large inline Custom HTML (> 10 KB) on every page."),
    "X20": (D, "A22", "Low", "Third-party library from a public CDN or bucket without integrity attribute."),
    "X22": (D, "A22", "Medium", "Function defined in Custom HTML but never called."),
    "X23": (D, "A22", "Low", "Code parses Google cookie internals (_ga), whose format can change."),
}
# Rules whose every emission is its own candidate (one group of objects); other rules gather all their
# emissions into one candidate.
CLUSTERS = {"V04", "V05", "V07"}
PLACEHOLDER_RES = [
    (re.compile(r"##[A-Za-z _-]{2,40}##"), "##...##"),
    (re.compile(r"<\?php"), "<?php ... ?>"),
    (re.compile(r"\$\{[A-Z_]{2,40}\}"), "${MACRO}"),
    (re.compile(r"(?<![{\w])\{(?:[A-Z_]{3,40}|required|sale_amount|order_id|amount)\}(?!\})"), "{TOKEN}"),
    (re.compile(r"['\"]\[(?:[a-z][a-z0-9_-]{2,40}|[A-Z_]{3,40})\]['\"]"), "\"[token]\""),
    (re.compile(r"['\"]<[A-Z_]{3,40}>['\"]"), "\"<TOKEN>\""),
    (re.compile(r"['\"](?:COOKIE_CONSENT|CONSENTSTRING|CONSENT_STRING|EMAIL|VOUCHER_CODE|ORDER_ID|ORDER_VALUE)['\"]"),
     "\"UPPERCASE_TOKEN\""),
    (re.compile(r"insert_[a-z_]{4,}"), "insert_..."),
]

try:  # optional parser: syntax check only, nothing is executed
    import esprima  # type: ignore
except Exception:  # pragma: no cover
    esprima = None


def js_syntax_error(code: str) -> str | None:
    if esprima is None or not code.strip():
        return None
    try:
        esprima.parseScript(REF_RE.sub("__gtmvar__", code), {"tolerant": False})
        return None
    except Exception as exc:  # noqa: BLE001
        return str(exc)[:120]


def script_blocks(html: str) -> list[tuple[str, str]]:
    return [(m.group(1), m.group(2)) for m in re.finditer(r"<script\b([^>]*)>(.*?)</script\s*>", html, re.S | re.I)]


def run(model: Model, emit, fact) -> None:
    tags, variables = model.layer("tag"), model.layer("variable")
    fact("js_syntax_check", "available" if esprima else "unavailable (install esprima to enable)")
    inventory = defaultdict(list)
    for t in tags:
        for vendor in vendors_of(model, t):
            inventory[vendor].append(t.key)
    fact("vendor_inventory", {k: len(v) for k, v in sorted(inventory.items())})

    for tmpl in model.layer("template"):
        gallery = tmpl.raw.get("galleryReference") or {}
        users = [k for k, _ in model.consumers(tmpl.key)]
        if "facebookarchive" in str(gallery.get("owner")) and users:
            emit("V02", f"Template {tmpl.name!r} comes from an archived repository", [tmpl.key] + users)
        if gallery.get("isModified"):
            emit("X18", f"Gallery template {tmpl.name!r} modified locally (no gallery updates)", [tmpl.key] + users)
        if not gallery:
            emit("X18", f"Custom template {tmpl.name!r} has no gallery reference", [tmpl.key] + users, severity="Low")

    meta_ids, meta_track, meta_pageview = defaultdict(list), [], []
    meta_template_pv = [t.key for t in tags if not t.paused and t.type.startswith("cvt_") and pval(t.raw, "pixelId")
                        and pval(t.raw, "standardEventName") == "PageView"]
    every_page = {ALL_PAGES, INIT, CONSENT_INIT}
    for t in tags:
        if t.type == "img" and not t.paused:
            url = pval(t.raw, "url")
            if url.startswith("http://"):
                emit("V09", "Custom Image tag over http://", [t.key])
            for rx, label in PLACEHOLDER_RES:
                if rx.search(url):
                    emit("V08", f"Unresolved placeholder {label} in image URL", [t.key])
                    break
        am = {r.get("name"): r.get("value") for r in table_rows(t.raw, "advancedMatchingList")}
        if am.get("fn") and am.get("fn") == am.get("ln"):
            emit("V10", f"fn and ln both mapped to {am.get('fn')}", [t.key])
        if t.type != "html":
            continue
        html = pval(t.raw, "html")
        if not t.paused:
            for m in re.finditer(r"fbq\s*\(\s*['\"]init['\"]\s*,\s*['\"](\d+)", html):
                meta_ids[m.group(1)].append(t.key)
            if re.search(r"fbq\s*\(\s*['\"]track['\"]", html):
                meta_track.append(t.key)
            if re.search(r"fbq\s*\(\s*['\"]track['\"]\s*,\s*['\"]PageView", html):
                meta_pageview.append(t.key)
        blocks = script_blocks(html)
        if "document.write" in html:
            emit("X01", "Custom HTML uses document.write", [t.key])
        if pval(t.raw, "supportDocumentWrite") == "true" and "document.write" not in html:
            emit("X02", "Support document.write enabled but unused", [t.key])
        for attrs, code in blocks:
            if re.search(r"src\s*=\s*['\"]http://", attrs, re.I):
                emit("X04", "Script loaded over http://", [t.key])
            if code.strip() and not re.search(r"type\s*=\s*['\"](?!text/javascript|module)", attrs, re.I):
                error = js_syntax_error(code)
                if error:
                    emit("X14", f"JavaScript syntax error: {error}", [t.key])
            m = re.search(r"src\s*=\s*['\"]([^'\"]+)", attrs)
            if m and re.search(r"cdnjs|jsdelivr|unpkg|s3[.-][\w-]*\.amazonaws\.com", m.group(1)) and \
                    "integrity" not in attrs:
                emit("X20", f"Library from public CDN/bucket without integrity: {m.group(1)[:60]}", [t.key])
        code_all = " ".join(c for _, c in blocks)
        outside = re.sub(r"<script\b.*?</script\s*>|<noscript\b.*?</noscript\s*>|<!--.*?-->|<img[^>]*>|"
                         r"<iframe\b.*?</iframe>|<style\b.*?</style>|<div[^>]*>|</div>|<a\b.*?</a>", "", html,
                         flags=re.S | re.I)
        if re.search(r"\w\s*\(\s*['\"]", outside) and not t.paused:
            emit("X08", "Code outside <script> elements (rendered as text, never executed)", [t.key])
        if re.search(r"\beval\s*\(|new\s+Function\s*\(", html):
            emit("X05", "eval/new Function in Custom HTML", [t.key])
        if re.search(r"(?<![\w.])(jQuery|\$)\s*(\(|\.)", code_all):
            emit("X06", "Custom HTML depends on jQuery ($/jQuery)", [t.key])
        if re.search(r"document\.cookie\s*=", html):
            emit("X10", "Custom HTML writes cookies", [t.key])
        if re.search(r"(localStorage|sessionStorage)\.setItem", html):
            emit("X11", "Custom HTML writes web storage", [t.key])
        if re.search(r"setInterval\s*\(", html) and not re.search(r"clearInterval", html):
            emit("X09", "setInterval without clearInterval", [t.key])
        if re.search(r"console\.(log|debug|info)\s*\(", html):
            emit("X17", "console logging", [t.key])
        if len(html) > 10000 and not t.paused and set(map(str, t.raw.get("firingTriggerId") or [])) & every_page:
            emit("X19", f"{len(html) // 1024} KB inline Custom HTML on every page", [t.key])
        if len(code_all) < 5000:
            for fn in set(re.findall(r"function\s+([A-Za-z_]\w*)\s*\(", code_all)):
                if len(re.findall(rf"\b{re.escape(fn)}\b", code_all)) == 1:
                    emit("X22", f"Function {fn}() is defined but never called", [t.key])
        if re.search(r"\{\{[^}]*_ga[^}]*\}\}\s*\.split", html):
            emit("X23", "Parses Google cookie internals", [t.key])
        if re.search(r"['\"]http://", html) and re.search(r"collector|track|pixel|report|stats", html, re.I):
            emit("V09", "Tracking request over http:// (protocol fallback or hard-coded)", [t.key], severity="Low")
        clean = re.sub(r"/\*.*?\*/|(?<![:'\"])//[^\n]*|<!--.*?-->", "", html, flags=re.S)
        for rx, label in PLACEHOLDER_RES:
            if rx.search(clean) and not t.paused:
                emit("V08", f"Unresolved placeholder {label}", [t.key])
                break
    for pixel, users in meta_ids.items():
        if len(users) > 1:
            emit("V04", f"Meta pixel {pixel[:4]}... initialised in {len(users)} active tags", users)
    if len(meta_ids) > 1 and meta_track:
        emit("V05", f"{len(meta_ids)} Meta pixels initialised; {len(meta_track)} tags use fbq('track')", meta_track[:8])
    if meta_pageview and meta_template_pv:
        emit("V07", "Meta PageView sent by Custom HTML base code and by a Meta template tag",
             meta_pageview[:4] + meta_template_pv[:4])
    uet_html = [t.key for t in tags if not t.paused and t.type == "html" and "new UET(" in pval(t.raw, "html")]
    uet_tmpl = [t.key for t in tags if not t.paused and t.type == "baut" and pval(t.raw, "eventType") == "PAGE_LOAD"]
    if uet_html and uet_tmpl:
        emit("V07", "UET base code in Custom HTML and in a UET template page-load tag", uet_html + uet_tmpl[:3])
    for v in variables:
        if v.type != "jsm":
            continue
        code = pval(v.raw, "javascript")
        body = re.sub(r"/\*.*?\*/|//[^\n]*", "", code, flags=re.S)
        if "return" not in body:
            emit("X14", "Custom JavaScript variable has no return statement", [v.key])
        error = js_syntax_error("var __f = " + code.strip().rstrip(";") + ";")
        if error:
            emit("X14", f"Custom JavaScript syntax error: {error}", [v.key])
        if re.search(r"(?<![\w.])(jQuery|\$)\s*(\(|\.)", code):
            emit("X06", "Custom JavaScript depends on jQuery", [v.key])
        if re.search(r"console\.(log|debug|info)\s*\(", code):
            emit("X17", "console logging in Custom JavaScript", [v.key])
        if re.search(r"\{\{[^}]*_ga[^}]*\}\}[\s\S]{0,40}\.(split|match)", code):
            emit("X23", "Parses Google cookie internals", [v.key])
