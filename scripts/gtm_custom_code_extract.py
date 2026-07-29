#!/usr/bin/env python3
"""Extract deterministic facts from GTM Custom HTML and Custom JavaScript."""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
import re
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any

from gtm_lib import (
    as_list,
    code_identity_text,
    container_version,
    custom_template_executable_code,
    param_value,
    refs,
    source_descriptor,
    source_integrity_findings,
    stable_hash,
)
from gtm_privacy import sanitize_url

URL_RE = re.compile(r"https?://[^\s\"'<>\\)]+", re.I)
EVENT_LISTENER_RE = re.compile(r"addEventListener\s*\(\s*['\"]([^'\"]+)['\"]", re.I)
REMOVE_EVENT_LISTENER_RE = re.compile(r"\bremoveEventListener\s*\(", re.I)
ONCE_EVENT_LISTENER_RE = re.compile(
    r"addEventListener\s*\([^;]{0,600}\bonce\s*:\s*true\b",
    re.I | re.S,
)
LISTENER_GUARD_RE = re.compile(
    r"\b(?:window\s*\.\s*)?[A-Za-z_$][\w$]*(?:listener|bound|initialized|registered)"
    r"\s*(?:[!=]=|=)|\bif\s*\(\s*!\s*(?:window\s*\.)?[A-Za-z_$][\w$]*",
    re.I,
)
DATA_LAYER_PUSH_RE = re.compile(r"\bdataLayer\s*\.\s*push\s*\(", re.I)
DATA_LAYER_RESET_RE = re.compile(r"\b(?:window\s*\.\s*)?dataLayer\s*\.\s*reset\s*\(", re.I)
DATA_LAYER_REF_RE = re.compile(r"\bdataLayer\b", re.I)
COOKIE_RE = re.compile(r"\bdocument\s*\.\s*cookie\b|(?:^|[^A-Za-z])cookie(?:[^A-Za-z]|$)", re.I)
COOKIE_LITERAL_WRITE_RE = re.compile(
    r"\bdocument\s*\.\s*cookie\s*=\s*(['\"`])(?P<cookie>.*?)(?<!\\)\1",
    re.I | re.S,
)
LOCAL_STORAGE_RE = re.compile(r"\blocalStorage\b", re.I)
SESSION_STORAGE_RE = re.compile(r"\bsessionStorage\b", re.I)
DOM_RE = re.compile(
    r"\bdocument\s*\.\s*(querySelector|getElementById|getElementsBy|createElement|body|head)"
    r"|\bclassList\b|\binnerHTML\b|\bappendChild\b|\binsertBefore\b|\bstyle\s*\.",
    re.I,
)
DOM_SELECTOR_RE = re.compile(
    r"\bdocument\s*\.\s*(?:querySelector|getElementById|getElementsBy)", re.I
)
DOM_MUTATION_RE = re.compile(
    r"\bdocument\s*\.\s*(?:createElement|write)\b|\bclassList\b|\binnerHTML\b|"
    r"\bappendChild\b|\binsertBefore\b|\bstyle\s*\.",
    re.I,
)
NETWORK_RE = re.compile(r"\bfetch\s*\(|\bXMLHttpRequest\b|\bsendBeacon\s*\(", re.I)
UNSAFE_EVAL_RE = re.compile(
    r"\beval\s*\(|\bnew\s+Function\s*\(|\bset(?:Timeout|Interval)\s*\(\s*['\"`]",
    re.I,
)
DOCUMENT_WRITE_RE = re.compile(r"\bdocument\s*\.\s*write\s*\(", re.I)
HTML_WRITE_RE = re.compile(
    r"\binnerHTML\b|\bouterHTML\b|\binsertAdjacentHTML\s*\(",
    re.I,
)
MESSAGE_LISTENER_RE = re.compile(r"addEventListener\s*\(\s*['\"]message['\"]", re.I)
ORIGIN_CHECK_RE = re.compile(r"\b(?:event|e|evt)\s*\.\s*origin\b|\borigin\b", re.I)
HTTP_URL_RE = re.compile(r"http://[^\s\"'<>\\)]+", re.I)
GLOBAL_WRITE_RE = re.compile(r"\bwindow\s*\.\s*[A-Za-z_$][\w$]*\s*=", re.I)
GTM_INTERNAL_OBJECT_RE = re.compile(
    r"\b(?:window\s*\.\s*)?google_tag_manager\b",
    re.I,
)
MANUAL_GTAG_RE = re.compile(r"(?<![\w.])gtag\s*\(", re.I)
DEBUGGER_RE = re.compile(r"\bdebugger\s*;?", re.I)
DYNAMIC_SCRIPT_RE = re.compile(
    r"createElement\s*\(\s*['\"]script['\"]|\.src\s*=",
    re.I,
)
FIXED_PRODUCT_INDEX_RE = re.compile(
    r"\becommerce\.(?:purchase|add|remove|detail|checkout)\.products"
    r"(?:\[\d+\]|\.\d+)(?:[A-Za-z0-9_\.\[\]]*)",
    re.I,
)
RETURN_EXPRESSION_RE = re.compile(r"\breturn\s+([^;\r\n]+)", re.I)
SLOT_SUFFIX_RE = re.compile(r"^(.*?)(?:[\s_.\-\[]+)(\d{1,3})\]?$", re.I)
OPTIMIZE_REMNANT_RE = re.compile(
    r"googleoptimize\.com/optimize\.js|\bgoogle_optimize\b|"
    r"\bdataLayer\s*\.\s*hide\b|async-hide",
    re.I,
)
JAVASCRIPT_TOKEN_RE = re.compile(
    r"(?:^|[;{}\s])(?:var|let|const|function|return|if|for|while)\b|"
    r"\b(?:window|document|dataLayer)\s*\.|\b(?:fbq|gtag|fetch)\s*\(",
    re.I,
)
ASYNC_CMP_CALLBACK_RE = re.compile(
    r"(?:__tcfapi|__cmp|addEventListener|onConsentChanged|"
    r"addVendorStatusListener|addPurposeStatusListener)"
    r"\s*\([^;]{0,1200}(?:function\s*\(|(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>)",
    re.I | re.S,
)
STRONG_SECRET_ASSIGNMENT_RE = re.compile(
    r"\b(?P<name>client[_-]?secret|api[_-]?secret|access[_-]?token|"
    r"refresh[_-]?token|authorization|password|private[_-]?key)\b"
    r"\s*[:=]\s*(['\"`])(?P<value>(?:(?!\2).){8,})\2",
    re.I | re.S,
)
API_KEY_ASSIGNMENT_RE = re.compile(
    r"\b(?:api[_-]?key|subscription[_-]?key)\b\s*[:=]\s*"
    r"(['\"`])(?P<value>(?:(?!\1).){12,})\1",
    re.I | re.S,
)
JWT_RE = re.compile(
    r"(['\"`])eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\1"
)
PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", re.I)
CACHE_BUSTER_RE = re.compile(
    r"(?:[?&](?:cb|cachebuster|cache_buster|gtmcb)=|"
    r"\b(?:cachebuster|cache_buster)\b|\bDate\s*\.\s*now\s*\(\s*\))",
    re.I,
)
BASE64_RE = re.compile(r"\b(?:atob|btoa)\s*\(|\b[A-Za-z0-9+/]{80,}={0,2}\b")
MUTATION_OBSERVER_RE = re.compile(r"\bMutationObserver\s*\(", re.I)
IDENTITY_IGNORED = {"accountId", "containerId", "fingerprint", "path"}


def has_manual_gtag_call(code: str) -> bool:
    without_definition = re.sub(
        r"\bfunction\s+gtag\s*\(",
        "function __gtag_definition__(",
        code,
        flags=re.I,
    )
    return bool(MANUAL_GTAG_RE.search(without_definition))


def comparable_config(obj: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in obj.items() if key not in IDENTITY_IGNORED}


def object_id(obj: dict[str, Any], layer: str) -> str:
    keys = {
        "tag": "tagId",
        "variable": "variableId",
        "customTemplate": "templateId",
    }
    value = obj.get(keys[layer]) or obj.get("name")
    return "" if value is None else str(value)


def object_type(obj: dict[str, Any], layer: str) -> str:
    return str(obj.get("type") or ("customTemplate" if layer == "customTemplate" else ""))


def code_for(layer: str, obj: dict[str, Any]) -> str:
    if layer == "tag":
        return str(param_value(obj, "html") or "")
    if layer == "variable":
        return str(param_value(obj, "javascript") or "")
    return custom_template_executable_code(obj.get("templateData"))


def code_hash(code: str) -> str:
    identity = code_identity_text(code)
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16] if identity.strip() else ""


def reconciliation_key(layer: str, obj: dict[str, Any], code: str) -> str:
    return "|".join(
        [
            layer,
            object_id(obj, layer),
            str(obj.get("name") or ""),
            object_type(obj, layer),
            code_hash(code) or stable_hash(comparable_config(obj)),
        ]
    )


def urls(code: str) -> list[str]:
    return sorted({sanitize_url(match.group(0).rstrip(".,);")) for match in URL_RE.finditer(code)})


def external_scripts(code: str) -> list[str]:
    found = [url for url in urls(code) if ".js" in url.lower()]
    if re.search(r"createElement\s*\(\s*['\"]script['\"]", code, re.I):
        found.append("dynamic script element")
    return sorted(set(found))


def script_loader_count(code: str) -> int:
    """Count configured script elements without double-counting their URL assignments."""
    dynamic = len(re.findall(r"createElement\s*\(\s*['\"]script['\"]", code, re.I))
    static = len(re.findall(r"<script\b[^>]*\bsrc\s*=", code, re.I))
    return dynamic + static


def looks_like_unwrapped_javascript(layer: str, code: str) -> bool:
    if layer != "tag" or not code.strip() or re.search(r"<script\b", code, re.I):
        return False
    return bool(JAVASCRIPT_TOKEN_RE.search(code))


def secret_like_credential_signals(code: str) -> list[str]:
    """Return redacted credential classes; never return literal candidate values."""
    signals: set[str] = set()
    for match in STRONG_SECRET_ASSIGNMENT_RE.finditer(code):
        name = re.sub(r"[^a-z0-9]+", "_", match.group("name").lower()).strip("_")
        value = match.group("value")
        if refs(value):
            continue
        signals.add(f"literal_{name}")
    if API_KEY_ASSIGNMENT_RE.search(code):
        signals.add("literal_api_key_candidate")
    if JWT_RE.search(code):
        signals.add("literal_jwt_candidate")
    if PRIVATE_KEY_RE.search(code):
        signals.add("literal_private_key")
    return sorted(signals)


def storage_details(code: str, storage_name: str) -> list[str]:
    pattern = re.compile(
        rf"{storage_name}\s*\.\s*(getItem|setItem|removeItem)\s*\(\s*['\"]?([^'\"\),]+)?", re.I
    )
    values = []
    for match in pattern.finditer(code):
        action = match.group(1)
        key = match.group(2) or "dynamic key"
        values.append(f"{action}:{key}")
    if not values and storage_name in code:
        values.append("referenced")
    return sorted(set(values))


def returned_value_type(code: str) -> str:
    return_text = " ".join(re.findall(r"\breturn\s+([^;\n]+)", code))
    if not return_text:
        return "side_effect_only_or_unknown"
    if re.fullmatch(r"\s*\{\{[^{}]+\}\}\s*", return_text):
        return "gtm_variable_reference_type_unresolved"
    if re.search(r"['\"`]", return_text):
        return "string_or_template_string"
    if re.search(r"\b(true|false)\b|!!", return_text):
        return "boolean_or_boolean_expression"
    if re.search(r"\b(Number|parseFloat|parseInt)\s*\(|[-+]?\d+(?:\.\d+)?", return_text):
        return "number_or_numeric_expression"
    if re.search(r"^\s*\[", return_text):
        return "array_or_array_expression"
    if re.search(r"^\s*\{", return_text):
        return "object_or_object_expression"
    return "dynamic_expression"


def expression_facts(code: str) -> dict[str, Any]:
    """Extract source-bound formula facts without pretending to execute JavaScript."""
    logical_lines = [line.strip() for line in code.splitlines() if line.strip()]
    expressions = [re.sub(r"\s+", " ", value).strip() for value in RETURN_EXPRESSION_RE.findall(code)]
    expression_rows: list[dict[str, Any]] = []
    fixed_slot_groups: dict[str, dict[str, Any]] = {}
    for expression in expressions:
        references = sorted(refs(expression))
        operators = {
            operator: expression.count(operator)
            for operator in ("+", "-", "*", "/", "%")
            if expression.count(operator)
        }
        for reference in references:
            normalized = re.sub(r"\s+", " ", reference.replace("_", " ").strip()).lower()
            match = SLOT_SUFFIX_RE.match(normalized)
            if not match:
                continue
            base = re.sub(r"\s+", " ", match.group(1)).strip(" ._-")
            if not base:
                continue
            group = fixed_slot_groups.setdefault(
                base,
                {"base": base, "indexes": set(), "references": set()},
            )
            group["indexes"].add(int(match.group(2)))
            group["references"].add(reference)
        expression_rows.append(
            {
                "expression": expression[:600],
                "expression_hash": stable_hash(expression),
                "referenced_gtm_variables": references,
                "arithmetic_operators": operators,
            }
        )

    serialized_groups = [
        {
            "base": group["base"],
            "indexes": sorted(group["indexes"]),
            "references": sorted(group["references"]),
        }
        for group in fixed_slot_groups.values()
        if len(group["indexes"]) >= 2
    ]
    plus_count = sum(
        row.get("arithmetic_operators", {}).get("+", 0) for row in expression_rows
    )
    fixed_slot_aggregation = bool(serialized_groups and plus_count)
    return {
        "logical_line_count": len(logical_lines),
        "return_expressions": expression_rows,
        "fixed_slot_groups": sorted(serialized_groups, key=lambda row: row["base"]),
        "fixed_slot_aggregation": fixed_slot_aggregation,
        "formula_review_required": fixed_slot_aggregation,
    }


def javascript_source(layer: str, code: str) -> str:
    if layer != "tag":
        return code
    blocks = re.findall(r"<script\b[^>]*>(.*?)</script\s*>", code, re.I | re.S)
    return "\n".join(blocks) if blocks else code


def javascript_ast_facts(layer: str, code: str) -> dict[str, Any]:
    """Add optional AST facts; line review and static signals remain separate obligations."""
    source = javascript_source(layer, code)
    substitutions = sorted(refs(source))
    parser_source = re.sub(r"\{\{[^{}]+\}\}", "__gtm_variable_reference__", source)
    normalized = parser_source != source
    if not source.strip():
        return {
            "javascript_parser": "not_applicable",
            "javascript_parser_version": "",
            "parser_input_normalized": False,
            "parser_gtm_substitutions": [],
            "ast_node_counts": {},
            "ast_calls": [],
            "ast_branch_count": 0,
            "ast_return_count": 0,
            "ast_parse_errors": [],
        }
    try:
        import esprima  # type: ignore
    except ImportError:
        return {
            "javascript_parser": "not_installed_static_review_still_required",
            "javascript_parser_version": "",
            "parser_input_normalized": normalized,
            "parser_gtm_substitutions": substitutions,
            "ast_node_counts": {},
            "ast_calls": [],
            "ast_branch_count": 0,
            "ast_return_count": 0,
            "ast_parse_errors": [],
        }

    try:
        parser_version = version("esprima")
    except PackageNotFoundError:
        parser_version = str(getattr(esprima, "__version__", "unknown"))

    try:
        parsed = esprima.parseScript(parser_source, {"tolerant": True}).toDict()
    except Exception as exc:  # Parser failures are evidence, not fatal extraction errors.
        return {
            "javascript_parser": "esprima_parse_failed",
            "javascript_parser_version": parser_version,
            "parser_input_normalized": normalized,
            "parser_gtm_substitutions": substitutions,
            "ast_node_counts": {},
            "ast_calls": [],
            "ast_branch_count": 0,
            "ast_return_count": 0,
            "ast_parse_errors": [str(exc)[:240]],
        }

    counts: collections.Counter[str] = collections.Counter()
    calls: set[str] = set()
    parse_errors = [str(error)[:240] for error in parsed.get("errors", [])]

    def visit(node: Any) -> None:
        if isinstance(node, list):
            for item in node:
                visit(item)
            return
        if not isinstance(node, dict):
            return
        node_type = str(node.get("type") or "")
        if node_type:
            counts[node_type] += 1
        if node_type == "CallExpression":
            callee = node.get("callee") or {}
            if callee.get("type") == "Identifier":
                calls.add(str(callee.get("name") or ""))
            elif callee.get("type") == "MemberExpression":
                prop = callee.get("property") or {}
                calls.add(str(prop.get("name") or prop.get("value") or "member_call"))
        for child in node.values():
            visit(child)

    visit(parsed)
    branch_types = ("IfStatement", "ConditionalExpression", "SwitchCase", "LogicalExpression")
    return {
        "javascript_parser": "esprima",
        "javascript_parser_version": parser_version,
        "parser_input_normalized": normalized,
        "parser_gtm_substitutions": substitutions,
        "ast_node_counts": dict(sorted(counts.items())),
        "ast_calls": sorted(call for call in calls if call)[:80],
        "ast_branch_count": sum(counts[name] for name in branch_types),
        "ast_return_count": counts["ReturnStatement"],
        "ast_parse_errors": parse_errors,
    }


def side_effects(code: str) -> list[str]:
    effects = []
    if DATA_LAYER_PUSH_RE.search(code):
        effects.append("dataLayer push")
    if DATA_LAYER_RESET_RE.search(code):
        effects.append("dataLayer model reset")
    if re.search(r"\.setItem\s*\(", code):
        effects.append("storage write")
    if re.search(r"\bdocument\s*\.\s*cookie\s*=", code, re.I):
        effects.append("cookie write")
    if DOM_SELECTOR_RE.search(code):
        effects.append("DOM read")
    if DOM_MUTATION_RE.search(code):
        effects.append("DOM write")
    if EVENT_LISTENER_RE.search(code):
        effects.append("event listener")
    if external_scripts(code):
        effects.append("external script load")
    if NETWORK_RE.search(code):
        effects.append("network call")
    if GLOBAL_WRITE_RE.search(code):
        effects.append("window/global write")
    if has_manual_gtag_call(code):
        effects.append("manual gtag call")
    return effects


def custom_template_visibility(layer: str, code: str) -> str:
    if layer != "customTemplate":
        return "not_applicable"
    if not code.strip():
        return "opaque"
    return "partial"


def container_evidence_limits(code: str, effects: list[str]) -> list[str]:
    limits: list[str] = []
    if DOM_SELECTOR_RE.search(code):
        limits.append(
            "The container cannot prove that referenced DOM selectors exist on every configured route."
        )
    elif DOM_MUTATION_RE.search(code):
        limits.append(
            "The container cannot prove the external page effect of the configured DOM mutation."
        )
    if EVENT_LISTENER_RE.search(code):
        limits.append(
            "The container cannot prove how often the page invokes or retains exported event listeners."
        )
    if external_scripts(code) or NETWORK_RE.search(code):
        limits.append(
            "The container proves configured endpoints but not external script delivery or vendor acceptance."
        )
    if COOKIE_RE.search(code) or LOCAL_STORAGE_RE.search(code) or SESSION_STORAGE_RE.search(code):
        limits.append(
            "The container cannot prove external CMP state or browser storage availability."
        )
    if not limits and effects:
        limits.append(
            "The exported code has browser side effects whose external outcome is not provable from container configuration."
        )
    if not limits:
        limits.append("No material external behavior limit affects this static code judgment.")
    return limits


def code_health_findings(layer: str, code: str) -> list[str]:
    findings: list[str] = []
    if not code.strip():
        findings.append("No code body was exported for this object.")
    if custom_template_visibility(layer, code) == "opaque":
        findings.append(
            "Custom-template export exposes metadata or permissions but no reviewable "
            "executable behavior; correctness remains unproven from this source."
        )
    if len(code) > 8000:
        findings.append(
            "Very large custom code block; split or replace with a maintained template when possible."
        )
    elif len(code) > 3000:
        findings.append("Large custom code block; simplify so future changes are easier to review.")
    if looks_like_unwrapped_javascript(layer, code):
        findings.append(
            "Custom HTML contains JavaScript without an exported <script> wrapper; "
            "wrap the JavaScript so Tag Manager executes the intended code."
        )
    if layer == "tag" and re.search(r"<script\b", code, re.I):
        findings.append(
            "Custom HTML uses an inline script; keep it only when a native tag or template "
            "cannot do the same job."
        )
    if GLOBAL_WRITE_RE.search(code):
        findings.append("Writes shared window-level state, so other page scripts may depend on it.")
    if EVENT_LISTENER_RE.search(code):
        findings.append(
            "Registers browser event listeners; exported guards and trigger scope should "
            "prevent repeated registration."
        )
        if not (
            REMOVE_EVENT_LISTENER_RE.search(code)
            or ONCE_EVENT_LISTENER_RE.search(code)
            or LISTENER_GUARD_RE.search(code)
        ):
            findings.append(
                "Registers a browser event listener without an exported remove, once-only "
                "option, or registration guard; repeated GTM execution can accumulate handlers."
            )
    if has_manual_gtag_call(code):
        findings.append(
            "Calls gtag() directly inside GTM; compare its destination, event, consent, and "
            "routing with native Google tags before retaining a parallel sender."
        )
    if DEBUGGER_RE.search(code):
        findings.append("Contains a debugger statement that should not remain in production code.")
    if DOM_SELECTOR_RE.search(code):
        findings.append(
            "Reads the page DOM; the container cannot prove selector availability "
            "across page variants."
        )
    if DOM_MUTATION_RE.search(code):
        findings.append(
            "Changes the page DOM; confirm the mutation is required and scoped to the intended route."
        )
    if layer == "variable" and ASYNC_CMP_CALLBACK_RE.search(code):
        findings.append(
            "Custom JavaScript variable starts a callback-based CMP read; a GTM variable "
            "must return synchronously, so the callback result may arrive after evaluation."
        )
    if "literal_api_key_candidate" in secret_like_credential_signals(code):
        findings.append(
            "Contains a literal API-key candidate; evidence is redacted. Confirm that it "
            "is intentionally browser-public and origin-restricted, otherwise remove and rotate it."
        )
    return findings


def code_security_findings(code: str) -> list[str]:
    findings: list[str] = []
    cookie_attribute_findings = []
    for match in COOKIE_LITERAL_WRITE_RE.finditer(code):
        literal = match.group("cookie")
        missing = [
            attribute
            for attribute, pattern in (
                ("Secure", r"(?:^|;)\s*secure(?:\s*;|$)"),
                ("SameSite", r"(?:^|;)\s*samesite\s*="),
            )
            if not re.search(pattern, literal, re.I)
        ]
        if missing:
            cookie_attribute_findings.append(
                "Literal cookie write omits exported "
                + " and ".join(missing)
                + " attributes; verify the approved cookie policy and add the applicable attributes."
            )
    checks = (
        (
            DATA_LAYER_RESET_RE.search(code),
            "Calls dataLayer.reset(), which clears GTM's internal data model and can remove "
            "values needed by later tags.",
        ),
        (
            GTM_INTERNAL_OBJECT_RE.search(code),
            "Accesses the internal google_tag_manager object, an unsupported implementation "
            "surface that can change without notice.",
        ),
        (
            UNSAFE_EVAL_RE.search(code),
            "Runs text as JavaScript, which is risky and hard to debug.",
        ),
        (
            DOCUMENT_WRITE_RE.search(code),
            "Calls document.write(); retain it only with the explicit GTM support setting "
            "and a source-proven requirement, otherwise replace the page write.",
        ),
        (
            HTML_WRITE_RE.search(code),
            "Writes HTML into the page; confirm visitor-provided text cannot be inserted.",
        ),
        (
            MESSAGE_LISTENER_RE.search(code) and not ORIGIN_CHECK_RE.search(code),
            "Listens to messages from other windows without an exported origin check.",
        ),
        (
            HTTP_URL_RE.search(code),
            "Loads or calls an unencrypted http:// URL; use https:// or remove it.",
        ),
        (
            DYNAMIC_SCRIPT_RE.search(code) and ".src" in code,
            "Creates or changes script URLs in code; keep only trusted, stable sources.",
        ),
        (
            COOKIE_RE.search(code)
            or LOCAL_STORAGE_RE.search(code)
            or SESSION_STORAGE_RE.search(code),
            "Uses cookies or browser storage; confirm no sensitive visitor data is stored.",
        ),
    )
    findings.extend(message for matched, message in checks if matched)
    strong_secret_signals = [
        signal
        for signal in secret_like_credential_signals(code)
        if signal != "literal_api_key_candidate"
    ]
    if strong_secret_signals:
        findings.append(
            "Contains a literal secret-like credential candidate "
            f"({', '.join(strong_secret_signals)}); evidence is redacted. Remove it from "
            "the container and rotate the credential if confirmed."
        )
    findings.extend(dict.fromkeys(cookie_attribute_findings))
    return findings


def code_optimization_findings(
    layer: str, code: str, effects: list[str], formulas: dict[str, Any]
) -> list[str]:
    findings: list[str] = []
    if script_loader_count(code) > 1:
        findings.append(
            "Loads more than one script; consolidate duplicate loaders when they initialize "
            "the same vendor."
        )
    if FIXED_PRODUCT_INDEX_RE.search(code):
        findings.append(
            "Uses fixed product positions from an old ecommerce data structure; replace with "
            "item-array handling."
        )
    if formulas.get("fixed_slot_aggregation"):
        groups = ", ".join(
            f"{group['base']} slots {group['indexes']}"
            for group in as_list(formulas.get("fixed_slot_groups"))
        )
        findings.append(
            "Adds fixed numbered value slots instead of resolving a scalable business total"
            + (f" ({groups})." if groups else ".")
        )
    if layer == "variable" and not effects and len(code) < 450 and refs(code):
        findings.append(
            "Looks like a small helper variable; check whether a built-in variable, lookup "
            "table, or regex table can replace it."
        )
    if DATA_LAYER_PUSH_RE.search(code) and refs(code):
        findings.append(
            "Bridges GTM variables into a dataLayer push; keep it small and document the "
            "expected output fields."
        )
    if OPTIMIZE_REMNANT_RE.search(code):
        findings.append(
            "Contains a Google Optimize or anti-flicker remnant; remove the obsolete "
            "loader/hiding code after confirming no current experiment platform owns it."
        )
    return findings


def code_health_status(
    health: list[str], security: list[str], optimization: list[str]
) -> tuple[str, str]:
    if security:
        return (
            "technical_risk_review_required",
            "Harden before cleanup execution: remove risky browser APIs, keep only trusted "
            "sources, and validate the resulting container configuration.",
        )
    if health or optimization:
        return (
            "technical_cleanup_candidate",
            "Simplify where practical, then validate the edited object, references, and "
            "consumers in a new container export.",
        )
    return (
        "no_static_technical_issue",
        "No technical cleanup signal from the static export; still review business purpose "
        "separately.",
    )


def technical_code_review(
    layer: str,
    code: str,
    effects: list[str],
    formulas: dict[str, Any] | None = None,
) -> dict[str, Any]:
    formulas = formulas or expression_facts(code)
    health = code_health_findings(layer, code)
    security = code_security_findings(code)
    optimization = code_optimization_findings(layer, code, effects, formulas)
    status, recommendation = code_health_status(health, security, optimization)
    summary_parts = health + security + optimization
    return {
        "technical_code_health_status": status,
        "technical_code_health_findings": health,
        "technical_code_security_findings": security,
        "technical_code_optimization_findings": optimization,
        "technical_plain_language_summary": " ".join(summary_parts)
        if summary_parts
        else "No static technical issue detected in the exported code.",
        "technical_code_recommendation": recommendation,
    }


def technical_action_candidate(
    review: dict[str, Any], parser_status: str = "", parser_errors: list[str] | None = None
) -> str:
    status = review.get("technical_code_health_status")
    security = review.get("technical_code_security_findings") or []
    optimization = review.get("technical_code_optimization_findings") or []
    health = review.get("technical_code_health_findings") or []
    if security:
        return "fix_required"
    if any(
        marker in str(item)
        for item in health
        for marker in (
            "without an exported <script> wrapper",
            "callback-based CMP read",
        )
    ):
        return "fix_required"
    if any("No code body" in str(item) for item in health):
        return "owner_decision_needed"
    if optimization or health:
        return "consolidate_candidate"
    if parser_status in {
        "not_installed_static_review_still_required",
        "esprima_parse_failed",
    } or parser_errors:
        return "owner_decision_needed"
    if status == "no_static_technical_issue":
        return "keep"
    return "owner_decision_needed"


def technical_expected_state(action: str) -> str:
    if action in {"fix_required", "harden_required"}:
        return (
            "The same useful measurement behavior remains, but risky browser APIs, "
            "unapproved script sources, unsafe storage, or fragile page manipulation are removed."
        )
    if action == "consolidate_candidate":
        return (
            "The object is replaced by a simpler native GTM feature or one canonical helper, "
            "with the same output and timing proven before production mutation."
        )
    if action == "owner_decision_needed":
        return (
            "Owner confirms whether the code is still needed before delete, rebuild, "
            "or documented-exception decisions."
        )
    return "No technical cleanup is proposed from static code evidence."


def has_finding(review: dict[str, Any], text: str) -> bool:
    needle = text.lower()
    for key in (
        "technical_code_health_findings",
        "technical_code_security_findings",
        "technical_code_optimization_findings",
    ):
        if any(needle in str(item).lower() for item in review.get(key) or []):
            return True
    return False


def compact_values(values: list[Any], limit: int = 4) -> str:
    clean = [str(value) for value in values if value not in (None, "")]
    if not clean:
        return "none exported"
    suffix = "" if len(clean) <= limit else f" (+{len(clean) - limit} more)"
    return ", ".join(clean[:limit]) + suffix


def technical_exact_action(
    row: dict[str, Any], review: dict[str, Any], action: str
) -> str:
    actions: list[str] = []

    if has_finding(review, "Runs text as JavaScript"):
        actions.append(
            "Remove eval/new Function/string timer execution and replace it with direct code, a lookup table, or a static branch."
        )
    if has_finding(review, "dataLayer.reset"):
        actions.append(
            "Remove dataLayer.reset(); replace it with event-scoped fields or explicit key updates that preserve values required by later tags."
        )
    if has_finding(review, "google_tag_manager"):
        actions.append(
            "Replace direct google_tag_manager access with documented GTM variables, templates, dataLayer values, or supported APIs."
        )
    if has_finding(review, "Writes HTML into the page"):
        actions.append(
            "Replace direct HTML insertion with safe text/attribute updates, or prove the inserted value is never visitor-controlled."
        )
    if has_finding(review, "Calls document.write"):
        actions.append(
            "Replace document.write() with a native/template loader or scoped DOM insertion; "
            "if it is exceptionally retained, align the explicit Support document.write setting."
        )
    if has_finding(review, "without an exported <script> wrapper"):
        actions.append(
            "Wrap the JavaScript body in <script></script> without changing its variables, "
            "trigger, consent, or vendor behavior."
        )
    if has_finding(review, "callback-based CMP read"):
        actions.append(
            "Replace the callback-based CMP read with a synchronously available consent "
            "value populated before the consuming event, or move the async work into a tag."
        )
    if has_finding(review, "Google Optimize or anti-flicker remnant"):
        actions.append(
            "Remove the obsolete Optimize loader and anti-flicker branch after confirming "
            "that no active replacement experimentation platform depends on it."
        )
    if has_finding(review, "literal secret-like credential candidate"):
        actions.append(
            "Remove the embedded credential, rotate it at the owning service, and replace "
            "the integration with an approved server-side or restricted public credential route."
        )
    if has_finding(review, "literal API-key candidate"):
        actions.append(
            "Confirm the API key is browser-public and origin-restricted; otherwise remove "
            "and rotate it rather than storing it in GTM."
        )
    if has_finding(review, "without an exported origin check"):
        actions.append(
            "Add an explicit allowed-origin check before accepting postMessage data, or remove the message listener."
        )
    if has_finding(review, "http://"):
        actions.append(
            "Replace every http:// endpoint with an approved https:// endpoint, or remove the call when no secure endpoint exists."
        )
    if row.get("external_scripts_loaded"):
        actions.append(
            "Keep only approved HTTPS script loaders "
            f"({compact_values(row.get('external_scripts_loaded') or [])}); remove duplicate or dynamic loader branches."
        )
    if (
        row.get("cookies_read_written")
        or row.get("localStorage_use")
        or row.get("sessionStorage_use")
    ):
        actions.append(
            "Confirm consent runs before cookie/storage access, remove sensitive visitor values, and document the allowed key names."
        )
    if has_finding(review, "Literal cookie write omits"):
        actions.append(
            "Add the approved Secure and SameSite attributes to each literal cookie write, or replace the custom writer with the maintained consent-controlled implementation."
        )
    if row.get("dom_selector_reads"):
        actions.append(
            "Guard missing page selectors and replace DOM scraping with a dataLayer or GTM variable source when one exists."
        )
    if row.get("dom_mutations"):
        actions.append(
            "Limit the DOM mutation to the intended element and route, and remove it when no approved page behavior depends on it."
        )
    if row.get("event_listeners"):
        actions.append(
            "Ensure the browser listener is registered once per page view and only on the intended route."
        )
    if has_finding(review, "without an exported remove"):
        actions.append(
            "Add a once-only option, explicit removal, or stable registration guard so repeated GTM execution cannot accumulate listeners."
        )
    if has_finding(review, "Calls gtag() directly"):
        actions.append(
            "Compare the manual gtag call with native Google tag routes and keep one consent-aligned sender unless the separate destination is explicitly required."
        )
    if has_finding(review, "debugger statement"):
        actions.append("Remove the debugger statement from production custom code.")
    if row.get("dataLayer_pushes_or_writes"):
        actions.append(
            "List the exact dataLayer event and fields written, keep one canonical writer, and remove a duplicate writer only when exported logic proves equivalence."
        )
    if has_finding(review, "fixed product positions"):
        actions.append(
            "Replace fixed product-position ecommerce access with item-array handling that works for one or many products."
        )
    if has_finding(review, "small helper variable"):
        actions.append(
            "Compare the terminal source, transformation, return type, and consumers with a built-in variable, lookup table, regex table, or one canonical CJS variable before replacement."
        )
    if has_finding(review, "more than one script"):
        actions.append(
            "Merge duplicate loaders for the same vendor so one event creates one expected network/script request."
        )
    if has_finding(review, "window-level state"):
        actions.append(
            "Remove shared window-level state, or namespace and document it when another approved script requires it."
        )

    if not actions and action == "consolidate_candidate":
        actions.append(
            "Simplify the code into the smallest native GTM feature or canonical helper that preserves the exported output and timing."
        )
    if not actions and action == "owner_decision_needed":
        actions.append(
            "Ask the business or implementation owner whether the object is still needed before deleting, rebuilding, or documenting an exception."
        )
    if not actions:
        actions.append("No technical action is proposed from the static code scan.")

    prefix = {
        "fix_required": "Fix before cleanup execution: ",
        "harden_required": "Fix before cleanup execution: ",
        "consolidate_candidate": "Simplification candidate: ",
        "owner_decision_needed": "Decision needed: ",
        "keep": "Keep: ",
    }.get(action, "Review: ")
    return prefix + " ".join(actions)


def technical_preconditions(layer: str, action: str) -> str:
    if action in {"fix_required", "harden_required"}:
        return (
            "Confirm the business purpose, approved endpoints/keys, consent requirement, "
            "and affected routes before changing code."
        )
    if action == "consolidate_candidate":
        if layer == "variable":
            return "Confirm the terminal source, transformation, return type, and all consumer expectations before replacing the helper."
        return "Identify the exact configured event, destination, payload, consent setting, and trigger route that must remain equivalent."
    if action == "owner_decision_needed":
        return "Owner must confirm keep, rebuild, delete, or documented-exception route."
    return "No cleanup precondition from the technical scan."


def technical_qa_steps(layer: str, row: dict[str, Any], action: str) -> str:
    if action == "keep":
        return (
            "No technical container check is required unless approved cleanup changes this object."
        )
    steps = [
        "re-export the workspace and compare the changed code and configuration with the approved operation",
        "rebuild the dependency graph and confirm every reference and consumer remains valid",
    ]
    if layer == "variable":
        steps.append("recheck terminal sources, transformations, and declared return types")
    if row.get("dataLayer_pushes_or_writes"):
        steps.append("compare the configured dataLayer event name and written fields")
    if row.get("external_scripts_loaded") or row.get("network_calls"):
        steps.append("compare configured endpoints, loader count, and parameter mappings")
    if (
        row.get("cookies_read_written")
        or row.get("localStorage_use")
        or row.get("sessionStorage_use")
    ):
        steps.append("recheck exported consent settings and storage-access guards")
    if row.get("dom_reads_writes") or row.get("event_listeners"):
        steps.append(
            "recheck trigger scope and exported guards for missing selectors or repeated listeners"
        )
    return "; ".join(steps) + "."


def technical_rollback_note(row: dict[str, Any], action: str) -> str:
    if action == "keep":
        return "No rollback needed for the technical scan."
    return (
        f"Rollback by restoring exported object {row.get('object_id') or row.get('object_name')} "
        f"with code_hash={row.get('code_hash')} and config_hash={row.get('config_hash')}."
    )


def technical_handoff_packet(row: dict[str, Any]) -> str:
    return (
        f"Share object_identity={row.get('object_identity')}; "
        f"object_id={row.get('object_id')}; code_hash={row.get('code_hash')}; "
        f"referenced_gtm_variables={compact_values(row.get('referenced_gtm_variables') or [])}; "
        f"external_scripts={compact_values(row.get('external_scripts_loaded') or [])}; "
        f"side_effects={compact_values(row.get('side_effects') or [])}."
    )


def technical_current_behavior(
    layer: str, object_name: str, code: str, effects: list[str], row: dict[str, Any]
) -> str:
    signals = []
    if effects:
        signals.append("side effects: " + ", ".join(effects))
    if row.get("event_listeners"):
        signals.append("event listeners: " + ", ".join(row["event_listeners"]))
    if row.get("external_scripts_loaded"):
        signals.append("external scripts: " + ", ".join(row["external_scripts_loaded"][:4]))
    if row.get("localStorage_use"):
        signals.append("localStorage: " + ", ".join(row["localStorage_use"]))
    if row.get("sessionStorage_use"):
        signals.append("sessionStorage: " + ", ".join(row["sessionStorage_use"]))
    if row.get("dataLayer_pushes_or_writes"):
        signals.append("pushes or writes to dataLayer")
    signal_text = "; ".join(signals) if signals else "no static side effect signal"
    return (
        f"{layer} {object_name!r} contains {len(code)} characters of exported code; {signal_text}."
    )


def build_variable_consumers(cv: dict[str, Any]) -> dict[str, list[str]]:
    consumers: dict[str, list[str]] = collections.defaultdict(list)
    for layer, id_key in (
        ("tag", "tagId"),
        ("trigger", "triggerId"),
        ("variable", "variableId"),
    ):
        for item in as_list(cv.get(layer)):
            for ref in sorted(refs(item)):
                if layer == "variable" and ref == item.get("name"):
                    continue
                consumers[ref].append(
                    f"{layer} {item.get(id_key) or ''} - {item.get('name') or ''}".strip()
                )
    return dict(consumers)


def extract_export(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    blocking_integrity = [
        row for row in source_integrity_findings(data) if row.get("blocking")
    ]
    if blocking_integrity:
        raise ValueError(
            "source integrity gate blocked custom-code extraction: "
            + ", ".join(
                sorted(
                    str(row.get("finding_type") or "source_integrity_error")
                    for row in blocking_integrity
                )
            )
        )
    cv = container_version(data)
    variable_consumers = build_variable_consumers(cv)
    rows = []

    custom_objects: list[tuple[str, dict[str, Any]]] = []
    custom_objects.extend(
        ("tag", tag)
        for tag in as_list(cv.get("tag"))
        if str(tag.get("type", "")).lower() == "html" or param_value(tag, "html")
    )
    custom_objects.extend(
        ("variable", variable)
        for variable in as_list(cv.get("variable"))
        if str(variable.get("type", "")).lower() == "jsm" or param_value(variable, "javascript")
    )
    custom_objects.extend(
        ("customTemplate", template) for template in as_list(cv.get("customTemplate"))
    )

    for layer, obj in custom_objects:
        code = code_for(layer, obj)
        object_name = str(obj.get("name") or "")
        effects = side_effects(code)
        evidence_limits = container_evidence_limits(code, effects)
        template_visibility = custom_template_visibility(layer, code)
        if template_visibility == "opaque":
            evidence_limits = [
                "The exported custom-template metadata does not expose executable behavior, "
                "so implementation correctness cannot be certified from this source."
            ]
        external_script_urls = external_scripts(code)
        finding_id = f"TECH-{len(rows) + 1:05d}"
        row = {
            "technical_finding_id": finding_id,
            "layer": layer,
            "object_id": object_id(obj, layer),
            "object_name": object_name,
            "type": object_type(obj, layer),
            "object_identity": reconciliation_key(layer, obj, code),
            "source_lens": "technical",
            "code_hash": code_hash(code),
            "config_hash": stable_hash(comparable_config(obj)),
            "code_length": len(code),
            "referenced_gtm_variables": sorted(refs(obj)),
            "dataLayer_reads": bool(DATA_LAYER_REF_RE.search(code)),
            "dataLayer_pushes_or_writes": bool(DATA_LAYER_PUSH_RE.search(code)),
            "dataLayer_resets": bool(DATA_LAYER_RESET_RE.search(code)),
            "google_tag_manager_internal_access": bool(GTM_INTERNAL_OBJECT_RE.search(code)),
            "manual_gtag_calls": has_manual_gtag_call(code),
            "debugger_statements": bool(DEBUGGER_RE.search(code)),
            "cookies_read_written": bool(COOKIE_RE.search(code)),
            "localStorage_use": storage_details(code, "localStorage"),
            "sessionStorage_use": storage_details(code, "sessionStorage"),
            "dom_reads_writes": bool(DOM_RE.search(code)),
            "dom_selector_reads": bool(DOM_SELECTOR_RE.search(code)),
            "dom_mutations": bool(DOM_MUTATION_RE.search(code)),
            "event_listeners": sorted(set(EVENT_LISTENER_RE.findall(code))),
            "external_scripts_loaded": external_script_urls,
            "network_calls": bool(NETWORK_RE.search(code) or external_script_urls),
            "document_write_calls": bool(DOCUMENT_WRITE_RE.search(code)),
            "javascript_without_script_wrapper": looks_like_unwrapped_javascript(
                layer, code
            ),
            "optimize_or_antiflicker_signals": bool(OPTIMIZE_REMNANT_RE.search(code)),
            "async_cmp_callback_candidate": bool(
                layer == "variable" and ASYNC_CMP_CALLBACK_RE.search(code)
            ),
            "secret_like_credential_signals": secret_like_credential_signals(code),
            "cache_buster_signals": bool(CACHE_BUSTER_RE.search(code)),
            "base64_signals": bool(BASE64_RE.search(code)),
            "mutation_observer_signals": bool(MUTATION_OBSERVER_RE.search(code)),
            "returned_value_type": (
                "unknown_opaque"
                if template_visibility == "opaque"
                else returned_value_type(code)
                if layer == "variable"
                else "side_effect_tag_or_template"
            ),
            "side_effects": effects,
            "consumers": variable_consumers.get(object_name, []) if layer == "variable" else [],
            "behavior_can_be_understood_from_export": (
                "opaque"
                if template_visibility == "opaque"
                else "partial"
                if effects or layer == "customTemplate"
                else "yes"
            ),
            "container_evidence_limits": evidence_limits,
        }
        formulas = expression_facts(code)
        row.update(formulas)
        row.update(javascript_ast_facts(layer, code))
        review = technical_code_review(layer, code, effects, formulas)
        row.update(review)
        action = technical_action_candidate(
            review,
            str(row.get("javascript_parser") or ""),
            as_list(row.get("ast_parse_errors")),
        )
        row["technical_action_candidate"] = action
        row["technical_current_behavior"] = technical_current_behavior(
            layer, object_name, code, effects, row
        )
        row["technical_expected_clean_state"] = technical_expected_state(action)
        row["technical_exact_proposed_action"] = technical_exact_action(
            row, review, action
        )
        row["technical_preconditions"] = technical_preconditions(layer, action)
        row["technical_qa_steps"] = technical_qa_steps(layer, row, action)
        row["technical_rollback_note"] = technical_rollback_note(row, action)
        row["technical_handoff_packet"] = technical_handoff_packet(row)
        row["technical_cleanup_implication"] = row["technical_exact_proposed_action"]
        row["operation_packet_required"] = action != "keep"
        row["source_independent_of_baseline"] = True
        rows.append(row)

    return {
        **source_descriptor(path),
        "kind": "gtm_custom_code_extraction",
        "custom_code_count": len(rows),
        "rows": rows,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("export", type=Path, help="Path to a GTM container export JSON")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output")
    args = parser.parse_args()

    result = extract_export(args.export)
    print(json.dumps(result, ensure_ascii=False, indent=2 if args.pretty else None))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
