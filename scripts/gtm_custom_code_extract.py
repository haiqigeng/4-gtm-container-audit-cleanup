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
WEAK_ORIGIN_SUBSTRING_RE = re.compile(
    r"\b(?:event|e|evt)\s*\.\s*origin\s*\.\s*(?:indexOf|includes)\s*\(",
    re.I,
)
MESSAGE_DATA_LAYER_PUSH_RE = re.compile(
    r"\bdataLayer\s*\.\s*push\s*\(\s*(?:event|e|evt)\s*\.\s*data"
    r"(?:\s*\.\s*[A-Za-z_$][\w$]*)?\s*\)",
    re.I,
)
MESSAGE_PAYLOAD_GUARD_RE = re.compile(
    r"(?:typeof\s+(?:event|e|evt)\s*\.\s*data"
    r"(?:\s*\.\s*(?:payload|data))?\s*"
    r"(?:===?|!==?)\s*['\"](?:object|string)['\"]|"
    r"Array\s*\.\s*isArray\s*\(\s*(?:event|e|evt)\s*\.\s*data"
    r"(?:\s*\.\s*(?:payload|data))?|"
    r"(?:event|e|evt)\s*\.\s*data(?:\s*\.\s*(?:payload|data))?\s*&&\s*"
    r"(?:event|e|evt)\s*\.\s*data(?:\s*\.\s*(?:payload|data))?\s*\.)",
    re.I,
)
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
MUTATION_OBSERVER_DISCONNECT_RE = re.compile(r"\.\s*disconnect\s*\(", re.I)
SET_INTERVAL_RE = re.compile(r"\bsetInterval\s*\(", re.I)
CLEAR_INTERVAL_RE = re.compile(r"\bclearInterval\s*\(", re.I)
SET_TIMEOUT_RE = re.compile(r"\bsetTimeout\s*\(", re.I)
CLEAR_TIMEOUT_RE = re.compile(r"\bclearTimeout\s*\(", re.I)
FUNCTION_DECLARATION_RE = re.compile(
    r"\bfunction\s+([A-Za-z_$][\w$]*)\s*\([^)]*\)\s*\{", re.I
)
COOKIE_ASSIGNMENT_RE = re.compile(
    r"\bdocument\s*\.\s*cookie\s*=\s*(?P<rhs>[^;]{1,1600})", re.I | re.S
)
COOKIE_DAY_MULTIPLIER_RE = re.compile(
    r"\b(?P<input>days?|expires?|duration|ttl)\b\s*\*\s*"
    r"(?P<factor>\d+(?:\.\d+)?)\s*\*\s*24\s*\*\s*60\s*\*\s*60\s*\*\s*1000\b",
    re.I,
)
READY_STATE_RE = re.compile(r"\bdocument\s*\.\s*readyState\b", re.I)
WINDOW_LOAD_LISTENER_RE = re.compile(
    r"(?:window\s*\.\s*)?addEventListener\s*\(\s*['\"]load['\"]", re.I
)
EMPTY_CATCH_RE = re.compile(r"\bcatch\s*\([^)]*\)\s*\{\s*\}", re.I | re.S)
CONSOLE_RE = re.compile(r"\bconsole\s*\.\s*(?:log|debug|info|trace)\s*\(", re.I)
HARDCODED_ENVIRONMENT_RE = re.compile(
    r"\b(?:G-[A-Z0-9]{6,}|AW-[0-9]{6,}|DC-[0-9]{4,}|GTM-[A-Z0-9]+)\b|"
    r"https?://(?:localhost|(?:dev|staging|preprod|qa)[.-])",
    re.I,
)
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


def cookie_write_facts(code: str) -> list[dict[str, Any]]:
    """Classify literal writes without treating deletion as cookie creation."""

    facts: list[dict[str, Any]] = []
    for match in COOKIE_LITERAL_WRITE_RE.finditer(code):
        literal = match.group("cookie")
        parts = [part.strip() for part in literal.split(";")]
        first = parts[0] if parts else ""
        name, separator, _value = first.partition("=")
        attributes: dict[str, str | bool] = {}
        for part in parts[1:]:
            attr_name, attr_separator, attr_value = part.partition("=")
            normalized = attr_name.strip().casefold()
            if normalized:
                attributes[normalized] = attr_value.strip() if attr_separator else True
        max_age = str(attributes.get("max-age") or "").strip()
        expires = str(attributes.get("expires") or "").strip().casefold()
        deletion = bool(
            re.fullmatch(r"-?\d+", max_age)
            and int(max_age) <= 0
            or re.search(
                r"(?:^|\b)(?:thu,?\s*)?(?:01\s+jan\s+1970|jan\s+01\s+1970|"
                r"1970-01-01|expires\s+in\s+the\s+past)",
                expires,
                re.I,
            )
        )
        facts.append(
            {
                "operation": "delete" if deletion else "set_or_update",
                "name": name.strip() if separator else "",
                "path": str(attributes.get("path") or ""),
                "domain": str(attributes.get("domain") or ""),
                "secure": "secure" in attributes,
                "same_site": str(attributes.get("samesite") or ""),
                "max_age": max_age,
                "expires": expires,
            }
        )
    return facts


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


def _balanced_brace_body(source: str, opening_brace: int) -> str:
    """Return one JavaScript block body without pretending to be a full parser."""

    depth = 0
    quote = ""
    escaped = False
    line_comment = False
    block_comment = False
    index = opening_brace
    while index < len(source):
        char = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""
        if line_comment:
            if char in "\r\n":
                line_comment = False
            index += 1
            continue
        if block_comment:
            if char == "*" and following == "/":
                block_comment = False
                index += 2
                continue
            index += 1
            continue
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            index += 1
            continue
        if char == "/" and following == "/":
            line_comment = True
            index += 2
            continue
        if char == "/" and following == "*":
            block_comment = True
            index += 2
            continue
        if char in "'\"`":
            quote = char
            index += 1
            continue
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return source[opening_brace + 1 : index]
        index += 1
    return ""


def declared_function_bodies(layer: str, code: str) -> dict[str, str]:
    source = javascript_source(layer, code)
    bodies: dict[str, str] = {}
    for match in FUNCTION_DECLARATION_RE.finditer(source):
        body = _balanced_brace_body(source, match.end() - 1)
        if body:
            bodies[match.group(1)] = body
    return bodies


def recursive_timeout_facts(layer: str, code: str) -> list[dict[str, Any]]:
    """Find source-visible self-scheduling setTimeout loops and their bounds."""

    facts: list[dict[str, Any]] = []
    for name, body in declared_function_bodies(layer, code).items():
        escaped_name = re.escape(name)
        direct = re.search(
            rf"\bsetTimeout\s*\(\s*{escaped_name}\b", body, re.I
        )
        callback = any(
            re.search(rf"\b{escaped_name}\s*\(", match.group(0), re.I)
            for match in re.finditer(
                r"\bsetTimeout\s*\(.{0,700}?\)", body, re.I | re.S
            )
        )
        if not (direct or callback):
            continue
        counter_term = r"(?:attempts?|tries|retries|retry|count|polls?|deadline|max\w*)"
        has_limit = bool(
            re.search(
                rf"\bif\s*\([^)]*\b{counter_term}\b[^)]*(?:>=|>|<=|<|===?|!==?)[^)]*\)",
                body,
                re.I,
            )
            or re.search(
                rf"\bif\s*\([^)]*(?:Date\s*\.\s*now\s*\(\)|\b{counter_term}\b)"
                rf"[^)]*(?:deadline|timeout|max\w*)[^)]*\)",
                body,
                re.I,
            )
        )
        facts.append(
            {
                "function": name,
                "bounded": has_limit,
                "scheduling": "direct_callback" if direct else "nested_callback",
            }
        )
    return facts


def cookie_duration_multiplier_facts(code: str) -> list[dict[str, str]]:
    facts: list[dict[str, str]] = []
    for match in COOKIE_DAY_MULTIPLIER_RE.finditer(code):
        factor = float(match.group("factor"))
        declares_days = bool(
            match.group("input").lower().startswith("day")
            or re.search(r"\b(?:is|in|as)\s+days?\b", code, re.I)
        )
        if declares_days and factor != 1:
            facts.append(
                {
                    "input": match.group("input"),
                    "factor": match.group("factor"),
                    "expression": re.sub(r"\s+", " ", match.group(0)).strip(),
                }
            )
    return facts


def dynamic_cookie_missing_attributes(code: str) -> list[str]:
    """Identify non-literal cookie setters that visibly omit modern attributes."""

    if not COOKIE_ASSIGNMENT_RE.search(code):
        return []
    literal_facts = cookie_write_facts(code)
    if any(fact.get("operation") == "set_or_update" for fact in literal_facts):
        return []
    if literal_facts and all(fact.get("operation") == "delete" for fact in literal_facts):
        return []
    deletion_signals = bool(
        re.search(
            r"\b(?:delete|remove|erase)Cookie\b|max-age\s*=\s*-|"
            r"(?:01\s+jan\s+1970|1970-01-01)|setTime\s*\(\s*0\s*\)",
            code,
            re.I,
        )
    )
    setter_signals = bool(
        re.search(r"\bsetCookie\b|\b(?:expires?|days?|ttl)\b", code, re.I)
    )
    if deletion_signals and not setter_signals:
        return []
    missing = []
    if not re.search(r"\bSecure\b", code, re.I):
        missing.append("Secure")
    if not re.search(r"\bSameSite\b", code, re.I):
        missing.append("SameSite")
    return missing


def string_coercion_undefined_facts(layer: str, code: str) -> list[dict[str, str]]:
    """Find String(value) where the visible producer can fall through as undefined."""

    facts: list[dict[str, str]] = []
    bodies = declared_function_bodies(layer, code)
    for returned in re.finditer(
        r"\breturn\s+String\s*\(\s*([A-Za-z_$][\w$]*)\s*\)\s*;?", code, re.I
    ):
        variable = returned.group(1)
        assignment = re.search(
            rf"\b(?:var|let|const)\s+{re.escape(variable)}\s*=\s*"
            r"([A-Za-z_$][\w$]*)\s*\(",
            code,
        )
        if not assignment:
            continue
        producer = assignment.group(1)
        body = bodies.get(producer, "")
        if not body or not re.search(r"\bif\s*\([^)]*\)\s*return\b", body, re.I):
            continue
        tail = re.sub(r"\s+", " ", body).strip()
        if re.search(
            r"(?:^|[;}])\s*(?:return\b[^;]*|throw\b[^;]*);?\s*$", tail, re.I
        ):
            continue
        facts.append({"variable": variable, "producer": producer})
    return facts


def semantic_name_output_findings(layer: str, object_name: str, code: str) -> list[str]:
    normalized_name = re.sub(r"[^a-z0-9]+", " ", object_name.lower()).strip()
    if (
        layer == "variable"
        and re.search(r"\b(?:local\s+)?hour\b", normalized_name)
        and re.search(r"\bDate\s*\.\s*now\s*\(\s*\)", code)
        and not re.search(r"\bget(?:UTC)?Hours\s*\(", code, re.I)
    ):
        return [
            "Variable name promises an hour value but the exported function returns "
            "Date.now(), which is an epoch timestamp in milliseconds."
        ]
    return []


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


def code_health_findings(
    layer: str,
    code: str,
    ast_facts: dict[str, Any] | None = None,
    object_name: str = "",
) -> list[str]:
    findings: list[str] = []
    ast_facts = ast_facts or {}
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
        if ONCE_EVENT_LISTENER_RE.search(code) and not LISTENER_GUARD_RE.search(code):
            findings.append(
                "Listener lifecycle relies on once:true without a stable registration "
                "guard; once limits a registered callback but does not prevent duplicate "
                "registrations before the event occurs."
            )
        elif not (
            REMOVE_EVENT_LISTENER_RE.search(code)
            or LISTENER_GUARD_RE.search(code)
        ):
            findings.append(
                "Registers a browser event listener without an exported remove, once-only "
                "option, or registration guard; repeated GTM execution can accumulate handlers."
            )
        if WINDOW_LOAD_LISTENER_RE.search(code) and not READY_STATE_RE.search(code):
            findings.append(
                "Registers a window load listener without a document.readyState branch; "
                "the handler can be missed when GTM executes after load has already fired."
            )
    if SET_INTERVAL_RE.search(code) and not CLEAR_INTERVAL_RE.search(code):
        findings.append(
            "Starts setInterval without an exported clearInterval lifecycle; repeated GTM "
            "execution can retain duplicate polling loops."
        )
    for fact in recursive_timeout_facts(layer, code):
        if not fact["bounded"]:
            findings.append(
                "Recursively schedules setTimeout for function "
                f"{fact['function']!r} without an exported attempt, duration, or "
                "completion bound; the polling loop can continue for the page lifetime."
            )
    if MUTATION_OBSERVER_RE.search(code) and not MUTATION_OBSERVER_DISCONNECT_RE.search(code):
        findings.append(
            "Creates a MutationObserver without an exported disconnect lifecycle; bound its "
            "target, completion condition, and repeated-execution behavior."
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
    if layer == "variable" and returned_value_type(code) == "dynamic_expression":
        findings.append(
            "Custom JavaScript variable exposes mixed or unproven return types; define null, "
            "undefined, error, and fallback behavior for every consumer path."
        )
    for fact in string_coercion_undefined_facts(layer, code):
        findings.append(
            f"String() converts {fact['variable']!r} from {fact['producer']!r}, whose "
            "exported function can fall through without a value; missing input becomes the "
            "literal string 'undefined'."
        )
    findings.extend(semantic_name_output_findings(layer, object_name, code))
    branch_count = int(ast_facts.get("ast_branch_count") or 0)
    if branch_count >= 16:
        findings.append(
            f"Contains {branch_count} parsed branch expressions; reduce nesting or split "
            "independent responsibilities while preserving exact outputs and timing."
        )
    if EMPTY_CATCH_RE.search(code):
        findings.append(
            "Contains an empty catch block that hides failures; handle the expected error or "
            "remove the catch without changing the success path."
        )
    if CONSOLE_RE.search(code):
        findings.append(
            "Contains production console logging; remove debug-only output unless it is an "
            "approved operational diagnostic."
        )
    nonblank_lines = [line for line in code.splitlines() if line.strip()]
    if len(code) > 1200 and len(nonblank_lines) <= 3:
        findings.append(
            "Code is densely minified or compressed, reducing reviewability; use readable "
            "maintained source without changing its configured behavior."
        )
    if HARDCODED_ENVIRONMENT_RE.search(code):
        findings.append(
            "Contains a hardcoded container, destination, or environment identifier; verify "
            "portability and move approved environment-specific values to canonical GTM inputs."
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
    cookie_facts = cookie_write_facts(code)
    set_scopes: dict[str, set[tuple[str, str]]] = collections.defaultdict(set)
    for fact in cookie_facts:
        if fact["operation"] == "set_or_update" and fact["name"]:
            set_scopes[str(fact["name"])].add(
                (str(fact["path"]), str(fact["domain"]))
            )
    for fact in cookie_facts:
        if fact["operation"] == "delete":
            name = str(fact["name"] or "<dynamic name>")
            scope = (str(fact["path"]), str(fact["domain"]))
            known_scopes = set_scopes.get(name, set())
            if not fact["name"] or not known_scopes or scope not in known_scopes:
                cookie_attribute_findings.append(
                    "Literal cookie deletion has no source-proven matching set/update scope; "
                    f"verify the exact name/path/domain for {name!r}. Secure and SameSite are "
                    "not automatically added to deletion writes."
                )
            continue
        missing = [
            attribute
            for attribute, present in (
                ("Secure", bool(fact["secure"])),
                ("SameSite", bool(fact["same_site"])),
            )
            if not present
        ]
        if missing:
            cookie_attribute_findings.append(
                "Literal cookie set/update omits exported "
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
            MESSAGE_LISTENER_RE.search(code) and WEAK_ORIGIN_SUBSTRING_RE.search(code),
            "Checks postMessage origin with substring matching on event.origin; an unrelated "
            "origin containing the trusted text can pass. Use exact origins or an exact "
            "allowlist lookup.",
        ),
        (
            MESSAGE_LISTENER_RE.search(code)
            and MESSAGE_DATA_LAYER_PUSH_RE.search(code)
            and not MESSAGE_PAYLOAD_GUARD_RE.search(code),
            "Pushes a postMessage payload directly into dataLayer without an exported payload "
            "shape/type allowlist; validate the accepted object and fields before the push.",
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
    missing_dynamic_attributes = dynamic_cookie_missing_attributes(code)
    if missing_dynamic_attributes:
        findings.append(
            "Dynamic cookie set/update omits exported "
            + " and ".join(missing_dynamic_attributes)
            + " attributes; add the policy-approved attributes or use the maintained "
            "consent-controlled cookie implementation."
        )
    for fact in cookie_duration_multiplier_facts(code):
        findings.append(
            "Cookie duration multiplies the declared day count by "
            f"{fact['factor']} before the normal day-to-millisecond conversion "
            f"({fact['expression']}); remove the unintended extra multiplier or rename and "
            "document the actual input unit."
        )
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
    if len(code) > 1200 and HARDCODED_ENVIRONMENT_RE.search(code):
        findings.append(
            "Separates portable logic from environment-specific IDs/endpoints poorly; "
            "centralize the approved configuration instead of duplicating code per environment."
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
    ast_facts: dict[str, Any] | None = None,
    object_name: str = "",
) -> dict[str, Any]:
    formulas = formulas or expression_facts(code)
    health = code_health_findings(layer, code, ast_facts, object_name)
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
            "Recursively schedules setTimeout",
            "missing input becomes the literal string 'undefined'",
            "name promises an hour value",
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
            "with the same output and timing proven before a separate authorised implementation."
        )
    if action == "owner_decision_needed":
        return (
            "Owner confirms whether the code is still needed before delete, rebuild, "
            "or documented-exception decisions."
        )
    return "No technical cleanup is proposed from static code evidence."


def technical_disposition(
    row: dict[str, Any], review: dict[str, Any], action: str
) -> str:
    """Select one analyst-readable outcome from the complete static review."""

    if action == "keep":
        return "keep"
    if action == "owner_decision_needed":
        return "owner"
    if any(
        has_finding(review, marker)
        for marker in (
            "literal secret-like credential",
            "Runs text as JavaScript",
            "dataLayer.reset",
            "callback-based CMP read",
            "without an exported <script> wrapper",
        )
    ):
        return "repair"
    if any(
        has_finding(review, marker)
        for marker in ("Google Optimize", "debugger statement", "No code body")
    ):
        return "remove"
    if has_finding(review, "more than one script"):
        return "consolidate"
    if any(
        has_finding(review, marker)
        for marker in (
            "small helper variable",
            "Calls gtag() directly",
            "google_tag_manager",
            "fixed product positions",
        )
    ):
        return "replace"
    if any(
        has_finding(review, marker)
        for marker in (
            "Large custom code block",
            "Very large custom code block",
            "densely minified",
            "parsed branch expressions",
            "empty catch block",
        )
    ):
        return "refactor"
    if len(str(row.get("technical_plain_language_summary") or "")) > 1200:
        return "shorten"
    return "optimise"


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
            "the integration with an approved restricted external credential service."
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
    if has_finding(review, "origin with substring matching"):
        actions.append(
            "Replace event.origin substring matching with equality against the complete approved origin or membership in an exact-origin allowlist."
        )
    if has_finding(review, "postMessage payload directly into dataLayer"):
        actions.append(
            "Before dataLayer.push(), require the approved payload type and copy only the allowed event and parameter fields into a new object."
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
    if has_finding(review, "Literal cookie set/update omits"):
        actions.append(
            "For each cookie set/update, add only the policy-approved Secure and SameSite attributes, or replace the custom writer with the maintained consent-controlled implementation."
        )
    if has_finding(review, "Dynamic cookie set/update omits"):
        actions.append(
            "Add the policy-approved Secure and SameSite attributes to the dynamic cookie setter, preserving its exact name, path, domain, value, and consent route."
        )
    if has_finding(review, "Cookie duration multiplies the declared day count"):
        actions.append(
            "Remove the extra duration multiplier so the declared day count is converted once with days × 24 × 60 × 60 × 1000, then preserve the intended retention period explicitly."
        )
    if has_finding(review, "Literal cookie deletion has no source-proven"):
        actions.append(
            "For each cookie deletion, match the original cookie name, path, and domain exactly; do not add Secure or SameSite merely because the write deletes a cookie."
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
            "Align listener registration with the tag trigger, paused state, document readiness, and intended route; use a stable page-level guard and a real cleanup path where the lifecycle requires one."
        )
    if has_finding(review, "without an exported remove") or has_finding(
        review, "relies on once:true"
    ):
        actions.append(
            "Prevent duplicate registration with a stable guard or trigger-level once-per-page execution; use once:true only to limit callback execution, not as proof that registration cannot duplicate."
        )
    if has_finding(review, "window load listener without"):
        actions.append(
            "If document.readyState already indicates load completion, run the handler immediately; otherwise register the load listener behind the same stable guard."
        )
    if has_finding(review, "setInterval without"):
        actions.append(
            "Store the interval handle and clear it at the source-proven completion or teardown condition, or replace polling with the existing event/dataLayer signal."
        )
    if has_finding(review, "Recursively schedules setTimeout"):
        actions.append(
            "Add a finite attempt or elapsed-time limit to the recursive timeout and stop scheduling after success or expiry; prefer an existing readiness event when available."
        )
    if has_finding(review, "MutationObserver without"):
        actions.append(
            "Disconnect the observer after its bounded completion condition and prevent duplicate observer construction on repeated tag execution."
        )
    if has_finding(review, "Calls gtag() directly"):
        actions.append(
            "Compare the manual gtag call with native Google tag routes and keep one consent-aligned sender unless the separate destination is explicitly required."
        )
    if has_finding(review, "debugger statement"):
        actions.append("Remove the debugger statement from production custom code.")
    if has_finding(review, "literal string 'undefined'"):
        actions.append(
            "Return an explicit empty/null fallback before String() coercion so an absent source cannot become the literal text 'undefined'."
        )
    if has_finding(review, "name promises an hour value"):
        actions.append(
            "Either return the intended local hour with Date.getHours() or rename the variable and every consumer to state that it returns an epoch-millisecond timestamp."
        )
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
        steps.append("recheck terminal sources, value mappings, and declared return types")
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
            "cookie_writes": cookie_write_facts(code),
            "localStorage_use": storage_details(code, "localStorage"),
            "sessionStorage_use": storage_details(code, "sessionStorage"),
            "dom_reads_writes": bool(DOM_RE.search(code)),
            "dom_selector_reads": bool(DOM_SELECTOR_RE.search(code)),
            "dom_mutations": bool(DOM_MUTATION_RE.search(code)),
            "event_listeners": sorted(set(EVENT_LISTENER_RE.findall(code))),
            "listener_lifecycle": {
                "registration_count": len(EVENT_LISTENER_RE.findall(code)),
                "has_stable_registration_guard": bool(LISTENER_GUARD_RE.search(code)),
                "uses_once_true": bool(ONCE_EVENT_LISTENER_RE.search(code)),
                "has_remove_listener": bool(REMOVE_EVENT_LISTENER_RE.search(code)),
                "window_load_listener": bool(WINDOW_LOAD_LISTENER_RE.search(code)),
                "ready_state_branch": bool(READY_STATE_RE.search(code)),
            },
            "timer_lifecycle": {
                "set_interval": bool(SET_INTERVAL_RE.search(code)),
                "clear_interval": bool(CLEAR_INTERVAL_RE.search(code)),
                "set_timeout": bool(SET_TIMEOUT_RE.search(code)),
                "clear_timeout": bool(CLEAR_TIMEOUT_RE.search(code)),
                "recursive_timeout_functions": recursive_timeout_facts(layer, code),
            },
            "observer_lifecycle": {
                "mutation_observer": bool(MUTATION_OBSERVER_RE.search(code)),
                "disconnect": bool(MUTATION_OBSERVER_DISCONNECT_RE.search(code)),
            },
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
            "postmessage_security": {
                "listener": bool(MESSAGE_LISTENER_RE.search(code)),
                "origin_check_present": bool(ORIGIN_CHECK_RE.search(code)),
                "weak_origin_substring_check": bool(WEAK_ORIGIN_SUBSTRING_RE.search(code)),
                "direct_data_layer_payload_push": bool(
                    MESSAGE_DATA_LAYER_PUSH_RE.search(code)
                ),
                "payload_shape_guard": bool(MESSAGE_PAYLOAD_GUARD_RE.search(code)),
            },
            "cookie_duration_multiplier_facts": cookie_duration_multiplier_facts(code),
            "dynamic_cookie_missing_attributes": dynamic_cookie_missing_attributes(code),
            "string_coercion_undefined_facts": string_coercion_undefined_facts(
                layer, code
            ),
            "semantic_name_output_findings": semantic_name_output_findings(
                layer, object_name, code
            ),
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
        review = technical_code_review(
            layer, code, effects, formulas, row, object_name=object_name
        )
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
        row["technical_disposition"] = technical_disposition(row, review, action)
        row["technical_disposition_vocabulary"] = [
            "keep",
            "optimise",
            "repair",
            "shorten",
            "refactor",
            "consolidate",
            "replace",
            "remove",
            "owner",
        ]
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
