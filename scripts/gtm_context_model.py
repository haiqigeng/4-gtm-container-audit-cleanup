#!/usr/bin/env python3
"""Build the persistent business and implementation context for a GTM audit."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from gtm_baseline_audit import build_execution_reachability
from gtm_consent_model import normalized_context_hosts, server_route_hosts
from gtm_lib import (
    ID_KEYS,
    SEMANTIC_LAYERS,
    as_list,
    behavior_projection,
    container_version,
    source_descriptor,
    source_integrity_findings,
    stable_hash,
)
from gtm_skill_identity import declared_identity_errors

CMP_PATTERNS = {
    "Didomi": re.compile(r"\bdidomi\b", re.I),
    "OneTrust": re.compile(r"\bone ?trust\b|optanon", re.I),
    "Cookiebot": re.compile(r"\bcookiebot\b|consent\.cookiebot\.com|cbid", re.I),
    "Consentmanager": re.compile(r"\bconsentmanager\b|cmpbox", re.I),
    "Axeptio": re.compile(r"\baxeptio\b", re.I),
}
ECOMMERCE_RE = re.compile(
    r"\b(?:purchase|view_item|add_to_cart|remove_from_cart|begin_checkout|"
    r"ecommerce\.(?:items|value|transaction_id))\b",
    re.I,
)
LEAD_RE = re.compile(
    r"\b(?:generate_lead|lead|quote|devis|form_submit|application|contact)\b",
    re.I,
)
PUBLISHER_RE = re.compile(
    r"\b(?:google ad manager|doubleclick for publishers|dfp|prebid|"
    r"adunit|ad_unit|page\.display|publisher)\b",
    re.I,
)
FUNNEL_RE = re.compile(r"\b(?:funnel|question|step|etape|checkout|form)\b", re.I)
COUNTRY_TOKEN_RE = re.compile(r"(?:^|[\s_\-/])([A-Z]{2})(?:$|[\s_\-/])")
ACRONYM_RE = re.compile(r"\b[A-Z][A-Z0-9]{1,7}\b")
URL_RE = re.compile(r"https?://[^\s\"'<>\\)]+", re.I)
ISO_ALPHA2 = frozenset(
    ["AD", "AE", "AF", "AG", "AI", "AL", "AM", "AO", "AQ", "AR", "AS", "AT", "AU", "AW", "AX", "AZ", "BA", "BB", "BD", "BE", "BF", "BG", "BH", "BI", "BJ", "BL", "BM", "BN", "BO", "BQ", "BR", "BS", "BT", "BV", "BW", "BY", "BZ", "CA", "CC", "CD", "CF", "CG", "CH", "CI", "CK", "CL", "CM", "CN", "CO", "CR", "CU", "CV", "CW", "CX", "CY", "CZ", "DE", "DJ", "DK", "DM", "DO", "DZ", "EC", "EE", "EG", "EH", "ER", "ES", "ET", "FI", "FJ", "FK", "FM", "FO", "FR", "GA", "GB", "GD", "GE", "GF", "GG", "GH", "GI", "GL", "GM", "GN", "GP", "GQ", "GR", "GS", "GT", "GU", "GW", "GY", "HK", "HM", "HN", "HR", "HT", "HU", "ID", "IE", "IL", "IM", "IN", "IO", "IQ", "IR", "IS", "IT", "JE", "JM", "JO", "JP", "KE", "KG", "KH", "KI", "KM", "KN", "KP", "KR", "KW", "KY", "KZ", "LA", "LB", "LC", "LI", "LK", "LR", "LS", "LT", "LU", "LV", "LY", "MA", "MC", "MD", "ME", "MF", "MG", "MH", "MK", "ML", "MM", "MN", "MO", "MP", "MQ", "MR", "MS", "MT", "MU", "MV", "MW", "MX", "MY", "MZ", "NA", "NC", "NE", "NF", "NG", "NI", "NL", "NO", "NP", "NR", "NU", "NZ", "OM", "PA", "PE", "PF", "PG", "PH", "PK", "PL", "PM", "PN", "PR", "PS", "PT", "PW", "PY", "QA", "RE", "RO", "RS", "RU", "RW", "SA", "SB", "SC", "SD", "SE", "SG", "SH", "SI", "SJ", "SK", "SL", "SM", "SN", "SO", "SR", "SS", "ST", "SV", "SX", "SY", "SZ", "TC", "TD", "TF", "TG", "TH", "TJ", "TK", "TL", "TM", "TN", "TO", "TR", "TT", "TV", "TW", "TZ", "UA", "UG", "UM", "US", "UY", "UZ", "VA", "VC", "VE", "VG", "VI", "VN", "VU", "WF", "WS", "YE", "YT", "ZA", "ZM", "ZW"]
)

CONTEXT_FIELDS = (
    "website_url",
    "business_model",
    "cmp",
    "markets",
    "server_routing_hosts",
    "server_consent_gating_hosts",
    "advanced_consent_mode_approvals",
    "spa",
    "canonical_ids",
    "staging_hosts",
    "do_not_touch",
    "naming_policy",
    "requested_deliverable",
)
INFERENCE_EVIDENCE = {
    "website_url": "container.domainName",
    "business_model": "reachable active-object behavior",
    "container_type": "locked WEB container usageContext",
    "cmp": "reachable active-object CMP identifiers",
    "markets": "domain ccTLD, container prefix, or Zone scope",
    "server_routing_hosts": "recognized route fields on reachable tags and Google configurations",
    "server_consent_gating_hosts": "analyst-approved downstream consent-gating ownership by exact route host",
    "advanced_consent_mode_approvals": (
        "analyst-approved destination and browser/server route scope with explicit evidence"
    ),
    "spa": "reachable History Change trigger configuration",
    "canonical_ids": "analyst-owned canonical destination or object decision",
    "staging_hosts": "behavior-bearing development/staging/QA endpoint",
    "do_not_touch": "analyst-owned exact execution fence",
    "naming_policy": "analyst-owned policy or completed container-local naming analysis",
    "requested_deliverable": "full-run contract: audit plus exact optimization plan",
}
STAGING_HOST_RE = re.compile(
    r"^(?:localhost|127\.0\.0\.1|"
    r"(?:dev|development|stage|staging|qa|uat|sandbox|preprod)(?:[-.].+))$",
    re.I,
)
ADVANCED_CONSENT_MODE_APPROVAL_FIELDS = {
    "destination_id",
    "transport_scope",
    "route_host",
    "approval_status",
    "evidence",
}
ADVANCED_CONSENT_MODE_TRANSPORT_SCOPES = {
    "direct_browser",
    "client_to_server",
}
DESTINATION_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,80}$")


def normalize_advanced_consent_mode_approvals(value: Any) -> list[dict[str, str]]:
    """Validate explicit Advanced Mode approval at destination and route grain."""

    if not isinstance(value, list):
        raise ValueError("advanced_consent_mode_approvals must be a list")
    normalized: list[dict[str, str]] = []
    identities: set[tuple[str, str, str]] = set()
    for index, raw in enumerate(value, start=1):
        label = f"advanced_consent_mode_approvals[{index}]"
        if not isinstance(raw, dict) or set(raw) != ADVANCED_CONSENT_MODE_APPROVAL_FIELDS:
            raise ValueError(f"{label} fields differ from the closed approval schema")
        destination_id = str(raw.get("destination_id") or "").strip().upper()
        transport_scope = str(raw.get("transport_scope") or "").strip()
        route_host_raw = str(raw.get("route_host") or "").strip()
        approval_status = str(raw.get("approval_status") or "").strip()
        evidence = str(raw.get("evidence") or "").strip()
        if not DESTINATION_ID_RE.fullmatch(destination_id):
            raise ValueError(f"{label}.destination_id is invalid")
        if transport_scope not in ADVANCED_CONSENT_MODE_TRANSPORT_SCOPES:
            raise ValueError(f"{label}.transport_scope is invalid")
        if approval_status != "approved":
            raise ValueError(f"{label}.approval_status must be approved")
        if len(evidence.split()) < 3:
            raise ValueError(f"{label}.evidence must identify a concrete approval basis")
        route_host = ""
        if transport_scope == "direct_browser":
            if route_host_raw:
                raise ValueError(f"{label}.route_host must be empty for direct_browser")
        else:
            normalized_hosts = normalized_context_hosts([route_host_raw])
            if len(normalized_hosts) != 1:
                raise ValueError(f"{label}.route_host must identify one exact host")
            route_host = normalized_hosts[0]
        identity = (destination_id.casefold(), transport_scope, route_host)
        if identity in identities:
            raise ValueError(f"{label} duplicates another scoped approval")
        identities.add(identity)
        normalized.append(
            {
                "destination_id": destination_id,
                "transport_scope": transport_scope,
                "route_host": route_host,
                "approval_status": approval_status,
                "evidence": evidence,
            }
        )
    return sorted(
        normalized,
        key=lambda row: (
            row["destination_id"].casefold(),
            row["transport_scope"],
            row["route_host"],
        ),
    )


def load_provided(path: Path | None) -> dict[str, Any]:
    if path is None:
        return {}
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("provided context must be a JSON object")
    return payload


def serialized_container(cv: dict[str, Any]) -> str:
    return json.dumps(cv, ensure_ascii=False, sort_keys=True)


def container_type(cv: dict[str, Any]) -> str:
    contexts = {
        str(value).upper()
        for value in as_list((cv.get("container") or {}).get("usageContext"))
    }
    if "WEB" in contexts:
        return "web"
    return "unknown"


def inferred_business_model(text: str) -> str:
    ecommerce = bool(ECOMMERCE_RE.search(text))
    lead = bool(LEAD_RE.search(text))
    publisher = bool(PUBLISHER_RE.search(text))
    detected = [
        label
        for label, present in (
            ("ecommerce", ecommerce),
            ("lead_generation", lead),
            ("publisher", publisher),
        )
        if present
    ]
    return "+".join(detected) if detected else "unknown"


def hostnames(text: str) -> list[str]:
    values = set()
    for match in URL_RE.finditer(text):
        try:
            host = urlsplit(match.group(0).rstrip(".,);\"")).hostname
        except ValueError:
            host = None
        if host:
            values.add(host.lower())
    return sorted(values)


def staging_hostnames(text: str) -> list[str]:
    return [host for host in hostnames(text) if STAGING_HOST_RE.fullmatch(host)]


def normalize_spa(value: Any) -> str:
    if isinstance(value, bool):
        return "yes" if value else "no"
    normalized = str(value or "").strip().lower()
    if normalized in {"yes", "true", "spa", "single_page_application"}:
        return "yes"
    if normalized in {"no", "false", "multi_page_application", "mpa"}:
        return "no"
    return "unknown"


def inferred_website_url(cv: dict[str, Any]) -> str:
    container = cv.get("container") if isinstance(cv.get("container"), dict) else {}
    raw_values = [container.get("domainName"), cv.get("domainName")]
    for value in [
        item
        for raw in raw_values
        for item in (raw if isinstance(raw, list) else [raw])
    ]:
        candidate = str(value or "").strip()
        if not candidate:
            continue
        if not re.match(r"^[a-z][a-z0-9+.-]*://", candidate, re.I):
            candidate = f"https://{candidate}"
        try:
            if urlsplit(candidate).hostname:
                return candidate
        except ValueError:
            continue
    return ""


def inferred_markets(cv: dict[str, Any], website_url: str) -> list[str]:
    """Return only high-confidence market evidence, not arbitrary two-letter acronyms."""
    markets: set[str] = set()
    container = cv.get("container") if isinstance(cv.get("container"), dict) else {}
    container_name = str(container.get("name") or cv.get("name") or "")
    container_prefix = re.match(r"^\s*([A-Z]{2})\s*[-_/]", container_name)
    if container_prefix and container_prefix.group(1) in ISO_ALPHA2:
        markets.add(container_prefix.group(1))
    for layer in ("zone",):
        for obj in as_list(cv.get(layer)):
            for match in COUNTRY_TOKEN_RE.finditer(str(obj.get("name") or "")):
                if match.group(1) in ISO_ALPHA2:
                    markets.add(match.group(1))
    try:
        host = urlsplit(website_url).hostname or ""
    except ValueError:
        host = ""
    suffix = host.rsplit(".", 1)[-1].upper() if "." in host else ""
    if suffix in ISO_ALPHA2:
        markets.add(suffix)
    return sorted(markets)


def context_value_present(field: str, value: Any, provided: bool = False) -> bool:
    if provided and field in {
        "cmp",
        "markets",
        "server_routing_hosts",
        "server_consent_gating_hosts",
        "advanced_consent_mode_approvals",
        "canonical_ids",
        "staging_hosts",
        "do_not_touch",
    }:
        return isinstance(value, list)
    if provided and field == "spa":
        return normalize_spa(value) in {"yes", "no"}
    if provided and field in {
        "website_url",
        "business_model",
        "naming_policy",
        "requested_deliverable",
    }:
        return isinstance(value, str) and value.strip().lower() not in {
            "",
            "unknown",
            "undecided",
        }
    if isinstance(value, (list, dict)):
        return bool(value)
    return str(value or "").strip().lower() not in {"", "unknown", "undecided"}


def build_context_evidence(
    inferred: dict[str, Any], provided: dict[str, Any]
) -> dict[str, dict[str, str]]:
    evidence: dict[str, dict[str, str]] = {}
    for field in ("container_type", *CONTEXT_FIELDS):
        if field in provided and context_value_present(field, provided.get(field), True):
            evidence[field] = {
                "status": "provided",
                "basis": "analyst-supplied intake context",
            }
        elif context_value_present(field, inferred.get(field)):
            evidence[field] = {
                "status": "high_confidence_inferred",
                "basis": INFERENCE_EVIDENCE.get(field, "deterministic container evidence"),
            }
        else:
            evidence[field] = {
                "status": "unresolved",
                "basis": "not proven by the export or supplied intake context",
            }
    return evidence


def context_content_hash(
    source_sha256: str,
    context: dict[str, Any],
    inferred_context: dict[str, Any] | None = None,
    provided_context: dict[str, Any] | None = None,
    provided_fields: list[str] | None = None,
    context_evidence: dict[str, Any] | None = None,
) -> str:
    return stable_hash(
        {
            "source_sha256": source_sha256,
            "context": context,
            "inferred_context": inferred_context or {},
            "provided_context": provided_context or {},
            "provided_fields": sorted(provided_fields or []),
            "context_evidence": context_evidence or {},
        },
        32,
    )


def build_context_model(
    export_path: Path,
    provided_path: Path | None = None,
    provided_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    data = json.loads(export_path.read_text(encoding="utf-8"))
    blocking_integrity = [
        row for row in source_integrity_findings(data) if row.get("blocking")
    ]
    if blocking_integrity:
        raise ValueError(
            "source integrity gate blocked context inference: "
            + ", ".join(
                sorted(
                    str(row.get("finding_type") or "source_integrity_error")
                    for row in blocking_integrity
                )
            )
        )
    cv = container_version(data)
    provided = dict(provided_context or load_provided(provided_path))
    unsupported_fields = sorted(set(provided) - set(CONTEXT_FIELDS))
    if unsupported_fields:
        raise ValueError(
            "provided context contains unsupported fields: "
            + ", ".join(unsupported_fields)
        )
    if "advanced_consent_mode_approvals" in provided:
        provided["advanced_consent_mode_approvals"] = (
            normalize_advanced_consent_mode_approvals(
                provided["advanced_consent_mode_approvals"]
            )
        )
    behavior_cv = behavior_projection(cv)
    reachability = build_execution_reachability(cv)
    active_keys = set(reachability.get("active_object_keys") or [])
    active_objects = {
        layer: [
            obj
            for obj in as_list(cv.get(layer))
            if f"{layer}:{obj.get(ID_KEYS[layer]) or obj.get('name') or ''}" in active_keys
        ]
        for layer in SEMANTIC_LAYERS
    }
    text = serialized_container(behavior_cv)
    active_text = serialized_container(behavior_projection(active_objects))
    names = [
        str(item.get("name") or "")
        for layer in (*SEMANTIC_LAYERS, "folder")
        for item in as_list(cv.get(layer))
    ]
    route_hosts = sorted(
        {
            host
            for layer in ("tag", "gtagConfig")
            for obj in active_objects.get(layer, [])
            for host in server_route_hosts(obj)
        }
    )
    explicit_gateway = bool(
        re.search(r"google tag gateway|tag_gateway|first.party.mode", text, re.I)
    )
    gateway_status = (
        "export_signal_detected"
        if explicit_gateway
        else "not_visible_in_container_export"
    )
    website_url = inferred_website_url(cv)
    active_history_triggers = [
        obj
        for obj in active_objects.get("trigger", [])
        if str(obj.get("type") or "").upper() == "HISTORY_CHANGE"
    ]
    detected_staging_hosts = staging_hostnames(active_text)
    inferred = {
        "website_url": website_url,
        "business_model": inferred_business_model(active_text),
        "container_type": container_type(cv),
        "requested_deliverable": "audit_and_optimization_plan",
        "cmp": sorted(
            name for name, pattern in CMP_PATTERNS.items() if pattern.search(active_text)
        ),
        "server_routing_hosts": route_hosts,
        "server_consent_gating_hosts": [],
        "advanced_consent_mode_approvals": [],
        "spa": "yes" if active_history_triggers else "unknown",
        "canonical_ids": [],
        "staging_hosts": detected_staging_hosts,
        "do_not_touch": [],
        "naming_policy": "unknown",
        "external_hosts": hostnames(text),
        "google_tag_gateway": {
            "status": gateway_status,
            "first_party_route_hosts": route_hosts,
            "container_only_limit": (
                "GTM export evidence may not include the Admin-level gateway status; "
                "confirm an active domain in Google tag gateway settings when material."
            ),
        },
        "markets": inferred_markets(cv, website_url),
        "naming_acronyms": sorted(
            {
                token
                for name in names
                for token in ACRONYM_RE.findall(name)
                if token not in {"GTM", "GA4", "HTML", "URL", "CJS", "DLV", "TR", "TG"}
            }
        )[:80],
        "business_signals": sorted(
            {
                signal
                for signal, pattern in (
                    ("ecommerce", ECOMMERCE_RE),
                    ("lead_or_quote", LEAD_RE),
                    ("publisher_or_ads", PUBLISHER_RE),
                    ("funnel_or_form", FUNNEL_RE),
                )
                if pattern.search(active_text)
            }
        ),
    }
    accepted_provided = {
        field: value
        for field, value in provided.items()
        if field != "requested_deliverable"
        and context_value_present(field, value, provided=True)
    }
    if "spa" in accepted_provided:
        accepted_provided["spa"] = normalize_spa(accepted_provided["spa"])
    context = {**inferred, **accepted_provided}
    evidence = build_context_evidence(inferred, accepted_provided)
    payload = {
        **source_descriptor(export_path),
        "kind": "gtm_audit_context",
        "schema_version": 2,
        "context": context,
        "inferred_context": inferred,
        "provided_context": provided,
        "provided_fields": sorted(accepted_provided),
        "context_evidence": evidence,
    }
    payload["context_sha256"] = context_content_hash(
        payload["source_sha256"],
        context,
        inferred,
        provided,
        payload["provided_fields"],
        evidence,
    )
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("export", type=Path)
    parser.add_argument("--provided", type=Path)
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()
    _identity_report, identity_errors = declared_identity_errors(
        Path(__file__).resolve().parents[1]
    )
    if identity_errors:
        print(
            json.dumps(
                {
                    "status": "blocked",
                    "stage": "runtime_identity_before_intake",
                    "errors": identity_errors,
                },
                ensure_ascii=False,
                indent=2 if args.pretty else None,
            )
        )
        return 2
    result = build_context_model(args.export, args.provided)
    print(json.dumps(result, ensure_ascii=False, indent=2 if args.pretty else None))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
