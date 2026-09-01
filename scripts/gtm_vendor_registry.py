#!/usr/bin/env python3
"""Load and validate the versioned official vendor-documentation registry."""

from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
import urllib.error
import urllib.request
from datetime import date
from functools import lru_cache
from pathlib import Path
from typing import Any

REGISTRY_PATH = (
    Path(__file__).resolve().parents[1] / "references" / "03-rules" / "vendor-registry.toml"
)
URL_CHECK_USER_AGENT = "Mozilla/5.0 (compatible; gtm-skill-doc-check/1.0)"
VENDOR_NEUTRAL_FIELDS = {
    "accountId",
    "containerId",
    "workspaceId",
    "fingerprint",
    "path",
    "tagManagerUrl",
    "notes",
    "parentFolderId",
    "name",
    "monitoringMetadata",
    "monitoringMetadataTagNameKey",
}
COMMENT_OR_LITERAL_RE = re.compile(
    r"(?P<literal>'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\"|`(?:\\.|[^`\\])*`)"
    r"|(?P<comment>/\*.*?\*/|//[^\r\n]*|<!--.*?-->)",
    re.S,
)


def load_registry(path: Path = REGISTRY_PATH) -> dict[str, Any]:
    with path.open("rb") as handle:
        return tomllib.load(handle)


@lru_cache(maxsize=8)
def _compiled_vendors(path_text: str, modified_ns: int) -> tuple[dict[str, Any], ...]:
    del modified_ns
    path = Path(path_text)
    vendors = []
    for entry in load_registry(path).get("vendors", []):
        vendors.append(
            {
                **entry,
                "compiled_patterns": [
                    re.compile(pattern, re.I) for pattern in entry.get("patterns", [])
                ],
            }
        )
    return tuple(vendors)


def compiled_vendors(path: Path = REGISTRY_PATH) -> tuple[dict[str, Any], ...]:
    resolved = path.resolve()
    return _compiled_vendors(str(resolved), resolved.stat().st_mtime_ns)


def detect_vendor_text(text: str) -> tuple[str, str]:
    entry = vendor_record(text)
    return str(entry.get("name", "Unclassified")), str(entry.get("category", "unclassified"))


def strip_code_comments(value: str) -> str:
    """Remove comments while preserving quoted endpoints and call arguments."""

    return COMMENT_OR_LITERAL_RE.sub(
        lambda match: match.group("literal") or " ",
        value,
    )


def behavior_bearing_vendor_text(
    obj: dict[str, Any], layer: str = ""
) -> str:
    """Serialize only configuration that can identify an executed integration.

    Names, notes, monitoring labels, template help/tests/terms, and other GTM UI
    metadata are not vendor evidence.  Native template identity, configured
    parameters, executable calls, and endpoints remain available.
    """

    if layer == "customTemplate":
        from gtm_lib import custom_template_executable_code

        payload: Any = {
            "type": obj.get("type"),
            "templateId": obj.get("templateId"),
            "executable_code": custom_template_executable_code(
                obj.get("templateData", obj)
            ),
        }
    else:
        payload = obj

    def project(value: Any, parent_key: str = "") -> Any:
        if isinstance(value, dict):
            return {
                key: project(child, key)
                for key, child in value.items()
                if key not in VENDOR_NEUTRAL_FIELDS
            }
        if isinstance(value, list):
            return [project(child, parent_key) for child in value]
        if isinstance(value, str) and parent_key.lower() in {
            "html",
            "javascript",
            "executable_code",
        }:
            return strip_code_comments(value)
        return value

    return json.dumps(project(payload), ensure_ascii=False, sort_keys=True)


def vendor_records(text: str) -> list[dict[str, Any]]:
    """Return every registry match while preserving preferred primary ordering."""
    entries = compiled_vendors()
    preferred_names: list[str] = []
    if re.search(r"\bUA-\d|universal analytics|\"type\"\s*:\s*\"ua\"", text, re.I):
        preferred_names.append("Universal Analytics (legacy)")
    elif re.search(r"\bAW-[A-Z0-9-]+|google ads|adwords|conversion linker", text, re.I):
        preferred_names.append("Google Ads")
    matched = [
        entry
        for entry in entries
        if any(pattern.search(text) for pattern in entry["compiled_patterns"])
    ]
    ordered = [
        entry
        for preferred_name in preferred_names
        for entry in entries
        if entry.get("name") == preferred_name
    ]
    ordered.extend(matched)
    unique: dict[str, dict[str, Any]] = {}
    for entry in ordered:
        unique.setdefault(str(entry.get("name") or ""), entry)
    return list(unique.values())


def vendor_record(text: str) -> dict[str, Any]:
    matches = vendor_records(text)
    if matches:
        return matches[0]
    return {"name": "Unclassified", "category": "unclassified", "official_docs": []}


def official_url_error(url: str, timeout: int = 12) -> str | None:
    """Return an error only when both lightweight HEAD and GET checks fail."""
    last_error = "unknown response"
    for method in ("HEAD", "GET"):
        headers = {"User-Agent": URL_CHECK_USER_AGENT}
        if method == "GET":
            headers["Range"] = "bytes=0-0"
        request = urllib.request.Request(url, method=method, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                if response.status < 400:
                    return None
                last_error = f"HTTP {response.status}"
        except urllib.error.HTTPError as exc:
            last_error = f"HTTP {exc.code}"
        except (urllib.error.URLError, TimeoutError, ValueError) as exc:
            last_error = str(exc)
    return last_error


def validate_registry(
    path: Path, online: bool = False, max_age_days: int = 180
) -> tuple[list[str], list[str]]:
    errors, warnings, _ = validate_registry_report(path, online, max_age_days)
    return errors, warnings


def validate_registry_report(
    path: Path, online: bool = False, max_age_days: int = 180
) -> tuple[list[str], list[str], dict[str, int]]:
    """Validate the registry and return explicit official-source outcomes."""

    errors: list[str] = []
    warnings: list[str] = []
    source_counts = {"attempted": 0, "succeeded": 0, "failed": 0}
    registry = load_registry(path)
    schema_version = registry.get("schema_version")
    if schema_version not in {1, 2}:
        errors.append("schema_version must be 1 or 2")
    try:
        reviewed = date.fromisoformat(str(registry.get("reviewed_on") or ""))
        age = (date.today() - reviewed).days
        if age < 0:
            errors.append("reviewed_on cannot be in the future")
        if age > max_age_days:
            warnings.append(f"registry review is {age} days old; refresh official sources")
    except ValueError:
        errors.append("reviewed_on must use YYYY-MM-DD")

    seen_names = set()
    for index, vendor in enumerate(registry.get("vendors", []), start=1):
        name = str(vendor.get("name") or "")
        if not name:
            errors.append(f"vendor {index}: missing name")
        if name in seen_names:
            errors.append(f"vendor {index}: duplicate name {name!r}")
        seen_names.add(name)
        patterns = vendor.get("patterns")
        if not isinstance(patterns, list) or not patterns:
            errors.append(f"vendor {name!r}: missing patterns")
            patterns = []
        for pattern in patterns:
            if not isinstance(pattern, str) or not pattern:
                errors.append(f"vendor {name!r}: patterns must be non-empty strings")
                continue
            try:
                re.compile(pattern, re.I)
            except re.error as exc:
                errors.append(f"vendor {name!r}: invalid pattern {pattern!r}: {exc}")
        docs = vendor.get("official_docs", [])
        if not isinstance(docs, list) or not docs:
            errors.append(f"vendor {name!r}: missing official_docs")
            docs = []
        elif len(docs) != len(set(docs)):
            errors.append(f"vendor {name!r}: duplicate official_docs URL")
        for url in docs:
            if not isinstance(url, str) or not re.fullmatch(r"https://[^\s]+", url):
                errors.append(f"vendor {name!r}: official_docs must use absolute HTTPS URLs")
        unsupported = vendor.get("unsupported_standard_events", [])
        replacements = vendor.get("event_replacements", [])
        for field, values in (
            ("unsupported_standard_events", unsupported),
            ("event_replacements", replacements),
        ):
            if not isinstance(values, list) or any(
                not isinstance(value, str) or not value.strip() for value in values
            ):
                errors.append(f"vendor {name!r}: {field} must be a list of non-empty strings")
            elif len(values) != len(set(values)):
                errors.append(f"vendor {name!r}: {field} contains duplicates")
        if isinstance(replacements, list):
            for replacement in replacements:
                if not isinstance(replacement, str):
                    continue
                parts = [part.strip() for part in replacement.split("=>")]
                if len(parts) != 2 or not all(parts):
                    errors.append(
                        f"vendor {name!r}: event replacement {replacement!r} must use old=>new"
                    )
                elif isinstance(unsupported, list) and parts[0] not in unsupported:
                    errors.append(
                        f"vendor {name!r}: replacement source {parts[0]!r} is not listed "
                        "in unsupported_standard_events"
                    )
        contracts = vendor.get("contracts", [])
        if contracts and schema_version != 2:
            errors.append(
                f"vendor {name!r}: versioned contracts require registry schema_version 2"
            )
        if contracts and not re.fullmatch(
            r"\d{4}-\d{2}-\d{2}(?:\.\d+)?",
            str(vendor.get("contract_version") or ""),
        ):
            errors.append(
                f"vendor {name!r}: contract_version must use YYYY-MM-DD or YYYY-MM-DD.N"
            )
        if not isinstance(contracts, list) or any(
            not isinstance(contract, dict) for contract in contracts
        ):
            errors.append(f"vendor {name!r}: contracts must be a list of tables")
            contracts = []
        contract_ids: set[str] = set()
        allowed_contract_fields = {
            "id",
            "event",
            "status",
            "replacement",
            "required_fields",
            "deduplication_fields",
            "required_consent_fields",
            "required_routing_fields",
            "field_rules",
            "deprecated_endpoints",
        }
        for contract_index, contract in enumerate(contracts, start=1):
            contract_id = str(contract.get("id") or "").strip()
            prefix = f"vendor {name!r}: contract {contract_index}"
            if not contract_id:
                errors.append(f"{prefix} is missing id")
            elif contract_id in contract_ids:
                errors.append(f"vendor {name!r}: duplicate contract id {contract_id!r}")
            contract_ids.add(contract_id)
            unknown_fields = sorted(set(contract) - allowed_contract_fields)
            if unknown_fields:
                errors.append(f"{prefix} has unknown fields {unknown_fields!r}")
            status = str(contract.get("status") or "supported").lower()
            if status not in {"supported", "deprecated", "unsupported"}:
                errors.append(f"{prefix} has invalid status {status!r}")
            event = str(contract.get("event") or "").strip()
            replacement = str(contract.get("replacement") or "").strip()
            if status in {"deprecated", "unsupported"} and not event:
                errors.append(f"{prefix} requires event for status {status!r}")
            if replacement and not event:
                errors.append(f"{prefix} cannot define replacement without event")
            for field in (
                "required_fields",
                "deduplication_fields",
                "required_consent_fields",
                "required_routing_fields",
                "deprecated_endpoints",
            ):
                values = contract.get(field, [])
                if not isinstance(values, list) or any(
                    not isinstance(value, str) or not value.strip()
                    for value in values
                ):
                    errors.append(f"{prefix} {field} must contain non-empty strings")
                elif len(values) != len(set(values)):
                    errors.append(f"{prefix} {field} contains duplicates")
            for endpoint in contract.get("deprecated_endpoints", []):
                if not re.fullmatch(r"https?://[^\s]+", str(endpoint)):
                    errors.append(
                        f"{prefix} deprecated_endpoints must use absolute HTTP(S) URLs"
                    )
            field_rules = contract.get("field_rules", [])
            if not isinstance(field_rules, list) or any(
                not isinstance(rule, dict) for rule in field_rules
            ):
                errors.append(f"{prefix} field_rules must be a list of tables")
                field_rules = []
            field_names: set[str] = set()
            for rule_index, rule in enumerate(field_rules, start=1):
                rule_prefix = f"{prefix} field rule {rule_index}"
                field_name = str(rule.get("field") or "").strip()
                if not field_name:
                    errors.append(f"{rule_prefix} is missing field")
                elif field_name in field_names:
                    errors.append(
                        f"{prefix} repeats field rule for {field_name!r}"
                    )
                field_names.add(field_name)
                unknown_rule_fields = sorted(
                    set(rule) - {"field", "value_type", "exact_length", "pattern"}
                )
                if unknown_rule_fields:
                    errors.append(
                        f"{rule_prefix} has unknown fields {unknown_rule_fields!r}"
                    )
                value_type = str(rule.get("value_type") or "")
                if value_type and value_type not in {"string", "number", "boolean"}:
                    errors.append(
                        f"{rule_prefix} has invalid value_type {value_type!r}"
                    )
                exact_length = rule.get("exact_length")
                if exact_length is not None and (
                    not isinstance(exact_length, int) or exact_length < 1
                ):
                    errors.append(f"{rule_prefix} exact_length must be a positive integer")
                pattern = str(rule.get("pattern") or "")
                if pattern:
                    try:
                        re.compile(pattern)
                    except re.error as exc:
                        errors.append(f"{rule_prefix} has invalid pattern: {exc}")
        if online:
            for url in docs:
                source_counts["attempted"] += 1
                if not isinstance(url, str) or not re.fullmatch(r"https://[^\s]+", url):
                    source_counts["failed"] += 1
                    continue
                try:
                    url_error = official_url_error(url)
                except Exception as exc:  # A release source check must fail closed.
                    url_error = f"{type(exc).__name__}: {exc}"
                if url_error:
                    source_counts["failed"] += 1
                    errors.append(
                        f"{name}: required official URL check failed: {url}: {url_error}"
                    )
                else:
                    source_counts["succeeded"] += 1
    if online and source_counts["attempted"] == 0:
        errors.append("online validation attempted no required official sources")
    return errors, warnings, source_counts


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registry", type=Path, default=REGISTRY_PATH)
    parser.add_argument("--online", action="store_true")
    parser.add_argument("--max-age-days", type=int, default=120)
    args = parser.parse_args()
    try:
        errors, warnings, source_counts = validate_registry_report(
            args.registry,
            args.online,
            args.max_age_days,
        )
    except Exception as exc:
        errors = [f"registry validation failed: {args.registry}: {exc}"]
        warnings = []
        source_counts = {"attempted": 0, "succeeded": 0, "failed": 0}
    for warning in warnings:
        print(f"WARNING: {warning}")
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
    print(
        json.dumps(
            {
                "status": "fail" if errors else "pass",
                "online": args.online,
                "warnings": len(warnings),
                "official_sources": source_counts,
            },
            sort_keys=True,
        )
    )
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
