#!/usr/bin/env python3
"""Privacy helpers for generated GTM evidence and user-facing artifacts."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

SENSITIVE_KEY_RE = re.compile(
    r"(?i)(?:api[_-]?key|access[_-]?token|refresh[_-]?token|token|secret|password|"
    r"authorization|email|phone|user[_-]?id|client[_-]?id)"
)
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
WINDOWS_USER_PATH_RE = re.compile(r"(?i)\b[A-Z]:\\Users\\[^\\\s]+")
POSIX_USER_PATH_RE = re.compile(r"(?i)(?:^|\s)/(?:home|Users)/[^/\s]+")
SENSITIVE_ASSIGNMENT_RE = re.compile(
    r"(?i)(api[_-]?key|access[_-]?token|refresh[_-]?token|token|secret|password|"
    r"authorization|email|phone|user[_-]?id|client[_-]?id)"
    r"\s*[:=]\s*(?:\"([^\"]*)\"|'([^']*)'|([^&\s,;]+))"
)
SPREADSHEET_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r", "\n")


def sanitize_url(value: str) -> str:
    try:
        split = urlsplit(value)
    except ValueError:
        return "<invalid-url>"
    hostname = split.hostname or ""
    port = f":{split.port}" if split.port else ""
    netloc = hostname + port
    query = urlencode(
        [
            (key, "<redacted>" if SENSITIVE_KEY_RE.search(key) else "<value>")
            for key, _ in parse_qsl(split.query, keep_blank_values=True)
        ]
    )
    return urlunsplit((split.scheme, netloc, split.path, query, ""))


def redact_text(value: Any) -> str:
    text = str(value or "")
    text = EMAIL_RE.sub("<redacted-email>", text)
    text = WINDOWS_USER_PATH_RE.sub(r"C:\\Users\\<redacted>", text)
    text = POSIX_USER_PATH_RE.sub(" /home/<redacted>", text)
    return SENSITIVE_ASSIGNMENT_RE.sub(
        r"\1=<redacted>",
        text,
    )


def spreadsheet_safe_text(value: Any) -> str:
    """Force user-controlled spreadsheet content to remain literal text."""
    text = str(value or "")
    stripped = text.lstrip()
    if stripped.startswith(SPREADSHEET_FORMULA_PREFIXES):
        return "'" + text
    return text


def privacy_findings(value: Any) -> list[str]:
    text = str(value or "")
    findings = []
    if EMAIL_RE.search(text):
        findings.append("email_address")
    if WINDOWS_USER_PATH_RE.search(text) or POSIX_USER_PATH_RE.search(text):
        findings.append("local_user_path")
    assignments = list(SENSITIVE_ASSIGNMENT_RE.finditer(text))
    if any(
        next((group for group in match.groups()[1:] if group is not None), "").strip("\"'")
        not in {"<redacted>", "<redacted-email>"}
        for match in assignments
    ):
        findings.append("possible_secret_or_identifier")
    return sorted(set(findings))
