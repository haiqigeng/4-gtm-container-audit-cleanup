"""Masking for secrets and personal values in every model-facing or analyst-facing output."""

from __future__ import annotations

import hashlib
import re

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
CRED_NAME_RE = re.compile(r"(secret|token|api[_-]?key|apikey|password|passwd|private[_-]?key|consumer[_-]?key|bearer|"
                          r"access[_-]?key|signature|oauth|client[_-]?secret)", re.I)
CRED_ASSIGN_RE = re.compile(
    r"(?i)((?:secret|token|api[_-]?key|apikey|password|passwd|consumer[_-]?key|access[_-]?key|client[_-]?secret)"
    r"[\w-]*\\?['\"]?\s*[:=]\s*\\?['\"])([^'\"\\]{12,})")
PII_NAME_RE = re.compile(r"(^|[_\-\s.])(e-?mail|mail|phone|tel|telephone|mobile|firstname|first_name|prenom|lastname|"
                         r"last_name|surname|nom|address|adresse|street|postcode|postal_?code|zip|zip_?code|birth|dob|"
                         r"ssn|iban)([_\-\s.]|$)", re.I)
PII_VAR_RE = re.compile(r"e-?mail|phone|t[eé]l[eé]phone|prenom|first.?name|last.?name|\bnom\b|surname|address|adresse|"
                        r"postal|zip|city|ville", re.I)
HASH_HINT_RE = re.compile(r"hash|sha-?256|sha256|crypt|encrypted|md5", re.I)
IMAGE_SUFFIXES = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp")


def mask(value: str) -> str:
    value = str(value)
    return f"<masked {len(value)} chars sha:{hashlib.sha256(value.encode()).hexdigest()[:8]}>"


def redact(text: str) -> str:
    """Mask literal emails and credential-like assignments; keep everything else literal."""
    if not text:
        return text
    text = EMAIL_RE.sub(lambda m: m.group(0) if m.group(0).lower().endswith(IMAGE_SUFFIXES) else mask(m.group(0)), text)
    return CRED_ASSIGN_RE.sub(lambda m: m.group(1) + mask(m.group(2)), text)


def redact_param(key: str, value: str) -> str:
    """Mask a value whose field name marks it as a credential; otherwise apply text redaction."""
    if CRED_NAME_RE.search(key or "") and value and "{{" not in value and len(value) >= 12:
        return mask(value)
    return redact(value)


NAME_FIELDS = ("name", "parameter", "key")
VALUE_FIELDS = ("value", "parameterValue")


def mask_structure(node):
    """The one display projection for GTM structures and action payloads.

    Field identities (parameter keys, table row names) stay readable; a value is masked when its own field
    or its table row names a credential; every other string gets text redaction (emails, assignments).
    """
    if isinstance(node, list):
        return [mask_structure(v) for v in node]
    if isinstance(node, str):
        return redact(node)
    if not isinstance(node, dict):
        return node
    if node.get("type") == "MAP" and isinstance(node.get("map"), list):
        entries = {m.get("key"): m for m in node["map"] if isinstance(m, dict)}
        row_name = next((str(entries[k].get("value", "")) for k in NAME_FIELDS if k in entries), "")
        masked_map = []
        for m in node["map"]:
            if isinstance(m, dict) and m.get("key") in VALUE_FIELDS and isinstance(m.get("value"), str):
                masked_map.append({**m, "value": redact_param(row_name, m["value"])})
            else:
                masked_map.append(mask_structure(m))
        return {**node, "map": masked_map}
    out = {}
    for k, v in node.items():
        if k == "value" and isinstance(v, str) and isinstance(node.get("key"), str):
            out[k] = redact_param(node["key"], v)
        elif k in ("key", "type"):
            out[k] = v
        else:
            out[k] = mask_structure(v)
    return out


def mask_action(action: dict) -> dict:
    """An operation's action through the same projection. A scalar value has no field of its own, so its
    identity is the path that addresses it (`...row:parameter=client_secret.map:parameterValue.value`)."""
    masked = mask_structure(action)
    if isinstance(action.get("value"), str) and action.get("path"):
        masked["value"] = redact_param(action["path"], action["value"])
    return masked
