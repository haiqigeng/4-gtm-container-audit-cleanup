"""Path grammar for operation actions (records.md, Path segments): split a path into segments and name a
list item by its identity. Shared by the simulation, the interface steps and the workbook."""

from __future__ import annotations

import json
import re

from .privacy import NAME_FIELDS


ROW_END = re.compile(r"\.(?=parameter:|map:|row:|list(?:[.\[]|$)|value$|map(?:[.\[]|$)|\[)|\[")


def segments(path: str) -> list[str]:
    """Split a path on dots, except inside a `row:<field>=<value>` value (values such as `user_data.email`)."""
    out, rest = [], path
    while rest:
        if rest.startswith("row:"):
            m = ROW_END.search(rest)
            seg, rest = (rest[:m.start()], rest[m.start():].lstrip(".")) if m else (rest, "")
            out.append(seg)
            continue
        part, _, rest = rest.partition(".")
        out += [p for p in re.split(r"(\[\d+\])", part) if p]
    return out


def item_identity(value) -> str:
    """How a list item is addressed: `row:<field>=<value>` for a table row, otherwise its JSON value."""
    if isinstance(value, dict) and value.get("type") == "MAP":
        entries = {m.get("key"): m.get("value") for m in value.get("map", []) or [] if isinstance(m, dict)}
        field = next((f for f in NAME_FIELDS if f in entries), None)
        if field:
            return f"row:{field}={entries[field]}"
    return json.dumps(value, sort_keys=True, ensure_ascii=False)
