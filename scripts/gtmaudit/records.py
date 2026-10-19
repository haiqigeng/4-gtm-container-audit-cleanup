"""Authored records: one JSONL file per worker, validated on every `add`.

A worker never edits another worker's file. The integrator changes others' records only
through `decision` records; the verifier only through `verdict` records.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .source import OBJECT_FIELDS

AREAS = tuple(f"A{n:02d}" for n in range(2, 27))  # defined for workers in records.md
CLASSES = ("defect", "optimisation", "keep", "decision", "evidence_limit")
SEVERITIES = ("Critical", "High", "Medium", "Low", "None")
READINESS = ("ready", "conditional", "blocked", "n/a")
WORKER_RE = re.compile(r"^(D[1-5][a-z]?|INT|VER)$")
# Texts the analyst reads (policy.md > Writing). They cite objects by key; the workbook shows names.
READER_FIELDS = {
    "finding": ("title", "situation", "impact", "recommendation", "question"),
    "operation": ("title", "preconditions", "verification", "rollback"),
    "summary": ("target", "naming", "limits"),
}
INTERNAL_RE = re.compile(r"\b(?:D[1-5][a-z]?|INT|VER)-(?:F|OP)\d+\b|\bC-\d{3,}\b|\bA(?:0[2-9]|1\d|2[0-6])\b"
                         r"|\b(?:parameter|map|row):|\b(?:tag|trigger|variable|template|folder)\d+\b"
                         r"|\b(?:" + "|".join(k for k in OBJECT_FIELDS if re.search("[a-z][A-Z]", k)) + r")\b")


class RecordError(ValueError):
    pass


def _require(record: dict, fields: dict[str, type], where: str) -> None:
    for name, kind in fields.items():
        if name not in record:
            raise RecordError(f"{where}: missing '{name}'")
        if not isinstance(record[name], kind):
            raise RecordError(f"{where}: '{name}' must be {kind.__name__}")
        if kind is str and not record[name].strip():
            raise RecordError(f"{where}: '{name}' is empty")


def _only(record: dict, allowed: set[str], where: str) -> None:
    extra = set(record) - allowed
    if extra:
        raise RecordError(f"{where}: unknown field(s) {sorted(extra)}")


def _object_ref(value: Any, known: set[str], where: str) -> None:
    if not isinstance(value, str) or not (value in known or value == "container" or value.startswith("new:")):
        raise RecordError(f"{where}: unknown object {value!r} (use an exact key such as tag:12, 'container', "
                          f"or a new:<layer>:<label> reference from a create action)")


def _plain(r: dict, kind: str, where: str) -> None:
    """Reader texts use GTM labels and cite objects by key; ids, area codes, paths and export fields stay out."""
    for name in READER_FIELDS[kind]:
        m = INTERNAL_RE.search(str(r.get(name, "")))
        if m:
            raise RecordError(f"{where}: {name} contains the internal notation {m.group(0)!r}; write it as the analyst "
                              f"sees it in GTM (field labels, values as shown) and cite objects by key such as tag:12 "
                              f"(policy.md, Writing)")


FINDING_FIELDS = {"type", "id", "area", "title", "class", "basis", "severity", "objects", "situation", "impact",
                  "recommendation", "question", "readiness", "operations", "candidates"}
OPERATION_FIELDS = {"type", "id", "title", "findings", "actions", "depends_on", "preconditions", "verification",
                    "rollback"}


def validate_finding(r: dict, worker: str, known: set[str]) -> None:
    where = f"finding {r.get('id', '?')}"
    _only(r, FINDING_FIELDS, where)
    _require(r, {"id": str, "area": str, "title": str, "class": str, "severity": str, "objects": list,
                 "situation": str, "impact": str}, where)
    _plain(r, "finding", where)
    if not r["id"].startswith(f"{worker}-"):
        raise RecordError(f"{where}: id must start with '{worker}-'")
    if r["area"] not in AREAS:
        raise RecordError(f"{where}: area must be one of {AREAS}")
    if r["class"] not in CLASSES:
        raise RecordError(f"{where}: class must be one of {CLASSES}")
    if r["severity"] not in SEVERITIES:
        raise RecordError(f"{where}: severity must be one of {SEVERITIES}")
    basis = r.get("basis", "")
    if r["class"] == "defect" and basis not in ("source", "policy"):
        raise RecordError(f"{where}: a defect needs basis 'source' (configuration error) or 'policy' "
                          f"(departure from the selected audit policy)")
    if r["class"] != "defect" and basis:
        raise RecordError(f"{where}: basis is only for defects")
    readiness = r.get("readiness", "n/a")
    if readiness not in READINESS:
        raise RecordError(f"{where}: readiness must be one of {READINESS}")
    if r["class"] in ("defect", "optimisation"):
        if readiness == "n/a":
            raise RecordError(f"{where}: an actionable finding needs readiness ready, conditional or blocked")
        if not r.get("recommendation", "").strip():
            raise RecordError(f"{where}: an actionable finding needs a recommendation")
        if readiness in ("ready", "conditional") and not r.get("operations"):
            raise RecordError(f"{where}: ready/conditional work needs its exact operation(s); "
                              f"use blocked plus a question when an input is missing")
        if readiness in ("conditional", "blocked") and not r.get("question", "").strip():
            raise RecordError(f"{where}: conditional/blocked work names the missing input in 'question'")
    else:
        if readiness != "n/a":
            raise RecordError(f"{where}: readiness is n/a for {r['class']}")
        if r.get("operations"):
            raise RecordError(f"{where}: only defects and optimisations carry operations")
    if r["class"] in ("decision", "evidence_limit") and not r.get("question", "").strip():
        raise RecordError(f"{where}: {r['class']} needs the exact question")
    if r["class"] == "keep" and r["severity"] != "None":
        raise RecordError(f"{where}: keep findings have severity None")
    if not r["objects"]:
        raise RecordError(f"{where}: objects must not be empty")
    for o in r["objects"]:
        _object_ref(o, known, where)
    for name in ("operations", "candidates"):
        if not isinstance(r.get(name, []), list):
            raise RecordError(f"{where}: {name} must be a list")


CREATE_LAYERS = ("tag", "trigger", "variable", "folder")
# One payload contract per action kind: field -> kind of value. records.md documents this table and
# operations.Target.apply reads exactly these fields.
ACTION_FIELDS = {
    "set": {"object": "ref", "path": "path", "value": "value"},
    "add": {"object": "ref", "path": "path", "value": "value"},
    "remove": {"object": "ref", "path": "path"},
    "create": {"layer": "layer", "ref": "new_ref", "object": "gtm_object"},
    "delete": {"object": "ref"},
    "pause": {"object": "ref"},
    "unpause": {"object": "ref"},
    "rename": {"object": "ref", "name": "text"},
    "remap": {"from": "ref", "to": "ref"},
}


def action_objects(action: dict) -> list[str]:
    """Object keys an action addresses, per its payload contract (a create addresses its new: ref)."""
    fields = ACTION_FIELDS.get(action.get("do"), {})
    return [action[f] for f, kind in fields.items() if kind in ("ref", "new_ref") and isinstance(action.get(f), str)]


def _check_field(a: dict, field: str, kind: str, known: set[str], where: str) -> None:
    value = a[field]
    if kind == "ref":
        _object_ref(value, known, f"{where} {field}")
    elif kind in ("path", "text"):
        if not isinstance(value, str) or not value.strip():
            raise RecordError(f"{where}: {field} must be a non-empty string")
    elif kind == "layer":
        if value not in CREATE_LAYERS:
            raise RecordError(f"{where}: create layer must be one of {CREATE_LAYERS}")
    elif kind == "new_ref":
        if not isinstance(value, str) or not re.fullmatch(rf"new:{a.get('layer')}:[\w-]+", value):
            raise RecordError(f"{where}: create ref must look like new:{a.get('layer')}:label")
    elif kind == "gtm_object" and (not isinstance(value, dict) or not str(value.get("name", "")).strip()):
        raise RecordError(f"{where}: create object must be the complete GTM object (a JSON object with a name)")


def validate_action(a: dict, known: set[str], where: str) -> None:
    if not isinstance(a, dict) or a.get("do") not in ACTION_FIELDS:
        raise RecordError(f"{where}: action 'do' must be one of {tuple(ACTION_FIELDS)}")
    fields = ACTION_FIELDS[a["do"]]
    missing = set(fields) - set(a)
    if missing:
        raise RecordError(f"{where}: {a['do']} needs {sorted(missing)}")
    _only(a, {"do", *fields}, where)
    for field, kind in fields.items():
        _check_field(a, field, kind, known, where)


def validate_operation(r: dict, worker: str, known: set[str]) -> None:
    where = f"operation {r.get('id', '?')}"
    _only(r, OPERATION_FIELDS, where)
    _require(r, {"id": str, "title": str, "findings": list, "actions": list, "verification": str, "rollback": str},
             where)
    _plain(r, "operation", where)
    if not r["id"].startswith(f"{worker}-OP"):
        raise RecordError(f"{where}: id must start with '{worker}-OP'")
    if not r["findings"] or not r["actions"]:
        raise RecordError(f"{where}: findings and actions must not be empty")
    for i, a in enumerate(r["actions"]):
        validate_action(a, known, f"{where} action {i}")


def validate(r: dict, worker: str, known: set[str], candidate_ids: set[str]) -> None:
    if not isinstance(r, dict) or "type" not in r:
        raise RecordError("each record is a JSON object with a 'type'")
    kind = r["type"]
    if kind == "finding":
        validate_finding(r, worker, known)
        bad = set(r.get("candidates", [])) - candidate_ids
        if bad:
            raise RecordError(f"finding {r['id']}: unknown candidate(s) {sorted(bad)}")
    elif kind == "operation":
        validate_operation(r, worker, known)
    elif kind == "dismiss":
        _only(r, {"type", "candidates", "reason"}, "dismiss")
        _require(r, {"candidates": list, "reason": str}, "dismiss")
        bad = set(r["candidates"]) - candidate_ids
        if bad or not r["candidates"]:
            raise RecordError(f"dismiss: unknown or empty candidate list {sorted(bad)}")
    elif kind == "discovery":
        _only(r, {"type", "note", "objects"}, "discovery")
        _require(r, {"note": str}, "discovery")
        for o in r.get("objects", []):
            _object_ref(o, known, "discovery")
    elif kind == "handoff":
        _only(r, {"type", "to", "note", "objects"}, "handoff")
        _require(r, {"to": str, "note": str}, "handoff")
    elif kind == "decision":
        if worker != "INT":
            raise RecordError("only the integrator (INT) records decisions")
        _only(r, {"type", "action", "ids", "reason", "record"}, "decision")
        _require(r, {"action": str, "ids": list, "reason": str}, "decision")
        if r["action"] not in ("merge", "reject", "replace", "resolve"):
            raise RecordError("decision action: merge (ids -> record), reject, replace (one id -> record), "
                              "or resolve (verdict ids handled)")
        if r["action"] in ("merge", "replace") and not isinstance(r.get("record"), dict):
            raise RecordError(f"decision {r['action']} needs the resulting record")
        if r["action"] in ("merge", "replace"):
            inner = r["record"]
            (validate_finding if inner.get("type") == "finding" else validate_operation)(inner, "INT", known)
    elif kind == "summary":
        if worker != "INT":
            raise RecordError("only the integrator (INT) records the summary")
        _only(r, {"type", "target", "naming", "limits"}, "summary")
        _require(r, {"target": str, "naming": str, "limits": str}, "summary")
        _plain(r, "summary", "summary")
    elif kind == "verdict":
        if worker != "VER":
            raise RecordError("only the verifier (VER) records verdicts")
        _only(r, {"type", "target", "verdict", "reason", "change"}, "verdict")
        _require(r, {"target": str, "verdict": str, "reason": str}, "verdict")
        if r["verdict"] not in ("confirm", "downgrade", "fix", "reject"):
            raise RecordError("verdict must be confirm, downgrade, fix or reject")
        if r["verdict"] in ("downgrade", "fix") and not r.get("change", "").strip():
            raise RecordError("downgrade/fix verdicts state the required change")
    else:
        raise RecordError("type must be finding, operation, dismiss, discovery, handoff, decision, summary or verdict")


class Store:
    def __init__(self, out: Path):
        self.out = Path(out)
        self.work = self.out / "work"

    def path(self, worker: str) -> Path:
        return self.work / f"{worker}.jsonl"

    def read(self, worker: str) -> list[dict]:
        p = self.path(worker)
        if not p.exists():
            return []
        return [json.loads(line) for line in p.read_text(encoding="utf-8").splitlines() if line.strip()]

    def workers(self) -> list[str]:
        return sorted(p.stem for p in self.work.glob("*.jsonl")) if self.work.exists() else []

    def all_ids(self) -> dict[str, str]:
        out = {}
        for w in self.workers():
            for r in self.read(w):
                if r.get("type") in ("finding", "operation"):
                    out[r["id"]] = w
                if r.get("type") == "decision" and isinstance(r.get("record"), dict):
                    out[r["record"]["id"]] = w
        return out

    def append(self, worker: str, records: list[dict], known: set[str], candidate_ids: set[str]) -> list[str]:
        if not WORKER_RE.match(worker):
            raise RecordError("worker must be D1..D5 (optional letter suffix), INT or VER")
        ids = self.all_ids()
        existing = self.read(worker)
        messages = []
        for r in records:
            validate(r, worker, known, candidate_ids)
            rid = r.get("id") if r.get("type") in ("finding", "operation") else None
            if rid and rid in ids and ids[rid] != worker:
                raise RecordError(f"{rid} belongs to {ids[rid]}; change another worker's record through an "
                                  f"integrator decision")
            if rid and any(e.get("id") == rid for e in existing):
                existing = [r if e.get("id") == rid else e for e in existing]
                messages.append(f"replaced {r['type']} {rid}")
            else:
                existing.append(r)
                messages.append(f"ok {r['type']} {rid or ''}".strip())
            if rid:
                ids[rid] = worker
        self.work.mkdir(parents=True, exist_ok=True)
        self.path(worker).write_text("".join(json.dumps(e, ensure_ascii=False) + "\n" for e in existing),
                                     encoding="utf-8")
        return messages
