"""The live audit: stored records projected through integrator decisions, then finalized and simulated.

`effective` is the single definition of which findings and operations are live, under which ids, and how
they link. `check`, `finalize`, coverage and the workbook all read that projection.
"""

from __future__ import annotations

from collections import defaultdict

from .checks import applicability
from .operations import simulate
from .records import Store, action_objects
from .source import Model

OPEN = ("conditional", "blocked")


def work_problems(model: Model, live: dict, context: dict) -> dict[str, dict]:
    """Every per-operation and per-finding work rule, in one place for `check` and `finalize`.

    Beyond applicability, work is never more ready than what it relies on: a ready operation, its declared
    prerequisites and every value it newly sends whose source or meaning another finding leaves open; a ready
    finding, the operations it links.
    """
    findings, operations = live["findings"], live["operations"]
    results = applicability(model, list(operations.values()), context)
    for f in findings.values():
        if f.get("readiness") != "ready":
            continue
        waiting = [o for o in f.get("operations", []) if operations.get(o, {}).get("readiness") in OPEN]
        results[f["id"]] = {"errors": [
            f"is ready but its change {o} waits for an answer (it also serves "
            f"{', '.join(x for x in operations[o]['findings'] if x != f['id'])}); make this finding conditional on "
            f"the same question, or split the operation" for o in waiting], "warnings": []}
    unsettled = [f for f in findings.values() if f.get("question") and
                 (f["class"] in ("decision", "evidence_limit") or f.get("readiness") in OPEN)]
    for op_id, op in operations.items():
        if op["readiness"] != "ready":
            continue
        errors = results[op_id]["errors"]
        for dep in op.get("depends_on", []):
            if operations.get(dep, {}).get("readiness") in OPEN:
                errors.append(f"is ready but depends on {dep}, which waits for an answer; make its finding "
                              f"conditional on the same question")
        sent = results[op_id]["sends"]
        for f in unsettled:
            shared = sorted(set(f["objects"]) & sent)
            if shared and f["id"] not in op["findings"]:
                errors.append(f"is ready but newly sends {', '.join(shared)}, whose meaning {f['id']} leaves open; "
                              f"make its finding conditional on that same question, or settle {f['id']}")
    return results


def verdict_problems(live: dict, verdicts: list[dict]) -> tuple[list[str], list[str]]:
    """The one reading of verdict history, for `check` and `finalize`.

    A verdict targets a live record, or one an integrator decision has since replaced, merged, rejected or
    resolved: that history stays valid. Returns (verdicts on ids nothing knows, verdicts still waiting for a
    decision).
    """
    known = set(live["findings"]) | set(live["operations"]) | live["handled"]
    unknown = [f"verdict targets {v['target']}, which is neither a live record nor one an integrator decision "
               f"handled" for v in verdicts if v["target"] not in known]
    unhandled = [f"verifier {v['verdict']} on {v['target']} is not yet handled by an integrator decision (replace, "
                 f"reject, merge or resolve)" for v in verdicts
                 if v["verdict"] != "confirm" and v["target"] in known and v["target"] not in live["handled"]]
    return unknown, unhandled


def effective(store: Store) -> dict:
    """Live findings/operations after integrator decisions, with aliases followed and links made mutual."""
    errors: list[str] = []
    findings: dict[str, dict] = {}
    operations: dict[str, dict] = {}
    dismissals, handoffs, discoveries = [], [], []
    for worker in store.workers():
        for r in store.read(worker):
            kind = r["type"]
            if kind == "finding":
                findings[r["id"]] = {**r, "worker": worker}
            elif kind == "operation":
                operations[r["id"]] = {**r, "worker": worker}
            elif kind == "dismiss":
                dismissals.append({**r, "worker": worker})
            elif kind == "handoff":
                handoffs.append({**r, "worker": worker})
            elif kind == "discovery":
                discoveries.append({**r, "worker": worker})

    aliases: dict[str, str] = {}
    handled: set[str] = set()
    decisions = [r for r in store.read("INT") if r["type"] == "decision"]
    for d in decisions:
        for rid in d["ids"]:
            if d["action"] == "resolve":
                handled.add(rid)
                continue
            if rid not in findings and rid not in operations:
                errors.append(f"decision {d['action']} names unknown id {rid}")
                continue
            findings.pop(rid, None)
            operations.pop(rid, None)
            handled.add(rid)
            if d["action"] in ("merge", "replace"):
                aliases[rid] = d["record"]["id"]
        if d["action"] in ("merge", "replace"):
            rec = {**d["record"], "worker": "INT"}
            (findings if rec["type"] == "finding" else operations)[rec["id"]] = rec

    def follow(i: str) -> str:
        seen = set()
        while i in aliases and i not in seen:
            seen.add(i)
            i = aliases[i]
        return i
    for f in findings.values():
        f["operations"] = sorted({follow(o) for o in f.get("operations", [])})
    for o in operations.values():
        o["findings"] = sorted({follow(f) for f in o.get("findings", [])})
        o["depends_on"] = sorted({follow(x) for x in o.get("depends_on", []) or []})
    for f in findings.values():
        for op in f["operations"]:
            if op not in operations:
                errors.append(f"{f['id']} links missing operation {op}")
    for o in operations.values():
        live = [f for f in o["findings"] if f in findings]
        if not live:
            errors.append(f"{o['id']} supports no remaining finding")
        for f in live:
            if o["id"] not in findings[f]["operations"]:
                findings[f]["operations"].append(o["id"])
        o["readiness"] = _readiness(o, findings)
        for dep in o["depends_on"]:
            if dep not in operations:
                errors.append(f"{o['id']} depends on missing operation {dep}")
    return {"findings": findings, "operations": operations, "aliases": aliases, "handled": handled,
            "decisions": decisions, "dismissals": dismissals, "handoffs": handoffs, "discoveries": discoveries,
            "errors": errors}


def finalize(model: Model, store: Store, candidates: list[dict], context: dict) -> dict:
    live = effective(store)
    findings, operations = live["findings"], live["operations"]
    dismissals, handoffs, discoveries = live["dismissals"], live["handoffs"], live["discoveries"]
    errors, warnings = list(live["errors"]), []
    verdicts = [r for r in store.read("VER") if r["type"] == "verdict"]
    unknown, unhandled = verdict_problems(live, verdicts)
    errors += unknown + unhandled

    confirmed = {c for f in findings.values() for c in f.get("candidates", [])}
    dismissed = {c for d in dismissals for c in d["candidates"]}
    for c in candidates:
        if c["id"] not in confirmed and c["id"] not in dismissed:
            errors.append(f"candidate {c['id']} ({c['domain']} {c['rule']}) is neither confirmed nor dismissed")
    if not any(d["worker"].startswith("D5") for d in discoveries):
        warnings.append("D5 recorded no blind-pass discovery")
    summaries = [r for r in store.read("INT") if r["type"] == "summary"]
    if not summaries:
        errors.append("the integrator has not recorded the summary (target, naming, limits)")
    sim = simulate(model, list(operations.values()), context)
    errors += [f"simulation: {e}" for e in sim["errors"]]
    warnings += [f"simulation: {w}" for w in sim["warnings"]]
    for key, result in work_problems(model, live, context).items():
        where = f"{key} with its declared prerequisites" if key in operations else key
        errors += [f"{where}: {e}" for e in result["errors"]]
        warnings += [f"{where}: {w}" for w in result["warnings"]]
    coverage = _coverage(model, findings, operations, sim)
    return {
        "source_sha256": model.sha256,
        "findings": sorted(findings.values(), key=_finding_order),
        "operations": sorted(operations.values(), key=lambda o: o["id"]),
        "coverage": coverage,
        "summary": summaries[-1] if summaries else {},
        "simulation": {k: sim[k] for k in ("ok", "errors", "warnings", "diff")},
        "dismissals": dismissals,
        "handoffs": handoffs,
        "discoveries": discoveries,
        "verdicts": verdicts,
        "errors": errors,
        "warnings": warnings,
    }


SEV = {s: i for i, s in enumerate(("Critical", "High", "Medium", "Low", "None"))}
CLASS_ORDER = {c: i for i, c in enumerate(("defect", "optimisation", "decision", "evidence_limit", "keep"))}


def _finding_order(f: dict):
    """The one reading order: priority, then what the reader does (fix, improve, decide, check, keep), then topic."""
    return (SEV.get(f["severity"], 9), CLASS_ORDER.get(f["class"], 9), f["area"], f["id"])


def _readiness(op: dict, findings: dict) -> str:
    levels = [findings[f].get("readiness", "n/a") for f in op["findings"] if f in findings]
    for level in ("blocked", "conditional", "ready"):
        if level in levels:
            return level
    return "n/a"


def _coverage(model: Model, findings: dict, operations: dict, sim: dict) -> list[dict]:
    by_object = defaultdict(set)
    for f in findings.values():
        for o in f["objects"]:
            by_object[o].add(f["id"])
    ops_by_object = defaultdict(set)
    for o in operations.values():
        for a in o["actions"]:
            for key in action_objects(a):
                ops_by_object[sim.get("refs", {}).get(key, key)].add(o["id"])
    rows = []
    for key, obj in model.objects.items():
        if obj.layer not in ("tag", "trigger", "variable", "template", "folder", "zone"):
            continue
        change = sim.get("diff", {}).get(key, {})
        ops = sorted(ops_by_object.get(key, ()))
        if change.get("change") == "deleted":
            outcome = "remove"
        elif change.get("renamed_from"):
            outcome = "rename_change" if len(change.get("fields", [])) > 1 else "rename"
        elif change or ops:
            outcome = "change"
        elif by_object.get(key):
            outcome = "finding"
        else:
            outcome = "none"
        rows.append({"object": key, "layer": obj.layer, "type": obj.type, "name": obj.name,
                     "folder": str(obj.raw.get("parentFolderId", "") or ""),
                     "status": "paused" if obj.paused else "active", "outcome": outcome,
                     "findings": sorted(by_object.get(key, ())), "operations": ops,
                     "new_name": change.get("name") if change.get("renamed_from") else None})
    created = {sim.get("refs", {}).get(a["ref"]): a for o in operations.values() for a in o["actions"]
               if a["do"] == "create"}
    for key in sim.get("created", []) or []:
        obj = created.get(key, {}).get("object", {})
        rows.append({"object": key, "layer": key.split(":")[0], "type": str(obj.get("type", "")),
                     "name": sim["diff"].get(key, {}).get("name", ""), "folder": str(obj.get("parentFolderId", "") or ""),
                     "status": "proposed", "outcome": "create", "findings": [],
                     "operations": sorted(ops_by_object.get(key, ())), "new_name": None})
    return rows
