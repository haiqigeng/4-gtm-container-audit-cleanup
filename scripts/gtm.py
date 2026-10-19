"""GTM container audit: one command-line entry point.

  intake   SOURCE [--context FILE]          material questions for the owner
  prepare  SOURCE --context FILE --out DIR [--plan FILE]  lock source, run rules, write packs
  show     DIR KEY [KEY ...]                readable object detail with consumers
  siblings DIR KEY                          objects sharing a pattern with KEY
  add      DIR --worker W --file F|-        validate and save records (JSON object, list or JSONL)
  list     DIR [--worker W] [--type T]      compact record listing
  status   DIR                              progress per worker and domain
  check    DIR --worker W                   completeness and validity of one worker's work
  finalize DIR                              merge, simulate, write final.json
  build    DIR                              write and verify the workbook
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gtmaudit import (  # noqa: E402
    VERSION,  # noqa: E402
    packs,
    render,
    rules,
    source,
)
from gtmaudit.final import effective, finalize, verdict_problems, work_problems  # noqa: E402
from gtmaudit.records import RecordError, Store  # noqa: E402

for stream in (sys.stdout, sys.stderr):
    stream.reconfigure(encoding="utf-8")


def fail(message: str, code: int = 2) -> None:
    print(f"error: {message}", file=sys.stderr)
    sys.exit(code)


def load_context(path: str | None) -> dict:
    if not path:
        return {}
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"cannot read context {path}: {exc}")


def load_out(out: str):
    out = Path(out)
    try:
        manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    except OSError:
        fail(f"{out} is not a prepared audit directory (run prepare first)")
    model = source.load(manifest["source"])
    if model.sha256 != manifest["sha256"]:
        fail("the source export changed since prepare; run prepare again into a new directory")
    context = json.loads((out / "context.json").read_text(encoding="utf-8"))
    candidates = json.loads((out / "candidates.json").read_text(encoding="utf-8"))["candidates"]
    return out, model, context, candidates


LIST_FIELDS = ("do_not_touch", "consent_mode_destinations", "consent_owned_hosts")


def questions(model: source.Model, context: dict) -> list[dict]:
    """Material questions not yet answered; each names the context field (or prepare option) it fills."""
    answers = context.get("answers") or {}
    tags = model.layer("tag")
    cmp_tags = [t.key for t in tags if source.is_cmp_tag(model, t)]
    consent_triggers = [t.key for t in model.layer("trigger") if source.has_consent_evidence(model, t.id)]
    google = [t for t in tags if t.type in source.GOOGLE_TAG_TYPES]
    destinations, hosts = set(), set()
    for t in google:
        d, h = source.consent_routes(model, t)
        destinations |= d
        hosts |= h
    qs = [
        {"fills": "source_complete", "required": True,
         "question": "Is this the complete web-container export (every tag, trigger and variable), not a selection?",
         "why": "A full audit needs the whole container; GTM can also export selected objects."},
        {"fills": "language", "question": "Is the website French-only? The workbook is then in French; otherwise in "
                                          "English (you can choose).", "why": "Workbook language."},
        {"fills": "--plan", "question": "Is there an approved tracking plan (CSV, XLSX or JSON file)?",
         "why": "Configured events are compared with the plan."},
        {"fills": "naming_convention", "question": "Should a specific naming convention be applied? (otherwise the "
                                                   "container's own convention, then the skill defaults)",
         "why": "Naming proposals follow your model first."},
        {"fills": "do_not_touch", "question": "Which objects must not be changed or removed? (exact keys or names)",
         "why": "Operations never touch protected objects."},
    ]
    if cmp_tags or consent_triggers:
        qs += [
            {"fills": "answers.cmp_mapping", "question": "Which CMP vendor/purpose identifiers correspond to which "
                                                         "tools (for example Didomi vendor IDs or OneTrust groups)?",
             "why": f"{len(consent_triggers)} triggers test consent values; names cannot prove the mapping.",
             "evidence": (cmp_tags + consent_triggers)[:8]},
            {"fills": "answers.cmp_lifecycle", "question": "After a visitor grants consent later on a page, does "
                                                           "the CMP push an update event without a reload?",
             "why": "Decides whether page-load tags blocked at first can fire after a later grant."},
        ]
    if destinations:
        qs.append({"fills": "consent_mode_destinations", "question": "Which Google destinations are approved for "
                                                                     "Advanced Consent Mode, if any?",
                   "why": "Only approved destinations may drop their client consent blocker.",
                   "evidence": sorted(destinations)})
    if hosts:
        qs.append({"fills": "consent_owned_hosts", "question": "Which server hosts own consent gating for the hits "
                                                               "routed to them, if any?",
                   "why": "Only approved hosts may receive hits without a client consent gate.",
                   "evidence": sorted(hosts)})

    def answered(field: str) -> bool:
        if field.startswith("answers."):
            return field[8:] in answers
        return field in context and field != "--plan"
    return [q for q in qs if not answered(q["fills"]) and not (q["fills"] == "source_complete" and
                                                               context.get("source_complete"))]


def validate_context(model: source.Model, context: dict) -> dict:
    if context.get("source_complete") is not True:
        fail("context.source_complete must be true (confirmed complete export); run intake first")
    for field in LIST_FIELDS:
        value = context.get(field, [])
        if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
            fail(f"context.{field} must be a list of strings")
    unknown = [k for k in context.get("do_not_touch", []) if k not in model.objects]
    if unknown:
        fail(f"context.do_not_touch names unknown objects {unknown}; use exact keys such as tag:12 (see intake)")
    return context


def cmd_intake(args) -> None:
    model = source.load(args.source)
    context = load_context(args.context)
    container = model.cv.get("container") or {}
    print(f"Container {container.get('publicId', '?')} \"{container.get('name', '')}\": "
          f"{len(model.layer('tag'))} tags, {len(model.layer('trigger'))} triggers, "
          f"{len(model.layer('variable'))} variables, {len(model.layer('template'))} templates.")
    print("Answer what you know; every question except source_complete can be skipped.")
    print(json.dumps(questions(model, context), ensure_ascii=False, indent=1))


def cmd_prepare(args) -> None:
    out = Path(args.out)
    if out.exists() and any(out.iterdir()):
        fail(f"{out} is not empty; prepare into a new directory")
    try:
        import openpyxl  # noqa: F401
    except ImportError:
        fail("openpyxl is required for the workbook: install it in this Python (pip install openpyxl)")
    model = source.load(args.source)
    context = validate_context(model, load_context(args.context))
    plan = packs.render_plan(Path(args.plan)) if args.plan else None
    result = rules.run(model)
    out.mkdir(parents=True, exist_ok=True)
    (out / "context.json").write_text(json.dumps(context, ensure_ascii=False, indent=1), encoding="utf-8")
    (out / "candidates.json").write_text(json.dumps({"candidates": rules.as_dicts(result.candidates),
                                                     "facts": result.facts}, ensure_ascii=False, indent=1),
                                         encoding="utf-8")
    written = packs.write_packs(model, result, context, out, plan)
    counts = Counter(o.layer for o in model.objects.values())
    manifest = {"skill_version": VERSION, "source": model.source_path, "sha256": model.sha256,
                "plan": str(Path(args.plan).resolve()) if args.plan else None,
                "counts": dict(counts), "packs": written,
                "candidates": dict(Counter(c.domain for c in result.candidates))}
    (out / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=1), encoding="utf-8")
    print(json.dumps({"out": str(out.resolve()), **manifest}, ensure_ascii=False, indent=1))


def cmd_show(args) -> None:
    _, model, _, _ = load_out(args.dir)
    for key in args.keys:
        obj = model.get(key)
        if not obj:
            print(f"{key}: not found")
            continue
        print(render.render(model, obj))
        deps = model.dependencies(key)
        if deps:
            print("depends on: " + "; ".join(f"{model.label(k)} [{kind}]" for k, kind in deps))
        print()


def cmd_siblings(args) -> None:
    _, model, _, _ = load_out(args.dir)
    if args.key not in model.objects:
        fail(f"{args.key} not found")
    groups = render.siblings(model, args.key)
    print(f"Siblings of {model.label(args.key)}:")
    for reason, keys in groups.items():
        print(f"- {reason} ({len(keys)}): " + "; ".join(model.label(k) for k in keys[:40]))
    if not groups:
        print("- none")


def _read_records(path: str) -> list[dict]:
    text = sys.stdin.read() if path == "-" else Path(path).read_text(encoding="utf-8")
    text = text.strip()
    try:
        data = json.loads(text)
        return data if isinstance(data, list) else [data]
    except json.JSONDecodeError:
        return [json.loads(line) for line in text.splitlines() if line.strip()]


def cmd_add(args) -> None:
    out, model, _, candidates = load_out(args.dir)
    try:
        messages = Store(out).append(args.worker, _read_records(args.file), set(model.objects),
                                     {c["id"] for c in candidates})
    except (RecordError, json.JSONDecodeError) as exc:
        fail(f"nothing saved: {exc}")
    print("\n".join(messages))


def cmd_list(args) -> None:
    out, _, _, _ = load_out(args.dir)
    store = Store(out)
    for worker in store.workers():
        if args.worker and worker != args.worker:
            continue
        for r in store.read(worker):
            if args.type and r["type"] != args.type:
                continue
            if r["type"] == "finding":
                print(f"{r['id']} [{r['class']}/{r['severity']}/{r.get('readiness', 'n/a')}] {r['area']} {r['title']} "
                      f"objects={r['objects'][:6]} ops={r.get('operations', [])}")
            elif r["type"] == "operation":
                print(f"{r['id']} [operation] {r['title']} findings={r['findings']} actions={len(r['actions'])}")
            elif args.type or args.worker:
                print(f"{worker} {json.dumps(r, ensure_ascii=False)[:300]}")


def _domain_progress(store: Store, candidates: list[dict]) -> dict[str, tuple[int, int]]:
    done = set()
    for worker in store.workers():
        for r in store.read(worker):
            if r["type"] == "finding":
                done |= set(r.get("candidates", []))
            if r["type"] == "dismiss":
                done |= set(r["candidates"])
    progress = {}
    for c in candidates:
        total, ok = progress.get(c["domain"], (0, 0))
        progress[c["domain"]] = (total + 1, ok + (c["id"] in done))
    return progress


def cmd_status(args) -> None:
    out, _, _, candidates = load_out(args.dir)
    store = Store(out)
    for domain, (total, done) in sorted(_domain_progress(store, candidates).items()):
        print(f"{domain}: candidates {done}/{total} disposed")
    for worker in store.workers():
        kinds = Counter(r["type"] for r in store.read(worker))
        print(f"{worker}: " + ", ".join(f"{k} {v}" for k, v in sorted(kinds.items())))
    if (out / "final.json").exists():
        final = json.loads((out / "final.json").read_text(encoding="utf-8"))
        print(f"final.json: {len(final['findings'])} findings, {len(final['operations'])} operations, "
              f"{len(final['errors'])} errors")


def cmd_check(args) -> None:
    out, model, context, candidates = load_out(args.dir)
    store = Store(out)
    worker = args.worker
    problems, notes = [], []
    records = store.read(worker)
    live = effective(store)
    own = {r["id"] for r in records if r["type"] in ("finding", "operation")}
    problems += [e for e in live["errors"] if e.split(" ")[0] in own or (worker == "INT" and e.startswith("decision"))]
    if worker[:2] in rules.DOMAINS:
        domain = worker[:2]
        done = set()
        for w in store.workers():
            if w[:2] == domain:
                for r in store.read(w):
                    done |= set(r.get("candidates", [])) if r["type"] in ("finding", "dismiss") else set()
        missing = [c["id"] for c in candidates if c["domain"] == domain and c["id"] not in done]
        if missing:
            problems.append(f"candidates not yet confirmed or dismissed: {missing}")
        if domain == "D5" and not any(r["type"] == "discovery" for r in records):
            problems.append("record at least one blind-pass discovery (or a discovery stating none) first")
    problems += verdict_problems(live, [r for r in records if r["type"] == "verdict"])[0]
    own_work = {r["id"] for r in [*live["operations"].values(), *live["findings"].values()] if r["worker"] == worker}
    if own_work:
        for key, result in work_problems(model, live, context).items():
            if key in own_work:
                where = f"{key} with its declared prerequisites" if key in live["operations"] else key
                problems += [f"{where}: {e}" for e in result["errors"]]
                notes += [f"{key}: {w}" for w in result["warnings"]]
    if worker == "INT":
        result = finalize(model, store, candidates, context)
        problems += result["errors"]
    print("ok" if not problems else "\n".join(f"- {p}" for p in problems))
    for note in notes:
        print(f"- note (name this prerequisite in the question): {note}")
    sys.exit(1 if problems else 0)


def cmd_finalize(args) -> None:
    out, model, context, candidates = load_out(args.dir)
    result = finalize(model, Store(out), candidates, context)
    (out / "final.json").write_text(json.dumps(result, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"final.json: {len(result['findings'])} findings, {len(result['operations'])} operations, "
          f"{len(result['errors'])} errors, {len(result['warnings'])} warnings")
    for e in result["errors"]:
        print(f"- error: {e}")
    for w in result["warnings"]:
        print(f"- warning: {w}")
    sys.exit(1 if result["errors"] else 0)


def cmd_build(args) -> None:
    from gtmaudit import workbook

    out, model, context, _ = load_out(args.dir)
    final_path = out / "final.json"
    if not final_path.exists():
        fail("run finalize first")
    final = json.loads(final_path.read_text(encoding="utf-8"))
    if final["errors"]:
        fail("final.json has errors; fix them and finalize again")
    path = workbook.build(model, final, context, out / "gtm-container-audit.xlsx")
    problems = workbook.verify(path, model, final, context)
    if problems:
        print("\n".join(f"- {p}" for p in problems))
        fail("workbook verification failed", 1)
    print(json.dumps({"workbook": str(path.resolve()), "findings": len(final["findings"]),
                      "operations": len(final["operations"]),
                      "questions": len({f["question"] for f in final["findings"] if f.get("question")})},
                     ensure_ascii=False))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("intake")
    p.add_argument("source")
    p.add_argument("--context")
    p = sub.add_parser("prepare")
    p.add_argument("source")
    p.add_argument("--context", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--plan", help="approved tracking plan (CSV, XLSX, JSON or text)")
    p = sub.add_parser("show")
    p.add_argument("dir")
    p.add_argument("keys", nargs="+")
    p = sub.add_parser("siblings")
    p.add_argument("dir")
    p.add_argument("key")
    p = sub.add_parser("add")
    p.add_argument("dir")
    p.add_argument("--worker", required=True)
    p.add_argument("--file", required=True)
    p = sub.add_parser("list")
    p.add_argument("dir")
    p.add_argument("--worker")
    p.add_argument("--type")
    for name in ("status", "finalize", "build"):
        sub.add_parser(name).add_argument("dir")
    p = sub.add_parser("check")
    p.add_argument("dir")
    p.add_argument("--worker", required=True)
    args = parser.parse_args()
    try:
        globals()[f"cmd_{args.command}"](args)
    except source.SourceError as exc:
        fail(str(exc))


if __name__ == "__main__":
    main()
