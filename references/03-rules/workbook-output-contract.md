# Analyst Workbook Readability Contract

This contract governs only the derived analyst workbook created after the
canonical eight-tab cleanup workbook passes its existing gate. It does not
replace or relax `workbook-architecture.md`.

## Contents

- [Position And Authority](#position-and-authority)
- [Required Inputs](#required-inputs)
- [Workbook Structure](#workbook-structure)
- [Completeness Without Column Inflation](#completeness-without-column-inflation)
- [A1 Overview](#a1-overview)
- [A2 Actions](#a2-actions)
- [A3 Decisions](#a3-decisions)
- [A4 Audit Register](#a4-audit-register)
- [A5 Custom HTML](#a5-custom-html)
- [Language](#language)
- [Transformation Manifest](#transformation-manifest)
- [Required Gate](#required-gate)

## Position And Authority

Run the readability step only after:

1. all three independent reviews pass;
2. reconciliation and future-state simulation pass;
3. the canonical workbook is built;
4. `gtm_audit_gate_check.py` passes on that canonical workbook; and
5. the canonical workbook passes the all-sheet privacy scan.

The canonical workbook and JSON audit package remain authoritative. The
readability builder copies the canonical workbook, adds human views, and never
feeds output back into a review, validator, compiler, simulator, or gate.

Use distinct roles:

- `cleanup_plan.xlsx`: unchanged canonical workbook and fallback;
- `cleanup_plan.analyst.xlsx`: preferred analyst deliverable only after the
  readability gate passes.

Deliver only the analyst workbook when its gate passes. If building or gating
it fails, reject that derived file and deliver the unchanged canonical
workbook. Do not rerun or alter the audit.

## Required Inputs

Read:

- canonical cleanup workbook;
- `audit_package_manifest.json`;
- `context.json`;
- `source_model.json`;
- `operational_review.json`;
- `configuration_review.json`;
- `architecture_review.json`;
- `technical_code_findings.json`;
- reconciled operations and their complete decision ledger;
- passing future-state gate; and
- passing three-run completion gate.

A decision-topic JSON may group owner decisions. It is optional at every record
count and is presentation input only. It cannot change a source disposition,
question, recommendation, priority, operation, or affected object.

Use this minimal shape:

```json
{
  "kind": "gtm_readability_decision_topics",
  "source_sha256": "<locked source SHA-256>",
  "topics": [
    {
      "topic_id": "D-01",
      "title": "Client-facing topic",
      "question": "One answer required from the owner",
      "recommendation": "The analyst's recommended direction",
      "source_ids": ["<owner decision ID>", "<owner decision ID>"]
    }
  ]
}
```

Every owner-decision source ID must occur once across the topic list. Do not
include keep, evidence-limit, or cleanup-operation records. The builder rejects
unknown, duplicate, missing, empty, or source-mismatched mappings. Group only
decisions that genuinely require the same owner answer. Without a map, the
deterministic fallback groups either identical normalized questions and
recommendations or cross-lens records with the same problem type, answer class,
and exact object scope. It never semantically combines two differently worded
decisions from the same review lens. This fallback works at any record count.

Context, source model, all three reviews, technical-code findings, reconciled
operations, and the future-state gate must each carry the locked source
SHA-256. A decision-topic artifact must carry that same hash. When the
completion gate exposes a top-level source hash, it must also match. Its
recognized legacy shape may omit that top-level field only when it has the
exact completion-gate kind, all three required runs, the audit-and-plan mode,
and a passing nested future-state result carrying the matching source hash.
Missing or mismatched required binding fails only the derived step.

`human_cleanup_rows.json` may remain in the package but is neither a coverage
authority nor a mutation-direction source for this transformation.

## Workbook Structure

Copy the canonical workbook and add these sheets before its unchanged sheets:

1. `A1 Overview`
2. `A2 Actions`
3. `A3 Decisions`
4. `A4 Audit Register`
5. `A5 Custom HTML`

Keep every original sheet name, value, formula, comment, hyperlink, dimensions,
and visibility state. Content preservation hashes exclude styles; the builder
must not write to original sheets.

The existing eight-tab limit and visibility rules continue to apply to the
canonical workbook. They do not apply to the derived analyst workbook. The
derived workbook is governed by this contract and its separate gate.

## Completeness Without Column Inflation

Completeness is a row-coverage rule, not a reason to duplicate technical
fields.

- A2 contains every atomic operation exactly once.
- A3 contains every `owner_decision_needed` source record exactly once.
- A4 contains every decision-ledger audit record exactly once.
- A5 contains every source Custom HTML tag exactly once.
- Every original technical sheet remains content-identical in the workbook and is
  hidden by default in the analyst copy.

Large affected-object lists may be shortened visibly only when the complete
redacted list remains in a cell note and in the unchanged technical evidence.
A shortened cell must state how many additional objects exist. No finding,
operation, decision, or Custom HTML tag may be shortened out of existence.

Do not add a Traceability sheet. Use stable IDs, links among visible human
sheets, cell notes, and the unchanged technical sheets. Do not create links to
hidden sheets. Explain in A1 how to unhide and filter technical evidence by ID
or object key.

## A1 Overview

Show only:

- project/site and container context when available;
- static audit and future-state status;
- audit-record, operation, owner-decision/topic, Custom HTML, and retained
  counts;
- operation counts by priority;
- the reconciliation arithmetic from source findings to atomic operations, retained/
  exception records, owner topics, and evidence limits;
- bulk-eligible versus individually approved operations, simulation-confirmed activation
  risk, and maintenance-only versus behavior-changing operations;
- material before/after object deltas;
- the first highest-priority cleanup actions and why they matter;
- the retained, changed, and owner-blocked measurement-family target state;
- the container-only evidence boundary;
- the next analyst step; and
- navigation between the human and technical layers.

Keep source hashes, detailed gate payloads, and machine metadata in the
manifest and `08 Source & Gates`.

Do not show a health score, invented duration, validator vocabulary, raw JSON
path, or unsupported claim such as:

- zero measurement loss;
- all integrations preserved;
- guaranteed live behaviour; or
- legal consent compliance confirmed.

## A2 Actions

Use exactly eight visible columns:

1. `Order + OP ID`
2. `Priority`
3. `Objects`
4. `Literal problem`
5. `Consequence if unchanged`
6. `Exact change`
7. `Preconditions / approval`
8. `Static verification + rollback`

Every row must be understandable without opening JSON or a hidden proof sheet.
State the exact configured problem separately from its concrete maintenance or
measurement consequence. Reject generic impact boilerplate and do not repeat the
same sentence in both columns. Translate the configured failure into its literal
effect: for example, an unbounded retry can poll for the page lifetime, a weak
origin check can accept an unrelated sender, a nullable string method can throw,
and late default consent can be evaluated after other tags. Family-preservation
counts and “see evidence” are traceability, not a substitute for that consequence.
`Exact change` comes only from structured
creations, additions, changes, remaps, renames, and deletions; editorial wording
may improve grammar but cannot select or reverse direction.

When a canonical object exists, state it first. Name every remap consumer,
source, target, and deleted object. Describe removal from the enabled
`builtInVariable` list as disable/deselect, not object deletion. State
operation-specific prerequisites and approval. Static verification must name the
post-change configuration/readback assertion and rollback route; it must not
invent Preview, browser, network, CMP, or vendor acceptance work.

Every action row carries a privacy-redacted cell note containing its complete
authoritative structured mutation: canonical key, creations, additions, changes
with full paths and values, remaps, renames, and deletions. Visible long values
may be shortened only when they explicitly point to that complete note. Creation
text names the new object as well as its layer/key. If the complete structured
mutation cannot fit losslessly in the bounded note, fail the derived build and
use the canonical fallback instead of publishing a partial action.

## A3 Decisions

Use exactly six visible columns:

1. `Decision`
2. `Question`
3. `Recommendation`
4. `Affected items`
5. `Measurement families`
6. `What the answer unlocks`

Group only source records requiring the same owner answer. Every source record
maps to exactly one topic. Explain which preserved/changed measurement families
depend on the answer and which exact operation, target state, or evidence-bound
conclusion becomes possible afterward.

For a one-source topic, include its source ID and object scope in the topic row.
For a multi-source topic, show the child count and keep every source ID as an
outline child row. Children may be collapsed by default. Parent topics never
replace source records.

If no editorial topic map is supplied, use a conservative deterministic
fallback: group only records with the same answer class, compatible exact object/route
scope, and target consequence. Keep every source record as an outline child. Folder,
naming, move, and rename decisions with large scopes show a draft target taxonomy or
rename/move proposal rather than a vague request to decide later.
This fallback must work at any source-record count and must not block workbook
delivery.

This sheet is a discussion agenda. It does not ingest approval, authorize
execution, or create a legally binding sign-off.

## A4 Audit Register

Use exactly six visible columns:

1. `ID`
2. `Area`
3. `Objects`
4. `Finding`
5. `Outcome / waiting for`
6. `Priority`

Use the reconciled decision ledger as the coverage authority. Preserve
independent source IDs even when several reviews concern the same object. The
outcome cell points to an A2 operation, A3 decision topic, or A5 Custom HTML row
when applicable. Use a compact semantic set: action plus operation ID; decision
plus topic ID; retained; documented exception; evidence limitation; or not
applicable.

Group rows by outcome for navigation. Keep action and owner-decision records
expanded. Retained, documented-exception, evidence-limit, and not-applicable
records may be outline-collapsed by default only when the visible group row
states the exact child count. Do not add visible source-scan, evidence-path,
confidence, owner, rollback, or operation-ID columns. Operation IDs belong in
the outcome text and links.

## A5 Custom HTML

Use exactly seven visible columns:

1. `Tag`
2. `State / execution context`
3. `Functional role`
4. `Technical health`
5. `Replacement / simplification candidate`
6. `Simplest safe target`
7. `Exact action / decision`

Inventory every Custom HTML tag from the locked source exactly once. State the
code length, paused/active state, configured execution/timing context, and material
static role without reproducing source code. Technical health covers parser/syntax,
control flow, returns/types/null/errors, async/sync, listeners/timers/observers,
globals, DOM/storage/privacy/security, network calls, script loading, performance, dead/duplicate
code, complexity/readability, hardcoded environments, deprecated APIs, portability,
and maintainability. Show the selected keep/optimise/repair/shorten/refactor/
consolidate/replace/remove/owner disposition.

Distinguish:

- direct dataLayer/GTM-source use;
- a potential dataLayer source sharing an exact normalized source key;
- legacy cookie, local/session storage, or DOM acquisition;
- a dataLayer producer rather than consumer;
- a vendor loader with no proven native replacement; and
- no source-proven replacement.

Column 5 also names source-qualified native tag/variable, maintained-template,
identical-code consolidation, and site-side producer candidates. Column 6 states the
smallest target that preserves the exported function. Column 7 identifies exact planned
operation IDs, owner topics, or a literal retained action. Do not hide a technical repair
behind a dataLayer-only recommendation.

A name/key match is a candidate, never proof of equivalence. State once in the
sheet that replacement requires comparison of value, type, format, timing, fallback,
route, consent state, trigger use, and every downstream consumer.

Cross-check candidate variables against every planned deletion. Surface the
exact operation ID when a candidate source is scheduled for deletion. This
warning does not cancel the operation, change a verdict, create an owner
decision, or prove that the candidate must be retained.

Link related owner-decision topics and Custom HTML rows among visible sheets so
an analyst can move from the decision agenda to the affected tag without a
separate mapping tab.

## Language

Default to English. `fr-FR` may localize builder-owned headings, statuses, and
fixed templates. Never translate IDs, GTM object names, source-authored
evidence, or structured mutation values. Do not build a general localization
framework in this release.

## Transformation Manifest

Write `cleanup_plan.analyst.manifest.json` beside the derived workbook. Refuse
any manifest path outside that directory or equal to an audit input or
workbook. The gate must verify manifest kind and schema before writing status;
it never repurposes an arbitrary JSON file. The manifest records:

- manifest kind/schema and language;
- locked source and skill version;
- basename and SHA-256 for every consumed input;
- canonical workbook hash plus each original sheet's state, dimensions, and
  value/formula/comment/hyperlink content hash;
- derived workbook hash, human-sheet order, and exact column contract;
- audit, operation, owner-source/topic, priority, and Custom HTML counts;
- decision-topic source mappings and Custom HTML cleanup conflicts;
- visible-sheet hyperlink map;
- gate statuses and errors;
- the unchanged canonical fallback.

The gate updates only this transformation manifest. It never writes to an audit
artifact or either workbook.

## Required Gate

After saving, the readability gate must:

- bind the output to SHA-256 hashes of every input it consumed;
- compare every original sheet against its pre-transformation content hash;
- verify exact A2 operation coverage, order, priority, standalone literal
  problem/consequence/change/static-verification utility, deterministic action
  direction, and complete structured-action notes;
- verify exact A3 owner-source coverage and one-topic mapping;
- verify exact A4 decision-ledger coverage;
- verify exact A5 Custom HTML coverage and valid conflict references;
- reject links to hidden or unknown sheets;
- reject formulas, placeholders, and unsupported absolute claims in human
  sheets;
- reopen the workbook;
- scan values and human-sheet notes for privacy findings; and
- record pass/fail checks in the transformation manifest.

Gate failure leaves the canonical workbook untouched and available. It never
changes or reruns the three audit scans.
