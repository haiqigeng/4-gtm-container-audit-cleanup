# Cleanup Workbook Architecture

This contract governs the canonical eight-tab `cleanup_plan.xlsx` only. Its
tab-count and visibility limits are intentionally unchanged. A derived
analyst-facing copy may be created only after this workbook passes its existing
gate and privacy scan; that copy is governed separately by
`workbook-output-contract.md` and `gtm_workbook_readability_gate.py`. Never run
the canonical eight-tab gate against the derived workbook.

The cleanup plan is a decision document for web analysts and marketing teams,
not a dump of agent internals.

## Contents

- [Canonical Tabs](#canonical-tabs)
- [Limits](#limits)
- [Cleanup Plan Columns](#cleanup-plan-columns)
- [General Problem Categories](#general-problem-categories)
- [Wording](#wording)
- [Separation From Change Log](#separation-from-change-log)

## Canonical Tabs

| Tab | Visibility | Purpose |
| --- | --- | --- |
| `01 Summary` | Visible | Source, scope, counts, status, route, and next step. |
| `02 Cleanup Plan` | Visible | Concise actionable issues and proposed operations. |
| `03 Operational Review` | Hidden | Run 1 findings, evidence, disposition, action. |
| `04 Configuration Review` | Hidden | Run 2 object-level behavior, verdict, defects, and action. |
| `05 Architecture Review` | Hidden | Run 3 families, chains, comparisons, target state. |
| `06 Custom Code Review` | Hidden | Object-level code coverage, behavior, effects, findings, decision. |
| `07 Reconciled Operations` | Hidden | Exact structured mutation packets. |
| `08 Source & Gates` | Hidden | Source hash and completion statuses. |

Hidden tabs remain available by unhiding. Do not password-protect them.

## Limits

- maximum eight tabs;
- exactly seven canonical columns in `02 Cleanup Plan`;
- maximum six columns in every other tab;
- only Summary and Cleanup Plan visible;
- wrapped top-aligned text;
- stable column widths, capped at 92;
- content-aware row heights, capped at 120;
- filters and frozen header row;
- no exact duplicate columns;
- no raw full export or full source code in visible tabs.
- no silent truncation in visible or hidden tabs. Hidden proof that exceeds one
  cell is continued losslessly on adjacent rows; overlong visible prose fails
  the build and must be rewritten more concisely.

## Cleanup Plan Columns

1. ID
2. Status
3. General problem category
4. Area / problem type
5. Affected object(s)
6. Problem / evidence
7. Action / priority / QA

Keep the header order exact. Apply the worksheet filter across all seven
columns. Preserve `layer:ID — Name` labels in `Affected object(s)` so an analyst
can use a text filter such as `tag:`, `trigger:`, `variable:`,
`builtInVariable:`, `folder:`, or `customTemplate:` without opening hidden
proof.

## General Problem Categories

Derive the broad category deterministically from the exact problem type. Use
only:

- `Removal & lifecycle`
- `Configuration & routing`
- `Duplication & consolidation`
- `Custom code & integrations`
- `Consent & governance`
- `Naming & organization`
- `Measurement & payload`

The broad category exists only for filtering. It never replaces or weakens the
specific `Area / problem type`, finding, evidence, action, or approval scope.
Keep the mapping centralized in `scripts/gtm_taxonomy.py`; do not let an agent
invent a category per row.

Keep one row per distinct actionable issue. A summary row may precede detailed
rows only when visual hierarchy makes the relationship clear. Homogeneous exact
duplicates, unused objects, naming, or folder work may remain one batch row,
but every atomic operation ID, action, affected object, approval choice, and QA
must be explicit. The workbook gate requires every operation ID exactly once.

Show every proposed operation and every unresolved owner question with the
analyst's recommended action. Consolidate nonblocking container-evidence limits
into one visible scope-boundary row; preserve every per-object boundary and
exact next action in the hidden reviews and machine-readable package. Do not
turn out-of-scope runtime certification into hundreds of visible cleanup tasks.
It must not prescribe runtime-QA handoffs or tests; those belong to a separate
explicitly requested acceptance workflow.
Use `layer:ID — Name` for object labels in operation, owner, and batch rows.
Omit “1 related decision” boilerplate for a single owner row; show counts only
for genuine groups.
Describe removal from the enabled `builtInVariable` list as
“Disable/deselect,” not as deleting a user-created GTM object.
The Summary must distinguish operations ready for scoped approval from the
specific objects still blocked by owner decisions, and must expose any action-
completeness failure.
When action completeness is not `pass`, show only one visible `BLOCKED-001`
draft row and accurate Summary counts. Keep the proposed mutations in the
machine-readable packet for correction, but do not display a partial operation
list as approval-ready.

Order visible rows by decision impact without changing operation IDs,
dependency-aware execution order, or hidden proof order. Lead with Critical and
High proposed actions and continue through lower-priority proposals before
unresolved owner/evidence decisions. For each action state the literal
configured problem, why GTM behaves that way, the exact change, preserved
settings/measurement, priority/approval, static verification, and rollback.
Use short analyst sentences rather than concatenating source fields under
machine-like labels. Raw JSON paths, hashes, validator phrases, and generic
“maintenance risk” text remain proof, not the primary explanation. When
invisible Unicode corrupts a variable reference, name the non-breaking or
non-standard space, show the readable intended `{{Variable}}`, and explain
that GTM performs exact name matching. The basis states active
reachability, impact, confidence, reversibility, and owner dependency. The Summary also counts retained/no-change decisions and
names a concise set of retained business families so the target architecture is
not described only through defects. It exposes measurement-family preservation,
the target-state architecture, and the container-only proof boundary.

## Wording

State the business or operational problem first, then enough technical detail to
debug it. Avoid internal terms such as run gate, source hash, candidate score,
branch ledger, or parser trace in visible rows. Avoid vague text such as
`review configuration`, `fix tracking`, or `custom code inspected`.

The visible plan and hidden proof must agree. The plan may consolidate wording,
but cannot blend unrelated problem types or hide a material object-level defect.
Hidden workbook proof uses one decision-oriented row per object, family,
comparison, and code object, with defects and unresolved contracts called out.
The machine-readable package remains the lossless source for every D3 check,
configuration branch, recursive trace/node, official contract, code line, and
member assessment. Do not duplicate that evidence into thousands of workbook
rows merely to prove it exists.

All cell content derived from container or analyst input must be literal text;
escape spreadsheet-formula prefixes. Privacy scanning covers hidden and visible
tabs by default.

## Separation From Change Log

Never add a change-log tab to the cleanup plan. The cleanup plan records proposed
work; the separate change log records executed/generated differences.

Validate with:

```powershell
python -B scripts/gtm_audit_gate_check.py cleanup_plan.xlsx --operations reconciled_operations.json --pretty
python -B scripts/gtm_privacy_scan.py cleanup_plan.xlsx
```
